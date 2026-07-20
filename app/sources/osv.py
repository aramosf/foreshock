"""Tier 4 — OSV.dev (advisories de ecosistemas de paquetes).

Regla de oro: OSV antes que scrapear GHSA. Descarga el volcado `all.zip` por
ecosistema, filtra por `published` (fecha real) de los últimos N meses, y de cada
advisory extrae TODO lo aprovechable:
  - id de OSV + todos los aliases (varios CVE/GHSA) -> identifiers
  - severity (vectores CVSS v3/v4) -> cvss_scores AUTORITATIVOS
  - affected[].package (+ purl) y ranges -> affected_products + affected_version_ranges
  - database_specific.cwe_ids -> candidates.cwe_ids
  - references -> candidates.reference_urls
  - withdrawn -> candidates.withdrawn
"""

from __future__ import annotations

import re

import json
import zipfile
from datetime import UTC, datetime, timedelta


from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingest.affected import AffectedInput, VersionRangeInput, classify_kind
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.cache import cached_download

log = get_logger(__name__)

BUCKET = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"


def _cve_alias(aliases: list[str]) -> str | None:
    for a in aliases:
        if a.upper().startswith("CVE-"):
            return a.upper()
    return None


def _cvss_vectors(rec: dict) -> list[str]:
    """Vectores CVSS de severity de nivel superior y de affected[]."""
    out: list[str] = []
    for sev in rec.get("severity") or []:
        score = sev.get("score", "")
        if isinstance(score, str) and score.startswith("CVSS:"):
            out.append(score)
    for a in rec.get("affected") or []:
        for sev in a.get("severity") or []:
            score = sev.get("score", "")
            if isinstance(score, str) and score.startswith("CVSS:"):
                out.append(score)
    return list(dict.fromkeys(out))  # únicos, en orden


_MALWARE_TITLE = re.compile(r"^\s*malicious (package|code)", re.IGNORECASE)


def _affected(rec: dict, is_malware: bool) -> tuple[list[AffectedInput], list[str]]:
    """Devuelve (afectados estructurados, etiquetas 'eco:name' para el snippet)."""
    items: list[AffectedInput] = []
    labels: list[str] = []
    for a in rec.get("affected") or []:
        pkg = a.get("package") or {}
        eco, name = pkg.get("ecosystem"), pkg.get("name")
        if not name:
            continue
        ranges: list[VersionRangeInput] = []
        for r in a.get("ranges") or []:
            vtype = r.get("type")
            # Un range OSV puede traer VARIOS pares introduced->fixed (p.ej.
            # [{introduced:0},{fixed:1.2},{introduced:2.0},{fixed:2.5}]): cada
            # `introduced` ABRE un rango nuevo y `fixed`/`last_affected` lo
            # cierran. Colapsarlos en uno solo perdería los pares intermedios.
            intro = fixed = last = None
            open_range = False
            for ev in r.get("events") or []:
                if "introduced" in ev:
                    if open_range:
                        ranges.append(VersionRangeInput(
                            introduced=intro, fixed=fixed, last_affected=last,
                            version_type=vtype))
                    intro, fixed, last = ev.get("introduced"), None, None
                    open_range = True
                if "fixed" in ev:
                    fixed = ev.get("fixed")
                    open_range = True
                if "last_affected" in ev:
                    last = ev.get("last_affected")
                    open_range = True
            if open_range and (intro or fixed or last):
                ranges.append(VersionRangeInput(
                    introduced=intro, fixed=fixed, last_affected=last, version_type=vtype))
        items.append(AffectedInput(
            product=name, ecosystem=eco, purl=pkg.get("purl"),
            kind=classify_kind(eco, is_malware),
            exact_versions=(a.get("versions") or None),
            ranges=ranges,
        ))
        rng = ""
        if ranges and ranges[0].fixed:
            rng = f"<{ranges[0].fixed}"
        labels.append(f"{eco}:{name} {rng}".strip())
    return items, labels


def _cwe_ids(rec: dict) -> list[str]:
    ds = rec.get("database_specific") or {}
    cwes = ds.get("cwe_ids") or ds.get("cwes") or []
    return [c for c in cwes if isinstance(c, str)]


def _references(rec: dict) -> list[str]:
    return [r.get("url") for r in (rec.get("references") or []) if r.get("url")]


@register
class OsvSource(BaseSource):
    name = "osv"
    kind = "OSV.dev ecosystem advisories (all.zip)"
    method = "api"
    tier = 4
    cadence_seconds = 21600  # 6 h (volcado grande)

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        # osv_months <= 0 -> sin ventana (histórico COMPLETO del ecosistema).
        cutoff = (datetime.now(UTC) - timedelta(days=30 * settings.osv_months)
                  if settings.osv_months > 0 else None)
        ecosystems = [e.strip() for e in settings.osv_ecosystems.split(",") if e.strip()]
        out: list[FetchedMention] = []
        for eco in ecosystems:
            try:
                out.extend(await self._scan_eco(ctx, eco, cutoff, settings.osv_max_per_ecosystem))
            except Exception as exc:  # noqa: BLE001 - un ecosistema no tumba la fuente
                log.warning("osv.eco_error", ecosystem=eco, error=str(exc))
        return out

    async def _scan_eco(self, ctx: FetchContext, eco: str, cutoff: datetime | None,
                        cap: int) -> list[FetchedMention]:
        # Descarga cacheada a disco (reusa el zip si es reciente; lo conserva para
        # recreaciones). ZipFile lee las entradas de forma perezosa -> sin OOM.
        # El cap NO se aplica en orden del zip (alfabético: descartaría los
        # advisories más recientes): primero se recolecta TODO lo que cae en la
        # ventana, se ordena por `modified` DESC y se corta después.
        collected: list[tuple[datetime, FetchedMention]] = []
        epoch = datetime.min.replace(tzinfo=UTC)  # sin fecha -> al final
        key = f"osv_{eco.replace('/', '_').replace(' ', '_')}.zip"
        zip_path = await cached_download(ctx.http, BUCKET.format(eco=eco), key=key)
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    rec = json.loads(zf.read(name))
                except (json.JSONDecodeError, KeyError):
                    continue
                m = self._to_mention(rec, cutoff)
                if m is not None:
                    collected.append((self._modified_at(rec) or epoch, m))
        collected.sort(key=lambda t: t[0], reverse=True)
        out = [m for _, m in (collected[:cap] if cap > 0 else collected)]
        if cap > 0 and len(collected) > cap:
            log.warning("osv.eco_capped", ecosystem=eco, cap=cap,
                        discarded=len(collected) - cap)
        log.info("osv.eco_done", ecosystem=eco, mentions=len(out))
        return out

    @staticmethod
    def _modified_at(rec: dict) -> datetime | None:
        """Fecha `modified` (fallback `published`) UTC-aware, para ordenar el cap.
        Descarta fechas cero/imposibles (< 1990, ver parse_advisory_date)."""
        for field in ("modified", "published"):
            dt = parse_advisory_date(rec.get(field))
            if dt is not None:
                return dt
        return None

    @staticmethod
    def _to_mention(rec: dict, cutoff: datetime | None) -> FetchedMention | None:
        # seen_at = fecha REAL de publicación; fallback a 'modified'. Se validan
        # ambas (parse_advisory_date descarta la fecha cero '0001-...' de Debian,
        # que si no aterrizaría como first_seen_at en el año 1).
        seen = parse_advisory_date(rec.get("published")) or parse_advisory_date(
            rec.get("modified"))
        if seen is not None and cutoff is not None and seen < cutoff:
            return None  # publicado fuera de la ventana (osv_months>0)
        osv_id = rec.get("id")
        aliases = rec.get("aliases") or []
        cve = _cve_alias(aliases)
        if not cve and not osv_id:
            return None
        # Advisories INFORMATIVOS (RUSTSEC "unmaintained"/"notice"...): no son
        # vulnerabilidades; se descartan para no ensuciar `pending`. El flag vive
        # en database_specific a nivel raíz O dentro de cada affected[].
        if (rec.get("database_specific") or {}).get("informational") or any(
            (a.get("database_specific") or {}).get("informational")
            for a in (rec.get("affected") or [])
        ):
            return None
        summary = rec.get("summary") or rec.get("details") or ""
        # Malware: por id MAL-*, por alias MAL-* (GHSA espejo de un MAL) o por
        # título "Malicious Package"/"malicious code" (GHSA sin alias MAL).
        is_malware = bool(
            (osv_id and osv_id.upper().startswith("MAL-"))
            or any(a.upper().startswith("MAL-") for a in aliases)
            or _MALWARE_TITLE.match(summary or "")
        )
        affected, labels = _affected(rec, is_malware)
        alias_txt = " ".join(a for a in aliases if a != cve)
        snippet = summary
        if labels:
            snippet = f"{summary} | affected: {', '.join(labels[:10])}"
        if alias_txt:
            snippet = f"{snippet} | aliases: {alias_txt}"
        return FetchedMention(
            url=f"https://osv.dev/vulnerability/{osv_id}" if osv_id else None,
            title=(summary[:200] or cve or osv_id),
            snippet=snippet[:2000] if snippet else None,
            cve_id=cve, native_id=osv_id, seen_at=seen,
            # aliases del MISMO advisory -> identidad declarada (fusionan correctamente).
            extra_ids=[a for a in aliases if a != cve] or None,
            affected=affected or None,
            cvss_vectors=_cvss_vectors(rec) or None,
            cwe_ids=_cwe_ids(rec) or None,
            reference_urls=_references(rec) or None,
            withdrawn=bool(rec.get("withdrawn")) or None,
        )
