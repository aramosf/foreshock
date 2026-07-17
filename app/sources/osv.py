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

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

from dateutil.parser import isoparse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingest.affected import AffectedInput, VersionRangeInput, classify_kind
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, register

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
            intro = fixed = last = None
            for ev in r.get("events") or []:
                intro = ev.get("introduced", intro)
                fixed = ev.get("fixed", fixed)
                last = ev.get("last_affected", last)
            if intro or fixed or last:
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
        cutoff = datetime.now(UTC) - timedelta(days=30 * settings.osv_months)
        ecosystems = [e.strip() for e in settings.osv_ecosystems.split(",") if e.strip()]
        out: list[FetchedMention] = []
        for eco in ecosystems:
            try:
                out.extend(await self._scan_eco(ctx, eco, cutoff, settings.osv_max_per_ecosystem))
            except Exception as exc:  # noqa: BLE001 - un ecosistema no tumba la fuente
                log.warning("osv.eco_error", ecosystem=eco, error=str(exc))
        return out

    async def _scan_eco(self, ctx: FetchContext, eco: str, cutoff: datetime, cap: int
                        ) -> list[FetchedMention]:
        resp = await ctx.http.get(BUCKET.format(eco=eco), timeout=120.0)
        resp.raise_for_status()
        out: list[FetchedMention] = []
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                if cap > 0 and len(out) >= cap:
                    break
                try:
                    rec = json.loads(zf.read(name))
                except (json.JSONDecodeError, KeyError):
                    continue
                # 'published' (fecha real), fallback a 'modified'.
                date_str = rec.get("published") or rec.get("modified")
                seen = None
                if date_str:
                    try:
                        seen = isoparse(date_str)
                        if seen < cutoff:
                            continue
                    except (ValueError, TypeError):
                        seen = None

                osv_id = rec.get("id")
                aliases = rec.get("aliases") or []
                cve = _cve_alias(aliases)
                if not cve and not osv_id:
                    continue
                is_malware = bool(osv_id and osv_id.upper().startswith("MAL-"))
                summary = rec.get("summary") or rec.get("details") or ""
                affected, labels = _affected(rec, is_malware)
                # Todos los aliases al snippet -> extract_identifiers los ancla.
                alias_txt = " ".join(a for a in aliases if a != cve)
                snippet = summary
                if labels:
                    snippet = f"{summary} | affected: {', '.join(labels[:10])}"
                if alias_txt:
                    snippet = f"{snippet} | aliases: {alias_txt}"
                out.append(
                    FetchedMention(
                        url=f"https://osv.dev/vulnerability/{osv_id}" if osv_id else None,
                        title=(summary[:200] or cve or osv_id),
                        snippet=snippet[:2000] if snippet else None,
                        cve_id=cve,
                        native_id=osv_id,
                        seen_at=seen,
                        affected=affected or None,
                        cvss_vectors=_cvss_vectors(rec) or None,
                        cwe_ids=_cwe_ids(rec) or None,
                        reference_urls=_references(rec) or None,
                        withdrawn=bool(rec.get("withdrawn")) or None,
                    )
                )
        log.info("osv.eco_done", ecosystem=eco, mentions=len(out))
        return out
