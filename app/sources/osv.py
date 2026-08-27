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

import asyncio
import heapq
import json
import os
import re
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from app.baseline.state import read_cursor, write_cursor
from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingest.affected import AffectedInput, VersionRangeInput, classify_kind
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.cache import cached_download

log = get_logger(__name__)

BUCKET = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
_BATCH_SIZE = 500
_CURSOR_OVERLAP = timedelta(minutes=5)


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
        """Compatibilidad para llamadas directas; el runner usa fetch_batches."""
        out: list[FetchedMention] = []
        async for batch in self.fetch_batches(ctx):
            out.extend(batch)
        return out

    async def fetch_batches(
        self, ctx: FetchContext
    ) -> AsyncIterator[list[FetchedMention]]:
        settings = get_settings()
        # La ventana solo se usa para inicializar un ecosistema sin watermark.
        # Después, `modified` de OSV gobierna el delta e incluye correcciones de
        # advisories antiguos sin reingerir el catálogo completo.
        cutoff = (datetime.now(UTC) - timedelta(days=30 * settings.osv_months)
                  if settings.osv_months > 0 else None)
        ecosystems = [e.strip() for e in settings.osv_ecosystems.split(",") if e.strip()]
        self._pending_cursors: dict[str, str] = {}
        for eco in ecosystems:
            try:
                async for batch in self._scan_eco_batches(
                    ctx, eco, cutoff, settings.osv_max_per_ecosystem
                ):
                    yield batch
            except Exception as exc:  # noqa: BLE001 - un ecosistema no tumba la fuente
                log.warning("osv.eco_error", ecosystem=eco, error=str(exc))

    async def _scan_eco_batches(
        self,
        ctx: FetchContext,
        eco: str,
        cutoff: datetime | None,
        cap: int,
    ) -> AsyncIterator[list[FetchedMention]]:
        # Descarga cacheada a disco (reusa el zip si es reciente; lo conserva para
        # recreaciones). ZipFile lee cada entrada de forma perezosa. Con cap se
        # mantiene un heap ACOTADO de los N más recientes; sin cap se emiten
        # lotes de _BATCH_SIZE en lugar de acumular todo el ecosistema.
        if not hasattr(self, "_pending_cursors"):
            self._pending_cursors = {}
        cursor_id = f"source:osv:{eco}"
        key = f"osv_{eco.replace('/', '_').replace(' ', '_')}.zip"
        zip_path = await cached_download(ctx.http, BUCKET.format(eco=eco), key=key)
        archive_cursor_id = f"source:osv-archive:{eco}"
        stat = os.stat(zip_path)
        archive_signature = f"{stat.st_size}:{stat.st_mtime_ns}"
        previous_archive, cursor_value = await asyncio.gather(
            asyncio.to_thread(read_cursor, archive_cursor_id),
            asyncio.to_thread(read_cursor, cursor_id),
        )
        if previous_archive == archive_signature:
            log.info("osv.eco_unchanged", ecosystem=eco, key=key)
            return

        cursor = parse_advisory_date(cursor_value)
        incremental_cutoff = cursor - _CURSOR_OVERLAP if cursor else None
        selected: list[tuple[datetime, int, FetchedMention]] = []
        batch: list[FetchedMention] = []
        epoch = datetime.min.replace(tzinfo=UTC)  # sin fecha -> al final
        max_modified = cursor
        emitted = scanned = skipped_cursor = 0
        sequence = 0
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if not info.filename.endswith(".json"):
                    continue
                scanned += 1
                try:
                    rec = json.loads(zf.read(info))
                except (json.JSONDecodeError, KeyError):
                    continue
                modified = self._modified_at(rec)
                if modified is not None and (
                    max_modified is None or modified > max_modified
                ):
                    max_modified = modified
                if cursor is not None and (
                    modified is None or modified < incremental_cutoff
                ):
                    skipped_cursor += 1
                    continue
                # En el primer run se aplica la ventana de bootstrap. Con
                # watermark se aceptan también updates recientes de advisories
                # antiguos.
                m = self._to_mention(rec, cutoff if cursor is None else None)
                if m is not None:
                    sequence += 1
                    if cap > 0:
                        item = (modified or epoch, sequence, m)
                        if len(selected) < cap:
                            heapq.heappush(selected, item)
                        else:
                            heapq.heappushpop(selected, item)
                    else:
                        batch.append(m)
                        if len(batch) >= _BATCH_SIZE:
                            emitted += len(batch)
                            yield batch
                            batch = []
        if cap > 0:
            ordered = [item[2] for item in sorted(selected, reverse=True)]
            for pos in range(0, len(ordered), _BATCH_SIZE):
                current = ordered[pos:pos + _BATCH_SIZE]
                emitted += len(current)
                yield current
        elif batch:
            emitted += len(batch)
            yield batch

        if cap > 0 and sequence > cap:
            log.warning("osv.eco_capped", ecosystem=eco, cap=cap,
                        discarded=sequence - cap)
        if max_modified is not None:
            self._pending_cursors[cursor_id] = max_modified.isoformat()
        self._pending_cursors[archive_cursor_id] = archive_signature
        log.info(
            "osv.eco_done",
            ecosystem=eco,
            scanned=scanned,
            skipped_cursor=skipped_cursor,
            mentions=emitted,
            incremental=cursor is not None,
        )

    def finalize(self) -> None:
        """Confirma watermarks solo después de persistir todos los lotes."""
        for cursor_id, value in getattr(self, "_pending_cursors", {}).items():
            write_cursor(cursor_id, value)

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
