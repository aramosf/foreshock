"""Tier 4 — OSV.dev (advisories de ecosistemas de paquetes).

Regla de oro del proyecto: OSV antes que scrapear GHSA. Descarga el volcado
`all.zip` por ecosistema, filtra por `modified` reciente (últimos N meses) y emite
menciones con el CVE (de los aliases) o el ID de OSV (PYSEC/GO/RUSTSEC…) como
identificador nativo, más los paquetes afectados con sus rangos.
"""

from __future__ import annotations

import io
import json
import zipfile

from dateutil.parser import isoparse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sources.base import BaseSource, FetchContext, register
from app.ingest.service import FetchedMention

log = get_logger(__name__)

BUCKET = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"


def _cve_alias(aliases: list[str]) -> str | None:
    for a in aliases:
        if a.upper().startswith("CVE-"):
            return a.upper()
    return None


def _packages(affected: list[dict]) -> list[str]:
    out = []
    for a in affected:
        pkg = a.get("package") or {}
        eco, name = pkg.get("ecosystem"), pkg.get("name")
        # rango: introduced/fixed del primer range
        rng = ""
        for r in a.get("ranges") or []:
            events = r.get("events") or []
            intro = next((e.get("introduced") for e in events if "introduced" in e), None)
            fixed = next((e.get("fixed") for e in events if "fixed" in e), None)
            if fixed:
                rng = f"<{fixed}"
            elif intro:
                rng = f">={intro}"
            break
        if name:
            out.append(f"{eco}:{name} {rng}".strip())
    return out


@register
class OsvSource(BaseSource):
    name = "osv"
    kind = "OSV.dev ecosystem advisories (all.zip)"
    method = "api"
    tier = 4
    cadence_seconds = 21600  # 6 h (volcado grande)

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        cutoff = None
        from datetime import UTC, datetime, timedelta
        cutoff = datetime.now(UTC) - timedelta(days=30 * settings.osv_months)
        ecosystems = [e.strip() for e in settings.osv_ecosystems.split(",") if e.strip()]
        out: list[FetchedMention] = []
        for eco in ecosystems:
            try:
                out.extend(await self._scan_eco(ctx, eco, cutoff, settings.osv_max_per_ecosystem))
            except Exception as exc:  # noqa: BLE001 - un ecosistema no tumba la fuente
                log.warning("osv.eco_error", ecosystem=eco, error=str(exc))
        return out

    async def _scan_eco(self, ctx: FetchContext, eco: str, cutoff, cap: int
                        ) -> list[FetchedMention]:
        resp = await ctx.http.get(BUCKET.format(eco=eco), timeout=120.0)
        resp.raise_for_status()
        out: list[FetchedMention] = []
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                if cap > 0 and len(out) >= cap:  # cap<=0 => sin límite
                    break
                try:
                    rec = json.loads(zf.read(name))
                except (json.JSONDecodeError, KeyError):
                    continue
                # Usamos 'published' (fecha real de publicación), NO 'modified':
                # OSV re-modifica registros antiguos, lo que colaba CVEs viejos y
                # contaminaba la serie temporal. Fallback a 'modified' si no hay.
                date_str = rec.get("published") or rec.get("modified")
                seen = None
                if date_str:
                    try:
                        seen = isoparse(date_str)
                        if seen < cutoff:
                            continue  # publicado fuera de la ventana -> se descarta
                    except (ValueError, TypeError):
                        seen = None
                osv_id = rec.get("id")
                cve = _cve_alias(rec.get("aliases") or [])
                if not cve and not osv_id:
                    continue
                summary = rec.get("summary") or rec.get("details") or ""
                pkgs = _packages(rec.get("affected") or [])
                snippet = summary
                if pkgs:
                    snippet = f"{summary} | affected: {', '.join(pkgs[:10])}"
                out.append(
                    FetchedMention(
                        url=f"https://osv.dev/vulnerability/{osv_id}" if osv_id else None,
                        title=(summary[:200] or cve or osv_id),
                        snippet=snippet[:2000] if snippet else None,
                        cve_id=cve,
                        native_id=osv_id,
                        seen_at=seen,
                    )
                )
        log.info("osv.eco_done", ecosystem=eco, mentions=len(out))
        return out
