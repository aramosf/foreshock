"""Tier 1 — VulnCheck KEV.

Catálogo de CVEs explotados más amplio y temprano que el de CISA (~80% más).
Requiere un token gratuito (FORESHOCK_VULNCHECK_TOKEN); si no hay token, la fuente
queda inactiva (devuelve []).
"""

from __future__ import annotations

from dateutil.parser import isoparse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

log = get_logger(__name__)


@register
class VulnCheckKevSource(BaseSource):
    name = "vulncheck_kev"
    kind = "VulnCheck KEV (API)"
    method = "api"
    tier = 1
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        if not settings.vulncheck_token:
            log.info("vulncheck.no_token")  # fuente inactiva sin token
            return []
        headers = {"Authorization": f"Bearer {settings.vulncheck_token}"}
        out: list[FetchedMention] = []
        page = 1
        while page <= settings.vulncheck_max_pages:
            resp = await get(
                ctx.http,
                f"{settings.vulncheck_api_base}/index/vulncheck-kev",
                params={"page": page, "limit": 100},
                headers=headers,
            )
            body = resp.json()
            items = body.get("data", [])
            if not items:
                break
            for it in items:
                cves = it.get("cve") or []
                added = it.get("date_added")
                kev_date = None
                if added:
                    try:
                        kev_date = isoparse(added).date()
                    except (ValueError, TypeError):
                        kev_date = None
                name = it.get("name") or (cves[0] if cves else None)
                for cve in cves:
                    out.append(
                        FetchedMention(
                            url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                            title=f"VulnCheck KEV: {name}"[:200],
                            snippet=(it.get("description") or "")[:2000] or None,
                            cve_id=cve,
                            flags={"in_kev": True, "kev_date": kev_date,
                                   "kev_source": "vulncheck"},
                        )
                    )
            meta = body.get("_meta") or {}
            if page >= int(meta.get("total_pages", page)):
                break
            page += 1
        return out
