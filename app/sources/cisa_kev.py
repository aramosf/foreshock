"""Tier 1 — CISA Known Exploited Vulnerabilities (KEV).

Catálogo autoritativo de CVEs *explotados en el mundo real*. Feed JSON público
sin auth. Marca cada candidate con `in_kev=True` (señal de máxima prioridad y
ground truth para la predicción P(entra en KEV)).
"""

from __future__ import annotations

from dateutil.parser import isoparse

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@register
class CisaKevSource(BaseSource):
    name = "cisa_kev"
    kind = "CISA Known Exploited Vulnerabilities (JSON feed)"
    method = "api"
    tier = 1
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        # Feed JSON oficial -> robots.txt no aplica (ver docstring de get()).
        resp = await get(ctx.http, FEED, respect_robots=False)
        data = resp.json()
        out: list[FetchedMention] = []
        for v in data.get("vulnerabilities", []):
            cve = v.get("cveID")
            if not cve:
                continue
            added = v.get("dateAdded")
            kev_date = None
            seen = None
            if added:
                try:
                    seen = isoparse(added)
                    kev_date = seen.date()
                except (ValueError, TypeError):
                    seen = None
            ransom = v.get("knownRansomwareCampaignUse")
            snippet = " | ".join(
                p for p in [
                    v.get("vendorProject"), v.get("product"),
                    v.get("vulnerabilityName"),
                    f"ransomware={ransom}" if ransom else None,
                    v.get("shortDescription"),
                ] if p
            )
            out.append(
                FetchedMention(
                    url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                    title=f"KEV: {v.get('vulnerabilityName') or cve}"[:200],
                    snippet=snippet[:2000] if snippet else None,
                    cve_id=cve,
                    seen_at=seen,
                    flags={"in_kev": True, "kev_date": kev_date, "kev_source": "cisa"},
                )
            )
        return out
