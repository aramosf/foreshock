"""Tier 2 — Cisco PSIRT (publicationService).

Advisories de Cisco (dispositivos de red/borde muy explotados). El endpoint
`publicationService.x?advisoryFormat=json` devuelve JSON (aunque el content-type
diga HTML) con los advisories recientes: identifier, title, cve, firstPublished,
severity, summary, url. Sin auth. Se ancla por CVE (política anti-over-merge:
una mención por CVE del advisory).
"""

from __future__ import annotations

import re

from app.core.logging import get_logger
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.http import get

log = get_logger(__name__)

FEED = ("https://sec.cloudapps.cisco.com/security/center/"
        "publicationService.x?advisoryFormat=json")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@register
class CiscoPsirtSource(BaseSource):
    name = "cisco_psirt"
    kind = "Cisco PSIRT security advisories"
    method = "api"
    tier = 2
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        # JSON servido como text/html; get() no fuerza content-type. Feed oficial.
        resp = await get(ctx.http, FEED, respect_robots=False)
        try:
            advisories = resp.json()
        except ValueError:
            log.warning("cisco.bad_json")
            return []
        out: list[FetchedMention] = []
        for adv in advisories:
            # 'cve' puede traer uno o varios; se recogen todos + los del summary.
            cves = sorted({m.group(0).upper() for m in
                           _CVE.finditer(f"{adv.get('cve', '')} {adv.get('summary', '')}")})
            if not cves:
                continue
            title = (adv.get("title") or "").strip()[:200]
            sev = adv.get("severity")
            summary = (adv.get("summary") or "").strip()
            snippet = (f"[{sev}] {title} | {summary}" if sev else f"{title} | {summary}")[:2000]
            seen = parse_advisory_date(adv.get("firstPublished"))
            url = adv.get("url")
            # 1 CVE -> mención única; N CVEs -> una por CVE (vulns distintas del
            # mismo boletín no deben colapsar en un candidate).
            for cve in cves:
                out.append(FetchedMention(
                    url=url, title=title or cve, snippet=snippet,
                    cve_id=cve, seen_at=seen))
        log.info("cisco.parsed", advisories=len(advisories), mentions=len(out))
        return out
