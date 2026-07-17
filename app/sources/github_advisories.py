"""Tier 4 — GitHub Security Advisories (GHSA) vía la API pública de GitHub.

Regla de oro del proyecto: no scrapear GHSA; usar la API. Trae ghsa_id, cve_id
(si asignado), resumen, y `vulnerabilities` con paquete (ecosystem+name) y
rangos de versión -> alimenta affected_products de forma estructurada.
"""

from __future__ import annotations

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

API = "https://api.github.com/advisories"


@register
class GitHubAdvisoriesSource(BaseSource):
    name = "github_advisories"
    kind = "GitHub Security Advisories (GHSA API)"
    method = "api"
    tier = 4
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        resp = await get(
            ctx.http,
            API,
            params={"per_page": 100, "sort": "published", "direction": "desc"},
            headers=headers,
        )
        data = resp.json()
        out: list[FetchedMention] = []
        for adv in data:
            ghsa = adv.get("ghsa_id")
            cve = adv.get("cve_id")
            summary = adv.get("summary") or ""
            # paquetes afectados -> al snippet (el enrichment los estructura después)
            pkgs = []
            for v in adv.get("vulnerabilities") or []:
                pkg = (v or {}).get("package") or {}
                eco, name = pkg.get("ecosystem"), pkg.get("name")
                rng = v.get("vulnerable_version_range")
                if name:
                    pkgs.append(f"{eco}:{name} {rng or ''}".strip())
            snippet = summary
            if pkgs:
                snippet = f"{summary} | affected: {', '.join(pkgs[:10])}"
            out.append(
                FetchedMention(
                    url=adv.get("html_url"),
                    title=summary[:200] if summary else (cve or ghsa),
                    snippet=snippet[:2000] if snippet else None,
                    cve_id=cve,
                    native_id=ghsa,
                )
            )
        return out
