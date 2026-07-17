"""Tier 4 — GitHub Security Advisories (GHSA) vía la API pública de GitHub.

Regla de oro del proyecto: no scrapear GHSA; usar la API. Trae ghsa_id, cve_id
(si asignado), resumen, y `vulnerabilities` con paquete (ecosystem+name) y
rangos de versión -> alimenta affected_products de forma estructurada.
"""

from __future__ import annotations

import re

from app.core.config import get_settings
from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

API = "https://api.github.com/advisories"

# Extrae la URL de la página siguiente del header Link (paginación por cursor).
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


@register
class GitHubAdvisoriesSource(BaseSource):
    name = "github_advisories"
    kind = "GitHub Security Advisories (GHSA API)"
    method = "api"
    tier = 4
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"

        out: list[FetchedMention] = []
        url: str | None = API
        params: dict[str, object] | None = {
            "per_page": 100, "sort": "published", "direction": "desc"
        }
        pages = 0
        # Paginación por header Link hasta github_advisories_max_pages.
        while url and pages < settings.github_advisories_max_pages:
            resp = await get(ctx.http, url, params=params, headers=headers)
            out.extend(self._parse(resp.json()))
            pages += 1
            m = _NEXT.search(resp.headers.get("Link", ""))
            url = m.group(1) if m else None
            params = None  # la URL 'next' ya lleva el cursor
        return out

    @staticmethod
    def _parse(data: list[dict]) -> list[FetchedMention]:
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
