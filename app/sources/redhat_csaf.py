"""Tier 2 — Red Hat Security Data API (CVE JSON).

Devuelve CVEs recientes con descripción, severidad y vector CVSS v3 cuando lo
hay. Alta señal y formato estructurado: el CVSS aquí es AUTORITATIVO.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from dateutil.parser import isoparse

from app.core.config import get_settings
from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

API = "https://access.redhat.com/hydra/rest/securitydata/cve.json"


@register
class RedHatCSAFSource(BaseSource):
    name = "redhat_csaf"
    kind = "Red Hat Security Data API (CVE JSON)"
    method = "api"
    tier = 2
    cadence_seconds = 3600

    per_page = 1000        # tope alto por página
    max_pages = 200        # cota de seguridad (permite históricos grandes)

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        lookback = get_settings().redhat_lookback_days
        after = (datetime.now(UTC) - timedelta(days=lookback)).strftime("%Y-%m-%d")
        out: list[FetchedMention] = []
        for page in range(1, self.max_pages + 1):
            # API JSON oficial -> robots.txt no aplica (ver docstring de get()).
            resp = await get(ctx.http, API, respect_robots=False,
                             params={"after": after, "per_page": self.per_page, "page": page})
            data = resp.json()
            if not data:
                break
            out.extend(self._parse(data))
            if len(data) < self.per_page:
                break  # última página
        return out

    @staticmethod
    def _parse(data: list[dict]) -> list[FetchedMention]:
        out: list[FetchedMention] = []
        for item in data:
            cve = item.get("CVE")
            if not cve:
                continue
            desc = item.get("bugzilla_description") or ""
            severity = item.get("severity")
            vector = item.get("cvss3_scoring_vector") or item.get("cvss_scoring_vector")
            snippet = desc
            if severity:
                snippet = f"[{severity}] {desc}"
            if vector:
                snippet = f"{snippet} | CVSS: {vector}"
            # seen_at = fecha REAL de publicación en Red Hat (señal temprana),
            # no el momento del fetch (que infla days_ahead/first_seen).
            seen = None
            pub = item.get("public_date")
            if pub:
                try:
                    seen = isoparse(pub)
                    if seen.tzinfo is None:
                        seen = seen.replace(tzinfo=UTC)
                except (ValueError, TypeError):
                    seen = None
            out.append(
                FetchedMention(
                    url=item.get("resource_url"),
                    title=desc[:200] if desc else cve,
                    snippet=snippet[:2000] if snippet else None,
                    cve_id=cve,
                    seen_at=seen,
                )
            )
        return out
