"""Tier 3 — ProjectDiscovery nuclei-templates (changelog del repo).

Un template nuevo para un CVE suele acompañar o preceder la explotación masiva.
Escanea los commits del repo (últimos N meses) que citan un CVE.
"""

from __future__ import annotations

from app.core.config import get_settings
from app.sources.base import BaseSource, FetchContext, register
from app.sources.github_commits import scan_single_repo
from app.ingest.service import FetchedMention

REPO = "projectdiscovery/nuclei-templates"


@register
class NucleiTemplatesSource(BaseSource):
    name = "nuclei_templates"
    kind = "nuclei-templates repo commit scan"
    method = "api"
    tier = 3
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        months = get_settings().github_commits_months
        return await scan_single_repo(ctx.http, REPO, months=months, synthesize=False)
