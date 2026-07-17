"""Tier 3 — Rapid7 metasploit-framework (changelog del repo).

Un módulo de exploit nuevo (commit/PR) = exploit fiable disponible, fuerte señal
de que un CVE va a ser (o está siendo) explotado. Escanea commits que citan CVEs.
"""

from __future__ import annotations

from app.core.config import get_settings
from app.sources.base import BaseSource, FetchContext, register
from app.sources.github_commits import scan_single_repo
from app.ingest.service import FetchedMention

REPO = "rapid7/metasploit-framework"


@register
class MetasploitSource(BaseSource):
    name = "metasploit"
    kind = "metasploit-framework repo commit scan"
    method = "api"
    tier = 3
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        months = get_settings().github_commits_months
        return await scan_single_repo(ctx.http, REPO, months=months, synthesize=False)
