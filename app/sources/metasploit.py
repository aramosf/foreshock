"""Tier 3 — Rapid7 metasploit-framework (changelog del repo).

Un módulo de exploit nuevo (commit/PR) = exploit fiable disponible, fuerte señal
de que un CVE va a ser (o está siendo) explotado. Escanea commits que citan CVEs
con watermark persistente en `github_repos` (origin='manual'): cada ejecución
solo mira los commits nuevos, no re-escanea la ventana completa.
"""

from __future__ import annotations

from app.sources.base import register
from app.sources.github_commits import SingleRepoCommitSource


@register
class MetasploitSource(SingleRepoCommitSource):
    name = "metasploit"
    kind = "metasploit-framework repo commit scan"
    method = "git"
    tier = 3
    cadence_seconds = 3600
    repo_full_name = "rapid7/metasploit-framework"
