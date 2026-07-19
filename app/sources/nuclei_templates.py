"""Tier 3 — ProjectDiscovery nuclei-templates (changelog del repo).

Un template nuevo para un CVE suele acompañar o preceder la explotación masiva.
Escanea los commits del repo que citan un CVE con watermark persistente en
`github_repos` (origin='manual'): cada ejecución solo mira los commits nuevos,
no re-escanea la ventana completa.
"""

from __future__ import annotations

from app.sources.base import register
from app.sources.github_commits import SingleRepoCommitSource


@register
class NucleiTemplatesSource(SingleRepoCommitSource):
    name = "nuclei_templates"
    kind = "nuclei-templates repo commit scan"
    method = "git"
    tier = 3
    cadence_seconds = 3600
    repo_full_name = "projectdiscovery/nuclei-templates"
