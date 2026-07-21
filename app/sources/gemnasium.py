"""Tier 4 — GitLab Advisory Database (gemnasium-db).

Advisories OSS curados por GitLab, organizados por `<ecosistema>/<paquete>/
<ID>.yml`, con CVE + GHSA, rangos afectados y versiones corregidas. Curación
independiente de OSV/GHSA: a veces publica antes o cubre casos que faltan.

Se mantiene un snapshot git (--depth 1) y se recorren los YAML publicados en la
ventana reciente (`pubdate`), emitiendo el CVE (o el GHSA si no hay CVE) con su
tecnología afectada estructurada. Idempotente por content_hash.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import yaml

from app.core.logging import get_logger
from app.ingest.affected import AffectedInput, VersionRangeInput
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.gitsrc import sync_repo

log = get_logger(__name__)

REPO_URL = "https://gitlab.com/gitlab-org/security-products/gemnasium-db.git"
# Ecosistemas (= directorios top del repo). package_slug = "<eco>/<paquete>".
_ECOSYSTEMS = ("pypi", "npm", "maven", "go", "cargo", "gem", "nuget",
               "packagist", "conan", "pub")
_WINDOW_DAYS = 180   # solo advisories con pubdate reciente (señal, no histórico)


def _ranges(affected_range: str | None) -> list[VersionRangeInput]:
    """Parsea la sintaxis gemnasium '>=5.0.0,<5.0.10||>=5.1.0,<5.1.4':
    '||' separa rangos, ',' une condiciones (introduced '>='/'>' y fixed '<')."""
    if not affected_range:
        return []
    out: list[VersionRangeInput] = []
    for seg in affected_range.split("||"):
        intro = fixed = None
        for cond in seg.split(","):
            cond = cond.strip()
            if cond.startswith(">="):
                intro = cond[2:].strip()
            elif cond.startswith(">"):
                intro = cond[1:].strip()
            elif cond.startswith("<"):
                fixed = cond.lstrip("<=").strip()
        if intro or fixed:
            out.append(VersionRangeInput(introduced=intro, fixed=fixed,
                                         raw=seg.strip()))
    return out


@register
class GemnasiumSource(BaseSource):
    name = "gemnasium"
    kind = "GitLab Advisory Database (gemnasium-db)"
    method = "git"
    tier = 4
    cadence_seconds = 43200  # 12 h (snapshot grande; el pull es barato)

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        repo = await sync_repo("gemnasium", REPO_URL)
        cutoff = datetime.now(UTC) - timedelta(days=_WINDOW_DAYS)
        return await asyncio.to_thread(self._walk, repo, cutoff)

    def _walk(self, repo: str, cutoff: datetime) -> list[FetchedMention]:
        out: list[FetchedMention] = []
        for eco in _ECOSYSTEMS:
            base = os.path.join(repo, eco)
            if not os.path.isdir(base):
                continue
            for root, _dirs, files in os.walk(base):
                for fn in files:
                    if not fn.endswith(".yml"):
                        continue
                    m = self._to_mention(os.path.join(root, fn), eco, cutoff)
                    if m is not None:
                        out.append(m)
        log.info("gemnasium.parsed", mentions=len(out))
        return out

    @staticmethod
    def _to_mention(path: str, eco: str, cutoff: datetime) -> FetchedMention | None:
        try:
            with open(path, encoding="utf-8") as fh:
                rec = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError):
            return None
        if not isinstance(rec, dict):
            return None
        seen = parse_advisory_date(rec.get("pubdate") or rec.get("date"))
        if seen is not None and seen < cutoff:
            return None
        ids = [str(i) for i in (rec.get("identifiers") or []) if i]
        cves = [i for i in ids if i.upper().startswith("CVE-")]
        others = [i for i in ids if not i.upper().startswith("CVE-")]
        if not cves and not others:
            return None
        slug = rec.get("package_slug") or f"{eco}/?"
        product = slug.split("/", 1)[1] if "/" in slug else slug
        title = (rec.get("title") or "").strip()[:200]
        desc = (rec.get("description") or "").strip()
        affected = [AffectedInput(
            product=product, ecosystem=eco,
            ranges=_ranges(rec.get("affected_range")),
            exact_versions=[str(v) for v in (rec.get("fixed_versions") or [])] or None,
        )]
        refs = [u for u in (rec.get("urls") or []) if isinstance(u, str)]
        common = {
            "url": refs[0] if refs else None,
            "title": title or (cves[0] if cves else others[0]),
            "snippet": (f"{title} | {desc}")[:2000] or None,
            "seen_at": seen,
            "affected": affected,
            "reference_urls": refs or None,
            "cwe_ids": [c for c in (rec.get("cwe_ids") or []) if isinstance(c, str)] or None,
        }
        if cves:
            # 1 CVE -> ese CVE + resto como aliases declarados (misma vuln).
            return FetchedMention(cve_id=cves[0], extra_ids=(cves[1:] + others) or None,
                                  **common)
        # Sin CVE: ancla por el primer código nativo (GHSA...).
        return FetchedMention(native_id=others[0], extra_ids=others[1:] or None, **common)
