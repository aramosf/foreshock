"""Tier 4 — CVEs del kernel de Linux (linux-cve-announce).

El kernel es CNA desde 2024 y asigna MILES de CVEs en su propio calendario,
normalmente ANTES de que NVD los enriquezca. Se consume el feed atom público de
anuncios (lore.kernel.org), ligero e incremental — evita clonar el enorme
vulns.git. Cada anuncio trae `CVE-…: <subsistema>: <descripción>` en el título;
se ancla por CVE y se marca la tecnología afectada como "Linux Kernel" (para que
entre en `pending` con producto conocido).
"""

from __future__ import annotations

import re

import feedparser

from app.core.logging import get_logger
from app.ingest.affected import AffectedInput
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.http import get

log = get_logger(__name__)

FEED = "https://lore.kernel.org/linux-cve-announce/new.atom"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@register
class KernelCveSource(BaseSource):
    name = "kernel_cve"
    kind = "Linux kernel CVEs (linux-cve-announce atom)"
    method = "rss"
    tier = 4
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        # Feed atom oficial -> robots.txt no aplica (ver docstring de get()).
        resp = await get(ctx.http, FEED, respect_robots=False)
        feed = feedparser.parse(resp.content)
        out: list[FetchedMention] = []
        for entry in feed.entries:
            title = entry.get("title", "")
            m = _CVE.search(title)
            if not m:
                continue
            cve = m.group(0).upper()
            # título = "CVE-XXXX-NNNN: <subsistema>: <descripción>"
            subject = title.split(":", 1)[1].strip() if ":" in title else title
            summary = re.sub(r"<[^>]+>", " ", entry.get("summary", ""))
            snippet = re.sub(r"\s+", " ", f"{subject} | {summary}").strip()[:2000]
            seen = parse_advisory_date(
                entry.get("published") or entry.get("updated"))
            out.append(FetchedMention(
                url=entry.get("link"),
                title=subject[:200] or cve,
                snippet=snippet or None,
                cve_id=cve,
                seen_at=seen,
                # Tecnología afectada conocida: el propio kernel.
                affected=[AffectedInput(product="Linux Kernel", vendor="Linux",
                                        kind="product")],
            ))
        log.info("kernel_cve.parsed", mentions=len(out))
        return out
