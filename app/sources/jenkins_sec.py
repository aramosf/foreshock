"""Tier 2 — Jenkins Security Advisories.

Jenkins (CI muy desplegado) publica advisories que agrupan varios CVEs (core y
plugins). El RSS lista los advisories; el CVE vive en la PÁGINA de cada uno, así
que se descargan las páginas de los advisories recientes y se extraen los CVEs.
Producto = "Jenkins" (grano de plataforma; el plugin concreto lo afina el
enriquecimiento).
"""

from __future__ import annotations

import calendar
import re
from datetime import UTC, datetime, timedelta

import feedparser

from app.core.logging import get_logger
from app.ingest.affected import AffectedInput
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get

log = get_logger(__name__)

FEED = "https://www.jenkins.io/security/advisories/rss.xml"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_WINDOW_DAYS = 120   # solo se descargan páginas de advisories recientes


@register
class JenkinsSecuritySource(BaseSource):
    name = "jenkins_security"
    kind = "Jenkins Security Advisories"
    method = "rss"
    tier = 2
    cadence_seconds = 43200  # 12 h

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        resp = await get(ctx.http, FEED, respect_robots=False)
        feed = feedparser.parse(resp.content)
        cutoff = datetime.now(UTC) - timedelta(days=_WINDOW_DAYS)
        out: list[FetchedMention] = []
        for entry in feed.entries:
            pp = entry.get("published_parsed") or entry.get("updated_parsed")
            seen = datetime.fromtimestamp(calendar.timegm(pp), tz=UTC) if pp else None
            if seen is not None and seen < cutoff:
                continue
            link = entry.get("link")
            if not link:
                continue
            try:
                page = await get(ctx.http, link, respect_robots=False)
            except Exception as exc:  # noqa: BLE001 - un aviso caído no tumba la fuente
                log.warning("jenkins.page_error", url=link, error=str(exc))
                continue
            cves = sorted({m.group(0).upper() for m in _CVE.finditer(page.text)})
            title = entry.get("title", "")
            for cve in cves:
                out.append(FetchedMention(
                    url=link, title=f"{title}: {cve}"[:200],
                    snippet=title or None, cve_id=cve, seen_at=seen,
                    affected=[AffectedInput(product="Jenkins", vendor="Jenkins")],
                ))
        log.info("jenkins.parsed", advisories=len(feed.entries), mentions=len(out))
        return out
