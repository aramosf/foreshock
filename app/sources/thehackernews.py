"""Tier 5 — The Hacker News (RSS). Noticias; a veces mencionan CVEs pronto,
sobre todo campañas de explotación activa.
"""

from __future__ import annotations

import calendar
from datetime import UTC, datetime

import feedparser

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

FEED_URL = "https://feeds.feedburner.com/TheHackersNews"


@register
class TheHackerNewsSource(BaseSource):
    name = "thehackernews"
    kind = "The Hacker News (RSS)"
    method = "rss"
    tier = 5
    cadence_seconds = 1800

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        # Feed RSS oficial -> robots.txt no aplica (ver docstring de get()).
        resp = await get(ctx.http, FEED_URL, respect_robots=False)
        feed = feedparser.parse(resp.text)
        out: list[FetchedMention] = []
        for entry in feed.entries:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            # Solo interesan entradas que mencionen un CVE (la ingesta filtra igual).
            blob = f"{title} {summary}"
            if "CVE-" not in blob.upper():
                continue
            # seen_at = fecha REAL de publicación del artículo, no el fetch.
            pp = entry.get("published_parsed") or entry.get("updated_parsed")
            seen = datetime.fromtimestamp(calendar.timegm(pp), tz=UTC) if pp else None
            out.append(
                FetchedMention(
                    url=entry.get("link"),
                    title=title,
                    snippet=summary[:2000] if summary else None,
                    seen_at=seen,
                )
            )
        return out
