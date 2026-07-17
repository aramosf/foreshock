"""Tier 1 — CERT/CC Vulnerability Notes (VU#). Los VU# suelen preceder al CVE.

Feed Atom público de kb.cert.org. Cada nota trae un VU# y, a menudo, el CVE
asociado cuando ya existe reserva.
"""

from __future__ import annotations

import feedparser

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

FEED_URL = "https://www.kb.cert.org/vuls/atomfeed/"


@register
class CertCCVuSource(BaseSource):
    name = "certcc_vu"
    kind = "CERT/CC Vulnerability Notes (Atom)"
    method = "rss"
    tier = 1
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        resp = await get(ctx.http, FEED_URL)
        feed = feedparser.parse(resp.text)
        out: list[FetchedMention] = []
        for entry in feed.entries:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            url = entry.get("link")
            seen = None
            out.append(
                FetchedMention(
                    url=url,
                    title=title,
                    snippet=summary[:2000] if summary else None,
                    seen_at=seen,
                    raw_html=None,
                )
            )
        return out
