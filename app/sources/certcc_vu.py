"""Tier 1 — CERT/CC Vulnerability Notes (VU#). Los VU# suelen preceder al CVE.

Feed Atom público de kb.cert.org. Cada nota trae un VU# y, a menudo, el CVE
asociado cuando ya existe reserva. Las menciones DECLARAN identificadores
(antes salían sin native_id/cve_id y la ingesta anclaba "al primer id del
texto"): se reutiliza la política anti-over-merge de feeds_rss:
  - 1 CVE  -> mención con ese CVE + el VU# (y demás códigos) como extra_ids.
  - N CVEs -> una mención por CVE, sin bundlear (el VU# queda en el snippet
              como referencia blanda; declararlo como extra fusionaría los N
              CVEs en un candidate -> over-merge).
  - 0 CVEs -> mención anclada por el VU# (pre-CVE puro).
"""

from __future__ import annotations

import calendar
from datetime import UTC, datetime

import feedparser

from app.sources.base import BaseSource, FetchContext, register
from app.sources.feeds_rss import _mentions_for_entry
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
        # Feed Atom oficial -> robots.txt no aplica (ver docstring de get()).
        resp = await get(ctx.http, FEED_URL, respect_robots=False)
        feed = feedparser.parse(resp.text)
        out: list[FetchedMention] = []
        for entry in feed.entries:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            url = entry.get("link")
            # Fecha real de publicación del feed (no el momento del fetch).
            pp = entry.get("published_parsed") or entry.get("updated_parsed")
            seen = datetime.fromtimestamp(calendar.timegm(pp), tz=UTC) if pp else None
            out.extend(_mentions_for_entry(title, summary, url, seen))
        return out
