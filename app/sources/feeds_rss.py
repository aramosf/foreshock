"""Fetchers RSS/Atom data-driven: un fetcher registrado por feed.

Cada entrada se convierte en menciones aplicando la MISMA política anti-over-merge
del resto del pipeline:
  - 1 CVE en la entrada  -> 1 mención con ese CVE + los códigos no-CVE de la entrada
    como aliases (ZDI-CAN/VU…): son la MISMA vuln, fusionan bien.
  - >1 CVE en la entrada -> 1 mención POR CVE (vulns distintas de un mismo boletín;
    cada una ancla su candidate, sin fusionar entre sí).
  - 0 CVE pero con código reconocido (p.ej. ZDI-CAN de un advisory ZDI "upcoming")
    -> 1 mención anclada por ese código (pre-CVE puro).
  - Sin ningún código reconocido -> nada (se descartaría igual por política).
"""

from __future__ import annotations

import asyncio
import calendar
from datetime import UTC, datetime

import feedparser

from app.core.logging import get_logger
from app.ingest.identifiers import RECOGNIZED_SCHEMES, extract_identifiers
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get

log = get_logger(__name__)

# UA de navegador SOLO para feeds que lo exijan de verdad (bloqueo por WAF):
# se activa por-feed con `browser_ua=True` en _FEEDS. Por defecto se usa el
# User-Agent identificable del proyecto (settings.user_agent, vía make_client).
_BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124 Safari/537.36")

# (name, kind, tier, url[, browser_ua]). Verificados vía probe: devuelven
# entradas con CVE/ZDI-CAN. El 5º campo opcional (bool) activa el UA de
# navegador SOLO para ese feed (ninguno lo necesita hoy).
_FEEDS: list[tuple] = [
    ("zdi_published", "Zero Day Initiative — published advisories", 1,
     "https://www.zerodayinitiative.com/rss/published/"),
    ("zdi_upcoming", "Zero Day Initiative — upcoming (pre-CVE, ZDI-CAN)", 1,
     "https://www.zerodayinitiative.com/rss/upcoming/"),
    ("certeu", "CERT-EU Security Advisories", 1,
     "https://cert.europa.eu/publications/security-advisories-rss"),
    ("siemens_cert", "Siemens ProductCERT Advisories", 2,
     "https://cert-portal.siemens.com/productcert/rss/advisories.atom"),
    ("paloalto", "Palo Alto Networks Security Advisories", 2,
     "https://security.paloaltonetworks.com/rss.xml"),
    ("spring_security", "Spring Security Advisories", 2,
     "https://spring.io/security.atom"),
    ("fortiguard_psirt", "FortiGuard PSIRT IR Advisories", 2,
     "https://www.fortiguard.com/rss/ir.xml"),
    ("msrc", "Microsoft Security Response Center (MSRC) Update Guide", 2,
     "https://api.msrc.microsoft.com/update-guide/rss"),
    ("fulldisclosure", "Full Disclosure Mailing List", 3,
     "https://seclists.org/rss/fulldisclosure.rss"),
    ("oss_security", "oss-security Mailing List", 3,
     "https://seclists.org/rss/oss-sec.rss"),
    ("veeam", "Veeam Security Advisories", 2,
     "https://www.veeam.com/services/open/kb/security-feed"),
    ("zdi_blog", "Zero Day Initiative Blog (roundups)", 5,
     "https://www.zerodayinitiative.com/blog/?format=rss"),
]


def _seen(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        t = entry.get(key)
        if t:
            return datetime.fromtimestamp(calendar.timegm(t), tz=UTC)
    return None


def _mentions_for_entry(title: str, summary: str, url: str | None,
                        seen: datetime | None) -> list[FetchedMention]:
    ids = extract_identifiers(title, summary)
    recognized = [i for i in ids if i.scheme in RECOGNIZED_SCHEMES]
    cves = [i.value for i in recognized if i.scheme == "CVE"]
    others = [i.value for i in recognized if i.scheme != "CVE"]
    snippet = f"{title} | {summary}"[:2000]
    ttl = (title or "")[:200]
    if len(cves) == 1:
        return [FetchedMention(url=url, title=ttl, snippet=snippet,
                               cve_id=cves[0], extra_ids=others or None, seen_at=seen)]
    if len(cves) > 1:
        # Varias vulns distintas en un boletín: una mención por CVE, sin bundlear.
        return [FetchedMention(url=url, title=ttl, snippet=snippet, cve_id=c, seen_at=seen)
                for c in cves]
    if others:  # sin CVE pero con código reconocido (ZDI-CAN/VU/GHSA/MSRC)
        return [FetchedMention(url=url, title=ttl, snippet=snippet,
                               native_id=others[0], extra_ids=others[1:] or None, seen_at=seen)]
    return []


async def _fetch_feed(ctx: FetchContext, url: str, browser_ua: bool = False,
                      ) -> list[FetchedMention]:
    # http.get(): retries con backoff + archivado del crudo + UA del proyecto
    # (antes se puenteaba con ctx.http.get y un UA Chrome falso fijo).
    # respect_robots=False: son feeds OFICIALES publicados para ser consumidos;
    # robots.txt aplica a crawlers, no a esto (ver docstring de get()).
    headers = {"User-Agent": _BROWSER_UA} if browser_ua else None
    resp = await get(ctx.http, url, respect_robots=False, headers=headers, timeout=30.0)
    # feedparser.parse es síncrono (parseo XML del feed completo): a un hilo para
    # no bloquear el event loop del worker.
    parsed = await asyncio.to_thread(feedparser.parse, resp.content)
    out: list[FetchedMention] = []
    for entry in parsed.entries:
        out.extend(_mentions_for_entry(
            entry.get("title", ""), entry.get("summary", ""),
            entry.get("link"), _seen(entry)))
    return out


class _RssFeedSource(BaseSource):
    """Base data-driven; cada feed concreto fija name/kind/tier/feed_url."""

    method = "rss"
    cadence_seconds = 3600
    feed_url = ""
    browser_ua = False   # opt-in por feed: UA de navegador si el WAF lo exige

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        return await _fetch_feed(ctx, self.feed_url, browser_ua=self.browser_ua)


# Registra un fetcher por feed (clases generadas dinámicamente).
for _name, _kind, _tier, _url, *_rest in _FEEDS:
    register(type(
        f"Rss_{_name}",
        (_RssFeedSource,),
        {"name": _name, "kind": _kind, "tier": _tier, "feed_url": _url,
         "browser_ua": bool(_rest and _rest[0])},
    ))
