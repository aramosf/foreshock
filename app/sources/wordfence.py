"""Tier 3 — Wordfence Intelligence (vulnerabilidades de WordPress).

WordPress (plugins/themes/core) es una superficie de ataque enorme; Wordfence
publica sus CVEs muy rápido, a menudo ANTES que NVD, con producto y versión
exactos. Feed v3 (~37k vulns, ~150 MB) que requiere API key gratuita
(FORESHOCK_WORDFENCE_API_KEY). La key tiene rate-limit estricto: se descarga con
caché de larga duración (una vez al día) y se recorren solo las publicadas en la
ventana reciente con CVE asignado.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingest.affected import AffectedInput
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.cache import cached_download

log = get_logger(__name__)

FEED = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
_CACHE_KEY = "wordfence_production.json"
_CACHE_TTL = 20 * 3600     # 20 h (rate-limit estricto de la key gratuita)
_WINDOW_DAYS = 120
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _cves(v: dict) -> list[str]:
    raw = v.get("cve")
    vals = raw if isinstance(raw, list) else ([raw] if raw else [])
    text = " ".join(str(x) for x in vals)
    # fallback: a veces el CVE aparece en title/references, no en 'cve'.
    text += " " + (v.get("title") or "")
    return sorted({m.group(0).upper() for m in _CVE.finditer(text)})


@register
class WordfenceSource(BaseSource):
    name = "wordfence"
    kind = "Wordfence Intelligence (WordPress vulns)"
    method = "api"
    tier = 3
    cadence_seconds = 86400  # diario (respeta el rate-limit de la key)

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        if not settings.wordfence_api_key:
            log.info("wordfence.no_key")  # inactiva sin key
            return []
        headers = {"Authorization": f"Bearer {settings.wordfence_api_key}"}
        path = await cached_download(ctx.http, FEED, _CACHE_KEY,
                                     ttl=_CACHE_TTL, headers=headers)
        cutoff = datetime.now(UTC) - timedelta(days=_WINDOW_DAYS)
        return await asyncio.to_thread(self._parse, path, cutoff)

    @staticmethod
    def _parse(path: str, cutoff: datetime) -> list[FetchedMention]:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        entries = data.values() if isinstance(data, dict) else data
        out: list[FetchedMention] = []
        for v in entries:
            if not isinstance(v, dict):
                continue
            seen = parse_advisory_date(v.get("published"))
            if seen is not None and seen < cutoff:
                continue
            cves = _cves(v)
            if not cves:
                continue   # sin CVE: la ID propia de Wordfence no es esquema reconocido
            affected: list[AffectedInput] = []
            for sw in (v.get("software") or []):
                name = sw.get("name") or sw.get("slug")
                if name:
                    affected.append(AffectedInput(
                        product=name, ecosystem="wordpress",
                        kind="product"))
            title = (v.get("title") or "").strip()[:200]
            refs = [r.get("url") for r in (v.get("references") or [])
                    if isinstance(r, dict) and r.get("url")]
            common = {
                "url": refs[0] if refs else None,
                "title": title or cves[0],
                "snippet": title or None,
                "seen_at": seen,
                "affected": affected or None,
                "reference_urls": refs[:50] or None,
            }
            if len(cves) == 1:
                out.append(FetchedMention(cve_id=cves[0], **common))
            else:
                for cve in cves:
                    out.append(FetchedMention(cve_id=cve, **common))
        log.info("wordfence.parsed", mentions=len(out))
        return out
