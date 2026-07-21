"""Tier 3 — Agregadores CVE → repos-PoC en GitHub (nomi-sec, trickest).

Índices comunitarios que mapean cada CVE a los repos de GitHub con su PoC/
exploit, actualizados a diario. Refuerzan la señal de weaponización: marcan
`has_public_poc` y aportan `reference_urls`. Se recorren solo los directorios de
años recientes (sparse-checkout) para acotar el volumen. Idempotente por
content_hash.

Nota: son señal de EXPLOTABILIDAD, no de tecnología afectada; su valor es
`has_public_poc`+refs sobre un CVE que suele existir ya por otras fuentes.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import UTC, datetime

from app.core.logging import get_logger
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.gitsrc import sync_repo

log = get_logger(__name__)

_CVE_FILE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)


class _PocRepoSource(BaseSource):
    """Base data-driven: subclase fija name/kind/repo_url y el parser de fichero."""

    method = "git"
    tier = 3
    cadence_seconds = 43200  # 12 h
    repo_url = ""
    lookback_years = 2   # cuántos años (incl. el actual) recorrer

    def _years(self) -> list[str]:
        y = datetime.now(UTC).year
        return [str(y - i) for i in range(self.lookback_years)]

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        years = self._years()
        repo = await sync_repo(self.name, self.repo_url, sparse_paths=years)
        return await asyncio.to_thread(self._walk, repo, years)

    def _walk(self, repo: str, years: list[str]) -> list[FetchedMention]:
        out: list[FetchedMention] = []
        for year in years:
            base = os.path.join(repo, year)
            if not os.path.isdir(base):
                continue
            for fn in os.listdir(base):
                m = _CVE_FILE.search(fn)
                if not m:
                    continue
                mention = self._parse_file(os.path.join(base, fn), m.group(1).upper())
                if mention is not None:
                    out.append(mention)
        log.info("poc_repos.parsed", source=self.name, mentions=len(out))
        return out

    def _parse_file(self, path: str, cve: str) -> FetchedMention | None:
        raise NotImplementedError


@register
class PocInGithubSource(_PocRepoSource):
    name = "poc_in_github"
    kind = "nomi-sec/PoC-in-GitHub (CVE -> repos PoC)"
    repo_url = "https://github.com/nomi-sec/PoC-in-GitHub.git"

    def _parse_file(self, path: str, cve: str) -> FetchedMention | None:
        try:
            with open(path, encoding="utf-8") as fh:
                repos = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(repos, list) or not repos:
            return None
        urls = [r.get("html_url") for r in repos if isinstance(r, dict) and r.get("html_url")]
        descs = [r.get("description") for r in repos if isinstance(r, dict) and r.get("description")]
        # seen_at = el PoC más ANTIGUO (primera vez que apareció una PoC pública).
        dates = [parse_advisory_date(r.get("created_at")) for r in repos
                 if isinstance(r, dict)]
        seen = min((d for d in dates if d is not None), default=None)
        return FetchedMention(
            url=urls[0] if urls else None,
            title=f"PoC público: {cve} ({len(urls)} repos)"[:200],
            snippet=(descs[0] if descs else None),
            cve_id=cve,
            seen_at=seen,
            flags={"has_public_poc": True},
            reference_urls=urls[:50] or None,
        )


@register
class TrickestCveSource(_PocRepoSource):
    name = "trickest_cve"
    kind = "trickest/cve (CVE -> PoC + producto)"
    repo_url = "https://github.com/trickest/cve.git"
    # trickest indexa MUCHÍSIMOS CVEs (sin fecha fiable): acotado al año actual
    # para centrarlo en señal reciente y no meter decenas de miles de menciones.
    lookback_years = 1

    _PRODUCT = re.compile(r"label=Product&message=([^&]+)")
    _GH = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+")

    def _parse_file(self, path: str, cve: str) -> FetchedMention | None:
        try:
            with open(path, encoding="utf-8") as fh:
                md = fh.read()
        except OSError:
            return None
        from urllib.parse import unquote
        urls = list(dict.fromkeys(self._GH.findall(md)))[:50]
        prod_m = self._PRODUCT.search(md)
        product = unquote(prod_m.group(1)).strip() if prod_m else None
        # trickest no trae fecha fiable: seen_at=None -> la ingesta usará now();
        # aceptable porque casi nunca es la fuente MÁS temprana del candidate.
        return FetchedMention(
            url=urls[0] if urls else None,
            title=f"{cve}: {product}" if product else cve,
            snippet=(f"trickest PoC index | product={product}" if product else None),
            cve_id=cve,
            flags={"has_public_poc": True},
            reference_urls=urls or None,
        )
