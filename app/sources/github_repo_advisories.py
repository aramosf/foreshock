"""Tier 2 — Advisories y releases POR-REPO de GitHub (REST).

Complementa a github_commits: el mensaje de un commit de fix a veces NO cita el
CVE, pero el `/security/advisories` del proyecto o sus `/releases` sí lo listan,
con el producto = el propio repo (señal 'pending' de tecnología conocida). Caso
motivador real: Netatalk/netatalk publica los CVEs de cada versión en las notas
de release y en sus repo-advisories antes de que NVD los enriquezca.

Escanea, por lotes sobre TODO el registro `github_repos` (ordenado por relevancia:
referencias/past_cve/criticality por encima del top-N por estrellas), dos
endpoints REST por repo:
  - GET /repos/{o}/{r}/security-advisories  -> GHSA propios del repo (con CVE).
  - GET /repos/{o}/{r}/releases             -> CVEs citados en nombre/cuerpo.

Marca de escaneo PROPIA (`adv_last_scanned_at`/`adv_watermark`, migración 0013):
NO comparte el watermark de commits. Idempotente por content_hash. El watermark
evita re-emitir en cada ciclo lo ya visto; en el PRIMER escaneo de un repo se
acota a `github_repo_scan_window_days`.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import httpx

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.ingest.affected import AffectedInput
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, parse_advisory_date, register
from app.sources.http import get

log = get_logger(__name__)

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class _RateLimited(RuntimeError):
    """Rate limit de la REST API agotado: cortar el lote y reanudar en el próximo run."""


def _split(full_name: str) -> tuple[str, str | None]:
    """'owner/repo' -> (repo, owner). Producto = el repo; vendor = el owner."""
    owner, _, repo = (full_name or "").partition("/")
    return (repo or full_name or ""), (owner or None)


def _advisory_mention(full_name: str, adv: dict) -> FetchedMention | None:
    """Un repo security-advisory -> mención. Ancla por CVE si lo tiene (GHSA como
    alias declarado); si no, por el GHSA. Producto: los paquetes del advisory si
    los trae, o el propio repo (para proyectos que no son un 'package ecosystem').
    """
    if not isinstance(adv, dict):
        return None
    ghsa = adv.get("ghsa_id")
    cve = adv.get("cve_id")
    if not cve and not ghsa:
        return None
    seen = (parse_advisory_date(adv.get("published_at"))
            or parse_advisory_date(adv.get("updated_at")))
    summary = (adv.get("summary") or "").strip()
    repo, owner = _split(full_name)
    affected: list[AffectedInput] = []
    for v in adv.get("vulnerabilities") or []:
        pkg = (v or {}).get("package") or {}
        name, eco = pkg.get("name"), pkg.get("ecosystem")
        if name:
            affected.append(AffectedInput(product=name, ecosystem=(eco or None),
                                          kind="product"))
    if not affected:
        affected = [AffectedInput(product=repo, vendor=owner, kind="product")]
    cwe_ids = [c.get("cwe_id") for c in (adv.get("cwes") or [])
               if isinstance(c, dict) and c.get("cwe_id")]
    html_url = adv.get("html_url")
    common = dict(
        url=html_url,
        title=(summary[:200] or cve or ghsa),
        snippet=(f"[repo advisory {full_name}] {summary}")[:2000] or None,
        seen_at=seen,
        affected=affected,
        reference_urls=[html_url] if html_url else None,
        cwe_ids=cwe_ids or None,
    )
    if cve:
        return FetchedMention(cve_id=cve, extra_ids=[ghsa] if ghsa else None, **common)
    return FetchedMention(native_id=ghsa, **common)


def _release_mentions(full_name: str, rel: dict) -> list[FetchedMention]:
    """Una release -> N menciones (una por CVE citado en nombre/cuerpo). Política
    anti-over-merge: varios CVEs en unas notas son vulns DISTINTAS -> una mención
    por CVE, cada una anclando su candidate. Producto = el propio repo."""
    if not isinstance(rel, dict):
        return []
    body = f"{rel.get('name') or ''}\n{rel.get('body') or ''}"
    cves = sorted({m.group(0).upper() for m in _CVE.finditer(body)})
    if not cves:
        return []
    seen = (parse_advisory_date(rel.get("published_at"))
            or parse_advisory_date(rel.get("created_at")))
    repo, owner = _split(full_name)
    tag = rel.get("tag_name") or rel.get("name") or ""
    url = rel.get("html_url")
    affected = [AffectedInput(product=repo, vendor=owner, kind="product")]
    out: list[FetchedMention] = []
    for cve in cves:
        out.append(FetchedMention(
            url=url,
            title=f"{full_name} {tag}: {cve}"[:200],
            snippet=(f"[release {full_name} {tag}] cita {cve}")[:2000],
            cve_id=cve,
            seen_at=seen,
            affected=affected,
            reference_urls=[url] if url else None,
        ))
    return out


def _emit(seen: datetime | None, cutoff: datetime, wm: datetime | None) -> bool:
    """¿Emitir este item? Con watermark: solo lo MÁS nuevo (evita re-crear lo ya
    ingerido cada ciclo). Sin watermark (primer escaneo): dentro de la ventana.
    Item sin fecha: solo en el primer escaneo (no re-emitir indatables cada vez)."""
    if seen is None:
        return wm is None
    if wm is not None:
        return seen > wm
    return seen >= cutoff


class GitHubRepoAdvisoriesSource(BaseSource):
    name = "github_repo_advisories"
    kind = "GitHub per-repo security advisories + release notes (CVE scan)"
    method = "api"
    tier = 2
    cadence_seconds = 3600

    def __init__(self) -> None:
        # (full_name, nuevo_adv_watermark) escaneados OK, pendientes de update_adv_scan.
        # Se aplican en finalize() SOLO tras persistir las menciones (idempotente).
        self._pending_scans: list[tuple[str, str | None]] = []

    def _headers(self, settings: Settings) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json",
             "X-GitHub-Api-Version": "2022-11-28"}
        if settings.github_token:
            h["Authorization"] = f"Bearer {settings.github_token}"
        return h

    async def _api(self, ctx: FetchContext, url: str, headers: dict,
                   params: dict | None = None) -> list | None:
        """GET a la REST API. [] o lista en éxito; None si el repo no tiene el
        recurso (404). Lanza _RateLimited si el 403/429 es por rate limit."""
        try:
            resp = await get(ctx.http, url, respect_robots=False,
                             headers=headers, params=params)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == 404:
                return None  # el repo no tiene releases/advisories (o ya no existe)
            if code in (403, 429) and exc.response.headers.get("X-RateLimit-Remaining") == "0":
                raise _RateLimited() from exc
            raise
        body = resp.json()
        return body if isinstance(body, list) else []

    async def _scan_repo(self, ctx: FetchContext, headers: dict, full: str,
                         cutoff: datetime, wm: datetime | None, settings: Settings,
                         ) -> tuple[list[FetchedMention], str | None]:
        base = settings.github_api_base
        out: list[FetchedMention] = []
        newest: datetime | None = None

        def _consider(m: FetchedMention) -> None:
            nonlocal newest
            if not _emit(m.seen_at, cutoff, wm):
                return
            out.append(m)
            if m.seen_at is not None and (newest is None or m.seen_at > newest):
                newest = m.seen_at

        advs = await self._api(ctx, f"{base}/repos/{full}/security-advisories",
                               headers, {"per_page": 100})
        for adv in advs or []:
            m = _advisory_mention(full, adv)
            if m is not None:
                _consider(m)

        rels = await self._api(ctx, f"{base}/repos/{full}/releases", headers,
                               {"per_page": settings.github_repo_scan_releases_per_repo})
        for rel in rels or []:
            for m in _release_mentions(full, rel):
                _consider(m)

        return out, (newest.isoformat() if newest is not None else None)

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        headers = self._headers(settings)

        from app.core.db import session_scope
        from app.sources.repo_registry import (
            harvest_references,
            harvest_top_n,
            next_batch_adv,
            registry_count,
        )

        # Bootstrap del registro si está vacío (mismo criterio que github_commits).
        if registry_count() == 0:
            log.info("repo_adv.registry_empty_bootstrap")
            harvest_references()
            await harvest_top_n(ctx.http, settings)

        with session_scope() as session:
            batch = next_batch_adv(session, settings.github_repo_scan_per_run)
        if not batch:
            log.warning("repo_adv.no_repos")
            return []

        cutoff = datetime.now(UTC) - timedelta(days=settings.github_repo_scan_window_days)
        out: list[FetchedMention] = []
        self._pending_scans = []
        failed = 0
        for full, watermark in batch:
            wm = parse_advisory_date(watermark)
            try:
                mentions, newest = await self._scan_repo(
                    ctx, headers, full, cutoff, wm, settings)
            except _RateLimited:
                log.warning("repo_adv.rate_limited", scanned=len(self._pending_scans))
                break  # corta el lote; finalize() marca lo hecho y se reanuda luego
            except Exception as exc:  # noqa: BLE001 - un repo no tumba el lote
                # Fallo (red/5xx/parse): NO se marca escaneado -> se reintenta.
                log.warning("repo_adv.repo_error", repo=full, error=str(exc))
                failed += 1
                continue
            out.extend(mentions)
            self._pending_scans.append((full, newest))
        log.info("repo_adv.batch_done", repos=len(batch),
                 scanned=len(self._pending_scans), failed=failed, mentions=len(out))
        return out

    def finalize(self) -> None:
        """Avanza adv_last_scanned_at/adv_watermark SOLO tras persistir el lote
        (lo invoca el runner). Si el fetch no llegó a persistirse, no corre y el
        siguiente re-escanea (idempotente por content_hash)."""
        if not self._pending_scans:
            return
        from app.core.db import session_scope
        from app.sources.repo_registry import update_adv_scan

        with session_scope() as session:
            for full, newest in self._pending_scans:
                update_adv_scan(session, full, newest)
        log.info("repo_adv.scan_marks_applied", repos=len(self._pending_scans))
        self._pending_scans = []


register(GitHubRepoAdvisoriesSource)
