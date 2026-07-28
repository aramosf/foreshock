"""Registro de repos GitHub a vigilar + estrategias de descubrimiento.

Una tabla `github_repos` (PK full_name) unifica todas las estrategias -> un repo
añadido por varias NO se duplica, y el `watermark` evita re-escanear commits ya
vistos. github_commits consume `next_batch`/`update_scan`; no descubre por su cuenta.

Estrategias:
  1. reference   - repos citados en referencias de advisories (mentions/cve_reference/
                   candidates.reference_urls) -> github.com/owner/repo.
  2. past_cve    - subconjunto de (1): refs de candidates que YA tienen CVE.
  3. distro      - cubierto por (1): los advisories de paquetes/distros referencian
                   el repo upstream. (Un mapeo distro->repo dedicado necesitaría repology.)
  4. criticality - OpenSSF Criticality Score (CSV externo, opt-in via config).
  5. downloads   - top PyPI por descargas -> repo (opt-in via config).
  0. top_n       - los top-N repos por estrellas (base histórica).
"""

from __future__ import annotations

import csv
import io
import re

import httpx
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.config import Settings
from app.core.db import session_scope
from app.core.logging import get_logger
from app.core.models import Candidate, CveReference, GithubRepo
from app.core.models import Mention as MentionRow

log = get_logger(__name__)

# Solo el host github.com (con www. opcional): el lookbehind negativo evita
# casar subdominios (gist.github.com) o hosts falsos (evilgithub.com); exigir
# '/' justo tras el host evita github.com.evil.org.
_GH = re.compile(
    r"(?:^|(?<=[^\w.-]))(?:https?://)?(?:www\.)?github\.com/"
    r"([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*)"
)
_SKIP_OWNERS = {
    "advisories", "sponsors", "marketplace", "orgs", "users", "about", "security",
    "blog", "features", "topics", "collections", "apps", "notifications", "settings",
    "pulls", "issues", "login", "join", "site", "enterprise", "readme", "search", "gist",
}
_PRIORITY = {"reference": 10, "past_cve": 20, "criticality": 15, "downloads": 15,
             "top_n": 0, "manual": 30}

# Repos-PoC / disclosure de un investigador (nombre con CVE-YYYY-NNNNN o
# segmentos poc/exploit/disclosure/advisory/writeup): señal válida ("hay un PoC
# circulando") pero de OTRA naturaleza que un fix upstream del proyecto afectado.
# No se excluyen; se etiquetan con repo_kind='poc' para poder distinguirlos.
_POC_NAME = re.compile(
    r"CVE-\d{4}-\d+"
    r"|(?:^|[-_/])(?:pocs?|exploits?|disclosures?|advisor(?:y|ies)|writeups?)(?:[-_/]|$)",
    re.IGNORECASE,
)


def classify_repo_kind(full_name: str) -> str:
    """'poc' si el nombre delata un repo-PoC/disclosure; 'project' en otro caso."""
    return "poc" if _POC_NAME.search(full_name or "") else "project"


def _headers(settings: Settings) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


def _extract_repo(url: str | None) -> str | None:
    if not url:
        return None
    m = _GH.search(url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if owner.lower() in _SKIP_OWNERS:
        return None
    repo = repo[:-4] if repo.endswith(".git") else repo
    if not repo or repo in {".", ".."}:
        return None
    return f"{owner}/{repo}"


def upsert_repos(session, repos: dict[str, dict]) -> int:
    """repos: {full_name: {origin, stars?, priority?}}. Dedup por PK; en conflicto
    sube la prioridad (GREATEST) y completa estrellas. Devuelve nº procesado."""
    if not repos:
        return 0
    rows = []
    for full, meta in repos.items():
        origin = meta.get("origin", "reference")
        rows.append({
            "full_name": full,
            "origin": origin,
            "repo_kind": classify_repo_kind(full),
            "stars": meta.get("stars"),
            "priority": meta.get("priority", _PRIORITY.get(origin, 0)),
        })
    stmt = pg_insert(GithubRepo.__table__)
    stmt = stmt.on_conflict_do_update(
        index_elements=["full_name"],
        set_={
            "priority": func.greatest(GithubRepo.__table__.c.priority, stmt.excluded.priority),
            "stars": func.coalesce(stmt.excluded.stars, GithubRepo.__table__.c.stars),
            "repo_kind": func.coalesce(GithubRepo.__table__.c.repo_kind, stmt.excluded.repo_kind),
        },
    )
    session.execute(stmt, rows)
    return len(rows)


# --- Estrategia 1/2/3: referencias de advisories ya en la BD ------------------
def harvest_references() -> dict[str, int]:
    found: dict[str, dict] = {}
    with_cve: set[str] = set()
    with session_scope() as session:
        # URLs de mentions.
        for (url, cve) in session.execute(
            select(MentionRow.url, MentionRow.extracted_cve).where(MentionRow.url.isnot(None))
        ):
            repo = _extract_repo(url)
            if repo:
                found.setdefault(repo, {"origin": "reference"})
                if cve:
                    with_cve.add(repo)
        # URLs de cve_reference.
        for (url,) in session.execute(select(CveReference.url).where(CveReference.url.isnot(None))):
            repo = _extract_repo(url)
            if repo:
                found.setdefault(repo, {"origin": "reference"})
        # candidates.reference_urls (array).
        for (arr, cve) in session.execute(
            select(Candidate.reference_urls, Candidate.cve_id).where(
                Candidate.reference_urls.isnot(None))
        ):
            for url in arr or []:
                repo = _extract_repo(url)
                if repo:
                    found.setdefault(repo, {"origin": "reference"})
                    if cve:
                        with_cve.add(repo)
        # Marca los que tienen CVE previo como past_cve (mayor prioridad).
        for repo in with_cve:
            found[repo] = {"origin": "past_cve"}
        upsert_repos(session, found)
    log.info("registry.harvest_references", repos=len(found), with_cve=len(with_cve))
    return {"reference": len(found) - len(with_cve), "past_cve": len(with_cve)}


# --- Estrategia 0: top-N por estrellas ---------------------------------------
async def harvest_top_n(client: httpx.AsyncClient, settings: Settings) -> dict[str, int]:
    base = settings.github_api_base
    repos: dict[str, dict] = {}
    upper: int | None = None
    floor = 50
    while len(repos) < settings.github_top_n:
        q = f"stars:>={floor}" if upper is None else f"stars:{floor}..{upper}"
        page_min: int | None = None
        for page in range(1, 11):
            resp = await client.get(
                f"{base}/search/repositories", headers=_headers(settings),
                params={"q": q, "sort": "stars", "order": "desc", "per_page": 100, "page": page},
            )
            if resp.status_code != 200:
                # Típicamente 403 por rate limit de la Search API sin token:
                # visible en logs (antes se cortaba en silencio con menos repos).
                log.warning("registry.top_n_http_error", status=resp.status_code,
                            query=q, page=page, body=resp.text[:200])
                break
            items = resp.json().get("items", [])
            if not items:
                break
            for it in items:
                page_min = it["stargazers_count"]
                repos.setdefault(it["full_name"],
                                 {"origin": "top_n", "stars": it["stargazers_count"]})
                if len(repos) >= settings.github_top_n:
                    break
            if len(repos) >= settings.github_top_n:
                break
        if page_min is None or page_min <= floor:
            break
        if upper is not None and page_min >= upper:
            # Sin progreso: >1000 repos con las mismas estrellas (límite de la
            # Search API). Repetir la misma franja iteraría para siempre.
            log.warning("registry.top_n_no_progress", stars=page_min, repos=len(repos))
            break
        upper = page_min
    with session_scope() as session:
        upsert_repos(session, repos)
    log.info("registry.harvest_top_n", repos=len(repos))
    return {"top_n": len(repos)}


# --- Estrategia 4: OpenSSF Criticality Score (CSV externo, opt-in) ------------
async def harvest_criticality(client: httpx.AsyncClient, settings: Settings) -> dict[str, int]:
    if not settings.criticality_csv_url:
        return {"criticality": 0}
    resp = await client.get(settings.criticality_csv_url, follow_redirects=True, timeout=120)
    resp.raise_for_status()
    repos: dict[str, dict] = {}
    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        for val in row.values():
            repo = _extract_repo(val)
            if repo:
                repos.setdefault(repo, {"origin": "criticality"})
                break
    with session_scope() as session:
        upsert_repos(session, repos)
    log.info("registry.harvest_criticality", repos=len(repos))
    return {"criticality": len(repos)}


# --- Estrategia 5: top PyPI por descargas -> repo (opt-in) -------------------
_PYPI_TOP = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"


async def harvest_pypi_downloads(client: httpx.AsyncClient, settings: Settings) -> dict[str, int]:
    top_n = settings.pypi_downloads_top_n
    if top_n <= 0:
        return {"downloads": 0}
    resp = await client.get(_PYPI_TOP, follow_redirects=True, timeout=60)
    resp.raise_for_status()
    rows = (resp.json().get("rows") or [])[:top_n]
    repos: dict[str, dict] = {}
    for row in rows:
        pkg = row.get("project")
        if not pkg:
            continue
        try:
            r = await client.get(f"https://pypi.org/pypi/{pkg}/json", timeout=30)
            if r.status_code != 200:
                continue
            urls = (r.json().get("info") or {}).get("project_urls") or {}
            for val in urls.values():
                repo = _extract_repo(val)
                if repo:
                    repos.setdefault(repo, {"origin": "downloads"})
                    break
        except Exception:  # noqa: BLE001 - un paquete no tumba la cosecha
            continue
    with session_scope() as session:
        upsert_repos(session, repos)
    log.info("registry.harvest_pypi_downloads", packages=len(rows), repos=len(repos))
    return {"downloads": len(repos)}


async def harvest_all(client: httpx.AsyncClient, settings: Settings) -> dict[str, int]:
    stats: dict[str, int] = {}
    stats.update(harvest_references())                       # 1/2/3 (datos propios)
    stats.update(await harvest_top_n(client, settings))      # 0
    stats.update(await harvest_criticality(client, settings))  # 4 (opt-in)
    stats.update(await harvest_pypi_downloads(client, settings))  # 5 (opt-in)
    return stats


# --- Consumo por github_commits ----------------------------------------------
# No re-escanear un repo antes de N horas: sin esta exclusión, ordenar por
# last_scanned_at convierte todo en un round-robin plano y la prioridad nunca
# manda (los repos proven-relevant esperan detrás de los 10k por estrellas).
RESCAN_MIN_HOURS = 6


def next_batch(session, n: int) -> list[tuple[str, str | None]]:
    """Siguiente lote a escanear: se EXCLUYE lo escaneado hace < RESCAN_MIN_HOURS
    y se ordena por prioridad DESC, nunca-escaneados primero, estrellas DESC.
    NOTA: el índice de github_repos se crea exactamente con esta ordenación
    (priority DESC, last_scanned_at ASC NULLS FIRST, stars DESC NULLS LAST);
    no cambiar una sin la otra."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import or_

    threshold = datetime.now(UTC) - timedelta(hours=RESCAN_MIN_HOURS)
    rows = session.execute(
        select(GithubRepo.full_name, GithubRepo.watermark)
        .where(or_(GithubRepo.last_scanned_at.is_(None),
                   GithubRepo.last_scanned_at < threshold))
        .order_by(
            GithubRepo.priority.desc(),
            GithubRepo.last_scanned_at.asc().nulls_first(),
            GithubRepo.stars.desc().nulls_last(),
        ).limit(n)
    ).all()
    return [(r[0], r[1]) for r in rows]


def next_batch_adv(session, n: int) -> list[tuple[str, str | None]]:
    """Como next_batch pero para el escaneo de advisories/releases: usa la marca
    PROPIA (adv_last_scanned_at/adv_watermark), no la de commits. Devuelve
    (full_name, adv_watermark). El índice idx_ghrepos_adv_scan sirve este ORDER BY.
    Solo repos 'project' (no repos-PoC: un /releases de un repo-PoC no aporta el
    software afectado, que es el objetivo de esta señal)."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import or_

    threshold = datetime.now(UTC) - timedelta(hours=RESCAN_MIN_HOURS)
    rows = session.execute(
        select(GithubRepo.full_name, GithubRepo.adv_watermark)
        .where(or_(GithubRepo.adv_last_scanned_at.is_(None),
                   GithubRepo.adv_last_scanned_at < threshold))
        .where(or_(GithubRepo.repo_kind.is_(None), GithubRepo.repo_kind != "poc"))
        .order_by(
            GithubRepo.priority.desc(),
            GithubRepo.adv_last_scanned_at.asc().nulls_first(),
            GithubRepo.stars.desc().nulls_last(),
        ).limit(n)
    ).all()
    return [(r[0], r[1]) for r in rows]


def update_adv_scan(session, full_name: str, watermark: str | None) -> None:
    """Avanza adv_last_scanned_at (siempre) y adv_watermark (si hay uno más nuevo).
    El watermark solo sube (max ISO): un lote antiguo no debe retroceder el cursor."""
    from datetime import UTC, datetime

    values: dict = {"adv_last_scanned_at": datetime.now(UTC)}
    if watermark:
        values["adv_watermark"] = func.greatest(
            func.coalesce(GithubRepo.__table__.c.adv_watermark, watermark), watermark)
    session.execute(
        GithubRepo.__table__.update()
        .where(GithubRepo.__table__.c.full_name == full_name)
        .values(**values)
    )


def get_watermark(session, full_name: str) -> str | None:
    """Watermark actual de un repo del registro (None si no existe/sin escanear)."""
    return session.execute(
        select(GithubRepo.watermark).where(GithubRepo.full_name == full_name)
    ).scalar_one_or_none()


def update_scan(session, full_name: str, watermark: str | None) -> None:
    from datetime import UTC, datetime
    values = {"last_scanned_at": datetime.now(UTC)}
    if watermark:
        values["watermark"] = watermark
    session.execute(
        GithubRepo.__table__.update()
        .where(GithubRepo.__table__.c.full_name == full_name)
        .values(**values)
    )


def registry_count() -> int:
    with session_scope() as session:
        return session.execute(select(func.count()).select_from(GithubRepo.__table__)).scalar_one()
