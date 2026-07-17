"""Tier 4 — Changelog/commits de los repos más populares de GitHub.

Vigila los top-N repos por estrellas y escanea sus commits de los últimos N
meses en busca de señal temprana de vulnerabilidades:

  1. Commits que CITAN un CVE (a menudo reservado, aún no público en NVD/MITRE)
     -> mención con ese CVE.
  2. Commits con lenguaje de FIX DE SEGURIDAD sin CVE asignado -> se anclan como
     candidate pre-CVE mediante un identificador sintético 'GHCOMMIT:owner/repo@sha',
     que la reconciliación podrá fusionar con el CVE cuando aparezca.

Escala: los top-N repos (por defecto 10.000) se resuelven una vez y se cachean;
en cada ejecución se procesa un lote rotatorio (crawl incremental) para respetar
el rate limit de GitHub. Requiere un PAT (github_token) para 5000 req/h.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta

import httpx

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, register

log = get_logger(__name__)

# Lenguaje de fix de seguridad (conservador para no inundar de ruido).
_SECFIX = re.compile(
    r"\b(security fix|vulnerabilit|remote code execution|\brce\b|\bxss\b|"
    r"sql injection|sqli|auth(?:entication)? bypass|\bssrf\b|deserializ|"
    r"path traversal|arbitrary (?:code|file)|buffer overflow|use[- ]after[- ]free|"
    r"privilege escalation|out[- ]of[- ]bounds)\b",
    re.IGNORECASE,
)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _headers(settings: Settings) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


def _rate_left(resp: httpx.Response) -> int:
    try:
        return int(resp.headers.get("X-RateLimit-Remaining", "1"))
    except ValueError:
        return 1


# --- lista de repos top-N (cache en disco) -----------------------------------
def _repo_list_path(settings: Settings) -> str:
    return os.path.join(settings.data_dir, "github_top_repos.json")


def _cursor_path(settings: Settings) -> str:
    return os.path.join(settings.data_dir, "github_commits_cursor.txt")


def _load_repo_list(settings: Settings) -> list[str] | None:
    path = _repo_list_path(settings)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    # rebuild semanal
    built = datetime.fromisoformat(data["built_at"])
    if datetime.now(UTC) - built > timedelta(days=7):
        return None
    return list(data["repos"])


def _save_repo_list(settings: Settings, repos: list[str]) -> None:
    os.makedirs(settings.data_dir, exist_ok=True)
    with open(_repo_list_path(settings), "w", encoding="utf-8") as fh:
        json.dump({"built_at": datetime.now(UTC).isoformat(), "repos": repos}, fh)


async def _build_repo_list(client: httpx.AsyncClient, settings: Settings) -> list[str]:
    """Construye la lista top-N por estrellas con ventanas descendentes de estrellas
    (la Search API tope 1000 resultados por consulta, así que se windowa)."""
    base = settings.github_api_base
    repos: list[str] = []
    seen: set[str] = set()
    upper: int | None = None
    floor = 50  # no bajamos de 50 estrellas
    while len(repos) < settings.github_top_n:
        q = f"stars:>={floor}" if upper is None else f"stars:{floor}..{upper}"
        page_min: int | None = None
        for page in range(1, 11):  # 10 páginas x 100 = 1000 máx por ventana
            resp = await client.get(
                f"{base}/search/repositories",
                headers=_headers(settings),
                params={"q": q, "sort": "stars", "order": "desc",
                        "per_page": 100, "page": page},
            )
            if resp.status_code != 200:
                log.warning("github.search_error", status=resp.status_code)
                return repos
            items = resp.json().get("items", [])
            if not items:
                break
            for it in items:
                full = it["full_name"]
                page_min = it["stargazers_count"]
                if full not in seen:
                    seen.add(full)
                    repos.append(full)
                    if len(repos) >= settings.github_top_n:
                        return repos
        if page_min is None or page_min <= floor:
            break
        upper = page_min  # siguiente ventana por debajo del mínimo visto
    return repos


def _state_path(settings: Settings) -> str:
    return os.path.join(settings.data_dir, "github_repo_state.json")


def _load_state(settings: Settings) -> dict[str, str]:
    """Watermark por repo: full_name -> ISO de la última fecha de commit escaneada."""
    path = _state_path(settings)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return dict(json.load(fh))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(settings: Settings, state: dict[str, str]) -> None:
    os.makedirs(settings.data_dir, exist_ok=True)
    tmp = _state_path(settings) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, _state_path(settings))  # escritura atómica


def _load_cursor(settings: Settings) -> int:
    path = _cursor_path(settings)
    if os.path.exists(path):
        try:
            return int(open(path).read().strip())
        except ValueError:
            return 0
    return 0


def _save_cursor(settings: Settings, cursor: int) -> None:
    os.makedirs(settings.data_dir, exist_ok=True)
    with open(_cursor_path(settings), "w", encoding="utf-8") as fh:
        fh.write(str(cursor))


async def _scan_repo(client: httpx.AsyncClient, settings: Settings, full: str,
                     since_iso: str, synthesize: bool | None = None
                     ) -> tuple[list[FetchedMention], str | None]:
    """Escanea commits desde `since_iso`. Devuelve (menciones, ISO del commit más
    reciente visto) para actualizar el watermark incremental del repo.

    `synthesize`: si True, los commits de fix de seguridad SIN CVE generan un
    candidate pre-CVE (GHCOMMIT). Por defecto usa el ajuste global; nuclei/metasploit
    lo desactivan (solo interesan los commits que ya citan un CVE)."""
    if synthesize is None:
        synthesize = settings.github_synthesize_candidates
    owner_repo = full
    resp = await client.get(
        f"{settings.github_api_base}/repos/{full}/commits",
        headers=_headers(settings),
        params={"since": since_iso, "per_page": 100},
    )
    if resp.status_code != 200:
        return [], None
    out: list[FetchedMention] = []
    newest: str | None = None
    for commit in resp.json():
        commit_date = (commit.get("commit") or {}).get("committer", {}).get("date")
        if commit_date and (newest is None or commit_date > newest):
            newest = commit_date
        msg = (commit.get("commit") or {}).get("message", "")
        cve = None
        m = _CVE.search(msg)
        if m:
            cve = m.group(0).upper()
        sec = bool(_SECFIX.search(msg))
        if not cve and not (sec and synthesize):
            continue
        sha = commit.get("sha", "")[:12]
        native = None
        if not cve and sec:
            native = f"GHCOMMIT:{owner_repo}@{sha}"
        first_line = msg.splitlines()[0] if msg else ""
        out.append(
            FetchedMention(
                url=commit.get("html_url"),
                title=f"{owner_repo}: {first_line}"[:200],
                snippet=f"[{owner_repo}] {msg}"[:2000],
                cve_id=cve,
                native_id=native,
                seen_at=datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
                if commit_date else None,
            )
        )
    return out, newest


async def scan_single_repo(client: httpx.AsyncClient, full: str, *, months: int,
                           synthesize: bool = False) -> list[FetchedMention]:
    """Escanea el changelog de UN repo concreto (nuclei-templates, metasploit…).
    `synthesize=False`: solo commits que citan un CVE (sin ruido de fixes sin CVE)."""
    settings = get_settings()
    cutoff = (datetime.now(UTC) - timedelta(days=30 * months))
    since_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    mentions, _ = await _scan_repo(client, settings, full, since_iso, synthesize=synthesize)
    return mentions


@register
class GitHubCommitsSource(BaseSource):
    name = "github_commits"
    kind = "GitHub top-N repos commit/changelog scan"
    method = "api"
    tier = 4
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        repos = _load_repo_list(settings)
        # Reconstruye si no hay caché o si el top-N pedido superó la lista cacheada
        # (permite subir CVERADAR_GITHUB_TOP_N sin borrar la caché a mano).
        if repos is None or len(repos) < settings.github_top_n:
            log.info("github.building_repo_list", top_n=settings.github_top_n,
                     cached=len(repos) if repos else 0)
            repos = await _build_repo_list(ctx.http, settings)
            if repos:
                _save_repo_list(settings, repos)
        if not repos:
            log.warning("github.no_repos")
            return []

        cutoff = (datetime.now(UTC) - timedelta(days=30 * settings.github_commits_months))
        cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        cursor = _load_cursor(settings)
        batch = repos[cursor:cursor + settings.github_repos_per_run]
        if len(batch) < settings.github_repos_per_run:
            batch += repos[: settings.github_repos_per_run - len(batch)]  # wrap
        next_cursor = (cursor + settings.github_repos_per_run) % max(len(repos), 1)

        state = _load_state(settings)  # watermark por repo (cache incremental)
        out: list[FetchedMention] = []
        for full in batch:
            # since = máximo entre el corte de N meses y lo ya escaneado -> incremental.
            since_iso = max(cutoff_iso, state.get(full, ""), key=lambda x: x or "")
            since_iso = since_iso or cutoff_iso
            try:
                mentions, newest = await _scan_repo(ctx.http, settings, full, since_iso)
                out.extend(mentions)
                if newest is not None:
                    state[full] = newest  # avanza el watermark
            except Exception as exc:  # noqa: BLE001 - un repo no tumba el lote
                log.warning("github.repo_error", repo=full, error=str(exc))
        _save_state(settings, state)
        _save_cursor(settings, next_cursor)
        log.info("github.batch_done", repos=len(batch), mentions=len(out),
                 cursor=next_cursor, watermarks=len(state))
        return out
