"""Tier 4 — Commits de los repos más populares de GitHub (vía clon *blobless*).

Vigila los top-N repos por estrellas y escanea sus commits desde un cutoff fijo
en busca de señal temprana: commits que CITAN un CVE (a menudo reservado, aún no
público en NVD) -> mención anclada a ese CVE. Los CVEs adicionales citados en el
mensaje se guardan como referencia blanda (en el pipeline de ingesta).

Estrategia de escaneo (2026-07): en vez de la REST API commit-a-commit (limitada
a 5000 req/h), se hace un **clon parcial**:

    git clone --filter=blob:none --no-checkout --shallow-since=<cutoff>

que NO descarga el contenido de los ficheros (solo objetos commit/tree), y luego
``git log`` local para leer los mensajes. Sin rate limit de API y con transferencia
mínima -> barrido de los 10k mucho más rápido. El clon se borra tras leer el log.

El descubrimiento de la lista top-N sigue usando la Search API (cacheada semanal).
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime, timedelta

import httpx

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, register

log = get_logger(__name__)

_SECFIX = re.compile(
    r"\b(security fix|vulnerabilit|remote code execution|\brce\b|\bxss\b|"
    r"sql injection|sqli|auth(?:entication)? bypass|\bssrf\b|deserializ|"
    r"path traversal|arbitrary (?:code|file)|buffer overflow|use[- ]after[- ]free|"
    r"privilege escalation|out[- ]of[- ]bounds)\b",
    re.IGNORECASE,
)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Separadores de registro/campo para el formato de git log (ASCII de control,
# improbables en un mensaje de commit).
_REC = "\x1e"
_FLD = "\x1f"
_LOG_FMT = f"%H{_FLD}%cI{_FLD}%B{_REC}"


def _headers(settings: Settings) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


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
    built = datetime.fromisoformat(data["built_at"])
    if datetime.now(UTC) - built > timedelta(days=7):
        return None
    return list(data["repos"])


def _save_repo_list(settings: Settings, repos: list[str]) -> None:
    os.makedirs(settings.data_dir, exist_ok=True)
    with open(_repo_list_path(settings), "w", encoding="utf-8") as fh:
        json.dump({"built_at": datetime.now(UTC).isoformat(), "repos": repos}, fh)


async def _build_repo_list(client: httpx.AsyncClient, settings: Settings) -> list[str]:
    """Construye la lista top-N por estrellas con ventanas descendentes (la Search
    API tope 1000 resultados por consulta, así que se windowa)."""
    base = settings.github_api_base
    repos: list[str] = []
    seen: set[str] = set()
    upper: int | None = None
    floor = 50
    while len(repos) < settings.github_top_n:
        q = f"stars:>={floor}" if upper is None else f"stars:{floor}..{upper}"
        page_min: int | None = None
        for page in range(1, 11):
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
        upper = page_min
    return repos


def _state_path(settings: Settings) -> str:
    return os.path.join(settings.data_dir, "github_repo_state.json")


def _load_state(settings: Settings) -> dict[str, str]:
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
    os.replace(tmp, _state_path(settings))


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


# --- escaneo por clon blobless -----------------------------------------------
def _clone_url(settings: Settings, full: str) -> str:
    """URL de clon; con token embebido para límites más altos (no se loguea)."""
    if settings.github_token:
        return f"https://x-access-token:{settings.github_token}@github.com/{full}.git"
    return f"https://github.com/{full}.git"


async def _run_git(*args: str, timeout: float = 180.0) -> tuple[int, str]:
    """Ejecuta git de forma async. Devuelve (returncode, stdout)."""
    proc = await asyncio.create_subprocess_exec(
        "git", *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, _err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, ""
    return proc.returncode or 0, out.decode("utf-8", "replace")


def _mentions_from_log(full: str, log_out: str,
                       synthesize: bool) -> tuple[list[FetchedMention], str | None]:
    out: list[FetchedMention] = []
    newest: str | None = None
    for rec in log_out.split(_REC):
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split(_FLD)
        if len(parts) < 3:
            continue
        sha, cdate, msg = parts[0], parts[1], parts[2]
        if cdate and (newest is None or cdate > newest):
            newest = cdate
        # TODOS los CVEs distintos del mensaje (no solo el primero): un commit que
        # arregla varios CVEs referencia a TODOS. Se emite UNA mención por CVE ->
        # cada una declara un único CVE y ancla su propio candidate, SIN fusionar
        # entre sí (no reintroduce over-merge). Un commit "batch de N CVEs" pasa a
        # ser N menciones independientes, no un bloque.
        cves: list[str] = []
        seen_cve: set[str] = set()
        for mm in _CVE.finditer(msg):
            v = mm.group(0).upper()
            if v not in seen_cve:
                seen_cve.add(v)
                cves.append(v)
        sec = bool(_SECFIX.search(msg))
        if not cves and not (sec and synthesize):
            continue
        first_line = msg.splitlines()[0] if msg else ""
        try:
            seen = datetime.fromisoformat(cdate) if cdate else None
        except ValueError:
            seen = None
        url = f"https://github.com/{full}/commit/{sha}"
        title = f"{full}: {first_line}"[:200]
        snippet = f"[{full}] {msg}"[:2000]
        if cves:
            for cve in cves:
                out.append(FetchedMention(url=url, title=title, snippet=snippet,
                                          cve_id=cve, native_id=None, seen_at=seen))
        else:  # commit de seguridad sin CVE (solo si synthesize)
            native = f"GHCOMMIT:{full}@{sha[:12]}"
            out.append(FetchedMention(url=url, title=title, snippet=snippet,
                                      cve_id=None, native_id=native, seen_at=seen))
    return out, newest


# --- caché comprimido del git-log por repo -----------------------------------
# Guarda SOLO los commits relevantes (citan CVE o lenguaje de fix de seguridad),
# comprimidos con gzip. Es *lossless* para el parser (`_mentions_from_log` sobre
# un commit sin CVE ni secfix no produce nada), pero descarta el 99% del log ->
# caché diminuto. Permite re-extraer tras un bug SIN volver a clonar.
def _gitlog_cache_dir(settings: Settings) -> str:
    return os.path.join(settings.cache_dir, "gitlog")


def _gitlog_cache_path(settings: Settings, full: str) -> str:
    safe = full.replace("/", "__")
    return os.path.join(_gitlog_cache_dir(settings), f"{safe}.log.gz")


def _write_gitlog_cache(settings: Settings, full: str, log_out: str) -> None:
    # Conserva solo los registros con CVE o secfix (suficiente para re-parsear).
    keep = [rec for rec in log_out.split(_REC)
            if rec.strip("\n") and (_CVE.search(rec) or _SECFIX.search(rec))]
    directory = _gitlog_cache_dir(settings)
    os.makedirs(directory, exist_ok=True)
    path = _gitlog_cache_path(settings, full)
    if not keep:
        # Sin commits relevantes: no dejamos fichero (ahorro de inodos/espacio).
        if os.path.exists(path):
            os.remove(path)
        return
    # Primera línea = repo (autoritativa); resto = log con separadores _REC.
    content = full + "\n" + (_REC.join(keep) + _REC)
    tmp = path + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)


def reextract_from_cache(settings: Settings) -> list[FetchedMention]:
    """Re-parsea TODOS los git-log cacheados (sin clonar) -> menciones. Para
    recuperarse de un bug de extracción: se re-corre `_mentions_from_log` con el
    código actual sobre la caché. Cero red."""
    directory = _gitlog_cache_dir(settings)
    if not os.path.isdir(directory):
        return []
    synth = settings.github_synthesize_candidates
    out: list[FetchedMention] = []
    for fn in sorted(os.listdir(directory)):
        if not fn.endswith(".log.gz"):
            continue
        try:
            with gzip.open(os.path.join(directory, fn), "rt",
                           encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        full, _, log_body = content.partition("\n")
        mentions, _ = _mentions_from_log(full, log_body, synth)
        out.extend(mentions)
    return out


async def _git_scan(settings: Settings, full: str, since_iso: str,
                    synthesize: bool) -> tuple[list[FetchedMention], str | None]:
    """Clona blobless+shallow-since, lee git log, CACHEA (gzip) y borra el clon."""
    since_date = since_iso[:10] or "2026-05-01"  # git acepta YYYY-MM-DD
    base = os.path.join(settings.data_dir, "clones")
    os.makedirs(base, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=base)
    try:
        code, _ = await _run_git(
            "clone", "--filter=blob:none", "--no-checkout", "--quiet",
            f"--shallow-since={since_date}", _clone_url(settings, full), tmp,
        )
        if code != 0:
            # shallow-since sin commits o repo inaccesible: nada que reportar.
            return [], None
        code, log_out = await _run_git(
            "-C", tmp, "log", f"--since={since_date}", f"--pretty=format:{_LOG_FMT}",
        )
        if code != 0:
            return [], None
        _write_gitlog_cache(settings, full, log_out)  # caché comprimido para re-extraer
        return _mentions_from_log(full, log_out, synthesize)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def scan_single_repo(client: httpx.AsyncClient, full: str, *, months: int,
                           synthesize: bool = False) -> list[FetchedMention]:
    """Escanea UN repo concreto (nuclei-templates, metasploit…) vía clon blobless.
    `client` se ignora (se usa git). `synthesize=False`: solo commits con CVE."""
    settings = get_settings()
    cutoff = datetime.now(UTC) - timedelta(days=30 * months)
    mentions, _ = await _git_scan(settings, full, cutoff.strftime("%Y-%m-%d"),
                                  synthesize=synthesize)
    return mentions


@register
class GitHubCommitsSource(BaseSource):
    name = "github_commits"
    kind = "GitHub top-N repos commit scan (blobless clone + git log)"
    method = "git"
    tier = 4
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        repos = _load_repo_list(settings)
        if repos is None or len(repos) < settings.github_top_n:
            log.info("github.building_repo_list", top_n=settings.github_top_n,
                     cached=len(repos) if repos else 0)
            repos = await _build_repo_list(ctx.http, settings)
            if repos:
                _save_repo_list(settings, repos)
        if not repos:
            log.warning("github.no_repos")
            return []

        if settings.github_commits_since:
            cutoff_iso = f"{settings.github_commits_since}T00:00:00Z"
        else:
            cutoff = datetime.now(UTC) - timedelta(days=30 * settings.github_commits_months)
            cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

        cursor = _load_cursor(settings)
        batch = repos[cursor:cursor + settings.github_repos_per_run]
        if len(batch) < settings.github_repos_per_run:
            batch += repos[: settings.github_repos_per_run - len(batch)]
        next_cursor = (cursor + settings.github_repos_per_run) % max(len(repos), 1)

        state = _load_state(settings)
        synthesize = settings.github_synthesize_candidates
        out: list[FetchedMention] = []
        for full in batch:
            since_iso = max(cutoff_iso, state.get(full, ""), key=lambda x: x or "")
            since_iso = since_iso or cutoff_iso
            try:
                mentions, newest = await _git_scan(settings, full, since_iso, synthesize)
                out.extend(mentions)
                if newest is not None:
                    state[full] = newest
            except Exception as exc:  # noqa: BLE001 - un repo no tumba el lote
                log.warning("github.repo_error", repo=full, error=str(exc))
        _save_state(settings, state)
        _save_cursor(settings, next_cursor)
        log.info("github.batch_done", repos=len(batch), mentions=len(out),
                 cursor=next_cursor, watermarks=len(state))
        return out
