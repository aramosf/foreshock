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

import gzip
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime, timedelta

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.ingest.service import FetchedMention
from app.sources.base import BaseSource, FetchContext, register
from app.sources.gitproc import run_git_process

log = get_logger(__name__)


class GitScanError(RuntimeError):
    """Fallo de git (clone/log/timeout) al escanear un repo. El llamador NO debe
    avanzar watermark ni last_scanned_at: el repo se reintenta en otro lote."""

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


# --- escaneo por clon blobless -----------------------------------------------
def _clone_url(settings: Settings, full: str) -> str:
    """URL de clon; con token embebido para límites más altos (no se loguea)."""
    if settings.github_token:
        return f"https://x-access-token:{settings.github_token}@github.com/{full}.git"
    return f"https://github.com/{full}.git"


async def _run_git(*args: str, timeout: float = 180.0) -> tuple[int, str, str]:
    """Ejecuta git de forma async. Devuelve (returncode, stdout, stderr).
    rc=124 en timeout (convención de coreutils `timeout`)."""
    return await run_git_process(*args, timeout=timeout)


def _mentions_from_log(full: str, log_out: str,
                       synthesize: bool) -> tuple[list[FetchedMention], str | None]:
    out: list[FetchedMention] = []
    newest: datetime | None = None
    for rec in log_out.split(_REC):
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split(_FLD)
        if len(parts) < 3:
            continue
        sha, cdate, msg = parts[0], parts[1], parts[2]
        # Watermark: %cI trae offsets heterogéneos (+02:00, -07:00…), comparar
        # strings ISO daría un orden falso. Se parsea a datetime aware y se
        # compara/normaliza en UTC.
        cdt: datetime | None = None
        if cdate:
            try:
                cdt = datetime.fromisoformat(cdate)
                if cdt.tzinfo is None:
                    cdt = cdt.replace(tzinfo=UTC)
                cdt = cdt.astimezone(UTC)
            except ValueError:
                cdt = None
        if cdt is not None and (newest is None or cdt > newest):
            newest = cdt
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
    return out, (newest.isoformat() if newest is not None else None)


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


def _read_gitlog_cache(path: str) -> list[str]:
    """Registros ya cacheados (sin la primera línea de repo). [] si no hay caché."""
    if not os.path.exists(path):
        return []
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []
    _, _, body = content.partition("\n")
    return [rec for rec in body.split(_REC) if rec.strip("\n")]


def _write_gitlog_cache(settings: Settings, full: str, log_out: str) -> None:
    # Conserva solo los registros con CVE o secfix (suficiente para re-parsear).
    keep = [rec for rec in log_out.split(_REC)
            if rec.strip("\n") and (_CVE.search(rec) or _SECFIX.search(rec))]
    directory = _gitlog_cache_dir(settings)
    os.makedirs(directory, exist_ok=True)
    path = _gitlog_cache_path(settings, full)
    if not keep:
        # Escaneo incremental sin commits relevantes NUEVOS: el histórico
        # cacheado sigue siendo válido -> no se toca (antes se borraba y la
        # caché se autodestruía en cada ventana vacía).
        return
    # FUSIÓN con la caché previa: cada escaneo cubre solo su ventana (desde el
    # watermark); reemplazar el fichero perdería los commits de ventanas
    # anteriores. Se une por sha (primer campo del registro).
    merged: dict[str, str] = {}
    for rec in _read_gitlog_cache(path) + keep:
        sha = rec.strip("\n").split(_FLD, 1)[0]
        merged.setdefault(sha, rec)
    # Primera línea = repo (autoritativa); resto = log con separadores _REC.
    content = full + "\n" + (_REC.join(merged.values()) + _REC)
    # Temporal ÚNICO + os.replace atómico (dos procesos no se pisan el .tmp).
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=os.path.basename(path) + ".",
                               suffix=".tmp")
    os.close(fd)
    try:
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


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
    """Clona blobless+shallow-since, lee git log, CACHEA (gzip) y borra el clon.

    Lanza GitScanError si git falla (clone/log/timeout): el llamador NO debe
    marcar el repo como escaneado, para que se reintente en el siguiente lote.
    """
    # Fallback al cutoff fijo de settings (única fuente de verdad, no duplicar).
    since_date = since_iso[:10] or settings.github_commits_since[:10]
    base = os.path.join(settings.data_dir, "clones")
    os.makedirs(base, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=base)
    try:
        code, _, err = await _run_git(
            "clone", "--filter=blob:none", "--no-checkout", "--quiet",
            f"--shallow-since={since_date}", _clone_url(settings, full), tmp,
        )
        if code != 0:
            # "error processing shallow info": el repo NO tiene commits desde
            # since_date (repos inactivos, comunísimos en la cohorte past_cve).
            # No es un fallo: es un escaneo vacío legítimo y el repo debe
            # quedar como escaneado — tratarlo como error lo reintentaría
            # eternamente al frente de la cola y atascaría el barrido entero.
            if "error processing shallow info" in err:
                log.debug("github.no_commits_in_window", repo=full, since=since_date)
                return [], None
            # Repo inaccesible, rate limit, timeout (124)… NO es "sin commits":
            # se señaliza para no avanzar watermark/last_scanned_at.
            log.warning("github.git_clone_failed", repo=full, rc=code,
                        stderr=err.strip()[:300])
            raise GitScanError(f"git clone {full} rc={code}: {err.strip()[:200]}")
        code, log_out, err = await _run_git(
            "-C", tmp, "log", f"--since={since_date}", f"--pretty=format:{_LOG_FMT}",
        )
        if code != 0:
            log.warning("github.git_log_failed", repo=full, rc=code,
                        stderr=err.strip()[:300])
            raise GitScanError(f"git log {full} rc={code}: {err.strip()[:200]}")
        _write_gitlog_cache(settings, full, log_out)  # caché comprimido para re-extraer
        return _mentions_from_log(full, log_out, synthesize)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def scan_single_repo(full: str, *, months: int,
                           synthesize: bool = False,
                           ) -> tuple[list[FetchedMention], tuple[str, str | None]]:
    """Escanea UN repo concreto (nuclei-templates, metasploit…) vía clon blobless
    con watermark persistente: el repo se registra en `github_repos` con
    origin='manual' (dedup por full_name) y se escanea solo desde su watermark
    (fallback: ventana de `months`). Devuelve (menciones, (full, nuevo_watermark))
    para que el llamador aplique `update_scan` en `finalize()` SOLO tras
    persistir las menciones. `synthesize=False`: solo commits con CVE."""
    from app.core.db import session_scope
    from app.sources.repo_registry import get_watermark, upsert_repos

    settings = get_settings()
    with session_scope() as session:
        upsert_repos(session, {full: {"origin": "manual"}})
        watermark = get_watermark(session, full)
    cutoff = (datetime.now(UTC) - timedelta(days=30 * months)).strftime("%Y-%m-%d")
    since = max(cutoff, (watermark or "")[:10]) or cutoff
    mentions, newest = await _git_scan(settings, full, since, synthesize=synthesize)
    return mentions, (full, newest)


class SingleRepoCommitSource(BaseSource):
    """Base para fuentes que vigilan UN repo fijo (metasploit, nuclei-templates)
    con watermark persistente en `github_repos` (origin='manual'). El watermark
    solo avanza en `finalize()`, tras persistir las menciones."""

    repo_full_name = ""       # owner/repo (lo fija la subclase)
    method = "git"

    def __init__(self) -> None:
        self._pending_scan: tuple[str, str | None] | None = None

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        months = get_settings().github_commits_months
        mentions, self._pending_scan = await scan_single_repo(
            self.repo_full_name, months=months, synthesize=False)
        return mentions

    def finalize(self) -> None:
        if self._pending_scan is None:
            return
        from app.core.db import session_scope
        from app.sources.repo_registry import update_scan

        full, newest = self._pending_scan
        with session_scope() as session:
            update_scan(session, full, newest)
        self._pending_scan = None


@register
class GitHubCommitsSource(BaseSource):
    name = "github_commits"
    kind = "GitHub top-N repos commit scan (blobless clone + git log)"
    method = "git"
    tier = 4
    cadence_seconds = 3600

    def __init__(self) -> None:
        # (full_name, watermark) escaneados con éxito, pendientes de update_scan.
        # Se aplican en finalize(): si el proceso muere antes de persistir las
        # menciones, el lote se re-escanea (idempotente por content_hash).
        self._pending_scans: list[tuple[str, str | None]] = []

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        settings = get_settings()
        from app.core.db import session_scope
        from app.sources.repo_registry import (
            harvest_references,
            harvest_top_n,
            next_batch,
            registry_count,
        )

        # Si el registro está vacío, cosecha base: top-N (estrellas) + referencias
        # de advisories (repos con CVE previo). Ambas alimentan la MISMA tabla.
        if registry_count() == 0:
            log.info("github.registry_empty_bootstrap")
            harvest_references()
            await harvest_top_n(ctx.http, settings)

        cutoff_date = (settings.github_commits_since
                       or (datetime.now(UTC)
                           - timedelta(days=30 * settings.github_commits_months)
                           ).strftime("%Y-%m-%d"))[:10]

        with session_scope() as session:
            batch = next_batch(session, settings.github_repos_per_run)
        if not batch:
            log.warning("github.no_repos")
            return []

        synthesize = settings.github_synthesize_candidates
        out: list[FetchedMention] = []
        self._pending_scans = []
        failed = 0
        for full, watermark in batch:
            since_date = max(cutoff_date, (watermark or "")[:10]) or cutoff_date
            try:
                mentions, newest = await _git_scan(settings, full, since_date, synthesize)
                out.extend(mentions)
            except Exception as exc:  # noqa: BLE001 - un repo no tumba el lote
                # Fallo de git (o parseo): NO se marca como escaneado -> el repo
                # conserva watermark/last_scanned_at y se reintenta en otro lote.
                log.warning("github.repo_error", repo=full, error=str(exc))
                failed += 1
                continue
            # Escaneo OK (aunque diera 0 menciones): pendiente de update_scan,
            # que finalize() aplica tras persistirse las menciones -> rota.
            self._pending_scans.append((full, newest))
        log.info("github.batch_done", repos=len(batch), failed=failed, mentions=len(out))
        return out

    def finalize(self) -> None:
        """Avanza watermarks/last_scanned_at SOLO tras persistir el lote (lo
        invoca el runner). Si el fetch no llegó a persistirse, no corre y el
        siguiente fetch re-escanea los mismos repos (idempotente)."""
        if not self._pending_scans:
            return
        from app.core.db import session_scope
        from app.sources.repo_registry import update_scan

        with session_scope() as session:
            for full, newest in self._pending_scans:
                update_scan(session, full, newest)
        log.info("github.scan_marks_applied", repos=len(self._pending_scans))
        self._pending_scans = []
