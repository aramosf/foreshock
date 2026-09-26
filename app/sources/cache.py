"""Cache de artefactos crudos en disco (regla de oro: todo dato crudo se persiste
para poder re-parsear/recrear sin volver a la fuente).

Dos modos:
- archive_response(): write-through de cada respuesta HTTP (API/HTML) a
  cache/raw/<sha2>/<sha>.bin + sidecar .meta.json. No omite el fetch; solo archiva.
- cached_download(): descarga por streaming de binarios grandes (zip de OSV) a
  cache/download/<key>; si el fichero es reciente (< ttl) lo REUSA (evita re-descargar
  cientos de MB). El fichero se conserva -> sirve para recreaciones futuras.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

# No re-escanear todo el árbol cache/raw en CADA respuesta HTTP: la poda solo
# comprueba el tamaño total como mucho una vez por _EVICT_CHECK_INTERVAL.
_EVICT_CHECK_INTERVAL = 60.0
_last_evict_check = 0.0
# Restos de un kill duro más viejos que esto se consideran huérfanos y se barren
# al arrancar el worker.
_STALE_TEMP_MAX_AGE = 86400  # 1 día


def _cache_dir() -> str:
    return get_settings().cache_dir


def archive_response(url: str, content: bytes, content_type: str | None = None) -> None:
    """Guarda una copia cruda de la respuesta (best-effort, no rompe el fetch)."""
    if not get_settings().cache_raw or not content:
        return
    try:
        h = hashlib.sha256(url.encode("utf-8")).hexdigest()
        directory = os.path.join(_cache_dir(), "raw", h[:2])
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, h)
        with open(path + ".bin", "wb") as fh:
            fh.write(content)
        with open(path + ".meta.json", "w", encoding="utf-8") as fh:
            json.dump({"url": url, "content_type": content_type,
                       "size": len(content), "fetched_at": int(time.time())}, fh)
    except OSError as exc:  # noqa: BLE001 - el archivado nunca debe tumbar la ingesta
        log.warning("cache.archive_error", url=url[:120], error=str(exc))
    _evict_raw_cache()  # poda best-effort si el archivo crudo supera el tope


def _evict_raw_cache() -> None:
    """Poda best-effort del archivo crudo (cache/raw): si el tamaño total supera
    `cache_raw_max_bytes`, borra los ficheros más ANTIGUOS (por mtime) hasta bajar
    del tope. Sin esto crece sin límite (fuentes con cursor/paginación mintan un
    .bin nuevo cada run). Se limita en frecuencia (cara si hay muchos ficheros) y
    NUNCA debe tumbar la ingesta (todo en try/except). <=0 => poda desactivada."""
    global _last_evict_check
    cap = get_settings().cache_raw_max_bytes
    if cap <= 0:
        return
    now = time.time()
    if now - _last_evict_check < _EVICT_CHECK_INTERVAL:
        return
    _last_evict_check = now
    try:
        root = os.path.join(_cache_dir(), "raw")
        if not os.path.isdir(root):
            return
        entries: list[tuple[float, int, str]] = []
        total = 0
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                fpath = os.path.join(dirpath, name)
                try:
                    st = os.stat(fpath)
                except OSError:
                    continue
                total += st.st_size
                entries.append((st.st_mtime, st.st_size, fpath))
        if total <= cap:
            return
        entries.sort()  # más antiguos primero (por mtime)
        for _mtime, size, fpath in entries:
            if total <= cap:
                break
            try:
                os.remove(fpath)
                total -= size
            except OSError:
                continue
        log.info("cache.raw_evicted", remaining_bytes=total, cap=cap)
    except OSError as exc:  # noqa: BLE001 - la poda nunca debe tumbar la ingesta
        log.warning("cache.evict_error", error=str(exc))


def sweep_stale_temp() -> None:
    """Barre al arrancar el worker los restos de un kill duro anterior: `*.tmp`
    huérfanos (cache/download, cache/gitlog) y directorios de clon blobless
    (data/clones) más viejos que _STALE_TEMP_MAX_AGE. Best-effort: nunca debe
    impedir el arranque (todo bajo try/except)."""
    settings = get_settings()
    cutoff = time.time() - _STALE_TEMP_MAX_AGE
    removed = 0
    # (a) *.tmp huérfanos de cached_download / caché de git-log.
    for sub in ("download", "gitlog"):
        directory = os.path.join(settings.cache_dir, sub)
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if not name.endswith(".tmp"):
                continue
            fpath = os.path.join(directory, name)
            try:
                if os.path.getmtime(fpath) < cutoff:
                    os.remove(fpath)
                    removed += 1
            except OSError:
                continue
    # (b) directorios de clon blobless (github_commits) que un kill dejó sin borrar.
    clones = os.path.join(settings.data_dir, "clones")
    try:
        names = os.listdir(clones)
    except OSError:
        names = []
    for name in names:
        dpath = os.path.join(clones, name)
        try:
            if os.path.isdir(dpath) and os.path.getmtime(dpath) < cutoff:
                shutil.rmtree(dpath, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    if removed:
        log.info("cache.swept_stale_temp", removed=removed)


async def cached_download(client: httpx.AsyncClient, url: str, key: str,
                          ttl: int | None = None,
                          headers: dict[str, str] | None = None) -> str:
    """Descarga `url` a cache/download/<key> por streaming. Reusa el fichero si es
    más reciente que `ttl` segundos. Devuelve la ruta local (conservada).
    `headers`: cabeceras extra (p.ej. Authorization para feeds con API key)."""
    settings = get_settings()
    ttl = settings.cache_reuse_ttl_seconds if ttl is None else ttl
    directory = os.path.join(_cache_dir(), "download")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, key)

    if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < ttl:
        log.info("cache.reuse", key=key, age_s=int(time.time() - os.path.getmtime(path)))
        return path

    # Nombre temporal ÚNICO (dos workers descargando la misma key no se pisan
    # el .tmp a medias) + os.replace atómico.
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=key + ".", suffix=".tmp")
    os.close(fd)
    try:
        # follow_redirects=True sin allowlist de host = SSRF latente (riesgo
        # ACEPTADO: la URL la fija el código, no entrada de usuario). El nº de
        # saltos lo ACOTA make_client (max_redirects=5) a nivel de cliente; stream()
        # no admite ese parámetro por-petición.
        async with client.stream("GET", url, timeout=300.0,
                                 headers=headers, follow_redirects=True) as resp:
            resp.raise_for_status()
            with open(tmp, "wb") as fh:
                async for chunk in resp.aiter_bytes():
                    fh.write(chunk)
        os.replace(tmp, path)  # publicación atómica
    except BaseException:
        # No dejamos temporales huérfanos si la descarga falla a medias.
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    log.info("cache.downloaded", key=key, size=os.path.getsize(path))
    return path
