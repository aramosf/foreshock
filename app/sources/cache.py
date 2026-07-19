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
import tempfile
import time

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


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


async def cached_download(client: httpx.AsyncClient, url: str, key: str,
                          ttl: int | None = None) -> str:
    """Descarga `url` a cache/download/<key> por streaming. Reusa el fichero si es
    más reciente que `ttl` segundos. Devuelve la ruta local (conservada)."""
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
        async with client.stream("GET", url, timeout=300.0) as resp:
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
