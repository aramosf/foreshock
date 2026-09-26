"""Clonado somero de repos git como FUENTE DE DATOS (no scanner de commits).

Para fuentes cuyo dato son ficheros dentro de un repo (gemnasium: YAML por
paquete; PoC-in-GitHub/trickest: JSON/MD por CVE): se mantiene un snapshot
`--depth 1` cacheado en /data/gitsrc/<name>, actualizado con fetch+reset (barato,
sin historia). Con `sparse_paths` (clon parcial blobless) se baja solo un
subconjunto de directorios — clave para repos enormes de los que solo interesan
los años recientes. Devuelve el directorio local del working tree.
"""

from __future__ import annotations

import os
import re
import shutil

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sources.gitproc import run_git_process

log = get_logger(__name__)

# Señales de un repo LOCAL corrupto/incoherente (no un fallo transitorio de red):
# solo en estos casos merece la pena borrar y re-clonar. Un timeout o un
# "Could not resolve host" NO deben destruir un clon válido.
_CORRUPT_REPO = re.compile(
    r"not a git repository"
    r"|bad object"
    r"|corrupt"
    r"|object file .* is empty"
    r"|loose object"
    r"|unable to read (?:tree|ref|the index)"
    r"|index file .* corrupt"
    r"|did not match any file"
    r"|(?:ambiguous argument|bad revision).*FETCH_HEAD"
    r"|does not point to a valid object",
    re.IGNORECASE,
)


async def _git(*args: str, cwd: str | None = None, timeout: float = 1800.0) -> tuple[int, str]:
    rc, out, err = await run_git_process(
        *args, cwd=cwd, timeout=timeout, merge_stderr=True,
    )
    return rc, out or err


def repo_dir(name: str) -> str:
    return os.path.join(get_settings().data_dir, "gitsrc", name)


async def _update_clone(name: str, d: str, sparse_paths: list[str] | None) -> str:
    """Actualiza un clon existente a FETCH_HEAD. Lanza RuntimeError si CUALQUIER
    paso de git falla: un reset fallido dejaría un árbol viejo/parcial que se
    reportaría como "actualizado" (dato silenciosamente obsoleto)."""
    rc, out = await _git("fetch", "--depth", "1", "origin", cwd=d)
    if rc != 0:
        raise RuntimeError(f"git fetch {name}: {out.strip()[:200]}")
    rc, out = await _git("reset", "--hard", "FETCH_HEAD", cwd=d)
    if rc != 0:
        raise RuntimeError(f"git reset {name}: {out.strip()[:200]}")
    if sparse_paths:
        rc, out = await _git("sparse-checkout", "reapply", cwd=d)
        if rc != 0:
            raise RuntimeError(f"git sparse-checkout reapply {name}: {out.strip()[:200]}")
    log.info("gitsrc.updated", name=name)
    return d


async def _fresh_clone(name: str, url: str, d: str, sparse_paths: list[str] | None) -> str:
    """Clon somero (parcial si hay sparse_paths). Lanza RuntimeError si git falla."""
    os.makedirs(os.path.dirname(d), exist_ok=True)
    args = ["clone", "--depth", "1", "--quiet"]
    if sparse_paths:
        args += ["--filter=blob:none", "--sparse"]
    rc, out = await _git(*args, url, d)
    if rc != 0:
        raise RuntimeError(f"git clone {name}: {out.strip()[:200]}")
    if sparse_paths:
        rc, out = await _git("sparse-checkout", "set", *sparse_paths, cwd=d)
        if rc != 0:
            raise RuntimeError(f"git sparse-checkout set {name}: {out.strip()[:200]}")
    log.info("gitsrc.cloned", name=name, sparse=bool(sparse_paths))
    return d


async def sync_repo(name: str, url: str, sparse_paths: list[str] | None = None) -> str:
    """Clona (o actualiza a la última) el repo y devuelve su directorio local.
    `sparse_paths`: si se da, clon parcial (blobless) con sparse-checkout de esos
    directorios (p.ej. ['2025', '2026'])."""
    d = repo_dir(name)
    if os.path.isdir(os.path.join(d, ".git")):
        try:
            return await _update_clone(name, d, sparse_paths)
        except RuntimeError as exc:
            # Fallo actualizando un clon existente. Un .git corrupto reventaría en
            # CADA run sin recuperarse: auto-cura borrando el directorio y
            # re-clonando UNA vez (un único intento por run; si el re-clon también
            # falla, propaga -> visible en sources.last_error y se reintenta en la
            # siguiente cadencia). Un fallo transitorio (red, timeout) NO borra el
            # clon válido: se propaga para reintentar tal cual.
            if not _CORRUPT_REPO.search(str(exc)):
                raise
            log.warning("gitsrc.reclone_corrupt", name=name, error=str(exc)[:200])
            shutil.rmtree(d, ignore_errors=True)
    return await _fresh_clone(name, url, d, sparse_paths)
