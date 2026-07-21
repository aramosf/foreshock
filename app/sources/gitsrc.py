"""Clonado somero de repos git como FUENTE DE DATOS (no scanner de commits).

Para fuentes cuyo dato son ficheros dentro de un repo (gemnasium: YAML por
paquete; PoC-in-GitHub/trickest: JSON/MD por CVE): se mantiene un snapshot
`--depth 1` cacheado en /data/gitsrc/<name>, actualizado con fetch+reset (barato,
sin historia). Con `sparse_paths` (clon parcial blobless) se baja solo un
subconjunto de directorios — clave para repos enormes de los que solo interesan
los años recientes. Devuelve el directorio local del working tree.
"""

from __future__ import annotations

import asyncio
import os

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


async def _git(*args: str, cwd: str | None = None, timeout: float = 1800.0) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=cwd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "timeout"
    return proc.returncode or 0, out.decode("utf-8", "replace")


def repo_dir(name: str) -> str:
    return os.path.join(get_settings().data_dir, "gitsrc", name)


async def sync_repo(name: str, url: str, sparse_paths: list[str] | None = None) -> str:
    """Clona (o actualiza a la última) el repo y devuelve su directorio local.
    `sparse_paths`: si se da, clon parcial (blobless) con sparse-checkout de esos
    directorios (p.ej. ['2025', '2026'])."""
    d = repo_dir(name)
    if os.path.isdir(os.path.join(d, ".git")):
        rc, out = await _git("fetch", "--depth", "1", "origin", cwd=d)
        if rc != 0:
            raise RuntimeError(f"git fetch {name}: {out.strip()[:200]}")
        await _git("reset", "--hard", "FETCH_HEAD", cwd=d)
        if sparse_paths:
            await _git("sparse-checkout", "reapply", cwd=d)
        log.info("gitsrc.updated", name=name)
        return d

    os.makedirs(os.path.dirname(d), exist_ok=True)
    args = ["clone", "--depth", "1", "--quiet"]
    if sparse_paths:
        args += ["--filter=blob:none", "--sparse"]
    rc, out = await _git(*args, url, d)
    if rc != 0:
        raise RuntimeError(f"git clone {name}: {out.strip()[:200]}")
    if sparse_paths:
        await _git("sparse-checkout", "set", *sparse_paths, cwd=d)
    log.info("gitsrc.cloned", name=name, sparse=bool(sparse_paths))
    return d
