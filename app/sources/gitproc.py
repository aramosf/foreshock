"""Ejecución segura de procesos Git dentro de los workers.

Los workers son procesos de larga vida. Un ``git`` cancelado o que supera su
timeout puede dejar helpers (git-remote-https, index-pack...) huérfanos. Este
helper crea un grupo de proceso por invocación (``start_new_session=True``), mata
el grupo completo con ``killpg`` en timeout/cancelación y SIEMPRE recoge
(``wait``) al hijo DIRECTO (el ``git``).

Los NIETOS (helpers que lanza el propio git) NO son hijos del worker: al morir
git se reparientan a PID 1, así que el worker NO puede recogerlos con ``waitpid``.
Su reaping depende del init/reaper del contenedor (``init: true`` en Compose, que
inyecta ``tini`` como PID 1). Por eso NO se hace aquí un ``waitpid(-1)`` manual: en
un proceso asyncio competiría con el child-watcher del event loop (podría robarle
la notificación SIGCHLD del hijo que ``proc.wait()`` espera y colgarlo).
"""

from __future__ import annotations

import asyncio
import os
import signal


async def _stop_process_group(proc: asyncio.subprocess.Process) -> None:
    """Termina el grupo de ``proc`` y recoge SIEMPRE el proceso DIRECTO. Los
    nietos, reparentados a PID 1 al morir git, los recoge el init del contenedor
    (``init: true``/tini); ver el docstring del módulo."""
    if proc.returncode is None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except (AttributeError, PermissionError):
            # Fallback defensivo para entornos sin grupos POSIX utilizables.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
    await proc.wait()


async def run_git_process(
    *args: str,
    cwd: str | None = None,
    timeout: float,
    merge_stderr: bool = False,
) -> tuple[int, str, str]:
    """Ejecuta ``git`` y devuelve ``(rc, stdout, stderr)``.

    ``rc=124`` representa timeout. En cancelación u otro error se limpia el
    grupo de procesos antes de propagar la excepción.
    """
    proc = await asyncio.create_subprocess_exec(
        "git",
        *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=(asyncio.subprocess.STDOUT if merge_stderr else asyncio.subprocess.PIPE),
        start_new_session=True,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        await _stop_process_group(proc)
        return 124, "", f"timeout tras {timeout}s"
    except BaseException:
        await _stop_process_group(proc)
        raise
    return (
        proc.returncode or 0,
        out.decode("utf-8", "replace"),
        "" if err is None else err.decode("utf-8", "replace"),
    )
