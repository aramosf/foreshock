"""Ejecución segura de procesos Git dentro de los workers.

Los workers son procesos de larga vida. Un ``git`` cancelado o que supera su
timeout puede dejar helpers (remote-http, index-pack...) huérfanos; si además el
contenedor no tiene un init/reaper, esos hijos se acumulan como zombies. Este
helper crea un grupo de proceso por invocación, mata el grupo completo en
timeout/cancelación y siempre espera al hijo directo.
"""

from __future__ import annotations

import asyncio
import os
import signal


async def _stop_process_group(proc: asyncio.subprocess.Process) -> None:
    """Termina el grupo de ``proc`` y recoge siempre el proceso directo."""
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
