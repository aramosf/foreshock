"""Telemetría mínima de procesos publicada por los workers.

Cada worker ve su propio namespace de procesos, por lo que puede contar PIDs,
hilos y zombies sin montar el socket privilegiado de Docker en la API. El
snapshot se guarda en ``sync_state`` y el dashboard administrativo lo considera
offline cuando el heartbeat envejece.
"""

from __future__ import annotations

import os
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app.baseline.state import write_cursor


def _read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _read_int(*paths: str) -> int | None:
    for path in paths:
        value = _read_text(path)
        if value is None or value == "max":
            continue
        try:
            return int(value)
        except ValueError:
            continue
    return None


def _process_snapshot() -> dict[str, Any]:
    processes = zombies = threads = 0
    names: Counter[str] = Counter()
    try:
        entries = list(os.scandir("/proc"))
    except OSError:
        entries = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        status = _read_text(f"/proc/{entry.name}/status")
        if status is None:
            continue
        processes += 1
        name = "?"
        state = ""
        proc_threads = 0
        for line in status.splitlines():
            key, _, value = line.partition(":")
            value = value.strip()
            if key == "Name":
                name = value
            elif key == "State":
                state = value[:1]
            elif key == "Threads":
                try:
                    proc_threads = int(value)
                except ValueError:
                    pass
        names[name] += 1
        threads += proc_threads
        zombies += state == "Z"
    return {
        "process_count": processes,
        "zombie_count": zombies,
        "thread_count": threads,
        "process_names": dict(names.most_common(8)),
    }


def collect_runtime_metrics(
    role: str,
    *,
    active: list[str] | None = None,
    queued: list[str] | None = None,
    scheduled: int | None = None,
) -> dict[str, Any]:
    """Snapshot JSON-serializable del namespace/cgroup actual."""
    metrics = {
        "role": role,
        "pid": os.getpid(),
        "observed_at": datetime.now(UTC).isoformat(),
        **_process_snapshot(),
        "pids_current": _read_int(
            "/sys/fs/cgroup/pids.current",
            "/sys/fs/cgroup/pids/pids.current",
        ),
        "pids_limit": _read_int(
            "/sys/fs/cgroup/pids.max",
            "/sys/fs/cgroup/pids/pids.max",
        ),
        "memory_current_bytes": _read_int(
            "/sys/fs/cgroup/memory.current",
            "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        ),
        "memory_limit_bytes": _read_int(
            "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        ),
        "active": sorted(active or []),
        "queued": sorted(queued or []),
    }
    if scheduled is not None:
        metrics["scheduled"] = scheduled
    return metrics


def publish_runtime_metrics(
    role: str,
    *,
    active: list[str] | None = None,
    queued: list[str] | None = None,
    scheduled: int | None = None,
) -> dict[str, Any]:
    """Publica el snapshot en ``sync_state`` y lo devuelve."""
    metrics = collect_runtime_metrics(
        role, active=active, queued=queued, scheduled=scheduled,
    )
    write_cursor(f"runtime:{role}", metrics["observed_at"], metrics)
    return metrics
