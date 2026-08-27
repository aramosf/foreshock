"""Concurrencia, escalonado y ciclo de vida de procesos de sources-worker."""

from __future__ import annotations

import asyncio

import pytest

from app.sources import gitproc, runner
from app.sources.__main__ import _startup_delay_seconds
from app.sources.base import BaseSource


def test_startup_slots_reparten_las_fuentes_en_la_ventana() -> None:
    names = ["osv", "github_commits", "cisa_kev", "redhat_csaf"]
    delays = [
        _startup_delay_seconds(name, 3600, names, 3600)
        for name in names
    ]
    assert min(delays) == 0
    assert max(delays) < 3600
    assert len(set(delays)) == len(names)
    assert _startup_delay_seconds("osv", 300, names, 3600) < 300
    assert _startup_delay_seconds("osv", 3600, names, 0) == 0


@pytest.mark.asyncio
async def test_run_source_limita_el_ciclo_completo(monkeypatch) -> None:
    active = 0
    peak = 0

    class FakeSource(BaseSource):
        method = "api"

        async def fetch(self, ctx):  # pragma: no cover - sustituido abajo
            return []

    names = [f"source_{i}" for i in range(8)]
    registry = {}
    for name in names:
        index = len(registry)
        cls = type(f"Source{index}", (FakeSource,), {"name": name})
        registry[name] = cls

    async def fake_bounded(name, inst):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return {"fetched": 0, "created": 0, "duplicate": 0, "errors": 0}

    monkeypatch.setattr(runner, "load_all", lambda: registry)
    monkeypatch.setattr(runner, "_run_source_bounded", fake_bounded)
    monkeypatch.setattr(
        runner, "_RUN_SEMAPHORE",
        asyncio.Semaphore(4),
    )
    await asyncio.gather(*(runner.run_source(name) for name in names))
    assert peak == 4


@pytest.mark.asyncio
async def test_runner_persiste_lotes_antes_de_confirmar(monkeypatch) -> None:
    events: list[tuple[str, int] | tuple[str]] = []

    class BatchedSource(BaseSource):
        name = "batched"

        async def fetch(self, ctx):
            return []

        async def fetch_batches(self, ctx):
            yield [1, 2]
            yield [3]

    def persist(name, mentions, stats):
        events.append(("persist", len(mentions)))
        stats["fetched"] += len(mentions)

    def complete(name, inst, stats):
        events.append(("complete", stats["fetched"]))

    monkeypatch.setattr(runner, "_persist_mentions_batch", persist)
    monkeypatch.setattr(runner, "_complete_source_run", complete)

    out = await runner._run_source_bounded("batched", BatchedSource())

    assert out["fetched"] == 3
    assert events == [("persist", 2), ("persist", 1), ("complete", 3)]


@pytest.mark.asyncio
async def test_git_timeout_mata_grupo_y_espera_al_hijo(monkeypatch) -> None:
    killed: list[tuple[int, int]] = []

    class FakeProcess:
        pid = 4242
        returncode = None
        waited = False

        async def communicate(self):
            raise TimeoutError

        async def wait(self):
            self.waited = True
            self.returncode = -9
            return self.returncode

        def kill(self):
            self.returncode = -9

    proc = FakeProcess()

    async def fake_create(*args, **kwargs):
        assert kwargs["start_new_session"] is True
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    monkeypatch.setattr(gitproc.os, "killpg", lambda pid, sig: killed.append((pid, sig)))

    rc, out, err = await gitproc.run_git_process("status", timeout=0.01)
    assert rc == 124 and out == "" and "timeout" in err
    assert killed and killed[0][0] == proc.pid
    assert proc.waited is True
