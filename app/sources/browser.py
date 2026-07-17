"""Pool de contextos Playwright seguro ante concurrencia.

Diseño (ver docs/SOURCES.md):
  - Un contexto persistente por fuente (user-data-dir propio) -> cookies/sesión
    durables y aislamiento entre fuentes.
  - Lock por fuente: nunca dos fetches concurrentes sobre el mismo contexto
    (los contextos Playwright NO son seguros para uso concurrente).
  - Semáforo global: acota páginas simultáneas (memoria).
  - Reciclado por nº de usos o ante crash: los contextos leakean memoria.

Playwright es una dependencia OPCIONAL (extra 'browser'). Si no está instalada,
importar este módulo falla solo al construir el pool, no al importar el paquete.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from app.core.config import get_settings
from app.core.logging import get_logger

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page

log = get_logger(__name__)


class BrowserPool:
    def __init__(self, max_concurrent: int | None = None, recycle_after: int | None = None):
        settings = get_settings()
        self._global = asyncio.Semaphore(max_concurrent or settings.browser_max_concurrent)
        self._recycle_after = recycle_after or settings.browser_recycle_after
        self._locks: dict[str, asyncio.Lock] = {}
        self._contexts: dict[str, Any] = {}
        self._uses: dict[str, int] = {}
        self._playwright: Any = None
        self._data_root = os.path.join(settings.data_dir, "browser")

    async def start(self) -> None:
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        os.makedirs(self._data_root, exist_ok=True)

    async def _acquire_context(self, source: str) -> "BrowserContext":
        ctx = self._contexts.get(source)
        if ctx is None:
            user_dir = os.path.join(self._data_root, source)
            os.makedirs(user_dir, exist_ok=True)
            ctx = await self._playwright.chromium.launch_persistent_context(
                user_dir,
                headless=True,
                user_agent=get_settings().user_agent,
            )
            self._contexts[source] = ctx
            self._uses[source] = 0
        return ctx

    async def _recycle(self, source: str) -> None:
        ctx = self._contexts.pop(source, None)
        self._uses.pop(source, None)
        if ctx is not None:
            try:
                await ctx.close()
            except Exception as exc:  # noqa: BLE001
                log.warning("browser.recycle_error", source=source, error=str(exc))

    @asynccontextmanager
    async def page(self, source: str) -> AsyncIterator["Page"]:
        """Cede una página exclusiva para `source` (lock por fuente + semáforo global)."""
        lock = self._locks.setdefault(source, asyncio.Lock())
        async with lock, self._global:
            try:
                ctx = await self._acquire_context(source)
                page = await ctx.new_page()
            except Exception:
                await self._recycle(source)  # crash -> respawn en el próximo intento
                raise
            try:
                yield page
            finally:
                try:
                    await page.close()
                finally:
                    self._uses[source] = self._uses.get(source, 0) + 1
                    if self._uses[source] >= self._recycle_after:
                        await self._recycle(source)

    async def close(self) -> None:
        for source in list(self._contexts):
            await self._recycle(source)
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None
