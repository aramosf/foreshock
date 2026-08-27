"""Framework de fuentes: contrato BaseSource + registro + contexto de fetch.

Cada fetcher vive en app/sources/<nombre>.py y declara una subclase de
BaseSource decorada con @register. Devuelve list[FetchedMention] o lotes
incrementales mediante ``fetch_batches``; NO escribe en BD (de eso se encarga
el pipeline de ingesta). Un fetcher que falla se aísla: el worker captura la
excepción, la loguea y sigue con el resto.

Métodos declarados en `method`:
  api      -> httpx contra una API JSON/XML
  rss      -> feed RSS/Atom (feedparser)
  scrape   -> HTML estático (httpx + selectolax)
  browser  -> requiere JS -> BrowserPool (Playwright, dependencia opcional)
  git      -> clon parcial + git log local (github_commits, metasploit, nuclei)
"""

from __future__ import annotations

import abc
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from dateutil.parser import isoparse

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.ingest.service import FetchedMention

if TYPE_CHECKING:
    import httpx

    from app.sources.browser import BrowserPool

log = get_logger(__name__)

# Suelo de validez para fechas de advisory. Algunas fuentes serializan una fecha
# "cero" (p.ej. OSV/Debian trae published="0001-01-01T00:00:00Z", el zero-value
# de Go) que isoparse acepta SIN error (el año 1 es válido) y acabaría como
# seen_at -> first_seen_at en el año 0001, contaminando days_ahead. Se descarta
# todo lo anterior a 1990 (antes de que existieran los CVE).
_MIN_ADVISORY_DATE = datetime(1990, 1, 1, tzinfo=UTC)


def parse_advisory_date(val: str | None) -> datetime | None:
    """ISO 8601 -> datetime UTC-aware, o None si falta, no parsea o es una fecha
    "cero"/imposible (< 1990). Usar para el seen_at de advisories (OSV, GHSA...)."""
    if not val:
        return None
    try:
        dt = isoparse(val)
    except (ValueError, TypeError, OverflowError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt if dt >= _MIN_ADVISORY_DATE else None


# Registro global: nombre -> clase de fuente.
REGISTRY: dict[str, type["BaseSource"]] = {}


def register(cls: type["BaseSource"]) -> type["BaseSource"]:
    """Decorador de clase que registra un fetcher por su `name`."""
    if not getattr(cls, "name", None):
        raise ValueError(f"{cls.__name__} debe definir 'name'")
    if cls.name in REGISTRY:
        raise ValueError(f"fuente duplicada: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls


@dataclass
class FetchContext:
    """Recursos compartidos que el worker inyecta a cada fetch."""

    http: "httpx.AsyncClient"
    settings: Settings = field(default_factory=get_settings)
    browser: "BrowserPool | None" = None


class BaseSource(abc.ABC):
    """Clase base de todos los fetchers.

    Subclases DEBEN definir los atributos de clase y `fetch`.
    """

    name: str = ""            # identificador único (== sources.name)
    kind: str = ""            # descripción legible del origen
    method: str = "api"       # api | rss | scrape | browser | git
    tier: int = 5             # 1..5 (prioridad de señal temprana)
    cadence_seconds: int = 3600

    @abc.abstractmethod
    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        """Obtiene menciones nuevas. Idempotencia la garantiza la ingesta."""
        raise NotImplementedError

    async def fetch_batches(
        self, ctx: FetchContext
    ) -> AsyncIterator[list[FetchedMention]]:
        """Iterador opcional para fuentes voluminosas.

        El comportamiento por defecto conserva el contrato histórico de una
        sola lista. Las fuentes grandes pueden sobrescribirlo para que el runner
        persista y libere cada lote antes de producir el siguiente.
        """
        yield await self.fetch(ctx)

    def finalize(self) -> None:
        """Hook opcional que el runner invoca SOLO tras persistir con éxito el
        lote de menciones. Para efectos que no deben adelantarse a la ingesta
        (p.ej. avanzar watermarks): si el proceso muere antes de persistir, el
        hook no corre y el siguiente fetch re-escanea (idempotente por
        content_hash). Por defecto no hace nada."""

    def seed_row(self) -> dict[str, object]:
        """Fila para la tabla `sources` (usada por el seeding/registro)."""
        return {
            "name": self.name,
            "kind": self.kind,
            "method": self.method,
            "tier": self.tier,
            "cadence_seconds": self.cadence_seconds,
        }


def load_all() -> dict[str, type[BaseSource]]:
    """Importa todos los módulos de fetchers para poblar REGISTRY."""
    import importlib
    import pkgutil

    import app.sources as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        # Módulos de infraestructura sin fetchers. __main__ es el entrypoint
        # del worker: importarlo aquí lo re-ejecutaría como módulo normal.
        if mod.name in {"base", "browser", "runner", "__main__"}:
            continue
        importlib.import_module(f"app.sources.{mod.name}")
    return REGISTRY
