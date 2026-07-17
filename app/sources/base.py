"""Framework de fuentes: contrato BaseSource + registro + contexto de fetch.

Cada fetcher vive en app/sources/<nombre>.py y declara una subclase de
BaseSource decorada con @register. Devuelve list[FetchedMention]; NO escribe
en BD (de eso se encarga el pipeline de ingesta). Un fetcher que falla se
aísla: el worker captura la excepción, la loguea y sigue con el resto.

Métodos declarados en `method`:
  api      -> httpx contra una API JSON/XML
  rss      -> feed RSS/Atom (feedparser)
  scrape   -> HTML estático (httpx + selectolax)
  browser  -> requiere JS -> BrowserPool (Playwright, dependencia opcional)
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.ingest.service import FetchedMention

if TYPE_CHECKING:
    import httpx

    from app.sources.browser import BrowserPool

log = get_logger(__name__)

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
    method: str = "api"       # api | rss | scrape | browser
    tier: int = 5             # 1..5 (prioridad de señal temprana)
    cadence_seconds: int = 3600

    @abc.abstractmethod
    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        """Obtiene menciones nuevas. Idempotencia la garantiza la ingesta."""
        raise NotImplementedError

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
        if mod.name in {"base", "browser", "runner", "robots"}:
            continue
        importlib.import_module(f"app.sources.{mod.name}")
    return REGISTRY
