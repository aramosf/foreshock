"""Canonicalización de nombres de software (vendor/product) — Foreshock.

Enlaza un nombre "sucio" leído de una fuente contra el vocabulario canónico
(`product_catalog`) por capas, de barato a caro. El LLM se usa SOLO como
*linker* restringido (elige entre candidatos existentes), nunca como
corrector de texto libre: eso evita alucinar productos y mantiene el
resultado reproducible para el dedup / cluster_fingerprint.

Pipeline:
    nombre sucio
      -> 1. exact    : match determinista contra product_aliases (clave normalizada)
      -> 2. fuzzy    : top-K candidatos del catálogo (trigram / embedding)
      -> 3. llm      : "¿cuál de estos K es? o 'ninguno'"  (elección acotada)
      -> 4. unresolved: baja confianza -> cola de revisión, se guarda raw

Cada resultado registra `method` y `confidence`; el crudo NUNCA se sobreescribe.
Las resoluciones confirmadas por LLM/humano se escriben como `product_aliases`
para que la próxima vez las resuelva la Capa 1 sin llamar al LLM.

Este módulo es un ESQUELETO: las capas 2 y 3 y la persistencia se implementan
más adelante contra la sesión de BD real.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum


class Method(str, Enum):
    EXACT = "exact"
    ALIAS = "alias"
    FUZZY = "fuzzy"
    LLM = "llm"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class CatalogEntry:
    """Una entrada canónica de product_catalog."""

    id: int
    vendor: str | None
    product: str
    ecosystem: str | None


@dataclass(frozen=True)
class Resolution:
    """Resultado de canonicalizar un nombre sucio."""

    raw: str
    catalog_id: int | None
    method: Method
    confidence: float
    # candidatos considerados (para auditoría / revisión humana)
    candidates: tuple[CatalogEntry, ...] = ()


# Umbral por debajo del cual NO se auto-acepta y se manda a revisión.
AUTO_ACCEPT_THRESHOLD = 0.85


def normalize_key(raw: str) -> str:
    """Clave normalizada para el match determinista (Capa 1).

    Lowercase, sin acentos, colapsa separadores y espacios. Debe ser estable:
    es la misma función usada al sembrar `product_aliases`.

    >>> normalize_key("  Fortinet   FortiOS ")
    'fortinet fortios'
    >>> normalize_key("Forti-OS")
    'forti os'
    """
    s = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode()
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return s.strip()


class ProductNormalizer:
    """Orquesta las capas. Las dependencias (repos/servicios) se inyectan;
    aquí van como Protocol/placeholder para no acoplar a la capa de BD todavía.
    """

    def __init__(
        self,
        alias_repo: "AliasRepo",
        catalog_search: "CatalogSearch",
        llm_linker: "LLMLinker | None" = None,
        top_k: int = 8,
    ) -> None:
        self._aliases = alias_repo
        self._search = catalog_search
        self._llm = llm_linker
        self._top_k = top_k

    def resolve(self, raw: str) -> Resolution:
        key = normalize_key(raw)

        # Capa 1 — determinista: alias conocido.
        hit = self._aliases.get(key)
        if hit is not None:
            return Resolution(raw=raw, catalog_id=hit, method=Method.ALIAS, confidence=1.0)

        # Capa 2 — fuzzy: candidatos del catálogo.
        candidates = tuple(self._search.top_k(key, self._top_k))
        if not candidates:
            return Resolution(raw=raw, catalog_id=None, method=Method.UNRESOLVED, confidence=0.0)

        # Capa 3 — LLM como linker restringido (elige entre candidates o 'ninguno').
        if self._llm is not None:
            pick = self._llm.pick(raw, candidates)
            if pick.catalog_id is not None and pick.confidence >= AUTO_ACCEPT_THRESHOLD:
                # aprender: persistir el alias para futuras resoluciones deterministas
                self._aliases.remember(key, pick.catalog_id, source="llm",
                                       confidence=pick.confidence)
                return Resolution(raw=raw, catalog_id=pick.catalog_id, method=Method.LLM,
                                  confidence=pick.confidence, candidates=candidates)

        # Capa 4 — sin resolver con confianza suficiente: a revisión.
        return Resolution(raw=raw, catalog_id=None, method=Method.UNRESOLVED,
                          confidence=0.0, candidates=candidates)


# --- Puertos (se implementan contra la BD / proveedor LLM más adelante) -------

class AliasRepo:  # pragma: no cover - interfaz
    def get(self, alias_normalized: str) -> int | None: ...
    def remember(self, alias_normalized: str, catalog_id: int, *,
                 source: str, confidence: float) -> None: ...


class CatalogSearch:  # pragma: no cover - interfaz
    def top_k(self, key: str, k: int) -> list[CatalogEntry]: ...


class LLMLinker:  # pragma: no cover - interfaz
    def pick(self, raw: str, candidates: tuple[CatalogEntry, ...]) -> Resolution: ...
