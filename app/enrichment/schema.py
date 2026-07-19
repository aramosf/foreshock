"""Schemas Pydantic para la salida estructurada del LLM (Capa 3).

Diseño clave (ver docs/ENRICHMENT.md):
  - El LLM NO devuelve un número CVSS. Devuelve las MÉTRICAS BASE; el score se
    calcula de forma determinista con la librería `cvss` (reproducible, auditable).
  - Los vectores CVSS AUTORITATIVOS se extraen por regex del texto de la fuente,
    no del LLM.
  - Toda salida lleva `confidence` explícito.

Robustez frente a LLMs reales: `extra="ignore"` (una clave inesperada no debe
abortar el enriquecimiento entero) y los Literal se normalizan a minúsculas
antes de validar (un "Network" capitalizado es salida habitual de un modelo).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

AttackVector = Literal["network", "adjacent", "local", "physical"]

_LITERAL_FIELDS = (
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality", "integrity", "availability",
)


def _lower(value: object) -> object:
    """Normaliza a minúsculas los valores de campos Literal ('' -> None)."""
    if isinstance(value, str):
        v = value.strip().lower()
        return v or None
    return value


class CVSSMetricsOut(BaseModel):
    """Métricas base CVSS v3.1 inferidas por el LLM (para derivar el score)."""

    model_config = {"extra": "ignore"}

    attack_vector: AttackVector | None = None
    attack_complexity: Literal["low", "high"] | None = None
    privileges_required: Literal["none", "low", "high"] | None = None
    user_interaction: Literal["none", "required"] | None = None
    scope: Literal["unchanged", "changed"] | None = None
    confidentiality: Literal["none", "low", "high"] | None = None
    integrity: Literal["none", "low", "high"] | None = None
    availability: Literal["none", "low", "high"] | None = None

    _norm = field_validator(*_LITERAL_FIELDS, mode="before")(_lower)


class AffectedProductOut(BaseModel):
    model_config = {"extra": "ignore"}

    vendor: str | None = None
    product: str
    ecosystem: str | None = None
    versions_raw: str | None = None       # string tal cual, p.ej. "< 7.4.3"
    fixed_version: str | None = None


class EnrichmentOut(BaseModel):
    """Salida completa del enriquecimiento por LLM para un candidate."""

    model_config = {"extra": "ignore"}

    affected_products: list[AffectedProductOut] = Field(default_factory=list)
    vuln_type: str | None = None          # RCE / SQLi / XSS / AuthBypass / ...
    attack_vector: AttackVector | None = None
    requires_auth: bool | None = None
    requires_interaction: bool | None = None
    has_public_poc: bool | None = None
    poc_urls: list[str] = Field(default_factory=list)
    cvss_metrics: CVSSMetricsOut | None = None
    summary: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    _norm = field_validator("attack_vector", mode="before")(_lower)
