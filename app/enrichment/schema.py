"""Schemas Pydantic para la salida estructurada del LLM (Capa 3).

Diseño clave (ver docs/ENRICHMENT.md):
  - El LLM NO devuelve un número CVSS. Devuelve las MÉTRICAS BASE; el score se
    calcula de forma determinista con la librería `cvss` (reproducible, auditable).
  - Los vectores CVSS AUTORITATIVOS se extraen por regex del texto de la fuente,
    no del LLM.
  - Toda salida lleva `confidence` explícito.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

AttackVector = Literal["network", "adjacent", "local", "physical"]


class CVSSMetricsOut(BaseModel):
    """Métricas base CVSS v3.1 inferidas por el LLM (para derivar el score)."""

    model_config = {"extra": "forbid"}

    attack_vector: AttackVector | None = None
    attack_complexity: Literal["low", "high"] | None = None
    privileges_required: Literal["none", "low", "high"] | None = None
    user_interaction: Literal["none", "required"] | None = None
    scope: Literal["unchanged", "changed"] | None = None
    confidentiality: Literal["none", "low", "high"] | None = None
    integrity: Literal["none", "low", "high"] | None = None
    availability: Literal["none", "low", "high"] | None = None


class AffectedProductOut(BaseModel):
    model_config = {"extra": "forbid"}

    vendor: str | None = None
    product: str
    ecosystem: str | None = None
    versions_raw: str | None = None       # string tal cual, p.ej. "< 7.4.3"
    fixed_version: str | None = None


class EnrichmentOut(BaseModel):
    """Salida completa del enriquecimiento por LLM para un candidate."""

    model_config = {"extra": "forbid"}

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
