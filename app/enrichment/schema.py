"""Schemas Pydantic para la salida estructurada del LLM (Capa 3).

Diseño clave (ver docs/ENRICHMENT.md):
  - El LLM NO devuelve un número CVSS. Devuelve las MÉTRICAS BASE; el score se
    calcula de forma determinista con la librería `cvss` (reproducible, auditable).
  - Los vectores CVSS AUTORITATIVOS se extraen por regex del texto de la fuente,
    no del LLM.
  - Toda salida lleva `confidence` explícito.

Robustez frente a LLMs reales: `extra="ignore"` (una clave inesperada no debe
abortar el enriquecimiento entero), los Literal se normalizan a minúsculas y los
valores fuera de vocabulario se descartan a None (un "Network" capitalizado es
salida habitual de un modelo; un "web" inventado no debe reventar la validación),
y los productos afectados malformados se descartan individualmente.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, ValidationInfo, field_validator

AttackVector = Literal["network", "adjacent", "local", "physical"]

_LITERAL_FIELDS = (
    "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality", "integrity", "availability",
)

# Vocabulario válido por campo Literal: un valor fuera de vocabulario del LLM
# NO debe invalidar todo el objeto -> se descarta (-> None) en vez de reventar.
_ALLOWED: dict[str, set[str]] = {
    "attack_vector": {"network", "adjacent", "local", "physical"},
    "attack_complexity": {"low", "high"},
    "privileges_required": {"none", "low", "high"},
    "user_interaction": {"none", "required"},
    "scope": {"unchanged", "changed"},
    "confidentiality": {"none", "low", "high"},
    "integrity": {"none", "low", "high"},
    "availability": {"none", "low", "high"},
}

# Tope de poc_urls que persistimos: el texto de las fuentes no es de fiar y no
# queremos acumular listas arbitrariamente largas de URLs.
_MAX_POC_URLS = 20


def _lower(value: object, info: ValidationInfo) -> object:
    """Normaliza a minúsculas los valores de campos Literal ('' -> None) y
    DESCARTA (-> None) los valores fuera de vocabulario, para que un Literal
    inesperado del LLM no aborte la validación del objeto entero."""
    if isinstance(value, str):
        v = value.strip().lower()
        if not v:
            return None
        allowed = _ALLOWED.get(info.field_name)
        if allowed is not None and v not in allowed:
            return None
        return v
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

    @field_validator("affected_products", mode="before")
    @classmethod
    def _drop_bad_products(cls, value: object) -> object:
        """Valida cada producto por separado y DESCARTA los malformados (p.ej.
        sin `product`), en lugar de dejar que una entrada mala invalide toda la
        salida del LLM (que provocaba un bucle de re-enriquecimiento infinito)."""
        if not isinstance(value, list):
            return value
        out: list[AffectedProductOut] = []
        for item in value:
            try:
                out.append(AffectedProductOut.model_validate(item))
            except Exception:  # noqa: BLE001 - entrada malformada: se descarta
                continue
        return out

    @field_validator("poc_urls", mode="before")
    @classmethod
    def _clean_poc_urls(cls, value: object) -> list[str]:
        """Sanea las poc_urls (endurecimiento anti-inyección): solo http(s) bien
        formadas, deduplicadas y acotadas. El texto de las fuentes NO es de fiar,
        así que no persistimos esquemas raros (javascript:, data:, file:...) ni
        listas ilimitadas."""
        if not isinstance(value, list):
            return []
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                continue
            u = item.strip()
            parts = urlsplit(u)
            if parts.scheme in ("http", "https") and parts.netloc and u not in seen:
                seen.add(u)
                cleaned.append(u)
            if len(cleaned) >= _MAX_POC_URLS:
                break
        return cleaned
