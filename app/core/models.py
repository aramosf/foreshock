"""Modelos SQLModel que reflejan el esquema Alembic (0001 + 0002).

IMPORTANTE: las migraciones son la fuente de verdad del esquema (escritas a
mano). Estos modelos son un mapeo ORM sobre las tablas existentes para la
ingesta y la CLI. Si cambias una migración, actualiza aquí en consonancia.

No se usa SQLModel.metadata para autogenerate (env.py -> target_metadata=None),
así que no hay riesgo de que estos modelos "creen" tablas por su cuenta.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    Float,
    ForeignKey,
    Integer,
    Text,
    text,
)
from sqlalchemy import (
    Column as SAColumn,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlmodel import Field, SQLModel


def _ts() -> SAColumn:
    """Timestamptz sin default (lo rellena la app o queda NULL)."""
    return SAColumn(TIMESTAMP(timezone=True))


def _ts_now() -> SAColumn:
    """Timestamptz con server_default now() -> SQLAlchemy lo omite en el INSERT."""
    return SAColumn(TIMESTAMP(timezone=True), server_default=text("now()"))


# ---------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------
class PublishedCVE(SQLModel, table=True):
    __tablename__ = "published_cves"

    id: str = Field(sa_column=SAColumn(Text, primary_key=True))
    state: str = Field(sa_column=SAColumn(Text, nullable=False))
    cvelist_published_at: datetime | None = Field(default=None, sa_column=_ts())
    cvelist_updated_at: datetime | None = Field(default=None, sa_column=_ts())
    nvd_published_at: datetime | None = Field(default=None, sa_column=_ts())
    nvd_last_modified_at: datetime | None = Field(default=None, sa_column=_ts())
    nvd_vuln_status: str | None = Field(default=None, sa_column=SAColumn(Text))
    nvd_first_observed_at: datetime | None = Field(default=None, sa_column=_ts())
    nvd_first_analyzed_observed_at: datetime | None = Field(default=None, sa_column=_ts())
    cna: str | None = Field(default=None, sa_column=SAColumn(Text))
    assigner_short_name: str | None = Field(default=None, sa_column=SAColumn(Text))
    raw_json: dict | None = Field(default=None, sa_column=SAColumn(JSONB))
    ingested_at: datetime | None = Field(default=None, sa_column=_ts_now())
    # --- Enriquecimiento estructurado (0006), derivado de raw_json (CVE JSON 5.0) ---
    # Campos DENORMALIZADOS "primarios" para filtros/orden rápidos; el detalle
    # completo vive en las tablas hijas cve_cvss / cve_cwe / cve_cpe / cve_reference.
    description_en: str | None = Field(default=None, sa_column=SAColumn(Text))
    primary_cvss_version: str | None = Field(default=None, sa_column=SAColumn(Text))
    primary_cvss_score: float | None = Field(default=None, sa_column=SAColumn(Float))
    primary_cvss_severity: str | None = Field(default=None, sa_column=SAColumn(Text))
    primary_cvss_vector: str | None = Field(default=None, sa_column=SAColumn(Text))
    primary_cwe: str | None = Field(default=None, sa_column=SAColumn(Text))
    has_exploit_ref: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    has_patch_ref: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    # SSVC (CISA ADP Vulnrichment): decisión oficial temprana de priorización.
    ssvc_exploitation: str | None = Field(default=None, sa_column=SAColumn(Text))
    ssvc_automatable: str | None = Field(default=None, sa_column=SAColumn(Text))
    ssvc_technical_impact: str | None = Field(default=None, sa_column=SAColumn(Text))
    enriched_at: datetime | None = Field(default=None, sa_column=_ts())


class SyncState(SQLModel, table=True):
    """Watermark persistente de los deltas baseline (0011). Una fila por fuente
    (`id` = 'nvd_delta', 'cvelist', ...). `cursor` guarda el último punto
    CONFIRMADO (fecha ISO, SHA de git...) y solo se escribe tras completar una
    pasada con éxito, para que un run fallido no pierda datos."""

    __tablename__ = "sync_state"

    id: str = Field(sa_column=SAColumn(Text, primary_key=True))
    cursor: str | None = Field(default=None, sa_column=SAColumn(Text))
    extra: dict | None = Field(default=None, sa_column=SAColumn(JSONB))
    updated_at: datetime | None = Field(
        default=None,
        sa_column=SAColumn(TIMESTAMP(timezone=True), nullable=False,
                           server_default=text("now()")),
    )


class Source(SQLModel, table=True):
    __tablename__ = "sources"

    id: int | None = Field(default=None, sa_column=SAColumn(Integer, primary_key=True))
    name: str = Field(sa_column=SAColumn(Text, unique=True, nullable=False))
    kind: str = Field(sa_column=SAColumn(Text, nullable=False))
    method: str = Field(sa_column=SAColumn(Text, nullable=False))
    tier: int = Field(sa_column=SAColumn(Integer, nullable=False))
    enabled: bool = Field(
        default=True,
        sa_column=SAColumn(Boolean, nullable=False, server_default=text("true")),
    )
    cadence_seconds: int = Field(sa_column=SAColumn(Integer, nullable=False))
    last_success_at: datetime | None = Field(default=None, sa_column=_ts())
    last_error: str | None = Field(default=None, sa_column=SAColumn(Text))
    last_error_at: datetime | None = Field(default=None, sa_column=_ts())
    created_at: datetime | None = Field(default=None, sa_column=_ts_now())


# ---------------------------------------------------------------------
# Rastreo
# ---------------------------------------------------------------------
class Candidate(SQLModel, table=True):
    __tablename__ = "candidates"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        sa_column=SAColumn(PGUUID(as_uuid=True), primary_key=True),
    )
    status: str = Field(
        default="candidate",
        sa_column=SAColumn(Text, nullable=False, server_default=text("'candidate'")),
    )
    # Referencia BLANDA (sin FK): el CVE puede estar reservado y no ingerido aún.
    cve_id: str | None = Field(default=None, sa_column=SAColumn(Text))
    merged_into: uuid.UUID | None = Field(
        default=None, sa_column=SAColumn(PGUUID(as_uuid=True), ForeignKey("candidates.id"))
    )
    cluster_fingerprint: str | None = Field(default=None, sa_column=SAColumn(Text))
    first_seen_at: datetime | None = Field(default=None, sa_column=_ts_now())
    last_seen_at: datetime | None = Field(default=None, sa_column=_ts_now())
    mention_count: int = Field(
        default=0, sa_column=SAColumn(Integer, nullable=False, server_default=text("0"))
    )
    source_count: int = Field(
        default=0, sa_column=SAColumn(Integer, nullable=False, server_default=text("0"))
    )
    promoted_at: datetime | None = Field(default=None, sa_column=_ts())
    days_ahead_vs_nvd_published: int | None = Field(default=None, sa_column=SAColumn(Integer))
    days_ahead_vs_nvd_present: int | None = Field(default=None, sa_column=SAColumn(Integer))
    days_ahead_vs_nvd_analyzed: int | None = Field(default=None, sa_column=SAColumn(Integer))
    affected_product: str | None = Field(default=None, sa_column=SAColumn(Text))
    affected_versions: str | None = Field(default=None, sa_column=SAColumn(Text))
    vuln_type: str | None = Field(default=None, sa_column=SAColumn(Text))
    attack_vector: str | None = Field(default=None, sa_column=SAColumn(Text))
    requires_auth: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    requires_interaction: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    has_public_poc: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    poc_urls: list[str] | None = Field(default=None, sa_column=SAColumn(ARRAY(Text)))
    cwe_ids: list[str] | None = Field(default=None, sa_column=SAColumn(ARRAY(Text)))
    reference_urls: list[str] | None = Field(default=None, sa_column=SAColumn(ARRAY(Text)))
    withdrawn: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    severity_hint: str | None = Field(default=None, sa_column=SAColumn(Text))
    in_kev: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    kev_date: date | None = Field(default=None, sa_column=SAColumn(Date))
    kev_source: str | None = Field(default=None, sa_column=SAColumn(Text))
    enrichment_confidence: float | None = Field(default=None, sa_column=SAColumn(Float))
    enrichment_method: str | None = Field(default=None, sa_column=SAColumn(Text))
    enrichment_updated_at: datetime | None = Field(default=None, sa_column=_ts())
    created_at: datetime | None = Field(default=None, sa_column=_ts_now())


class Identifier(SQLModel, table=True):
    __tablename__ = "identifiers"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    candidate_id: uuid.UUID = Field(
        sa_column=SAColumn(
            PGUUID(as_uuid=True), ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False
        )
    )
    scheme: str = Field(sa_column=SAColumn(Text, nullable=False))
    value: str = Field(sa_column=SAColumn(Text, nullable=False))
    first_seen_at: datetime | None = Field(default=None, sa_column=_ts_now())


class Mention(SQLModel, table=True):
    __tablename__ = "mentions"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    candidate_id: uuid.UUID = Field(
        sa_column=SAColumn(
            PGUUID(as_uuid=True), ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False
        )
    )
    source_id: int = Field(sa_column=SAColumn(Integer, ForeignKey("sources.id"), nullable=False))
    extracted_cve: str | None = Field(default=None, sa_column=SAColumn(Text))
    extracted_native: str | None = Field(default=None, sa_column=SAColumn(Text))
    url: str | None = Field(default=None, sa_column=SAColumn(Text))
    title: str | None = Field(default=None, sa_column=SAColumn(Text))
    snippet: str | None = Field(default=None, sa_column=SAColumn(Text))
    raw_html_path: str | None = Field(default=None, sa_column=SAColumn(Text))
    seen_at: datetime | None = Field(default=None, sa_column=_ts_now())
    content_hash: str = Field(sa_column=SAColumn(Text, nullable=False))


class CandidateLink(SQLModel, table=True):
    __tablename__ = "candidate_links"

    a: uuid.UUID = Field(
        sa_column=SAColumn(
            PGUUID(as_uuid=True),
            ForeignKey("candidates.id", ondelete="CASCADE"),
            primary_key=True,
        )
    )
    b: uuid.UUID = Field(
        sa_column=SAColumn(
            PGUUID(as_uuid=True),
            ForeignKey("candidates.id", ondelete="CASCADE"),
            primary_key=True,
        )
    )
    method: str = Field(sa_column=SAColumn(Text, nullable=False))
    confidence: float = Field(sa_column=SAColumn(Float, nullable=False))
    status: str = Field(
        default="suggested",
        sa_column=SAColumn(Text, nullable=False, server_default=text("'suggested'")),
    )
    rationale: str | None = Field(default=None, sa_column=SAColumn(Text))
    created_at: datetime | None = Field(default=None, sa_column=_ts_now())


class CVSSScore(SQLModel, table=True):
    __tablename__ = "cvss_scores"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    candidate_id: uuid.UUID = Field(
        sa_column=SAColumn(
            PGUUID(as_uuid=True), ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False
        )
    )
    version: str = Field(sa_column=SAColumn(Text, nullable=False))
    vector: str = Field(sa_column=SAColumn(Text, nullable=False))
    base_score: float | None = Field(default=None, sa_column=SAColumn(Float))
    base_severity: str | None = Field(default=None, sa_column=SAColumn(Text))
    provenance: str = Field(sa_column=SAColumn(Text, nullable=False))
    source: str = Field(sa_column=SAColumn(Text, nullable=False))
    inferred_metrics: list[str] | None = Field(default=None, sa_column=SAColumn(ARRAY(Text)))
    confidence: float | None = Field(default=None, sa_column=SAColumn(Float))
    recorded_at: datetime | None = Field(default=None, sa_column=_ts_now())


class EPSSScore(SQLModel, table=True):
    __tablename__ = "epss_scores"

    cve_id: str = Field(sa_column=SAColumn(Text, primary_key=True))
    score: float = Field(sa_column=SAColumn(Float, nullable=False))
    percentile: float = Field(sa_column=SAColumn(Float, nullable=False))
    model_version: str | None = Field(default=None, sa_column=SAColumn(Text))
    scored_date: date = Field(sa_column=SAColumn(Date, primary_key=True))
    fetched_at: datetime | None = Field(default=None, sa_column=_ts_now())


# ---------------------------------------------------------------------
# Enriquecimiento oficial de CVEs (0006) — detalle normalizado.
# cve_id es referencia BLANDA a published_cves.id (sin FK: un CVE puede
# aparecer en un ADP antes de existir la fila baseline). Idempotencia por
# delete-by-cve + insert al re-enriquecer.
# ---------------------------------------------------------------------
class CveCvss(SQLModel, table=True):
    __tablename__ = "cve_cvss"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    cve_id: str = Field(sa_column=SAColumn(Text, nullable=False))
    version: str = Field(sa_column=SAColumn(Text, nullable=False))       # 2.0/3.0/3.1/4.0
    source: str = Field(sa_column=SAColumn(Text, nullable=False))         # CNA shortName / cisa-adp
    type: str | None = Field(default=None, sa_column=SAColumn(Text))      # Primary/Secondary
    vector: str | None = Field(default=None, sa_column=SAColumn(Text))
    base_score: float | None = Field(default=None, sa_column=SAColumn(Float))
    base_severity: str | None = Field(default=None, sa_column=SAColumn(Text))
    exploitability_score: float | None = Field(default=None, sa_column=SAColumn(Float))
    impact_score: float | None = Field(default=None, sa_column=SAColumn(Float))
    recorded_at: datetime | None = Field(default=None, sa_column=_ts_now())


class CveCwe(SQLModel, table=True):
    __tablename__ = "cve_cwe"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    cve_id: str = Field(sa_column=SAColumn(Text, nullable=False))
    cwe_id: str = Field(sa_column=SAColumn(Text, nullable=False))         # CWE-79 o texto
    description: str | None = Field(default=None, sa_column=SAColumn(Text))
    source: str | None = Field(default=None, sa_column=SAColumn(Text))
    recorded_at: datetime | None = Field(default=None, sa_column=_ts_now())


class CveCpe(SQLModel, table=True):
    __tablename__ = "cve_cpe"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    cve_id: str = Field(sa_column=SAColumn(Text, nullable=False))
    cpe23: str = Field(sa_column=SAColumn(Text, nullable=False))
    vulnerable: bool | None = Field(default=None, sa_column=SAColumn(Boolean))
    version_start: str | None = Field(default=None, sa_column=SAColumn(Text))
    version_start_type: str | None = Field(default=None, sa_column=SAColumn(Text))
    version_end: str | None = Field(default=None, sa_column=SAColumn(Text))
    version_end_type: str | None = Field(default=None, sa_column=SAColumn(Text))
    source: str | None = Field(default=None, sa_column=SAColumn(Text))
    recorded_at: datetime | None = Field(default=None, sa_column=_ts_now())


class CveReference(SQLModel, table=True):
    __tablename__ = "cve_reference"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    cve_id: str = Field(sa_column=SAColumn(Text, nullable=False))
    url: str = Field(sa_column=SAColumn(Text, nullable=False))
    tags: list[str] | None = Field(default=None, sa_column=SAColumn(ARRAY(Text)))
    source: str | None = Field(default=None, sa_column=SAColumn(Text))
    recorded_at: datetime | None = Field(default=None, sa_column=_ts_now())


class GithubRepo(SQLModel, table=True):
    """Registro unificado de repos GitHub a vigilar por github_commits. PK por
    full_name => un repo añadido por varias estrategias es UNA fila (dedup). El
    watermark evita re-escanear commits ya vistos."""

    __tablename__ = "github_repos"

    full_name: str = Field(sa_column=SAColumn(Text, primary_key=True))     # owner/repo
    origin: str = Field(sa_column=SAColumn(Text, nullable=False))
    # 'poc' (repo-PoC/disclosure de un CVE) | 'project' (software real). 0012.
    repo_kind: str | None = Field(default=None, sa_column=SAColumn(Text))
    stars: int | None = Field(default=None, sa_column=SAColumn(Integer))
    priority: int = Field(
        default=0, sa_column=SAColumn(Integer, nullable=False, server_default=text("0"))
    )
    watermark: str | None = Field(default=None, sa_column=SAColumn(Text))
    first_seen_at: datetime | None = Field(default=None, sa_column=_ts_now())
    last_scanned_at: datetime | None = Field(default=None, sa_column=_ts())
    # Marca de escaneo INDEPENDIENTE de github_repo_advisories (advisories/releases
    # vía REST): no comparte watermark/last_scanned_at con el escaneo de commits. 0013.
    adv_watermark: str | None = Field(default=None, sa_column=SAColumn(Text))
    adv_last_scanned_at: datetime | None = Field(default=None, sa_column=_ts())


class CveSoftReference(SQLModel, table=True):
    """CVE MENCIONADO en la prosa de una nota (GHSA, commit, noticia) que NO es
    el CVE propio de esa nota. Referencia BLANDA: NO ancla, NO fusiona, NO entra
    en `identifiers` ni en el union-find. Solo registra "este CVE se mencionó
    aquí", para contarlo y darle contexto sin colapsar vulnerabilidades distintas.
    """

    __tablename__ = "cve_soft_references"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    cve_id: str = Field(sa_column=SAColumn(Text, nullable=False))
    mention_id: int = Field(
        sa_column=SAColumn(
            BigInteger, ForeignKey("mentions.id", ondelete="CASCADE"), nullable=False
        )
    )
    source_id: int = Field(sa_column=SAColumn(Integer, ForeignKey("sources.id"), nullable=False))
    # El candidate de la NOTA donde apareció (contexto de drill-down); blando.
    from_candidate_id: uuid.UUID | None = Field(
        default=None,
        sa_column=SAColumn(PGUUID(as_uuid=True), ForeignKey("candidates.id", ondelete="SET NULL")),
    )
    context: str | None = Field(default=None, sa_column=SAColumn(Text))
    seen_at: datetime | None = Field(default=None, sa_column=_ts_now())


# ---------------------------------------------------------------------
# Canonicalización de software (0002)
# ---------------------------------------------------------------------
class ProductCatalog(SQLModel, table=True):
    __tablename__ = "product_catalog"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    vendor: str | None = Field(default=None, sa_column=SAColumn(Text))
    product: str = Field(sa_column=SAColumn(Text, nullable=False))
    ecosystem: str | None = Field(default=None, sa_column=SAColumn(Text))
    cpe23: str | None = Field(default=None, sa_column=SAColumn(Text))
    purl: str | None = Field(default=None, sa_column=SAColumn(Text))
    source: str | None = Field(default=None, sa_column=SAColumn(Text))
    created_at: datetime | None = Field(default=None, sa_column=_ts_now())


class ProductAlias(SQLModel, table=True):
    __tablename__ = "product_aliases"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    alias_normalized: str = Field(sa_column=SAColumn(Text, nullable=False, unique=True))
    catalog_id: int = Field(
        sa_column=SAColumn(
            BigInteger, ForeignKey("product_catalog.id", ondelete="CASCADE"), nullable=False
        )
    )
    source: str = Field(sa_column=SAColumn(Text, nullable=False))
    confidence: float | None = Field(default=None, sa_column=SAColumn(Float))
    created_at: datetime | None = Field(default=None, sa_column=_ts_now())


class AffectedProduct(SQLModel, table=True):
    __tablename__ = "affected_products"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    candidate_id: uuid.UUID = Field(
        sa_column=SAColumn(
            PGUUID(as_uuid=True), ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False
        )
    )
    catalog_id: int | None = Field(
        default=None,
        sa_column=SAColumn(BigInteger, ForeignKey("product_catalog.id", ondelete="SET NULL")),
    )
    vendor: str | None = Field(default=None, sa_column=SAColumn(Text))
    product: str = Field(sa_column=SAColumn(Text, nullable=False))
    ecosystem: str | None = Field(default=None, sa_column=SAColumn(Text))
    cpe23: str | None = Field(default=None, sa_column=SAColumn(Text))
    purl: str | None = Field(default=None, sa_column=SAColumn(Text))
    default_status: str | None = Field(default=None, sa_column=SAColumn(Text))
    kind: str | None = Field(default=None, sa_column=SAColumn(Text))  # product/distro/malware
    exact_versions: list[str] | None = Field(default=None, sa_column=SAColumn(ARRAY(Text)))
    raw: str | None = Field(default=None, sa_column=SAColumn(Text))
    normalization_method: str | None = Field(default=None, sa_column=SAColumn(Text))
    normalization_confidence: float | None = Field(default=None, sa_column=SAColumn(Float))
    source: str | None = Field(default=None, sa_column=SAColumn(Text))
    confidence: float | None = Field(default=None, sa_column=SAColumn(Float))
    created_at: datetime | None = Field(default=None, sa_column=_ts_now())


class AffectedVersionRange(SQLModel, table=True):
    __tablename__ = "affected_version_ranges"

    id: int | None = Field(default=None, sa_column=SAColumn(BigInteger, primary_key=True))
    affected_product_id: int = Field(
        sa_column=SAColumn(
            BigInteger, ForeignKey("affected_products.id", ondelete="CASCADE"), nullable=False
        )
    )
    introduced: str | None = Field(default=None, sa_column=SAColumn(Text))
    fixed: str | None = Field(default=None, sa_column=SAColumn(Text))
    last_affected: str | None = Field(default=None, sa_column=SAColumn(Text))
    version_type: str | None = Field(default=None, sa_column=SAColumn(Text))
    raw: str | None = Field(default=None, sa_column=SAColumn(Text))
