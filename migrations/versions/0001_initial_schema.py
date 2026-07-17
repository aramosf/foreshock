"""initial schema — baseline, sources, candidates, identifiers, mentions,
candidate_links, cvss_scores (v3/v4), epss_scores + convenience views

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-16
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -----------------------------------------------------------------
    # published_cves — estado canónico (cvelistV5 + NVD 2.0)
    # -----------------------------------------------------------------
    op.create_table(
        "published_cves",
        sa.Column("id", sa.Text(), primary_key=True),  # CVE-YYYY-NNNN
        sa.Column("state", sa.Text(), nullable=False),
        # fechas auto-reportadas por la fuente (pueden venir backfilled)
        sa.Column("cvelist_published_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("cvelist_updated_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("nvd_published_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("nvd_last_modified_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("nvd_vuln_status", sa.Text()),
        # ground truth propio: cuándo LO VIMOS en NVD (inmune a backfill)
        sa.Column("nvd_first_observed_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("nvd_first_analyzed_observed_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("cna", sa.Text()),
        sa.Column("assigner_short_name", sa.Text()),
        sa.Column("raw_json", postgresql.JSONB()),
        sa.Column("ingested_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint(
            "state IN ('RESERVED','PUBLISHED','REJECTED')",
            name="ck_pubcves_state",
        ),
    )
    op.create_index("idx_pubcves_state", "published_cves", ["state"])
    op.create_index("idx_pubcves_nvd_published", "published_cves",
                    [sa.text("nvd_published_at DESC")])
    op.create_index("idx_pubcves_assigner", "published_cves", ["assigner_short_name"])

    # -----------------------------------------------------------------
    # sources
    # -----------------------------------------------------------------
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text(), nullable=False, unique=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("cadence_seconds", sa.Integer(), nullable=False),
        sa.Column("last_success_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("last_error_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint("method IN ('api','rss','scrape','browser')",
                           name="ck_sources_method"),
        sa.CheckConstraint("tier BETWEEN 1 AND 5", name="ck_sources_tier"),
    )
    op.create_index("idx_sources_enabled", "sources", ["enabled"],
                    postgresql_where=sa.text("enabled"))

    # -----------------------------------------------------------------
    # candidates — unidad de rastreo (existe con o sin CVE)
    # -----------------------------------------------------------------
    op.create_table(
        "candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'candidate'")),
        sa.Column("cve_id", sa.Text(), sa.ForeignKey("published_cves.id")),
        sa.Column("merged_into", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("candidates.id")),  # union-find self-ref
        sa.Column("cluster_fingerprint", sa.Text()),
        # agregados de menciones
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("mention_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("source_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        # promoción / reconciliación con NVD
        sa.Column("promoted_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("days_ahead_vs_nvd_published", sa.Integer()),
        sa.Column("days_ahead_vs_nvd_present", sa.Integer()),
        sa.Column("days_ahead_vs_nvd_analyzed", sa.Integer()),
        # enrichment (Capa 3)
        sa.Column("affected_product", sa.Text()),
        sa.Column("affected_versions", sa.Text()),
        sa.Column("vuln_type", sa.Text()),
        sa.Column("attack_vector", sa.Text()),
        sa.Column("requires_auth", sa.Boolean()),
        sa.Column("requires_interaction", sa.Boolean()),
        sa.Column("has_public_poc", sa.Boolean()),
        sa.Column("poc_urls", postgresql.ARRAY(sa.Text())),
        sa.Column("severity_hint", sa.Text()),
        sa.Column("enrichment_confidence", sa.Float()),
        sa.Column("enrichment_method", sa.Text()),
        sa.Column("enrichment_updated_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint(
            "status IN ('candidate','emerging','published','rejected','merged')",
            name="ck_cand_status"),
        sa.CheckConstraint(
            "attack_vector IN ('network','adjacent','local','physical') OR attack_vector IS NULL",
            name="ck_cand_attack_vector"),
        sa.CheckConstraint(
            "severity_hint IN ('likely-critical','likely-high','likely-medium','likely-low')"
            " OR severity_hint IS NULL",
            name="ck_cand_severity_hint"),
        sa.CheckConstraint(
            "enrichment_confidence BETWEEN 0 AND 1 OR enrichment_confidence IS NULL",
            name="ck_cand_enrichment_conf"),
    )
    op.create_index("idx_cand_status", "candidates", ["status"])
    op.create_index("idx_cand_cve", "candidates", ["cve_id"])
    op.create_index("idx_cand_last_seen", "candidates", [sa.text("last_seen_at DESC")])
    op.create_index("idx_cand_fingerprint", "candidates", ["cluster_fingerprint"])
    op.create_index("idx_cand_merged_into", "candidates", ["merged_into"],
                    postgresql_where=sa.text("merged_into IS NOT NULL"))

    # -----------------------------------------------------------------
    # identifiers — IDs nativos que anclan un candidate (CVE incluido)
    # -----------------------------------------------------------------
    op.create_table(
        "identifiers",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scheme", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("scheme", "value", name="uq_identifiers_scheme_value"),
    )
    op.create_index("idx_ident_candidate", "identifiers", ["candidate_id"])

    # -----------------------------------------------------------------
    # mentions — observaciones crudas (pueden no traer CVE)
    # -----------------------------------------------------------------
    op.create_table(
        "mentions",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id"), nullable=False),
        sa.Column("extracted_cve", sa.Text()),
        sa.Column("extracted_native", sa.Text()),
        sa.Column("url", sa.Text()),
        sa.Column("title", sa.Text()),
        sa.Column("snippet", sa.Text()),
        sa.Column("raw_html_path", sa.Text()),
        sa.Column("seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("content_hash", sa.Text(), nullable=False),
        # idempotencia: sin cve_id (la identidad del CVE va DENTRO del hash)
        sa.UniqueConstraint("source_id", "content_hash", name="uq_mentions_source_hash"),
    )
    op.create_index("idx_mentions_candidate", "mentions", ["candidate_id"])
    op.create_index("idx_mentions_seen", "mentions", [sa.text("seen_at DESC")])
    op.create_index("idx_mentions_source", "mentions", ["source_id"])

    # -----------------------------------------------------------------
    # candidate_links — enlaces difusos PROPUESTOS (no destructivos)
    # -----------------------------------------------------------------
    op.create_table(
        "candidate_links",
        sa.Column("a", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("b", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'suggested'")),
        sa.Column("rationale", sa.Text()),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("a", "b", name="pk_candidate_links"),
        sa.CheckConstraint("method IN ('fingerprint','embedding','llm')",
                           name="ck_links_method"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_links_confidence"),
        sa.CheckConstraint("status IN ('suggested','confirmed','rejected')",
                           name="ck_links_status"),
        sa.CheckConstraint("a < b", name="ck_links_canonical_pair"),
    )
    op.create_index("idx_links_status", "candidate_links", ["status"],
                    postgresql_where=sa.text("status = 'suggested'"))

    # -----------------------------------------------------------------
    # cvss_scores — v3.x y v4.0, autoritativo y derivado, multi-fuente
    # -----------------------------------------------------------------
    op.create_table(
        "cvss_scores",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("vector", sa.Text(), nullable=False),
        sa.Column("base_score", sa.Float()),
        sa.Column("base_severity", sa.Text()),
        sa.Column("provenance", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        # solo para derived:
        sa.Column("inferred_metrics", postgresql.ARRAY(sa.Text())),
        sa.Column("confidence", sa.Float()),
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("candidate_id", "version", "provenance", "source",
                            name="uq_cvss_candidate_version_prov_source"),
        sa.CheckConstraint("version IN ('3.0','3.1','4.0')", name="ck_cvss_version"),
        sa.CheckConstraint("base_score BETWEEN 0 AND 10 OR base_score IS NULL",
                           name="ck_cvss_base_score"),
        sa.CheckConstraint(
            "base_severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')"
            " OR base_severity IS NULL", name="ck_cvss_base_severity"),
        sa.CheckConstraint("provenance IN ('authoritative','derived')",
                           name="ck_cvss_provenance"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1 OR confidence IS NULL",
                           name="ck_cvss_confidence"),
    )
    op.create_index("idx_cvss_candidate", "cvss_scores", ["candidate_id"])

    # -----------------------------------------------------------------
    # epss_scores — FIRST.org, con histórico (solo CVE público)
    # Sin FK a published_cves: EPSS puede referir un CVE aún no ingerido.
    # -----------------------------------------------------------------
    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("model_version", sa.Text()),
        sa.Column("scored_date", sa.Date(), nullable=False),
        sa.Column("fetched_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("cve_id", "scored_date", name="pk_epss_scores"),
        sa.CheckConstraint("score BETWEEN 0 AND 1", name="ck_epss_score"),
        sa.CheckConstraint("percentile BETWEEN 0 AND 1", name="ck_epss_percentile"),
    )
    op.create_index("idx_epss_cve", "epss_scores", ["cve_id"])
    op.create_index("idx_epss_date", "epss_scores", [sa.text("scored_date DESC")])

    # -----------------------------------------------------------------
    # VISTAS
    # -----------------------------------------------------------------
    op.execute("""
        CREATE VIEW epss_current AS
        SELECT DISTINCT ON (cve_id)
               cve_id, score, percentile, model_version, scored_date, fetched_at
        FROM epss_scores
        ORDER BY cve_id, scored_date DESC;
    """)

    op.execute("""
        CREATE VIEW cvss_selected AS
        SELECT DISTINCT ON (candidate_id)
               candidate_id, version, vector, base_score, base_severity,
               provenance, source, confidence
        FROM cvss_scores
        ORDER BY candidate_id,
                 (provenance = 'authoritative') DESC,
                 CASE version WHEN '4.0' THEN 3 WHEN '3.1' THEN 2 ELSE 1 END DESC,
                 base_score DESC NULLS LAST;
    """)

    op.execute("""
        CREATE VIEW radar AS
        SELECT c.id, c.cve_id, c.status,
               c.affected_product, c.vuln_type, c.has_public_poc,
               c.first_seen_at, c.last_seen_at, c.mention_count, c.source_count,
               c.days_ahead_vs_nvd_present, c.days_ahead_vs_nvd_analyzed,
               cs.version       AS cvss_version,
               cs.base_score    AS cvss_score,
               cs.base_severity AS cvss_severity,
               cs.provenance    AS cvss_provenance,
               c.severity_hint,
               e.score          AS epss_score,
               e.percentile     AS epss_percentile
        FROM candidates c
        LEFT JOIN cvss_selected cs ON cs.candidate_id = c.id
        LEFT JOIN epss_current  e  ON e.cve_id = c.cve_id
        WHERE c.status IN ('candidate','emerging','published')
          AND c.merged_into IS NULL;
    """)


def downgrade() -> None:
    # Vistas primero (dependen de las tablas)
    op.execute("DROP VIEW IF EXISTS radar;")
    op.execute("DROP VIEW IF EXISTS cvss_selected;")
    op.execute("DROP VIEW IF EXISTS epss_current;")

    # Tablas en orden inverso de dependencias (FKs)
    op.drop_table("epss_scores")
    op.drop_table("cvss_scores")
    op.drop_table("candidate_links")
    op.drop_table("mentions")
    op.drop_table("identifiers")
    op.drop_table("candidates")
    op.drop_table("sources")
    op.drop_table("published_cves")
