"""Enriquecimiento oficial de CVEs desde raw_json (CVE JSON 5.0 / cvelistV5).

Aditiva: no toca datos existentes. Añade a `published_cves` columnas
DENORMALIZADAS (CVSS primario, CWE primario, flags de exploit/patch, SSVC de
CISA ADP, descripción EN) para filtros/cruces rápidos, y crea cuatro tablas
hijas normalizadas con el detalle completo:

  - cve_cvss     : todas las métricas CVSS (v2/v3/v4), por fuente (CNA/ADP).
  - cve_cwe      : debilidades (CWE) declaradas.
  - cve_cpe      : productos afectados en formato CPE 2.3 (structured).
  - cve_reference: referencias con sus tags (Exploit/Patch/Vendor Advisory...).

`cve_id` es referencia BLANDA (sin FK) a published_cves.id: un CVE puede
aparecer enriquecido antes de existir su fila baseline.

Revision ID: 0006_nvd_enrichment
Revises: 0005_rich_fields
Create Date: 2026-07-17
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

revision: str = "0006_nvd_enrichment"
down_revision: Union[str, None] = "0005_rich_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Columnas denormalizadas en published_cves ---
    op.add_column("published_cves", sa.Column("description_en", sa.Text()))
    op.add_column("published_cves", sa.Column("primary_cvss_version", sa.Text()))
    op.add_column("published_cves", sa.Column("primary_cvss_score", sa.Float()))
    op.add_column("published_cves", sa.Column("primary_cvss_severity", sa.Text()))
    op.add_column("published_cves", sa.Column("primary_cvss_vector", sa.Text()))
    op.add_column("published_cves", sa.Column("primary_cwe", sa.Text()))
    op.add_column("published_cves", sa.Column("has_exploit_ref", sa.Boolean()))
    op.add_column("published_cves", sa.Column("has_patch_ref", sa.Boolean()))
    op.add_column("published_cves", sa.Column("ssvc_exploitation", sa.Text()))
    op.add_column("published_cves", sa.Column("ssvc_automatable", sa.Text()))
    op.add_column("published_cves", sa.Column("ssvc_technical_impact", sa.Text()))
    op.add_column("published_cves", sa.Column("enriched_at", sa.TIMESTAMP(timezone=True)))
    op.create_index("idx_pcve_cvss_score", "published_cves", ["primary_cvss_score"])
    op.create_index("idx_pcve_cvss_severity", "published_cves", ["primary_cvss_severity"])
    op.create_index("idx_pcve_cwe", "published_cves", ["primary_cwe"])
    op.create_index("idx_pcve_ssvc_expl", "published_cves", ["ssvc_exploitation"])

    # --- cve_cvss ---
    op.create_table(
        "cve_cvss",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("type", sa.Text()),
        sa.Column("vector", sa.Text()),
        sa.Column("base_score", sa.Float()),
        sa.Column("base_severity", sa.Text()),
        sa.Column("exploitability_score", sa.Float()),
        sa.Column("impact_score", sa.Float()),
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_cve_cvss_cve", "cve_cvss", ["cve_id"])
    op.create_index("idx_cve_cvss_score", "cve_cvss", ["base_score"])

    # --- cve_cwe ---
    op.create_table(
        "cve_cwe",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("cwe_id", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("source", sa.Text()),
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_cve_cwe_cve", "cve_cwe", ["cve_id"])
    op.create_index("idx_cve_cwe_cwe", "cve_cwe", ["cwe_id"])

    # --- cve_cpe ---
    op.create_table(
        "cve_cpe",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("cpe23", sa.Text(), nullable=False),
        sa.Column("vulnerable", sa.Boolean()),
        sa.Column("version_start", sa.Text()),
        sa.Column("version_start_type", sa.Text()),
        sa.Column("version_end", sa.Text()),
        sa.Column("version_end_type", sa.Text()),
        sa.Column("source", sa.Text()),
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_cve_cpe_cve", "cve_cpe", ["cve_id"])
    op.create_index("idx_cve_cpe_cpe", "cve_cpe", ["cpe23"])

    # --- cve_reference ---
    op.create_table(
        "cve_reference",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("tags", ARRAY(sa.Text())),
        sa.Column("source", sa.Text()),
        sa.Column("recorded_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_cve_ref_cve", "cve_reference", ["cve_id"])
    op.create_index("idx_cve_ref_tags", "cve_reference", ["tags"], postgresql_using="gin")


def downgrade() -> None:
    op.drop_table("cve_reference")
    op.drop_table("cve_cpe")
    op.drop_table("cve_cwe")
    op.drop_table("cve_cvss")
    for idx in ("idx_pcve_ssvc_expl", "idx_pcve_cwe", "idx_pcve_cvss_severity",
                "idx_pcve_cvss_score"):
        op.drop_index(idx, table_name="published_cves")
    for col in ("enriched_at", "ssvc_technical_impact", "ssvc_automatable",
                "ssvc_exploitation", "has_patch_ref", "has_exploit_ref", "primary_cwe",
                "primary_cvss_vector", "primary_cvss_severity", "primary_cvss_score",
                "primary_cvss_version", "description_en"):
        op.drop_column("published_cves", col)
