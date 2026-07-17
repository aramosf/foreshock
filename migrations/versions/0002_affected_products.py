"""affected products + version ranges + product catalog & aliases
(canonicalización de nombres de software para watchlist/correlación)

Revision ID: 0002_affected
Revises: 0001_initial
Create Date: 2026-07-16
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_affected"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -----------------------------------------------------------------
    # product_catalog — vocabulario canónico (sembrado de CPE-dict + OSV)
    # Es la "verdad" contra la que se enlazan los nombres sucios.
    # -----------------------------------------------------------------
    op.create_table(
        "product_catalog",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("vendor", sa.Text()),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("ecosystem", sa.Text()),          # OSV: PyPI/npm/Go/...; NULL en software clásico
        sa.Column("cpe23", sa.Text()),
        sa.Column("purl", sa.Text()),
        sa.Column("source", sa.Text()),             # 'cpe-dict' | 'osv' | 'manual'
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        # NULLS NOT DISTINCT (PG15+): ecosystem NULL también deduplica
        sa.UniqueConstraint("vendor", "product", "ecosystem",
                            name="uq_catalog_vendor_product_ecosystem",
                            postgresql_nulls_not_distinct=True),
    )
    op.create_index("idx_catalog_product", "product_catalog", ["product"])
    op.create_index("idx_catalog_vendor", "product_catalog", ["vendor"])
    op.create_index("idx_catalog_cpe23", "product_catalog", ["cpe23"],
                    postgresql_where=sa.text("cpe23 IS NOT NULL"))

    # -----------------------------------------------------------------
    # product_aliases — clave normalizada -> entrada canónica.
    # Crece con lo que confirma el LLM/humano; la próxima vez resuelve
    # de forma determinista (Capa 1), sin volver a llamar al LLM.
    # -----------------------------------------------------------------
    op.create_table(
        "product_aliases",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("alias_normalized", sa.Text(), nullable=False),   # lowercased/stripped
        sa.Column("catalog_id", sa.BigInteger(),
                  sa.ForeignKey("product_catalog.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),             # 'seed' | 'llm' | 'manual'
        sa.Column("confidence", sa.Float()),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        # un alias resuelve de forma determinista a UNA entrada canónica
        sa.UniqueConstraint("alias_normalized", name="uq_alias_normalized"),
        sa.CheckConstraint("source IN ('seed','llm','manual')", name="ck_alias_source"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1 OR confidence IS NULL",
                           name="ck_alias_confidence"),
    )
    op.create_index("idx_alias_catalog", "product_aliases", ["catalog_id"])

    # -----------------------------------------------------------------
    # affected_products — producto afectado por candidate (multi-fila).
    # Guarda el raw extraído + el enlace canónico (catalog_id) + método.
    # -----------------------------------------------------------------
    op.create_table(
        "affected_products",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("candidates.id", ondelete="CASCADE"), nullable=False),
        sa.Column("catalog_id", sa.BigInteger(),
                  sa.ForeignKey("product_catalog.id", ondelete="SET NULL")),  # NULL si sin resolver
        # valores tal cual se extrajeron (raw / normalizados por la fuente)
        sa.Column("vendor", sa.Text()),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("ecosystem", sa.Text()),
        sa.Column("cpe23", sa.Text()),
        sa.Column("purl", sa.Text()),
        sa.Column("default_status", sa.Text()),          # affected/unaffected/unknown
        sa.Column("exact_versions", postgresql.ARRAY(sa.Text())),   # OSV versions[] enumeradas
        sa.Column("raw", sa.Text()),                     # string original del producto
        # trazabilidad de la canonicalización
        sa.Column("normalization_method", sa.Text()),    # exact/alias/fuzzy/llm/unresolved
        sa.Column("normalization_confidence", sa.Float()),
        sa.Column("source", sa.Text()),                  # de qué fuente/mención salió
        sa.Column("confidence", sa.Float()),             # confianza de la extracción
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("candidate_id", "vendor", "product", "ecosystem",
                            name="uq_affected_candidate_product",
                            postgresql_nulls_not_distinct=True),
        sa.CheckConstraint(
            "default_status IN ('affected','unaffected','unknown') OR default_status IS NULL",
            name="ck_affected_status"),
        sa.CheckConstraint(
            "normalization_method IN ('exact','alias','fuzzy','llm','unresolved')"
            " OR normalization_method IS NULL", name="ck_affected_norm_method"),
        sa.CheckConstraint(
            "normalization_confidence BETWEEN 0 AND 1 OR normalization_confidence IS NULL",
            name="ck_affected_norm_conf"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1 OR confidence IS NULL",
                           name="ck_affected_conf"),
    )
    op.create_index("idx_affected_candidate", "affected_products", ["candidate_id"])
    op.create_index("idx_affected_catalog", "affected_products", ["catalog_id"])
    op.create_index("idx_affected_unresolved", "affected_products", ["id"],
                    postgresql_where=sa.text("catalog_id IS NULL"))  # cola de pendientes

    # -----------------------------------------------------------------
    # affected_version_ranges — rangos estructurados por producto afectado.
    # Modelo estilo OSV/CVE-5.0: introduced / fixed / last_affected.
    # -----------------------------------------------------------------
    op.create_table(
        "affected_version_ranges",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("affected_product_id", sa.BigInteger(),
                  sa.ForeignKey("affected_products.id", ondelete="CASCADE"), nullable=False),
        sa.Column("introduced", sa.Text()),          # '0' o versión desde
        sa.Column("fixed", sa.Text()),               # versión corregida (exclusivo)
        sa.Column("last_affected", sa.Text()),       # última afectada (inclusivo)
        sa.Column("version_type", sa.Text()),        # semver/custom/rpm/...
        sa.Column("raw", sa.Text()),                 # string original: '< 7.4.3'
    )
    op.create_index("idx_ranges_affected_product", "affected_version_ranges",
                    ["affected_product_id"])


def downgrade() -> None:
    op.drop_table("affected_version_ranges")
    op.drop_table("affected_products")
    op.drop_table("product_aliases")
    op.drop_table("product_catalog")
