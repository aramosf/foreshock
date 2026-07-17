"""Persistencia enriquecida: affected_products.kind + campos ricos en candidates

- affected_products.kind: product | distro | malware (clasificación del software).
- candidates.cwe_ids / reference_urls / withdrawn: metadatos útiles que traen OSV
  y GHSA y que antes se descartaban (consultas por CWE, enlaces a fix/PoC, retirados).

Revision ID: 0005_rich_fields
Revises: 0004_kev_flags
Create Date: 2026-07-17
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

revision: str = "0005_rich_fields"
down_revision: Union[str, None] = "0004_kev_flags"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("affected_products", sa.Column("kind", sa.Text()))  # product/distro/malware
    op.create_index("idx_affected_kind", "affected_products", ["kind"])
    op.create_index("idx_affected_product_name", "affected_products", ["product"])
    op.add_column("candidates", sa.Column("cwe_ids", ARRAY(sa.Text())))
    op.add_column("candidates", sa.Column("reference_urls", ARRAY(sa.Text())))
    op.add_column("candidates", sa.Column("withdrawn", sa.Boolean()))


def downgrade() -> None:
    op.drop_column("candidates", "withdrawn")
    op.drop_column("candidates", "reference_urls")
    op.drop_column("candidates", "cwe_ids")
    op.drop_index("idx_affected_product_name", table_name="affected_products")
    op.drop_index("idx_affected_kind", table_name="affected_products")
    op.drop_column("affected_products", "kind")
