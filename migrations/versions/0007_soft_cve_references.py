"""Referencias BLANDAS de CVE: CVEs mencionados en la prosa de una nota que NO
son el CVE propio de esa nota.

Objetivo: contar y dar contexto a CVEs que aparecen citados en boletines/commits
(p.ej. un GHSA que menciona otros CVEs) SIN anclarlos ni fusionarlos al candidato
(eso causaría over-merge). Desacoplada del union-find: no toca `identifiers`.

`cve_id` es referencia blanda (sin FK a published_cves): el CVE citado puede no
estar publicado aún — de hecho ese es el caso interesante.

Revision ID: 0007_soft_cve_references
Revises: 0006_nvd_enrichment
Create Date: 2026-07-17
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PGUUID

revision: str = "0007_soft_cve_references"
down_revision: Union[str, None] = "0006_nvd_enrichment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cve_soft_references",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("mention_id", sa.BigInteger(),
                  sa.ForeignKey("mentions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("sources.id"), nullable=False),
        sa.Column("from_candidate_id", PGUUID(as_uuid=True),
                  sa.ForeignKey("candidates.id", ondelete="SET NULL")),
        sa.Column("context", sa.Text()),
        sa.Column("seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()")),
        sa.UniqueConstraint("mention_id", "cve_id", name="uq_soft_ref_mention_cve"),
    )
    op.create_index("idx_soft_ref_cve", "cve_soft_references", ["cve_id"])
    op.create_index("idx_soft_ref_source", "cve_soft_references", ["source_id"])


def downgrade() -> None:
    op.drop_index("idx_soft_ref_source", table_name="cve_soft_references")
    op.drop_index("idx_soft_ref_cve", table_name="cve_soft_references")
    op.drop_table("cve_soft_references")
