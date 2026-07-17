"""candidates.in_kev / kev_date — pertenencia a catálogos KEV (explotado in-the-wild)

CISA KEV y VulnCheck KEV no solo generan menciones: marcan el candidate como
"explotado en el mundo real". Es señal de máxima prioridad y ground truth para
la predicción (P(entra en KEV en N días)).

Revision ID: 0004_kev_flags
Revises: 0003_soft_cve
Create Date: 2026-07-17
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_kev_flags"
down_revision: Union[str, None] = "0003_soft_cve"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("candidates", sa.Column("in_kev", sa.Boolean()))
    op.add_column("candidates", sa.Column("kev_date", sa.Date()))
    op.add_column("candidates", sa.Column("kev_source", sa.Text()))  # 'cisa' | 'vulncheck'
    op.create_index("idx_cand_in_kev", "candidates", ["in_kev"],
                    postgresql_where=sa.text("in_kev"))


def downgrade() -> None:
    op.drop_index("idx_cand_in_kev", table_name="candidates")
    op.drop_column("candidates", "kev_source")
    op.drop_column("candidates", "kev_date")
    op.drop_column("candidates", "in_kev")
