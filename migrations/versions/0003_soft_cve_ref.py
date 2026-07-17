"""candidates.cve_id pasa a ser referencia blanda (sin FK a published_cves)

Motivo: un candidate puede referenciar un CVE que solo está RESERVADO y aún no
ha sido ingerido por el baseline (o que MITRE/NVD aún no publican). Forzar el FK
impediría registrar la señal temprana — justo la premisa de CVERadar. La
reconciliación con published_cves se hace por lookup, no por integridad
referencial.

Revision ID: 0003_soft_cve
Revises: 0002_affected
Create Date: 2026-07-17
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0003_soft_cve"
down_revision: Union[str, None] = "0002_affected"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("candidates_cve_id_fkey", "candidates", type_="foreignkey")
    # Índice para el lookup de reconciliación (ya existe idx_cand_cve de 0001).


def downgrade() -> None:
    op.create_foreign_key(
        "candidates_cve_id_fkey", "candidates", "published_cves",
        ["cve_id"], ["id"],
    )
