"""Registro unificado de repos de GitHub a vigilar (dedup + estado de escaneo).

Unifica el top-N y las watchlists auto-pobladas (referencias de advisories, repos
con CVE previo, criticality, descargas) en UNA tabla con clave por full_name -> un
repo añadido por varias estrategias es UNA fila (no se duplica el trabajo). Guarda
el watermark de escaneo por repo (sustituye a los ficheros JSON de estado).

Revision ID: 0010_github_repos_registry
Revises: 0009_source_tier_range
Create Date: 2026-07-18
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0010_github_repos_registry"
down_revision: Union[str, None] = "0009_source_tier_range"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "github_repos",
        sa.Column("full_name", sa.Text(), primary_key=True),  # owner/repo
        # top_n | reference | past_cve | criticality | downloads | manual
        sa.Column("origin", sa.Text(), nullable=False),
        sa.Column("stars", sa.Integer()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("watermark", sa.Text()),  # ISO del commit más reciente ya escaneado
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_scanned_at", sa.TIMESTAMP(timezone=True)),
    )
    # Orden de barrido: nunca escaneados primero, luego por prioridad y estrellas.
    op.create_index("idx_ghrepos_scan", "github_repos",
                    ["last_scanned_at", "priority", "stars"])
    op.create_index("idx_ghrepos_origin", "github_repos", ["origin"])


def downgrade() -> None:
    op.drop_index("idx_ghrepos_origin", table_name="github_repos")
    op.drop_index("idx_ghrepos_scan", table_name="github_repos")
    op.drop_table("github_repos")
