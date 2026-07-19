"""Watermarks persistentes de sync (sync_state) + índices de rendimiento.

- `sync_state`: cursor persistente por fuente baseline (delta NVD, cvelist...).
  Sin él, los deltas dependían del reloj/reflog y un run fallido o un worker
  parado perdía datos para siempre.
- Índice sobre `published_cves(cvelist_published_at)`: lo filtra/agrupa
  `trend_series` de la API y hoy hace seq scan.
- Índice sobre `candidates(first_seen_at)`: filtrado por periodo en
  trend/pending/emerging.
- Recrea `idx_ghrepos_scan` con el orden EXACTO del ORDER BY real del barrido
  de github_commits: `priority DESC, last_scanned_at ASC NULLS FIRST,
  stars DESC NULLS LAST` (el índice anterior no servía ese orden).

Revision ID: 0011_sync_state_perf_idx
Revises: 0010_github_repos_registry
Create Date: 2026-07-18
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0011_sync_state_perf_idx"
down_revision: Union[str, None] = "0010_github_repos_registry"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Watermark persistente de los deltas baseline (id = nombre de la fuente).
    op.create_table(
        "sync_state",
        sa.Column("id", sa.Text(), primary_key=True),  # p.ej. 'nvd_delta', 'cvelist'
        sa.Column("cursor", sa.Text()),                # último punto CONFIRMADO
        sa.Column("extra", JSONB(), nullable=True),    # metadatos auxiliares
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )

    # trend_series filtra/agrupa por cvelist_published_at (hoy: seq scan).
    op.create_index("idx_published_cvelist_published_at", "published_cves",
                    ["cvelist_published_at"])
    # Filtrado por periodo en trend/pending/emerging.
    op.create_index("idx_candidates_first_seen_at", "candidates", ["first_seen_at"])

    # El barrido real ordena por prioridad DESC, luego nunca-escaneados primero
    # (NULLS FIRST) y estrellas DESC; el índice antiguo (last_scanned_at,
    # priority, stars ASC) no servía ese ORDER BY.
    op.drop_index("idx_ghrepos_scan", table_name="github_repos")
    op.create_index(
        "idx_ghrepos_scan",
        "github_repos",
        [
            sa.text("priority DESC"),
            sa.text("last_scanned_at ASC NULLS FIRST"),
            sa.text("stars DESC NULLS LAST"),
        ],
    )


def downgrade() -> None:
    op.drop_index("idx_ghrepos_scan", table_name="github_repos")
    # Restaura el índice tal y como lo creó 0010.
    op.create_index("idx_ghrepos_scan", "github_repos",
                    ["last_scanned_at", "priority", "stars"])
    op.drop_index("idx_candidates_first_seen_at", table_name="candidates")
    op.drop_index("idx_published_cvelist_published_at", table_name="published_cves")
    op.drop_table("sync_state")
