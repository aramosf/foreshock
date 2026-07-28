"""Marca de escaneo propia para el fetcher github_repo_advisories.

El fetcher github_repo_advisories escanea /security-advisories y /releases de cada
repo del registro (los ~10k) vía REST. NO puede compartir `watermark`/
`last_scanned_at` con github_commits (esas columnas llevan el estado del escaneo de
COMMITS por clon git): si ambos escribieran las mismas columnas se pisarían el
cursor y el round-robin. Se añaden columnas dedicadas:
  - adv_last_scanned_at : cuándo se escanearon por última vez advisories/releases
                          (dirige el next_batch propio y la exclusión de re-escaneo).
  - adv_watermark       : ISO 8601 del published_at más reciente ya emitido
                          (solo se emiten items MÁS nuevos -> evita re-crear
                          menciones ya ingeridas en cada ciclo).

El índice replica EXACTAMENTE el ORDER BY del barrido (priority DESC,
adv_last_scanned_at ASC NULLS FIRST, stars DESC NULLS LAST): mismos criterios de
relevancia que idx_ghrepos_scan pero sobre la marca de escaneo de advisories.

Revision ID: 0013_github_repo_adv_scan
Revises: 0012_github_repo_kind
Create Date: 2026-07-23
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_github_repo_adv_scan"
down_revision: str | None = "0012_github_repo_kind"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("github_repos",
                  sa.Column("adv_watermark", sa.Text(), nullable=True))
    op.add_column("github_repos",
                  sa.Column("adv_last_scanned_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(
        "idx_ghrepos_adv_scan",
        "github_repos",
        [
            sa.text("priority DESC"),
            sa.text("adv_last_scanned_at ASC NULLS FIRST"),
            sa.text("stars DESC NULLS LAST"),
        ],
    )


def downgrade() -> None:
    op.drop_index("idx_ghrepos_adv_scan", table_name="github_repos")
    op.drop_column("github_repos", "adv_last_scanned_at")
    op.drop_column("github_repos", "adv_watermark")
