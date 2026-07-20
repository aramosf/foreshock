"""Etiqueta `repo_kind` en github_repos: distingue repos-PoC de proyectos.

Muchos repos entran al registro por la estrategia `past_cve` (repos citados en
las referencias de un advisory). Entre ellos hay repos-PoC de investigador
(nombre tipo `owner/CVE-2026-1234`, `.../PoC`, `.../disclosure`): son señal
válida ("hay un PoC circulando") pero de OTRA naturaleza que un fix upstream del
proyecto afectado. `repo_kind` los clasifica sin excluirlos:
  - 'poc'     -> repo-PoC / disclosure de un CVE
  - 'project' -> repo de un proyecto de software (por defecto)

Revision ID: 0012_github_repo_kind
Revises: 0011_sync_state_perf_idx
Create Date: 2026-07-21
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0012_github_repo_kind"
down_revision: Union[str, None] = "0011_sync_state_perf_idx"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("github_repos", sa.Column("repo_kind", sa.Text(), nullable=True))
    # Backfill heurístico: nombre con CVE-YYYY-NNNNN, o segmentos poc/exploit/
    # disclosure/advisory típicos de repos-PoC. El resto queda 'project'.
    op.execute(
        r"""
        UPDATE github_repos SET repo_kind = CASE
            WHEN full_name ~* 'CVE-[0-9]{4}-[0-9]+'
              OR full_name ~* '(^|[-_/])(poc|pocs|exploit|exploits|disclosure|disclosures|advisor(y|ies)|writeup|writeups)([-_/]|$)'
            THEN 'poc'
            ELSE 'project'
        END
        """
    )
    op.create_index("idx_ghrepos_kind", "github_repos", ["repo_kind"])


def downgrade() -> None:
    op.drop_index("idx_ghrepos_kind", table_name="github_repos")
    op.drop_column("github_repos", "repo_kind")
