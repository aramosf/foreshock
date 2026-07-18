"""Amplía sources.method para admitir 'git' (github_commits ahora clona con git).

Revision ID: 0008_source_method_git
Revises: 0007_soft_cve_references
Create Date: 2026-07-17
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0008_source_method_git"
down_revision: Union[str, None] = "0007_soft_cve_references"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_sources_method", "sources", type_="check")
    op.create_check_constraint(
        "ck_sources_method", "sources",
        "method IN ('api','rss','scrape','browser','git')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_sources_method", "sources", type_="check")
    op.create_check_constraint(
        "ck_sources_method", "sources",
        "method IN ('api','rss','scrape','browser')",
    )
