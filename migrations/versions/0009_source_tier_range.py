"""Amplía el rango de sources.tier a 1..9 (nuevo tier 6: github_commit_expandall).

Revision ID: 0009_source_tier_range
Revises: 0008_source_method_git
Create Date: 2026-07-17
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0009_source_tier_range"
down_revision: Union[str, None] = "0008_source_method_git"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_sources_tier", "sources", type_="check")
    op.create_check_constraint("ck_sources_tier", "sources", "tier BETWEEN 1 AND 9")


def downgrade() -> None:
    op.drop_constraint("ck_sources_tier", "sources", type_="check")
    op.create_check_constraint("ck_sources_tier", "sources", "tier BETWEEN 1 AND 5")
