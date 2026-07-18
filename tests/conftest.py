"""Fixtures de test para Foreshock.

- Los tests unitarios no requieren BD.
- Los tests de integración piden la fixture `db`, que limpia todas las tablas
  antes de cada test contra el Postgres real (DATABASE_URL del entorno). El
  esquema debe estar migrado (alembic upgrade head) antes de correr pytest.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.db import get_engine, session_scope
from app.sources.runner import sync_registry_to_db

_TABLES = [
    "affected_version_ranges", "affected_products", "product_aliases",
    "product_catalog", "cvss_scores", "epss_scores", "candidate_links",
    "cve_soft_references", "mentions", "identifiers", "candidates",
    "published_cves", "github_repos",
]


@pytest.fixture
def db() -> Iterator[None]:
    """Limpia datos (no las fuentes) antes de cada test de integración."""
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE " + ", ".join(_TABLES) + " RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture
def sources_seeded(db: None) -> None:
    """Garantiza que la tabla sources tiene los fetchers registrados."""
    sync_registry_to_db()


@pytest.fixture
def session() -> Iterator[Session]:
    with session_scope() as s:
        yield s
