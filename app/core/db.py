"""Acceso a base de datos (SQLAlchemy 2 / SQLModel, driver psycopg3 sync).

Se usa sesión síncrona: los fetchers hacen I/O de red async con httpx, pero
la escritura en BD se hace en bloques cortos y transaccionales, más simple y
suficiente para el volumen del radar. La conexión se toma de settings.database_url.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            future=True,
        )
    return _engine


def _factory() -> sessionmaker[Session]:
    global _Session
    if _Session is None:
        _Session = sessionmaker(bind=get_engine(), class_=Session, expire_on_commit=False)
    return _Session


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transacción con commit/rollback automático."""
    session = _factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Session:
    """Sesión suelta (el llamador gestiona commit/close). Útil en la CLI."""
    return _factory()()
