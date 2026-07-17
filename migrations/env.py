"""Alembic environment for EmergingCVE.

La URL de conexión se resuelve por prioridad:
  1. env var DATABASE_URL  (docker-compose / CI)
  2. sqlalchemy.url de alembic.ini  (fallback local)

target_metadata se deja en None: estas migraciones son escritas a mano
(no autogenerate) hasta que los modelos SQLModel existan. Cuando existan,
importa aquí `SQLModel.metadata` para habilitar --autogenerate.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Sobrescribe la URL con la env var si está presente.
_db_url = os.getenv("DATABASE_URL")
if _db_url:
    config.set_main_option("sqlalchemy.url", _db_url)

# target_metadata = SQLModel.metadata  # <- habilitar cuando existan los modelos
target_metadata = None


def run_migrations_offline() -> None:
    """Modo offline: emite SQL sin conectar (genera scripts)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Modo online: conecta y aplica dentro de una transacción."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
