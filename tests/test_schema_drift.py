"""Guardia de deriva modelos <-> migraciones.

Las migraciones Alembic son la fuente de verdad del esquema (escritas a mano) y
`app/core/models.py` es un espejo ORM que hay que mantener sincronizado a mano
(env.py fija target_metadata=None, así que `alembic check`/autogenerate no
detecta la deriva). Este test cierra ese hueco: contra la BD ya migrada
(DATABASE_URL, `alembic upgrade head`), comprueba que TODO lo que los modelos
declaran existe realmente en el esquema.

Dirección de la comprobación: modelos ⊆ esquema. Es la deriva PELIGROSA (un
modelo que referencia una tabla/columna que la migración no tiene revienta en
runtime). La inversa (columnas en BD no mapeadas en el modelo) se permite: los
modelos son un espejo deliberadamente parcial para la ingesta y la CLI.
"""

from __future__ import annotations

from sqlalchemy import inspect

import app.core.models  # noqa: F401  (registra las tablas en SQLModel.metadata)
from app.core.db import get_engine
from sqlmodel import SQLModel


def _db_schema() -> dict[str, set[str]]:
    """{tabla: {columnas}} del esquema realmente migrado."""
    insp = inspect(get_engine())
    return {
        name: {col["name"] for col in insp.get_columns(name)}
        for name in insp.get_table_names()
    }


def test_modelos_no_derivan_del_esquema_migrado() -> None:
    # Solo necesita la BD migrada (DATABASE_URL), no la fixture `db` que trunca.
    db = _db_schema()
    problemas: list[str] = []

    for table in SQLModel.metadata.sorted_tables:
        if table.name not in db:
            problemas.append(
                f"tabla '{table.name}' declarada en modelos pero AUSENTE en el esquema migrado"
            )
            continue
        faltan = {c.name for c in table.columns} - db[table.name]
        if faltan:
            problemas.append(
                f"tabla '{table.name}': columnas del modelo AUSENTES en el esquema migrado: "
                f"{sorted(faltan)}"
            )

    assert not problemas, "Deriva modelos<->migraciones detectada:\n- " + "\n- ".join(problemas)
