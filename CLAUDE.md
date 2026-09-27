# Foreshock — notas para agentes

- **Muchos comportamientos "raros" son fixes deliberados** (p.ej. KPIs
  `days_ahead` a NULL por la guarda de observación tardía, o el regex OSV
  sensible a mayúsculas): antes de "arreglar" algo extraño, mira `git log`/`git
  blame` del fragmento para entender el porqué.
- Métrica prioritaria del producto (directriz del usuario): **CVEs identificados
  en otras fuentes, con la tecnología afectada conocida, que NVD aún no ha
  publicado** (`foreshock pending`), y el KPI `days_ahead_vs_nvd_present`.
- Las migraciones Alembic escritas a mano son la fuente de verdad del esquema;
  `app/core/models.py` es un espejo que hay que mantener sincronizado.
- Tests: SIEMPRE contra la BD dedicada `foreshock_test` (los tests de
  integración **TRUNCAN** las tablas de la BD apuntada — nunca contra
  `foreshock`, que tiene los datos reales):
  `DATABASE_URL="postgresql+psycopg://foreshock:foreshock@localhost:5432/foreshock_test" .venv/bin/python -m pytest tests/ -q`
  Si no existe: `CREATE DATABASE foreshock_test OWNER foreshock;` + `alembic upgrade head` con esa DATABASE_URL.
