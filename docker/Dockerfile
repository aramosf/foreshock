# Imagen base común para migraciones y los workers de carga de datos.
FROM python:3.12-slim

# git es necesario para el clon/pull incremental de cvelistV5.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# uv para gestión de dependencias (según stack del proyecto)
RUN pip install --no-cache-dir uv

WORKDIR /app

# 1) Dependencias primero -> capa cacheable independiente del código.
COPY pyproject.toml ./
RUN uv pip install --system --no-cache \
    "sqlmodel>=0.0.22" "sqlalchemy>=2.0" "alembic>=1.13" "psycopg[binary]>=3.2" \
    "pydantic>=2.8" "pydantic-settings>=2.4" "structlog>=24.4" \
    "httpx>=0.27" "feedparser>=6.0" "selectolax>=0.3" "tenacity>=9.0" \
    "python-dateutil>=2.9" "apscheduler>=3.10" "redis>=5.0" "cvss>=3.2" \
    "typer>=0.12" "rich>=13.7" "fastapi>=0.115" "uvicorn[standard]>=0.30"

# 2) Código + migraciones.
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app

# 3) Instala el proyecto (sin re-resolver deps) para exponer el script `foreshock`.
RUN uv pip install --system --no-cache --no-deps .

# La URL real llega por env var DATABASE_URL (docker-compose).
CMD ["alembic", "upgrade", "head"]
