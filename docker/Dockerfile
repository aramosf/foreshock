# Imagen base común para migraciones y los workers de carga de datos.
FROM python:3.12-slim

# git es necesario para el clon/pull incremental de cvelistV5.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# uv para gestión de dependencias (según stack del proyecto)
RUN pip install --no-cache-dir uv

WORKDIR /app

# 1) Dependencias primero -> capa cacheable independiente del código.
#    Se instalan DESDE pyproject.toml (única fuente de verdad): sin lista
#    duplicada a mano que derive con el tiempo.
COPY pyproject.toml ./
RUN uv pip install --system --no-cache -r pyproject.toml

# 2) Código + migraciones.
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app

# 3) Instala el proyecto (sin re-resolver deps) para exponer el script `foreshock`.
RUN uv pip install --system --no-cache --no-deps .

# PENDIENTE: pasar a usuario no-root. Los volúmenes /data ya desplegados
# tienen owner root; antes de añadir USER hay que migrar la propiedad de esos
# datos (chown en un job puntual) o los workers perderían acceso.

# La URL real llega por env var DATABASE_URL (docker-compose).
CMD ["alembic", "upgrade", "head"]
