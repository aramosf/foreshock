#!/usr/bin/env bash
# ============================================================================
# start.sh — arranque unificado de TODO el sistema Foreshock (en Docker).
#
# Servicios (docker-compose.yml):
#   postgres        Base de datos (volumen persistente pgdata)
#   redis           Cola/estado de los workers
#   migrate         Aplica migraciones Alembic (alembic upgrade head) y termina
#   baseline-worker Sincroniza el baseline: cvelistV5 + NVD + EPSS (scheduler)
#   sources-worker  Ejecuta las fuentes de señal en sus cadencias (scheduler)
#   api             FastAPI + dashboard estático en http://localhost:8000
#
# Uso:
#   ./scripts/start.sh                 Arranca todo (modo operación normal)
#   ./scripts/start.sh --build         Reconstruye imágenes y arranca
#   ./scripts/start.sh --full-load     Arranca + carga inicial COMPLETA
#                                      (NVD/EPSS full + re-ingest histórico)
#   ./scripts/start.sh --stop-workers  Pausa SOLO los schedulers (para un
#                                      re-ingest manual seguro); deja api/db
#   ./scripts/start.sh --status        Muestra estado y sale
#
# Requisitos: Docker + docker compose. Tokens opcionales en .env
#   FORESHOCK_GITHUB_TOKEN=...      (sube el rate limit de GitHub / clones)
#   FORESHOCK_VULNCHECK_TOKEN=...   (fuente VulnCheck KEV)
#   FORESHOCK_NVD_API_KEY=...       (acelera el full sync de NVD)
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose"

_status() {
  $COMPOSE ps
  echo "----------------------------------------------------------------------"
  echo "Dashboard/API:  http://localhost:8000"
  echo "Progreso re-ingest (si lo hay): $COMPOSE run --rm sources-worker tail -f /data/reingest.log"
}

case "${1:-}" in
  --status)
    _status; exit 0 ;;
  --stop-workers)
    echo ">> Pausando schedulers (baseline-worker, sources-worker)…"
    $COMPOSE stop sources-worker baseline-worker
    echo ">> Hecho. api/postgres/redis siguen arriba."
    exit 0 ;;
esac

# .env (avisos no bloqueantes).
if [ ! -f .env ]; then
  echo "AVISO: no existe .env — las fuentes con token (GitHub, VulnCheck) irán limitadas."
fi

# Reconstruir imágenes si se pide.
if [ "${1:-}" = "--build" ]; then
  echo ">> Reconstruyendo imágenes…"
  $COMPOSE build
fi

echo ">> Levantando el sistema (migraciones -> workers -> api)…"
$COMPOSE up -d          # migrate corre primero; workers/api esperan a que acabe

# Carga inicial completa (primera vez): baseline full + re-ingest histórico.
if [ "${1:-}" = "--full-load" ]; then
  echo ">> Carga inicial COMPLETA solicitada."
  echo ">> 1) Pausando schedulers para no mezclar ingestas…"
  $COMPOSE stop sources-worker baseline-worker

  echo ">> 2) Baseline full: NVD (~270k) + EPSS (~350k)…"
  $COMPOSE run --rm sources-worker foreshock baseline nvd-full
  $COMPOSE run --rm sources-worker foreshock baseline epss-full

  echo ">> 3) Re-ingest histórico de la capa radar (en background)…"
  echo ">>    (trunca la capa radar y re-ingiere todo; baseline intacto)"
  $COMPOSE exec -T postgres psql -U cveradar -d cveradar -c \
    "TRUNCATE candidates, candidate_links, identifiers, mentions, cvss_scores, \
     affected_products, affected_version_ranges, cve_soft_references \
     RESTART IDENTITY CASCADE;"
  CID=$($COMPOSE run --rm -d -v "$(pwd)/scripts:/app/scripts" \
        sources-worker bash /app/scripts/reingest_full.sh | tail -1)
  echo ">>    re-ingest lanzado: $CID"
  echo ">>    Sigue el progreso: $COMPOSE run --rm sources-worker tail -f /data/reingest.log"
  echo ">> 4) Cuando el re-ingest TERMINE, reactiva los schedulers:"
  echo ">>    ./scripts/start.sh   (o: docker compose up -d)"
else
  echo ">> Sistema arriba en modo operación (schedulers activos)."
fi

echo "----------------------------------------------------------------------"
_status
