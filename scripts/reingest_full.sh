#!/usr/bin/env bash
# ============================================================================
# Re-ingest limpio full-history de la capa radar de Foreshock.
#
# PRE-REQUISITO: haber truncado la capa radar y que NO haya otro re-ingest ni
# los workers programados corriendo (evita mezclar ingestas -> ver docs/OPERATIONS).
#
# Reutiliza la caché de artefactos (/data/cache): OSV zips, GH Archive, etc.
# NO toca el baseline (published_cves, epss_scores) ni product_catalog.
#
# Uso (contenedor con el volumen `data` y las env de tokens montadas):
#   docker compose run --rm -d -v "$(pwd)/scripts:/app/scripts" \
#     sources-worker bash /app/scripts/reingest_full.sh
# Progreso:  docker compose run --rm sources-worker tail -f /data/reingest.log
# ============================================================================
# -E propaga el trap ERR; -e aborta al primer fallo (así "REINGEST DONE" solo
# se imprime si TODO terminó bien).
set -Eeuo pipefail
LOG=/data/reingest.log
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1
trap 'echo "================ REINGEST FAILED (rc=$?) $(date -u) ================"' ERR

# --- Ajustes full-history (no rodantes) -------------------------------------
export FORESHOCK_OSV_MONTHS=0                 # 0 = histórico completo
export FORESHOCK_OSV_MAX_PER_ECOSYSTEM=0      # 0 = sin cap
export FORESHOCK_REDHAT_LOOKBACK_DAYS=4000    # ~11 años (histórico)
export FORESHOCK_GITHUB_COMMITS_SINCE=2026-05-01   # cutoff FIJO (no rueda)
export FORESHOCK_GITHUB_TOP_N=10000

echo "================ REINGEST START $(date -u) ================"

# 0) Registrar fuentes del código en la tabla `sources` (incluye las nuevas).
foreshock sources sync

# 1) OSV histórico completo por ecosistema (reusa zips cacheados).
for eco in PyPI npm Go Maven NuGet RubyGems crates.io Packagist Pub Hex Debian Alpine Ubuntu; do
  echo "---- OSV $eco $(date -u) ----"
  FORESHOCK_OSV_ECOSYSTEMS="$eco" foreshock sources run osv
done

# 2) Resto de fuentes de señal (full history donde aplica).
for src in redhat_csaf github_advisories vulncheck_kev cisa_kev nuclei_templates metasploit certcc_vu thehackernews nessus; do
  echo "---- $src $(date -u) ----"
  foreshock sources run "$src"
done

# 3) github_commits (clon blobless + git log) — barrido incremental de los
#    top-N. Cada pasada procesa PER_RUN repos del registro: se calculan las
#    pasadas necesarias (ceil(TOP_N/PER_RUN)); antes había 15 hardcodeadas,
#    insuficientes para 10000/500 = 20.
TOP_N="${FORESHOCK_GITHUB_TOP_N:-10000}"
PER_RUN="${FORESHOCK_GITHUB_REPOS_PER_RUN:-500}"
PASSES=$(( (TOP_N + PER_RUN - 1) / PER_RUN ))
for i in $(seq 1 "$PASSES"); do
  echo "---- github_commits pass $i/$PASSES $(date -u) ----"
  foreshock sources run github_commits
done

# 4) Enriquecimiento NVD (CVSS/CWE/CPE/refs + SSVC) desde raw_json.
echo "---- ENRICH NVD $(date -u) ----"
foreshock baseline enrich-nvd

echo "================ REINGEST DONE $(date -u) ================"
