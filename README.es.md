# Foreshock

**Radar temprano de vulnerabilidades**: detecta, correlaciona y enriquece CVEs
*antes* de que MITRE/NVD los publiquen oficialmente, midiendo los "días de
ventaja" sobre NVD por fuente.

Este repositorio es el **backend de carga de datos** (sin UI): workers que
ingieren señal de fuentes públicas a una base de datos Postgres, un pipeline de
ingesta/reconciliación, enriquecimiento por LLM + CVSS, y una CLI de operación.

---

## Idea central

La unidad de rastreo es el **`candidate`**, que **puede existir antes de que haya
un CVE**. Un aviso de ZDI (`ZDI-CAN-…`), una nota de CERT/CC (`VU#…`) o un commit
de seguridad en un repo popular (`GHCOMMIT:owner/repo@sha`) crean un candidate
que luego se **reconcilia** con el CVE cuando este aparece. Sobre esa base se
calcula el KPI estrella: **`days_ahead_vs_nvd_present`** — cuánto antes vimos la
señal frente a la primera vez que *nosotros* observamos el CVE en NVD (robusto
frente al backfill de fechas de NVD).

Ver [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) y
[`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md).

## Arquitectura (docker-compose)

| Servicio | Rol |
|---|---|
| `postgres` | Postgres 16 — estado canónico y señal |
| `redis` | cache / rate-limit |
| `migrate` | aplica migraciones Alembic y termina (los workers esperan a que acabe) |
| `baseline-worker` | sincroniza cvelistV5 + NVD 2.0 + EPSS |
| `sources-worker` | ejecuta los fetchers en sus cadencias e ingiere las menciones |

```mermaid
flowchart LR
    subgraph EXT["Fuentes externas"]
        direction TB
        CVELIST["cvelistV5"]
        NVD["NVD 2.0 delta"]
        EPSSAPI["EPSS"]
        SRC["6 fetchers<br/>Tier 1-5 + GitHub commits"]
    end
    subgraph BW["baseline-worker"]
        JOBS["cvelist · nvd · epss"]
    end
    subgraph SW["sources-worker"]
        direction TB
        FETCH["fetch()"] --> INGEST["ingest_mention<br/>identifiers · reconcile · hash"] --> ENRICH["enrich<br/>LLM + CVSS"]
    end
    LLM["LLM mock/openai/anthropic/ollama"]
    subgraph PG["Postgres 16"]
        direction TB
        PUB["published_cves"]
        DATA["candidates · identifiers · mentions<br/>cvss_scores · epss_scores · affected_products"]
        VIEW["vistas: radar · cvss_selected · epss_current"]
    end
    CLI["CLI foreshock"]
    CVELIST --> JOBS
    NVD --> JOBS
    EPSSAPI --> JOBS
    SRC --> FETCH
    JOBS --> PUB
    INGEST --> DATA
    ENRICH --> DATA
    ENRICH <--> LLM
    PUB -. "reconciliación cve_id (sin FK)" .-> DATA
    DATA --- VIEW
    CLI --> PG

    classDef ext fill:#eef,stroke:#88a;
    classDef store fill:#efe,stroke:#7a7;
    classDef proc fill:#fee,stroke:#c88;
    class EXT,CVELIST,NVD,EPSSAPI,SRC ext;
    class PG,PUB,DATA,VIEW store;
    class BW,SW,JOBS,FETCH,INGEST,ENRICH proc;
```

Diagrama de componentes detallado en [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quickstart

```bash
# Levanta todo: postgres + redis + migraciones + workers
docker compose up --build

# Solo infraestructura para desarrollo
docker compose up -d postgres redis
docker compose run --rm migrate            # aplica migraciones
```

Operación con la CLI (`foreshock`, dentro de cualquier imagen del proyecto):

```bash
foreshock sources sync                       # registra los fetchers en la BD
foreshock sources list                       # estado de las fuentes
foreshock sources run redhat_csaf            # ejecuta un fetcher una vez
foreshock baseline sync                      # fuerza sync cvelist+NVD+EPSS
foreshock emerging list --since 24h --tier 1 --min-mentions 2
foreshock cve show CVE-2026-12345            # timeline + enriquecimiento
foreshock enrich CVE-2026-12345              # LLM + CVSS
foreshock stats                              # días de ventaja por fuente
```

## Fuentes implementadas (una por tier + GitHub commits)

| Fuente | Tier | Método | Señal |
|---|---|---|---|
| `certcc_vu` | 1 | rss | CERT/CC Vulnerability Notes (VU#) |
| `redhat_csaf` | 2 | api | Red Hat Security Data (CVSS autoritativo) |
| `nessus` | 3 | scrape | Tenable plugins (CVE reservado citado por scanner) |
| `github_advisories` | 4 | api | GitHub Security Advisories (GHSA + paquetes) |
| `github_commits` | 4 | api | **Top-N repos + changelog N meses** (CVE reservado / fix de seguridad pre-CVE) |
| `thehackernews` | 5 | rss | Noticias de explotación activa |

`github_commits` vigila los **top-N repos** (`FORESHOCK_GITHUB_TOP_N`, por defecto
10.000, escalable a 100.000+) y escanea sus commits de los últimos N meses. Es
**cacheado e incremental**: la lista de repos se cachea (rebuild semanal), se
procesan por lotes con un cursor rotatorio, y cada repo mantiene un *watermark*
(última fecha de commit escaneada). Detecta commits que citan un CVE (a menudo
reservado) y fixes de seguridad sin CVE, que quedan como candidates pre-CVE.
Ver [`docs/SOURCES.md`](docs/SOURCES.md).

## Enriquecimiento (Capa 3)

El LLM (configurable: `mock`/`openai`/`anthropic`/`ollama`, mock por defecto sin
API key) extrae **metadatos estructurados, no un número CVSS**. El CVSS sigue una
precedencia de 3 niveles: **autoritativo** (vector extraído del texto de la
fuente) → **derivado** (calculado desde métricas con la librería `cvss`) →
**`severity_hint`** cualitativo. Ver [`docs/ENRICHMENT.md`](docs/ENRICHMENT.md).

## Tests

```bash
# 49 tests (unit + integración contra Postgres real)
docker compose up -d postgres && docker compose run --rm migrate
docker compose run --rm --no-deps \
  -e DATABASE_URL=postgresql+psycopg://cveradar:cveradar@postgres:5432/cveradar \
  -v "$PWD":/app -w /app sources-worker \
  bash -lc "uv pip install --system -q pytest pytest-asyncio respx && pytest -q"
```

## Documentación

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — visión global y flujo de datos
- [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) — esquema y decisiones por tabla
- [`docs/INGESTION.md`](docs/INGESTION.md) — pipeline de ingesta y reconciliación
- [`docs/SOURCES.md`](docs/SOURCES.md) — fetchers y cómo añadir uno
- [`docs/ENRICHMENT.md`](docs/ENRICHMENT.md) — LLM + CVSS + normalización
- [`docs/BASELINE.md`](docs/BASELINE.md) — cvelistV5 + NVD + EPSS
- [`docs/CLI.md`](docs/CLI.md) — referencia de comandos
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — despliegue y operación
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — decisiones no obvias

## Stack

Python 3.12, SQLModel/SQLAlchemy 2, Alembic, Postgres 16, Redis, httpx, feedparser,
selectolax, APScheduler, Playwright (opcional), Typer, structlog. Docker + docker-compose.
