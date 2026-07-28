# Operación

Plataforma de carga de datos y dashboards de solo lectura. Todo se ejecuta con
`docker compose` sobre Postgres 16. Imagen común en `docker/Dockerfile` (Python 3.12-slim +
`git` + deps con `uv`).

---

## Quickstart

```bash
docker compose up            # levanta postgres, migrate, workers y API
```

Orden de arranque (definido en `docker-compose.yml`):

1. `postgres` arranca y pasa su healthcheck.
2. `migrate` corre `alembic upgrade head` y **termina**.
3. `baseline-worker` (`python -m app.baseline`) y `sources-worker`
   (`python -m app.sources`) arrancan solo cuando `migrate` acaba con éxito
   (`service_completed_successfully`) y quedan en bucle (`restart:
   unless-stopped`).

El `baseline-worker` hace una pasada inicial inmediata y luego programa
cvelist/NVD/EPSS a sus cadencias. El `sources-worker` registra los fetchers en
la tabla `sources` (`sync_registry_to_db`) y programa cada fuente habilitada.
Las primeras ejecuciones se reparten durante una hora y el ciclo completo de
cada fetcher queda acotado por límites global, Git y fuentes pesadas.

Dashboards: `/` para las señales y `/pending_status` para workers, fetchers,
procesos, PostgreSQL y cobertura de ingesta.

Para operar manualmente dentro de un contenedor:

```bash
docker compose run --rm baseline-worker foreshock sources list
docker compose run --rm baseline-worker foreshock baseline sync
docker compose run --rm baseline-worker foreshock emerging list --since 24h --tier 1
```

---

## Variables de entorno

Config centralizada en `app/core/config.py` (`pydantic-settings`, prefijo
`FORESHOCK_`, salvo las de infra con `validation_alias`). Defaults apuntan al
compose local; nunca se hardcodean secretos.

### Infra
| Var | Default | Uso |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://foreshock:foreshock@localhost:5432/foreshock` | Conexión Postgres (driver psycopg3 sync). |
| `FORESHOCK_DATA_DIR` | `/data` | Raíz de datos (raw HTML, cachés, contextos browser). |
| `FORESHOCK_RAW_HTML_DIR` | `/data/raw` | HTML crudo de menciones. |
| `FORESHOCK_CVELIST_REPO_DIR` | `/data/cvelistV5` | Clon de cvelistV5. |

### Baseline
| Var | Default |
|---|---|
| `FORESHOCK_CVELIST_REPO_URL` | `https://github.com/CVEProject/cvelistV5.git` |
| `FORESHOCK_CVELIST_SYNC_SECONDS` | `900` |
| `FORESHOCK_NVD_DELTA_SECONDS` | `7200` |
| `FORESHOCK_NVD_API_BASE` | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| `FORESHOCK_NVD_API_KEY` | `None` (sin key → pausa 6 s/página) |
| `FORESHOCK_EPSS_SYNC_SECONDS` | `86400` |
| `FORESHOCK_EPSS_API_BASE` | `https://api.first.org/data/v1/epss` |

### GitHub commits
`github_commits` ahora escanea vía **clon blobless + `git log`** (sin REST API ni
rate limit) y consume el registro `github_repos` (migración `0010`) vía
`next_batch`/`update_scan`, no ficheros JSON de estado.

| Var | Default | Uso |
|---|---|---|
| `FORESHOCK_GITHUB_API_BASE` | `https://api.github.com` | Search API de `harvest_top_n`. |
| `FORESHOCK_GITHUB_TOKEN` | `None` | PAT. Se embebe en la URL de clon; sube el límite de la Search API. |
| `FORESHOCK_GITHUB_TOP_N` | `10000` | Repos top por estrellas cosechados al watchlist (origin `top_n`). |
| `FORESHOCK_GITHUB_COMMITS_MONTHS` | `5` | Ventana relativa (fallback si `..._SINCE` no se fija). |
| `FORESHOCK_GITHUB_COMMITS_SINCE` | `2026-05-01` | Cutoff FIJO de commits (`YYYY-MM-DD`); si se fija, se usa en vez de la ventana y no rueda con el tiempo. |
| `FORESHOCK_GITHUB_REPOS_PER_RUN` | `150` | Repos por ejecución (`next_batch`, rotación nunca-escaneados primero). |
| `FORESHOCK_GITHUB_SYNTHESIZE_CANDIDATES` | `False` | **Off por defecto.** Los commits de seguridad sin CVE no se sintetizan como ancla `GHCOMMIT` (la ingesta los descartaría: no es un `RECOGNIZED_SCHEME`). |

### Watchlist de repos (registro) — estrategias opt-in
Además de `top_n` y de `reference`/`past_cve` (siempre activas), el registro
`github_repos` admite dos estrategias opt-in (`foreshock sources harvest-repos`):

| Var | Default | Uso |
|---|---|---|
| `FORESHOCK_CRITICALITY_CSV_URL` | `None` | CSV OpenSSF Criticality Score → repos (origin `criticality`). Opt-in. |
| `FORESHOCK_PYPI_DOWNLOADS_TOP_N` | `0` | `>0` ⇒ top-N PyPI por descargas → sus repos (origin `downloads`). Opt-in. |

### Fetchers / scraping educado
| Var | Default |
|---|---|
| `FORESHOCK_USER_AGENT` | `Foreshock/0.1 (+…; early-CVE research)` |
| `FORESHOCK_HTTP_TIMEOUT_SECONDS` | `30.0` |
| `FORESHOCK_MAX_RETRIES` | `3` |
| `FORESHOCK_RESPECT_ROBOTS` | `True` |
| `FORESHOCK_BROWSER_MAX_CONCURRENT` | `3` |
| `FORESHOCK_BROWSER_RECYCLE_AFTER` | `50` |
| `FORESHOCK_SOURCES_MAX_CONCURRENT` | `4` |
| `FORESHOCK_SOURCES_GIT_MAX_CONCURRENT` | `1` |
| `FORESHOCK_SOURCES_HEAVY_MAX_CONCURRENT` | `1` |
| `FORESHOCK_SOURCES_STARTUP_SPREAD_SECONDS` | `3600` |

### Enriquecimiento LLM
| Var | Default |
|---|---|
| `FORESHOCK_LLM_PROVIDER` | `mock` (`mock`/`openai`/`anthropic`/`ollama`) |
| `FORESHOCK_LLM_MODEL` | `mock-model` |
| `FORESHOCK_LLM_API_KEY` | `None` |
| `FORESHOCK_LLM_BASE_URL` | `None` (p.ej. Ollama `http://ollama:11434`) |
| `FORESHOCK_LLM_MAX_TOKENS` | `1024` |
| `FORESHOCK_ENRICHMENT_REENRICH_HOURS` | `24` |
| `FORESHOCK_ENRICHMENT_REENRICH_MIN_MENTIONS` | `3` |

### Otros
`FORESHOCK_EMERGING_MIN_MENTIONS` (`1`), `FORESHOCK_LOG_LEVEL` (`INFO`),
`FORESHOCK_LOG_JSON` (`True`).

`docker-compose.yml` pasa `FORESHOCK_NVD_API_KEY`, `FORESHOCK_LLM_PROVIDER`,
`FORESHOCK_LLM_API_KEY`, `FORESHOCK_LLM_MODEL` desde el entorno del host
(interpolación `${VAR:-default}`), típicamente via un fichero `.env`.

---

## Volúmenes

| Volumen | Montaje | Contenido |
|---|---|---|
| `pgdata` | `postgres:/var/lib/postgresql/data` | Datos de Postgres. |
| `data` | `baseline-worker` y `sources-worker` en `/data` | HTML crudo (`/data/raw/<source_id>/<hash>.html`), clon `cvelistV5`, caché de git-log de `github_commits` (`/data/cache/gitlog/<owner__repo>.log.gz`) y clones blobless efímeros (`/data/clones/`), contextos Playwright (`/data/browser/<source>`). El watchlist de repos ahora vive en la **tabla** `github_repos`, no en ficheros JSON. |

El volumen `data` es **compartido** por ambos workers, de ahí que las cachés de
GitHub y el HTML crudo sean visibles para ambos.

---

## Healthchecks

- `postgres`: `pg_isready -U foreshock -d foreshock` (interval 3s, retries 20).
- `migrate` no tiene healthcheck: es un job que corre y sale con éxito; los
  workers dependen de su `service_completed_successfully`.
- `api`: `/healthz` ejecuta `SELECT 1`; `/pending_status` muestra los heartbeats
  y la presión de ejecución de los workers.

---

## Tests

Los tests corren con `pytest` **dentro del contenedor** contra un Postgres
**migrado** (`alembic upgrade head` antes). `tests/conftest.py`:

- La fixture `db` hace `TRUNCATE … RESTART IDENTITY CASCADE` de todas las tablas
  de datos antes de cada test de integración (usa `DATABASE_URL` del entorno).
- `sources_seeded` garantiza que la tabla `sources` tenga los fetchers.
- Los tests unitarios (hashing, identifiers, cvss, normalize) no requieren BD.

`pyproject.toml`: `asyncio_mode = "auto"`, `testpaths = ["tests"]`. Deps de test
en el grupo `dev` (pytest, pytest-asyncio, pytest-cov, respx, ruff, mypy).

```bash
# con la infra levantada y el esquema migrado:
docker compose run --rm \
  -e DATABASE_URL=postgresql+psycopg://foreshock:foreshock@postgres:5432/foreshock \
  baseline-worker sh -c "uv pip install --system --no-cache pytest pytest-asyncio respx && pytest"
```

> La imagen de producción no incluye las deps `dev`; instálalas en el contenedor
> efímero o usa una imagen de desarrollo. Playwright (fetchers `browser`) es un
> extra opcional (`.[browser]`).
