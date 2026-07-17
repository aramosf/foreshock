# Operación

Backend de carga de datos sin UI. Todo se ejecuta con `docker compose` sobre
Postgres 16 + Redis 7. Imagen común en `docker/Dockerfile` (Python 3.12-slim +
`git` + deps con `uv`).

---

## Quickstart

```bash
docker compose up            # levanta postgres, redis, migrate, y los 2 workers
```

Orden de arranque (definido en `docker-compose.yml`):

1. `postgres` y `redis` arrancan y pasan su healthcheck.
2. `migrate` corre `alembic upgrade head` y **termina**.
3. `baseline-worker` (`python -m app.baseline`) y `sources-worker`
   (`python -m app.sources`) arrancan solo cuando `migrate` acaba con éxito
   (`service_completed_successfully`) y quedan en bucle (`restart:
   unless-stopped`).

El `baseline-worker` hace una pasada inicial inmediata y luego programa
cvelist/NVD/EPSS a sus cadencias. El `sources-worker` registra los fetchers en
la tabla `sources` (`sync_registry_to_db`) y programa cada fuente habilitada.

Para operar manualmente dentro de un contenedor:

```bash
docker compose run --rm baseline-worker cveradar sources list
docker compose run --rm baseline-worker cveradar baseline sync
docker compose run --rm baseline-worker cveradar emerging list --since 24h --tier 1
```

---

## Variables de entorno

Config centralizada en `app/core/config.py` (`pydantic-settings`, prefijo
`CVERADAR_`, salvo las de infra con `validation_alias`). Defaults apuntan al
compose local; nunca se hardcodean secretos.

### Infra
| Var | Default | Uso |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://cveradar:cveradar@localhost:5432/cveradar` | Conexión Postgres (driver psycopg3 sync). |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis. |
| `CVERADAR_DATA_DIR` | `/data` | Raíz de datos (raw HTML, cachés, contextos browser). |
| `CVERADAR_RAW_HTML_DIR` | `/data/raw` | HTML crudo de menciones. |
| `CVERADAR_CVELIST_REPO_DIR` | `/data/cvelistV5` | Clon de cvelistV5. |

### Baseline
| Var | Default |
|---|---|
| `CVERADAR_CVELIST_REPO_URL` | `https://github.com/CVEProject/cvelistV5.git` |
| `CVERADAR_CVELIST_SYNC_SECONDS` | `900` |
| `CVERADAR_NVD_DELTA_SECONDS` | `7200` |
| `CVERADAR_NVD_API_BASE` | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| `CVERADAR_NVD_API_KEY` | `None` (sin key → pausa 6 s/página) |
| `CVERADAR_EPSS_SYNC_SECONDS` | `86400` |
| `CVERADAR_EPSS_API_BASE` | `https://api.first.org/data/v1/epss` |

### GitHub commits
| Var | Default | Uso |
|---|---|---|
| `CVERADAR_GITHUB_API_BASE` | `https://api.github.com` | |
| `CVERADAR_GITHUB_TOKEN` | `None` | PAT → 5000 req/h. |
| `CVERADAR_GITHUB_TOP_N` | `10000` | Repos top a vigilar. |
| `CVERADAR_GITHUB_COMMITS_MONTHS` | `5` | Ventana de changelog. |
| `CVERADAR_GITHUB_REPOS_PER_RUN` | `150` | Repos por ejecución (crawl rotatorio). |
| `CVERADAR_GITHUB_SYNTHESIZE_CANDIDATES` | `True` | Candidate pre-CVE en fixes sin CVE. |

### Fetchers / scraping educado
| Var | Default |
|---|---|
| `CVERADAR_USER_AGENT` | `CVERadar/0.1 (+…; early-CVE research)` |
| `CVERADAR_HTTP_TIMEOUT_SECONDS` | `30.0` |
| `CVERADAR_MAX_RETRIES` | `3` |
| `CVERADAR_RESPECT_ROBOTS` | `True` |
| `CVERADAR_BROWSER_MAX_CONCURRENT` | `3` |
| `CVERADAR_BROWSER_RECYCLE_AFTER` | `50` |

### Enriquecimiento LLM
| Var | Default |
|---|---|
| `CVERADAR_LLM_PROVIDER` | `mock` (`mock`/`openai`/`anthropic`/`ollama`) |
| `CVERADAR_LLM_MODEL` | `mock-model` |
| `CVERADAR_LLM_API_KEY` | `None` |
| `CVERADAR_LLM_BASE_URL` | `None` (p.ej. Ollama `http://ollama:11434`) |
| `CVERADAR_LLM_MAX_TOKENS` | `1024` |
| `CVERADAR_ENRICHMENT_REENRICH_HOURS` | `24` |
| `CVERADAR_ENRICHMENT_REENRICH_MIN_MENTIONS` | `3` |

### Otros
`CVERADAR_EMERGING_MIN_MENTIONS` (`1`), `CVERADAR_LOG_LEVEL` (`INFO`),
`CVERADAR_LOG_JSON` (`True`).

`docker-compose.yml` pasa `CVERADAR_NVD_API_KEY`, `CVERADAR_LLM_PROVIDER`,
`CVERADAR_LLM_API_KEY`, `CVERADAR_LLM_MODEL` desde el entorno del host
(interpolación `${VAR:-default}`), típicamente via un fichero `.env`.

---

## Volúmenes

| Volumen | Montaje | Contenido |
|---|---|---|
| `pgdata` | `postgres:/var/lib/postgresql/data` | Datos de Postgres. |
| `data` | `baseline-worker` y `sources-worker` en `/data` | HTML crudo (`/data/raw/<source_id>/<hash>.html`), clon `cvelistV5`, cachés de github (`github_top_repos.json`, `github_commits_cursor.txt`, `github_repo_state.json`), contextos Playwright (`/data/browser/<source>`). |

El volumen `data` es **compartido** por ambos workers, de ahí que las cachés de
GitHub y el HTML crudo sean visibles para ambos.

---

## Healthchecks

- `postgres`: `pg_isready -U cveradar -d cveradar` (interval 3s, retries 20).
- `redis`: `redis-cli ping` (interval 3s, retries 20).
- `migrate` no tiene healthcheck: es un job que corre y sale con éxito; los
  workers dependen de su `service_completed_successfully`.

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
  -e DATABASE_URL=postgresql+psycopg://cveradar:cveradar@postgres:5432/cveradar \
  baseline-worker sh -c "uv pip install --system --no-cache pytest pytest-asyncio respx && pytest"
```

> La imagen de producción no incluye las deps `dev`; instálalas en el contenedor
> efímero o usa una imagen de desarrollo. Playwright (fetchers `browser`) es un
> extra opcional (`.[browser]`).
