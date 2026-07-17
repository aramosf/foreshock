# Operations

Headless data-loading backend, no UI. Everything runs with `docker compose` on
top of Postgres 16 + Redis 7. Common image in `docker/Dockerfile` (Python
3.12-slim + `git` + deps via `uv`).

---

## Quickstart

```bash
docker compose up            # brings up postgres, redis, migrate, and the 2 workers
```

Startup order (defined in `docker-compose.yml`):

1. `postgres` and `redis` start and pass their healthcheck.
2. `migrate` runs `alembic upgrade head` and **exits**.
3. `baseline-worker` (`python -m app.baseline`) and `sources-worker`
   (`python -m app.sources`) start only when `migrate` finishes successfully
   (`service_completed_successfully`) and stay in a loop (`restart:
   unless-stopped`).

The `baseline-worker` makes an immediate initial pass and then schedules
cvelist/NVD/EPSS at their cadences. The `sources-worker` registers the fetchers
into the `sources` table (`sync_registry_to_db`) and schedules each enabled
source.

To operate manually inside a container:

```bash
docker compose run --rm baseline-worker cveradar sources list
docker compose run --rm baseline-worker cveradar baseline sync
docker compose run --rm baseline-worker cveradar emerging list --since 24h --tier 1
```

---

## Environment variables

Configuration is centralized in `app/core/config.py` (`pydantic-settings`,
prefix `CVERADAR_`, except the infra ones with `validation_alias`). Defaults
point at the local compose; secrets are never hardcoded.

### Infra
| Var | Default | Use |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://cveradar:cveradar@localhost:5432/cveradar` | Postgres connection (psycopg3 sync driver). |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis. |
| `CVERADAR_DATA_DIR` | `/data` | Data root (raw HTML, caches, browser contexts). |
| `CVERADAR_RAW_HTML_DIR` | `/data/raw` | Raw mention HTML. |
| `CVERADAR_CVELIST_REPO_DIR` | `/data/cvelistV5` | cvelistV5 clone. |

### Baseline
| Var | Default |
|---|---|
| `CVERADAR_CVELIST_REPO_URL` | `https://github.com/CVEProject/cvelistV5.git` |
| `CVERADAR_CVELIST_SYNC_SECONDS` | `900` |
| `CVERADAR_NVD_DELTA_SECONDS` | `7200` |
| `CVERADAR_NVD_API_BASE` | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| `CVERADAR_NVD_API_KEY` | `None` (no key → 6 s/page pause) |
| `CVERADAR_EPSS_SYNC_SECONDS` | `86400` |
| `CVERADAR_EPSS_API_BASE` | `https://api.first.org/data/v1/epss` |

### GitHub commits
| Var | Default | Use |
|---|---|---|
| `CVERADAR_GITHUB_API_BASE` | `https://api.github.com` | |
| `CVERADAR_GITHUB_TOKEN` | `None` | PAT → 5000 req/h. |
| `CVERADAR_GITHUB_TOP_N` | `10000` | Top repos to watch. |
| `CVERADAR_GITHUB_COMMITS_MONTHS` | `5` | Changelog window. |
| `CVERADAR_GITHUB_REPOS_PER_RUN` | `150` | Repos per run (rotating crawl). |
| `CVERADAR_GITHUB_SYNTHESIZE_CANDIDATES` | `True` | Pre-CVE candidate for fixes without a CVE. |

### Fetchers / polite scraping
| Var | Default |
|---|---|
| `CVERADAR_USER_AGENT` | `CVERadar/0.1 (+…; early-CVE research)` |
| `CVERADAR_HTTP_TIMEOUT_SECONDS` | `30.0` |
| `CVERADAR_MAX_RETRIES` | `3` |
| `CVERADAR_RESPECT_ROBOTS` | `True` |
| `CVERADAR_BROWSER_MAX_CONCURRENT` | `3` |
| `CVERADAR_BROWSER_RECYCLE_AFTER` | `50` |

### LLM enrichment
| Var | Default |
|---|---|
| `CVERADAR_LLM_PROVIDER` | `mock` (`mock`/`openai`/`anthropic`/`ollama`) |
| `CVERADAR_LLM_MODEL` | `mock-model` |
| `CVERADAR_LLM_API_KEY` | `None` |
| `CVERADAR_LLM_BASE_URL` | `None` (e.g. Ollama `http://ollama:11434`) |
| `CVERADAR_LLM_MAX_TOKENS` | `1024` |
| `CVERADAR_ENRICHMENT_REENRICH_HOURS` | `24` |
| `CVERADAR_ENRICHMENT_REENRICH_MIN_MENTIONS` | `3` |

### Others
`CVERADAR_EMERGING_MIN_MENTIONS` (`1`), `CVERADAR_LOG_LEVEL` (`INFO`),
`CVERADAR_LOG_JSON` (`True`).

`docker-compose.yml` passes `CVERADAR_NVD_API_KEY`, `CVERADAR_LLM_PROVIDER`,
`CVERADAR_LLM_API_KEY`, `CVERADAR_LLM_MODEL` from the host environment
(`${VAR:-default}` interpolation), typically via a `.env` file.

---

## Volumes

| Volume | Mount | Contents |
|---|---|---|
| `pgdata` | `postgres:/var/lib/postgresql/data` | Postgres data. |
| `data` | `baseline-worker` and `sources-worker` at `/data` | Raw HTML (`/data/raw/<source_id>/<hash>.html`), `cvelistV5` clone, github caches (`github_top_repos.json`, `github_commits_cursor.txt`, `github_repo_state.json`), Playwright contexts (`/data/browser/<source>`). |

The `data` volume is **shared** by both workers, which is why the GitHub caches
and the raw HTML are visible to both.

---

## Healthchecks

- `postgres`: `pg_isready -U cveradar -d cveradar` (interval 3s, retries 20).
- `redis`: `redis-cli ping` (interval 3s, retries 20).
- `migrate` has no healthcheck: it is a job that runs and exits successfully;
  the workers depend on its `service_completed_successfully`.

---

## Tests

Tests run with `pytest` **inside the container** against a **migrated** Postgres
(`alembic upgrade head` beforehand). `tests/conftest.py`:

- The `db` fixture does `TRUNCATE … RESTART IDENTITY CASCADE` of all data tables
  before each integration test (uses `DATABASE_URL` from the environment).
- `sources_seeded` guarantees the `sources` table has the fetchers.
- The unit tests (hashing, identifiers, cvss, normalize) do not require a DB.

`pyproject.toml`: `asyncio_mode = "auto"`, `testpaths = ["tests"]`. Test deps in
the `dev` group (pytest, pytest-asyncio, pytest-cov, respx, ruff, mypy).

```bash
# with the infra up and the schema migrated:
docker compose run --rm \
  -e DATABASE_URL=postgresql+psycopg://cveradar:cveradar@postgres:5432/cveradar \
  baseline-worker sh -c "uv pip install --system --no-cache pytest pytest-asyncio respx && pytest"
```

> The production image does not include the `dev` deps; install them in the
> ephemeral container or use a development image. Playwright (`browser` fetchers)
> is an optional extra (`.[browser]`).
