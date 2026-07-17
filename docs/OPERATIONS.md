# Operations

CVERadar is a headless data-loading backend (no UI). Everything runs with
`docker compose` on top of Postgres 16 + Redis 7. All application processes are
built from one image (`docker/Dockerfile`: `python:3.12-slim` + `git` +
dependencies installed with `uv`).

---

## Quickstart

```bash
docker compose up            # postgres, redis, migrate, baseline-worker, sources-worker
```

Startup order (`docker-compose.yml`):

1. **`postgres`** and **`redis`** start and must pass their healthchecks.
2. **`migrate`** runs `alembic upgrade head` and **exits**. Every other
   application service `depends_on: migrate: condition:
   service_completed_successfully`.
3. **`baseline-worker`** (`python -m app.baseline`) and **`sources-worker`**
   (`python -m app.sources`) start only after `migrate` succeeds **and**
   `redis: condition: service_healthy`. Both are `restart: unless-stopped`.

On startup:
- `baseline-worker` schedules `_cvelist_job` / `_nvd_job` / `_epss_job` on
  `AsyncIOScheduler` at their cadences and runs an immediate first pass.
- `sources-worker` calls `sync_registry_to_db()` (registers the code's fetchers
  into the `sources` table), then schedules every `enabled` source at its
  `cadence_seconds` (`jitter=30`, `max_instances=1`), and re-reconciles the job
  set against the DB every 60 s (hot enable/disable and cadence changes).

Run operations manually inside a container:

```bash
docker compose run --rm baseline-worker cveradar sources list
docker compose run --rm baseline-worker cveradar baseline sync
docker compose run --rm baseline-worker cveradar emerging list --since 24h --tier 1
```

---

## Environment variables

Configuration is centralized in `app/core/config.py` (`pydantic-settings`,
`env_prefix="CVERADAR_"`, `env_file=".env"`, `extra="ignore"`). Two variables use
an explicit `validation_alias` and therefore have **no** `CVERADAR_` prefix:
`DATABASE_URL` and `REDIS_URL`. Defaults target the local compose network; no
secret is ever hardcoded.

### Infra / storage
| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://cveradar:cveradar@localhost:5432/cveradar` | Postgres DSN (psycopg3 driver). Compose overrides host to `postgres`. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL. Compose overrides host to `redis`. |
| `CVERADAR_DATA_DIR` | `/data` | Root for raw HTML, caches, browser contexts. |
| `CVERADAR_RAW_HTML_DIR` | `/data/raw` | Persisted raw mention HTML (`/data/raw/<source_id>/<hash>.html`). |
| `CVERADAR_CVELIST_REPO_DIR` | `/data/cvelistV5` | Local shallow clone of cvelistV5. |

### Baseline (cvelistV5 / NVD / EPSS)
| Variable | Default | Purpose |
|---|---|---|
| `CVERADAR_CVELIST_REPO_URL` | `https://github.com/CVEProject/cvelistV5.git` | Repo cloned/pulled for canonical CVE records. |
| `CVERADAR_CVELIST_SYNC_SECONDS` | `900` | cvelist job cadence (15 min). |
| `CVERADAR_NVD_DELTA_SECONDS` | `7200` | NVD delta job cadence (2 h). |
| `CVERADAR_NVD_API_BASE` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD 2.0 endpoint. |
| `CVERADAR_NVD_API_KEY` | `None` | NVD API key. Without it, the module pauses 6 s between pages (public rate limit). |
| `CVERADAR_EPSS_SYNC_SECONDS` | `86400` | EPSS job cadence (daily). |
| `CVERADAR_EPSS_API_BASE` | `https://api.first.org/data/v1/epss` | FIRST.org EPSS endpoint. |

### GitHub commits source
| Variable | Default | Purpose |
|---|---|---|
| `CVERADAR_GITHUB_API_BASE` | `https://api.github.com` | GitHub API base. |
| `CVERADAR_GITHUB_TOKEN` | `None` | PAT. Raises the rate limit to 5000 req/h; strongly recommended. |
| `CVERADAR_GITHUB_TOP_N` | `10000` | Number of most-starred repos to watch. Raising it triggers a repo-list rebuild. |
| `CVERADAR_GITHUB_COMMITS_MONTHS` | `5` | Changelog look-back window scanned per repo. |
| `CVERADAR_GITHUB_REPOS_PER_RUN` | `150` | Repos processed per run (rotating incremental crawl). *(compose passes `500` by default.)* |
| `CVERADAR_GITHUB_COMMITS_MAX_PAGES` | `10` | Max commit pages per repo/run (100 commits/page) followed via the `Link` header. |
| `CVERADAR_GITHUB_SYNTHESIZE_CANDIDATES` | `True` | Synthesize a pre-CVE `GHCOMMIT` candidate for security-fix commits that cite no CVE. |
| `CVERADAR_GITHUB_ADVISORIES_MAX_PAGES` | `30` | GHSA advisories pagination cap (100/page → ~3000). |

### VulnCheck KEV
| Variable | Default | Purpose |
|---|---|---|
| `CVERADAR_VULNCHECK_TOKEN` | `None` | Free token from vulncheck.com. **Without it the source is inactive (returns `[]`).** |
| `CVERADAR_VULNCHECK_API_BASE` | `https://api.vulncheck.com/v3` | VulnCheck API base. |
| `CVERADAR_VULNCHECK_MAX_PAGES` | `50` | Pagination cap (100 items/page). |

### OSV.dev
| Variable | Default | Purpose |
|---|---|---|
| `CVERADAR_OSV_ECOSYSTEMS` | `PyPI,Go,crates.io,RubyGems,Packagist` | Comma-separated OSV ecosystems whose `all.zip` dump is scanned. |
| `CVERADAR_OSV_MONTHS` | `5` | Only advisories with `published` within this window are kept. |
| `CVERADAR_OSV_MAX_PER_ECOSYSTEM` | `3000` | Cap of mentions per ecosystem per run. **`0` = no cap** (full ingest). |

### Fetchers / polite scraping
| Variable | Default | Purpose |
|---|---|---|
| `CVERADAR_USER_AGENT` | `CVERadar/0.1 (+https://github.com/cveradar; early-CVE research)` | Identifiable UA on every request. |
| `CVERADAR_HTTP_TIMEOUT_SECONDS` | `30.0` | httpx client timeout. |
| `CVERADAR_MAX_RETRIES` | `3` | Retry budget knob (the retry decorator retries only transient errors: transport, 429, 5xx). |
| `CVERADAR_RESPECT_ROBOTS` | `True` | Honour `robots.txt` for scrape fetchers (cached parser). |
| `CVERADAR_BROWSER_MAX_CONCURRENT` | `3` | Playwright pool concurrency (optional `browser` extra). |
| `CVERADAR_BROWSER_RECYCLE_AFTER` | `50` | Recycle a browser context after N uses. |

### LLM enrichment
| Variable | Default | Purpose |
|---|---|---|
| `CVERADAR_LLM_PROVIDER` | `mock` | One of `mock` / `openai` / `anthropic` / `ollama`. `mock` needs no network. |
| `CVERADAR_LLM_MODEL` | `mock-model` | Model id for the provider. |
| `CVERADAR_LLM_API_KEY` | `None` | Provider API key (secret). |
| `CVERADAR_LLM_BASE_URL` | `None` | Custom base URL (e.g. Ollama `http://ollama:11434`). |
| `CVERADAR_LLM_MAX_TOKENS` | `1024` | Max tokens per enrichment call. |
| `CVERADAR_ENRICHMENT_REENRICH_HOURS` | `24` | Re-enrich if the last enrichment is older than this. |
| `CVERADAR_ENRICHMENT_REENRICH_MIN_MENTIONS` | `3` | Re-enrich if this many new mentions arrived. |

### Promotion / logging
| Variable | Default | Purpose |
|---|---|---|
| `CVERADAR_EMERGING_MIN_MENTIONS` | `1` | Baseline promotion/emerging threshold. |
| `CVERADAR_LOG_LEVEL` | `INFO` | Log level. |
| `CVERADAR_LOG_JSON` | `True` | Structured JSON logging (structlog). |

`docker-compose.yml` forwards a subset from the host with `${VAR:-default}`
interpolation (typically via a `.env` file): `CVERADAR_NVD_API_KEY`,
`CVERADAR_LLM_PROVIDER` / `CVERADAR_LLM_API_KEY` / `CVERADAR_LLM_MODEL`,
`CVERADAR_GITHUB_TOKEN`, `CVERADAR_GITHUB_TOP_N`, `CVERADAR_GITHUB_REPOS_PER_RUN`
(compose default `500`), `CVERADAR_VULNCHECK_TOKEN`,
`CVERADAR_VULNCHECK_MAX_PAGES`, `CVERADAR_OSV_ECOSYSTEMS`,
`CVERADAR_OSV_MAX_PER_ECOSYSTEM`.

---

## Secrets (`.env`, git-ignored)

All tokens/keys live in a local `.env` at the repo root (read by both
`pydantic-settings` and `docker-compose`'s `${VAR}` interpolation). **`.env` is
git-ignored — never commit tokens.** The secret-bearing variables are:
`CVERADAR_NVD_API_KEY`, `CVERADAR_GITHUB_TOKEN`, `CVERADAR_VULNCHECK_TOKEN`,
`CVERADAR_LLM_API_KEY`. Example `.env`:

```dotenv
CVERADAR_GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
CVERADAR_NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CVERADAR_VULNCHECK_TOKEN=vulncheck_xxxxxxxx
CVERADAR_LLM_PROVIDER=openai
CVERADAR_LLM_API_KEY=sk-xxxxxxxx
CVERADAR_LLM_MODEL=gpt-4o-mini
```

Missing optional secrets degrade gracefully: no `CVERADAR_VULNCHECK_TOKEN` → the
VulnCheck source is inactive; no `CVERADAR_GITHUB_TOKEN` → GitHub sources still
run but at the 60 req/h unauthenticated limit; `CVERADAR_LLM_PROVIDER=mock` → no
LLM calls.

---

## Volumes

| Volume | Mount | Contents |
|---|---|---|
| `pgdata` | `postgres:/var/lib/postgresql/data` | Postgres data. |
| `data` | `baseline-worker` and `sources-worker` at `/data` | Raw HTML (`/data/raw/<source_id>/<hash>.html`); the cvelistV5 clone (`/data/cvelistV5`); GitHub caches (`github_top_repos.json`, `github_commits_cursor.txt`, `github_repo_state.json`); OSV `all.zip` temp files (streamed to a `NamedTemporaryFile` and unlinked). |

The `data` volume is **shared** by both workers, so the GitHub top-N list,
per-repo watermarks, crawl cursor, and raw HTML are visible to both.

---

## Healthchecks & worker dependencies

- `postgres`: `pg_isready -U cveradar -d cveradar` (interval 3s, retries 20).
- `redis`: `redis-cli ping` (interval 3s, retries 20).
- `migrate` has no healthcheck — it is a run-once job; other services wait on its
  `service_completed_successfully`.
- Both workers additionally `depends_on: redis: condition: service_healthy`, so
  they never start against a Redis that is not yet accepting connections.

---

## Running the tests

Tests run with `pytest` **inside a container** against a **migrated** Postgres
(`alembic upgrade head` first). `tests/conftest.py`:

- The `db` fixture `TRUNCATE … RESTART IDENTITY CASCADE` of all data tables
  before each integration test (uses `DATABASE_URL` from the environment).
- `sources_seeded` guarantees the `sources` table holds the registered fetchers.
- Pure unit tests (hashing, identifiers, cvss, normalize, flags) need no DB.

`pyproject.toml`: `asyncio_mode = "auto"`, `testpaths = ["tests"]`. Test
dependencies live in the `dev` group (`pytest`, `pytest-asyncio`, `pytest-cov`,
`respx`, `ruff`, `mypy`) and are **not** in the production image.

```bash
# with infra up and schema migrated:
docker compose run --rm \
  -e DATABASE_URL=postgresql+psycopg://cveradar:cveradar@postgres:5432/cveradar \
  baseline-worker sh -c "uv pip install --system --no-cache pytest pytest-asyncio respx && pytest"
```

> The `browser` fetchers depend on the optional `.[browser]` extra (Playwright),
> not installed in the base image.

---

## Typical operations

**Re-ingest one source now** (e.g. after fixing a fetcher or to force a pull):

```bash
docker compose run --rm sources-worker cveradar sources run osv
docker compose run --rm sources-worker cveradar sources run github_commits
```

**Force a baseline sync** (canonical state, incl. a full cvelist reprocess):

```bash
docker compose run --rm baseline-worker cveradar baseline sync --nvd-hours 6
docker compose run --rm baseline-worker cveradar baseline sync --full-cvelist
```

**Enable / disable a source** (picked up hot within 60 s):

```bash
docker compose run --rm sources-worker cveradar sources disable thehackernews
docker compose run --rm sources-worker cveradar sources enable vulncheck_kev
```

**Raise the GitHub top-N** without clearing caches — set
`CVERADAR_GITHUB_TOP_N` higher; on the next run the repo-list rebuilds because
`_load_repo_list` returns `None` when the cached list is shorter than the
requested top-N (or older than 7 days).

**Backfill affected products** for candidates ingested before rich persistence:

```bash
docker compose run --rm baseline-worker cveradar backfill-products --batch 2000
```

---

## Scaling notes

- **GitHub top-N (10k → 100k repos).** The top-N list is built once (windowed by
  descending star counts because the Search API caps at 1000 results/query),
  cached to `github_top_repos.json`, and rebuilt weekly. Each run processes a
  rotating slice of `github_repos_per_run` repos (cursor in
  `github_commits_cursor.txt`, wrapping around), with a per-repo commit-date
  watermark (`github_repo_state.json`) so re-scans are incremental. To go from
  10k to 100k, raise `CVERADAR_GITHUB_TOP_N` and either raise
  `CVERADAR_GITHUB_REPOS_PER_RUN` and/or shorten the source cadence; a PAT
  (`CVERADAR_GITHUB_TOKEN`, 5000 req/h) is required to keep up.
- **OSV without a cap.** OSV streams each ecosystem's `all.zip` to a temp file
  (avoids OOM on large dumps like npm/Debian) and reads entries lazily. Set
  `CVERADAR_OSV_MAX_PER_ECOSYSTEM=0` for full ingest and widen
  `CVERADAR_OSV_ECOSYSTEMS` as needed; the 6 h cadence keeps bandwidth bounded.
- **NVD.** With a key, NVD paginates 2000/page without the 6 s pause; widen
  `--nvd-hours` (or shorten `CVERADAR_NVD_DELTA_SECONDS`) to reduce the chance of
  missing a busy delta window.
