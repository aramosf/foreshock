# Operations

Foreshock is a data-loading and read-only dashboard platform. Everything runs
with `docker compose` on top of Postgres 16. All application processes are
built from one image (`docker/Dockerfile`: `python:3.12-slim` + `git` +
dependencies installed with `uv`).

---

## Quickstart

```bash
docker compose up            # postgres, migrate, workers and api
```

Startup order (`docker-compose.yml`):

1. **`postgres`** starts and must pass its healthcheck.
2. **`migrate`** runs `alembic upgrade head` and **exits**. Every other
   application service `depends_on: migrate: condition:
   service_completed_successfully`.
3. **`baseline-worker`**, **`sources-worker`** and **`api`** start only after
   `migrate` succeeds. They are `restart: unless-stopped`.

On startup:
- `baseline-worker` schedules `_cvelist_job` / `_nvd_job` / `_epss_job` on
  `AsyncIOScheduler` at their cadences and runs an immediate first pass.
- `sources-worker` calls `sync_registry_to_db()` (registers the code's fetchers
  into the `sources` table), then schedules every `enabled` source at its
  `cadence_seconds` (`jitter=30`, `max_instances=1`), spreads initial runs over
  one hour by default, and re-reconciles the job set against the DB every 60 s.

Dashboards: `/` for vulnerability signal and `/pending_status` for worker,
fetcher, process, database and ingestion status.

Run operations manually inside a container:

```bash
docker compose run --rm baseline-worker foreshock sources list
docker compose run --rm baseline-worker foreshock baseline sync
docker compose run --rm baseline-worker foreshock emerging list --since 24h --tier 1
```

---

## Environment variables

Configuration is centralized in `app/core/config.py` (`pydantic-settings`,
`env_prefix="FORESHOCK_"`, `env_file=".env"`, `extra="ignore"`). `DATABASE_URL`
uses an explicit `validation_alias` and therefore has **no** `FORESHOCK_` prefix.
Defaults target the local compose network; no
secret is ever hardcoded.

### Infra / storage
| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://foreshock:foreshock@localhost:5432/foreshock` | Postgres DSN (psycopg3 driver). Compose overrides host to `postgres`. |
| `FORESHOCK_DATA_DIR` | `/data` | Root for raw HTML, caches, browser contexts. |
| `FORESHOCK_RAW_HTML_DIR` | `/data/raw` | Persisted raw mention HTML (`/data/raw/<source_id>/<hash>.html`). |
| `FORESHOCK_CVELIST_REPO_DIR` | `/data/cvelistV5` | Local shallow clone of cvelistV5. |

### Baseline (cvelistV5 / NVD / EPSS)
| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_CVELIST_REPO_URL` | `https://github.com/CVEProject/cvelistV5.git` | Repo cloned/pulled for canonical CVE records. |
| `FORESHOCK_CVELIST_SYNC_SECONDS` | `900` | cvelist job cadence (15 min). |
| `FORESHOCK_NVD_DELTA_SECONDS` | `7200` | NVD delta job cadence (2 h). |
| `FORESHOCK_NVD_API_BASE` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD 2.0 endpoint. |
| `FORESHOCK_NVD_API_KEY` | `None` | NVD API key. Without it, the module pauses 6 s between pages (public rate limit). |
| `FORESHOCK_EPSS_SYNC_SECONDS` | `86400` | EPSS job cadence (daily). |
| `FORESHOCK_ENRICH_SYNC_SECONDS` | `7200` | Incremental enrichment cadence (2 h). Only touches dirty rows, so it is cheap to run at mirror pace. |
| `FORESHOCK_EPSS_API_BASE` | `https://api.first.org/data/v1/epss` | FIRST.org EPSS endpoint. |

### GitHub commits source
`github_commits` now scans via a **blobless git clone + `git log`** (no REST commit
API, no rate limit) and consumes the `github_repos` registry (migration `0010`) via
`next_batch`/`update_scan` instead of JSON state files.

| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_GITHUB_API_BASE` | `https://api.github.com` | GitHub API base (used by `harvest_top_n`'s Search API). |
| `FORESHOCK_GITHUB_TOKEN` | `None` | PAT. Embedded in the clone URL for higher limits; raises the Search API rate limit. Strongly recommended. |
| `FORESHOCK_GITHUB_TOP_N` | `10000` | Number of most-starred repos harvested into the `github_repos` watchlist (origin `top_n`). |
| `FORESHOCK_GITHUB_COMMITS_MONTHS` | `5` | Relative look-back window (fallback when `..._SINCE` is unset). |
| `FORESHOCK_GITHUB_COMMITS_SINCE` | `2026-05-01` | **Fixed** commit cutoff (`YYYY-MM-DD`). When set, used instead of the relative window and does not roll with time. |
| `FORESHOCK_GITHUB_REPOS_PER_RUN` | `150` | Repos scanned per run (`next_batch`, unscanned-first rotation). |
| `FORESHOCK_GITHUB_COMMITS_MAX_PAGES` | `10` | GHSA-era commit-page cap; **no longer used** by the git-based `github_commits`. |
| `FORESHOCK_GITHUB_SYNTHESIZE_CANDIDATES` | `False` | **Default off.** When off, bare security-fix commits with no CVE are not synthesized as `GHCOMMIT` anchors (ingestion would drop them anyway — not a `RECOGNIZED_SCHEME`). |
| `FORESHOCK_GITHUB_ADVISORIES_MAX_PAGES` | `30` | GHSA advisories pagination cap (100/page → ~3000). |

### GitHub repo watchlist (registry) — opt-in strategies
Beyond `top_n` and the always-on `reference`/`past_cve` (repos cited in advisory
references), the `github_repos` registry supports two opt-in discovery strategies
(`foreshock sources harvest-repos`):

| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_CRITICALITY_CSV_URL` | `None` | OpenSSF Criticality Score CSV URL → repos (origin `criticality`). Opt-in. |
| `FORESHOCK_PYPI_DOWNLOADS_TOP_N` | `0` | `>0` ⇒ top-N PyPI packages by 30-day downloads → their repos (origin `downloads`). Opt-in. |

### VulnCheck KEV
| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_VULNCHECK_TOKEN` | `None` | Free token from vulncheck.com. **Without it the source is inactive (returns `[]`).** |
| `FORESHOCK_VULNCHECK_API_BASE` | `https://api.vulncheck.com/v3` | VulnCheck API base. |
| `FORESHOCK_VULNCHECK_MAX_PAGES` | `50` | Pagination cap (100 items/page). |

### OSV.dev
| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_OSV_ECOSYSTEMS` | `PyPI,Go,crates.io,RubyGems,Packagist` | Comma-separated OSV ecosystems whose `all.zip` dump is scanned. |
| `FORESHOCK_OSV_MONTHS` | `5` | Initial-bootstrap publication window. Later runs follow the persisted OSV `modified` watermark. |
| `FORESHOCK_OSV_MAX_PER_ECOSYSTEM` | `3000` | Bounded bootstrap cap per ecosystem. **`0` = no cap**; persistence still streams in batches. |

Each ecosystem has persistent archive and `modified` watermarks in `sync_state`.
An unchanged cached ZIP is skipped completely. A changed ZIP is scanned, but
only the watermark overlap is emitted, in batches of 500; cursors advance only
after every emitted batch has been persisted.

### Red Hat Security Data
| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_REDHAT_LOOKBACK_DAYS` | `3` | Bootstrap window before the first successful run. Later runs use a persistent cursor with one day of overlap. |

### Fetchers / polite scraping
| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_USER_AGENT` | `Foreshock/0.1 (+https://github.com/foreshock; early-CVE research)` | Identifiable UA on every request. |
| `FORESHOCK_HTTP_TIMEOUT_SECONDS` | `30.0` | httpx client timeout. |
| `FORESHOCK_MAX_RETRIES` | `3` | Retry budget knob (the retry decorator retries only transient errors: transport, 429, 5xx). |
| `FORESHOCK_RESPECT_ROBOTS` | `True` | Honour `robots.txt` for scrape fetchers (cached parser). |
| `FORESHOCK_BROWSER_MAX_CONCURRENT` | `3` | Playwright pool concurrency (optional `browser` extra). |
| `FORESHOCK_BROWSER_RECYCLE_AFTER` | `50` | Recycle a browser context after N uses. |
| `FORESHOCK_SOURCES_MAX_CONCURRENT` | `4` | Maximum complete source lifecycles (fetch + parse + ingest). |
| `FORESHOCK_SOURCES_GIT_MAX_CONCURRENT` | `1` | Maximum concurrent Git sources/process groups. |
| `FORESHOCK_SOURCES_HEAVY_MAX_CONCURRENT` | `1` | Maximum concurrent large-batch sources. |
| `FORESHOCK_SOURCES_STARTUP_SPREAD_SECONDS` | `3600` | Window used to stagger initial source executions. |

### LLM enrichment
| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_LLM_PROVIDER` | `mock` | One of `mock` / `openai` / `anthropic` / `ollama`. `mock` needs no network. |
| `FORESHOCK_LLM_MODEL` | `mock-model` | Model id for the provider. |
| `FORESHOCK_LLM_API_KEY` | `None` | Provider API key (secret). |
| `FORESHOCK_LLM_BASE_URL` | `None` | Custom base URL (e.g. Ollama `http://ollama:11434`). |
| `FORESHOCK_LLM_MAX_TOKENS` | `1024` | Max tokens per enrichment call. |
| `FORESHOCK_ENRICHMENT_REENRICH_HOURS` | `24` | Re-enrich if the last enrichment is older than this. |
| `FORESHOCK_ENRICHMENT_REENRICH_MIN_MENTIONS` | `3` | Re-enrich if this many new mentions arrived. |

### Promotion / logging
| Variable | Default | Purpose |
|---|---|---|
| `FORESHOCK_EMERGING_MIN_MENTIONS` | `1` | Baseline promotion/emerging threshold. |
| `FORESHOCK_LOG_LEVEL` | `INFO` | Log level. |
| `FORESHOCK_LOG_JSON` | `True` | Structured JSON logging (structlog). |

`docker-compose.yml` forwards a subset from the host with `${VAR:-default}`
interpolation (typically via a `.env` file): `FORESHOCK_NVD_API_KEY`,
`FORESHOCK_LLM_PROVIDER` / `FORESHOCK_LLM_API_KEY` / `FORESHOCK_LLM_MODEL`,
`FORESHOCK_GITHUB_TOKEN`, `FORESHOCK_GITHUB_TOP_N`, `FORESHOCK_GITHUB_REPOS_PER_RUN`
(compose default `500`), `FORESHOCK_VULNCHECK_TOKEN`,
`FORESHOCK_VULNCHECK_MAX_PAGES`, `FORESHOCK_OSV_ECOSYSTEMS`,
`FORESHOCK_OSV_MAX_PER_ECOSYSTEM`, `FORESHOCK_OSV_MONTHS` and
`FORESHOCK_REDHAT_LOOKBACK_DAYS`.

### Container resource limits

Compose applies finite memory and PID limits by default. They remain
operator-overridable:

| Service | Memory default | PID default |
|---|---:|---:|
| PostgreSQL | `FORESHOCK_POSTGRES_MEM_LIMIT=8g` | `FORESHOCK_POSTGRES_PIDS_LIMIT=256` |
| sources-worker | `FORESHOCK_SOURCES_MEM_LIMIT=4g` | `FORESHOCK_SOURCES_PIDS_LIMIT=128` |
| baseline-worker | `FORESHOCK_BASELINE_MEM_LIMIT=3g` | `FORESHOCK_BASELINE_PIDS_LIMIT=96` |
| API | `FORESHOCK_API_MEM_LIMIT=1g` | `FORESHOCK_API_PIDS_LIMIT=64` |
| migrations | `FORESHOCK_MIGRATE_MEM_LIMIT=1g` | `FORESHOCK_MIGRATE_PIDS_LIMIT=64` |

Do not raise a limit as a substitute for fixing an unbounded fetch. The admin
dashboard reports both the configured limit and current cgroup usage.

PostgreSQL also sets `shm_size` (`FORESHOCK_POSTGRES_SHM_SIZE`, default `1gb`).
Docker's 64 MiB default for `/dev/shm` is too small for parallel workers: a
`VACUUM (ANALYZE)` over a table with several indexes fails with `could not
resize shared memory segment ... No space left on device`, and parallel queries
degrade silently for the same reason.

### Operational API window

All dashboard-facing API reads default to the canonical operational window
starting at `2026-01-01`. Historical rows remain stored. Generic inspection
endpoints accept `include_historical=true` for explicit audit use; the response
header `X-Foreshock-Operational-Since` exposes the active boundary.

---

## Secrets (`.env`, git-ignored)

All tokens/keys live in a local `.env` at the repo root (read by both
`pydantic-settings` and `docker-compose`'s `${VAR}` interpolation). **`.env` is
git-ignored — never commit tokens.** The secret-bearing variables are:
`FORESHOCK_NVD_API_KEY`, `FORESHOCK_GITHUB_TOKEN`, `FORESHOCK_VULNCHECK_TOKEN`,
`FORESHOCK_LLM_API_KEY`. Example `.env`:

```dotenv
FORESHOCK_GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
FORESHOCK_NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
FORESHOCK_VULNCHECK_TOKEN=vulncheck_xxxxxxxx
FORESHOCK_LLM_PROVIDER=openai
FORESHOCK_LLM_API_KEY=sk-xxxxxxxx
FORESHOCK_LLM_MODEL=gpt-4o-mini
```

Missing optional secrets degrade gracefully: no `FORESHOCK_VULNCHECK_TOKEN` → the
VulnCheck source is inactive; no `FORESHOCK_GITHUB_TOKEN` → GitHub sources still
run but at the 60 req/h unauthenticated limit; `FORESHOCK_LLM_PROVIDER=mock` → no
LLM calls.

---

## Volumes

| Volume | Mount | Contents |
|---|---|---|
| `pgdata` | `postgres:/var/lib/postgresql/data` | Postgres data. |
| `data` | `baseline-worker` and `sources-worker` at `/data` | Raw HTML (`/data/raw/<source_id>/<hash>.html`); the cvelistV5 clone (`/data/cvelistV5`); the `github_commits` git-log cache (`/data/cache/gitlog/<owner__repo>.log.gz`) and ephemeral blobless clones (`/data/clones/`); OSV `all.zip` temp files (streamed to a `NamedTemporaryFile` and unlinked). The GitHub repo watchlist now lives in the `github_repos` **table**, not JSON files. |

The `data` volume is **shared** by both workers, so the GitHub top-N list,
per-repo watermarks, crawl cursor, and raw HTML are visible to both.

---

## Healthchecks & worker dependencies

- `postgres`: `pg_isready -U foreshock -d foreshock` (interval 3s, retries 20).
- `migrate` has no healthcheck — it is a run-once job; other services wait on its
  `service_completed_successfully`.
- `api`: `/healthz` executes `SELECT 1` against PostgreSQL.
- Worker liveness and runtime pressure are visible at `/pending_status`.

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
  -e DATABASE_URL=postgresql+psycopg://foreshock:foreshock@postgres:5432/foreshock \
  baseline-worker sh -c "uv pip install --system --no-cache pytest pytest-asyncio respx && pytest"
```

> The `browser` fetchers depend on the optional `.[browser]` extra (Playwright),
> not installed in the base image.

---

## Typical operations

**Re-ingest one source now** (e.g. after fixing a fetcher or to force a pull):

```bash
docker compose run --rm sources-worker foreshock sources run osv
docker compose run --rm sources-worker foreshock sources run github_commits
```

**Force a baseline sync** (canonical state, incl. a full cvelist reprocess):

```bash
docker compose run --rm baseline-worker foreshock baseline sync --nvd-hours 6
docker compose run --rm baseline-worker foreshock baseline sync --full-cvelist
```

**Enable / disable a source** (picked up hot within 60 s):

```bash
docker compose run --rm sources-worker foreshock sources disable thehackernews
docker compose run --rm sources-worker foreshock sources enable vulncheck_kev
```

**Raise the GitHub top-N** — set `FORESHOCK_GITHUB_TOP_N` higher and run
`foreshock sources harvest-repos`; `harvest_top_n` upserts the additional
most-starred repos into the `github_repos` registry (dedup by `full_name`), and
`next_batch` picks up the newly-added, never-scanned repos first.

**Backfill affected products** for candidates ingested before rich persistence:

```bash
docker compose run --rm baseline-worker foreshock backfill-products --batch 2000
```

---

## Scaling notes

- **GitHub top-N (10k → 100k repos).** The most-starred repos are harvested into
  the `github_repos` registry (windowed by descending star counts because the
  Search API caps at 1000 results/query) and unified with the other discovery
  strategies (dedup by `full_name`). Each run scans a rotating batch of
  `github_repos_per_run` repos via `next_batch` (unscanned-first ordering), with a
  per-repo commit-date **watermark** in the table so re-scans are incremental.
  Scanning is a **blobless git clone + `git log`**, so there is **no REST rate
  limit** — the earlier 5000 req/h ceiling no longer applies. To go from 10k to
  100k, raise `FORESHOCK_GITHUB_TOP_N`, run `foreshock sources harvest-repos`, and
  raise `FORESHOCK_GITHUB_REPOS_PER_RUN` and/or shorten the source cadence; a PAT
  (`FORESHOCK_GITHUB_TOKEN`) still helps clone throughput and the harvest Search API.
- **OSV without a cap.** Full ingest is a bootstrap operation, not the normal
  long-running profile. Even with `FORESHOCK_OSV_MAX_PER_ECOSYSTEM=0`, mentions
  are persisted in bounded batches; subsequent runs use archive/`modified`
  watermarks. Restore the normal cap/window after a deliberate backfill.
- **NVD.** With a key, NVD paginates 2000/page without the 6 s pause; widen
  `--nvd-hours` (or shorten `FORESHOCK_NVD_DELTA_SECONDS`) to reduce the chance of
  missing a busy delta window.
