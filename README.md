# Foreshock

**Early vulnerability radar**: detects, correlates and enriches vulnerabilities
*before* MITRE/NVD publish them officially, and measures the **lead days** each source
gains over NVD.

This repository is the **data-ingestion backend** (no UI): worker processes that pull
signal from public sources into a Postgres 16 database, an ingestion/reconciliation
pipeline, LLM + CVSS enrichment, and an operations/query CLI.

> **Framing.** MITRE (cvelistV5) and OSV are the finish line — the authoritative record of
> what a vulnerability *is*. Foreshock doesn't replace them; it watches the **race** that
> happens before they cross that line (reserved id, exploit template, security commit, KEV
> entry) and timestamps everyone's position. See
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#what-foreshock-answers-that-mitreosv-cannot).

---

## Core idea

The tracking unit is the **`candidate`**, which **can exist before there is a CVE**. A ZDI
reservation (`ZDI-CAN-…`), a CERT/CC note (`VU#…`), an OSV advisory (`PYSEC-…`, `MAL-…`) or
a security commit in a popular repo (`GHCOMMIT:owner/repo@sha`) all create a candidate that
is later **reconciled** with the CVE when it appears. On top of that we compute the flagship
KPI **`days_ahead_vs_nvd_present`** — how much earlier we saw the signal versus the first
time *we* observed the CVE in NVD (robust against NVD date backfill).

## Architecture (docker-compose)

| Service | Role |
|---|---|
| `postgres` | Postgres 16 — canonical state and signal |
| `redis` | cache / rate-limit |
| `migrate` | applies Alembic migrations and exits (workers wait for it) |
| `baseline-worker` | syncs cvelistV5 + NVD 2.0 delta + EPSS on schedule |
| `sources-worker` | runs the 11 fetchers on their cadences (hot reconcile) and ingests the mentions |

```mermaid
flowchart LR
    subgraph EXT["External sources"]
        direction TB
        CVELIST["cvelistV5"]
        NVD["NVD 2.0 delta"]
        EPSSAPI["EPSS"]
        SRC["11 fetchers<br/>Tier 1-5 + GitHub commits"]
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
        VIEW["views: radar · cvss_selected · epss_current"]
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
    PUB -. "cve_id reconciliation (no FK)" .-> DATA
    DATA --- VIEW
    CLI --> PG

    classDef ext fill:#eef,stroke:#88a;
    classDef store fill:#efe,stroke:#7a7;
    classDef proc fill:#fee,stroke:#c88;
    class EXT,CVELIST,NVD,EPSSAPI,SRC ext;
    class PG,PUB,DATA,VIEW store;
    class BW,SW,JOBS,FETCH,INGEST,ENRICH proc;
```

Detailed component diagram in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quickstart

```bash
./scripts/start.sh              # start the whole system (migrate -> workers -> api)
./scripts/start.sh --full-load  # first-time: baseline full sync + historical re-ingest
./scripts/start.sh --status     # service + dashboard status
```

Full operational guide (startup, first-time load, safe re-ingest, the 12 sources,
monitoring, migrations, and pitfalls): **[`docs/RUNBOOK.md`](docs/RUNBOOK.md)**.

Under the hood `start.sh` is just:

```bash
# Bring everything up: postgres + redis + migrations + both workers + api
docker compose up -d --build

# Infrastructure only, for development
docker compose up -d postgres redis
docker compose run --rm migrate            # apply Alembic migrations
```

Configuration is 12-factor via environment variables (prefix `FORESHOCK_`, plus
`DATABASE_URL` / `REDIS_URL`), read from the environment or a local `.env`. Defaults point
at the docker-compose stack. Common ones:

```bash
FORESHOCK_LLM_PROVIDER=mock            # mock | openai | anthropic | ollama
FORESHOCK_LLM_MODEL=mock-model
FORESHOCK_LLM_API_KEY=                 # for openai/anthropic
FORESHOCK_NVD_API_KEY=                 # raises NVD rate limit
FORESHOCK_GITHUB_TOKEN=                # PAT -> 5000 req/h
FORESHOCK_GITHUB_TOP_N=10000           # popular repos to watch (scales to 100k+)
FORESHOCK_GITHUB_REPOS_PER_RUN=150     # incremental crawl batch size
FORESHOCK_VULNCHECK_TOKEN=             # free token from vulncheck.com
FORESHOCK_OSV_ECOSYSTEMS=PyPI,Go,crates.io,RubyGems,Packagist
```

## CLI (`foreshock`)

The `foreshock` entry point (`app/cli.py`, Typer) is available inside any project image.
Query commands accept `--format table|json|csv` (`-f`).

### `db` — migrations
```bash
foreshock db init                           # alembic upgrade head
```

### `sources` — fetcher management
```bash
foreshock sources sync                      # register code fetchers into the sources table
foreshock sources list                      # status: tier, method, enabled, cadence, last run/error
foreshock sources enable  <name>            # enable a source (picked up live within ~60s)
foreshock sources disable <name>            # disable a source (removed from scheduler live)
foreshock sources run     <name>            # run one fetcher once and print {fetched,created,duplicate,errors}
```

### `baseline` — canonical state
```bash
foreshock baseline sync                     # force cvelistV5 + NVD + EPSS now
foreshock baseline sync --nvd-hours 6       # widen the NVD delta window (default 3)
foreshock baseline sync --full-cvelist      # reprocess the whole cvelistV5 clone
```

### `emerging` — emerging candidates
```bash
foreshock emerging list --since 24h --tier 1 --min-mentions 2
foreshock emerging list --source osv --limit 100 --format json
#   --since 24h|7d|2w   --source <name>   --tier <1..5>
#   --min-mentions <n>  --limit <n>       --format table|json|csv
```

### `cve` — timeline + enrichment
```bash
foreshock cve show CVE-2026-12345           # ids, CVSS rows, EPSS, and the full mention timeline
foreshock cve show <candidate-uuid>         # also accepts a candidate id (for pre-CVE candidates)
```

### `enrich` — LLM + CVSS
```bash
foreshock enrich CVE-2026-12345             # run Layer-3 enrichment on a candidate (by CVE or uuid)
```

### `stats` — lead days per source
```bash
foreshock stats                             # avg days_ahead_vs_nvd_present per source + promotion rate
foreshock stats --format json
```

### `pending` — the flagship question
```bash
foreshock pending --kind product --top 20   # software with the most vulns lacking an official CVE
#   --kind product|distro|malware|all   --top <n>   --format table|json|csv
```

### `trend` — pending vulns over time
```bash
foreshock trend --kind product --months 12 --granularity month
#   --kind product|distro|malware|all   --granularity month|year
#   --months <n>   --format table|json|csv
# Buckets candidates by first_seen_at (earliest radar signal) to reveal growth / hockey-stick.
```

### `backfill-products` — derive affected software for old candidates
```bash
foreshock backfill-products                 # fill affected_products where missing
foreshock backfill-products --batch 2000    # commit every N candidates (default 1000)
# Derives software from GHCOMMIT repo / 'affected:' snippet / owner/repo title prefix.
# Idempotent; OSV already populates this at ingest time, so this covers the rest.
```

**The flagship question** this project answers — *"how many identified,
software-associated vulnerabilities have no official public CVE, and which software has the
most pending?"* — is `foreshock pending`:

```text
              Top software (kind=product)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ software                   ┃ cves_pendientes ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ openclaw                   │ 216             │
│ langchain-ai/langgraph     │ 26              │
│ ...                        │ ...             │
└────────────────────────────┴─────────────────┘
total=14630  con_software=14614  product=13100  distro=920  malware=594  kind=product
```

The `meta` footer (`total`, `con_software`, `product`, `distro`, `malware`) counts
candidates that are merged-tombstone-free and either have no `cve_id` or whose `cve_id` is
not yet `PUBLISHED` in `published_cves`. Numbers above are illustrative.

## Implemented sources (11)

| Source | Tier | Method | Signal |
|---|---|---|---|
| `cisa_kev` | 1 | api | CISA Known Exploited Vulnerabilities — sets `in_kev` (exploited in the wild) |
| `vulncheck_kev` | 1 | api | VulnCheck KEV — broader/earlier exploited catalog (needs a free token) |
| `certcc_vu` | 1 | rss | CERT/CC Vulnerability Notes (`VU#…`) |
| `redhat_csaf` | 2 | api | Red Hat Security Data — authoritative CVSS vectors |
| `nessus` | 3 | scrape | Tenable Nessus plugin feed (reserved CVE cited by the scanner) |
| `nuclei_templates` | 3 | api | ProjectDiscovery `nuclei-templates` commit scan (detection/exploit template = early signal) |
| `metasploit` | 3 | api | Rapid7 `metasploit-framework` commit scan (new exploit module) |
| `github_advisories` | 4 | api | GitHub Security Advisories (GHSA + affected packages, paginated) |
| `github_commits` | 4 | api | **Top-N repos + N-month changelog** commit scan (reserved CVE / pre-CVE security fix) |
| `osv` | 4 | api | OSV.dev ecosystem advisories (`all.zip`; PyPI, Go, crates.io, RubyGems, Packagist…) |
| `thehackernews` | 5 | rss | Active-exploitation news |

`cisa_kev` / `vulncheck_kev` don't just create mentions — they flag the candidate with
`in_kev` / `kev_date` / `kev_source` (exploited-in-the-wild signal, and ground truth for a
future prediction layer). `nuclei_templates` / `metasploit` catch **exploit/detection
artifacts before the CVE is public**. `github_commits` watches the top-N repos
(`FORESHOCK_GITHUB_TOP_N`, default 10,000, scalable to 100,000+), scans their last
`FORESHOCK_GITHUB_COMMITS_MONTHS` months of commits incrementally (cached repo list, rotating
cursor, per-repo watermark), and can synthesize `GHCOMMIT` candidates for security fixes
that cite no CVE. See [`docs/SOURCES.md`](docs/SOURCES.md).

## Enrichment (Layer 3)

The LLM (configurable `mock`/`openai`/`anthropic`/`ollama`, mock by default without an API
key) extracts **structured metadata, not a CVSS number**. CVSS follows a strict 3-level
precedence:

1. **authoritative** — a CVSS vector found verbatim in the source text (or a structured
   feed like OSV), scored with the `cvss` library;
2. **derived** — computed from the 8 base metrics the LLM inferred, only when *all 8* are
   present;
3. qualitative **`severity_hint`** (`likely-critical/high/medium/low`) when no numeric score
   exists.

The `cvss_selected` view picks the best per candidate (authoritative > derived, then newer
version, then higher score). Product names are canonicalized against `product_catalog` via
deterministic aliases before hitting the LLM. See [`docs/ENRICHMENT.md`](docs/ENRICHMENT.md).

## Tests

```bash
# 55 tests (unit + integration against a real Postgres)
docker compose up -d postgres && docker compose run --rm migrate
docker compose run --rm --no-deps \
  -e DATABASE_URL=postgresql+psycopg://foreshock:foreshock@postgres:5432/foreshock \
  -v "$PWD":/app -w /app sources-worker \
  bash -lc "uv pip install --system -q pytest pytest-asyncio respx && pytest -q"
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — processes, data flow, and what Foreshock answers that MITRE/OSV cannot
- [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) — every table, column, constraint, index and view
- [`docs/INGESTION.md`](docs/INGESTION.md) — ingestion and reconciliation pipeline
- [`docs/SOURCES.md`](docs/SOURCES.md) — fetchers and how to add one
- [`docs/ENRICHMENT.md`](docs/ENRICHMENT.md) — LLM + CVSS + normalization
- [`docs/BASELINE.md`](docs/BASELINE.md) — cvelistV5 + NVD + EPSS
- [`docs/CLI.md`](docs/CLI.md) — command reference
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — deployment and operation
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — non-obvious decisions

## Stack

Python 3.12 · SQLModel / SQLAlchemy 2 · Alembic · Postgres 16 · Redis · httpx · feedparser ·
selectolax · tenacity · APScheduler · `cvss` · Playwright (optional, `browser` extra) ·
Typer + rich · structlog · pydantic / pydantic-settings. Packaged with `uv` / hatchling;
Docker + docker-compose.
