# CVERadar

**Early vulnerability radar**: detects, correlates and enriches CVEs
*before* MITRE/NVD publish them officially, measuring the "lead days"
over NVD per source.

This repository is the **data ingestion backend** (no UI): workers that
ingest signal from public sources into a Postgres database, an
ingestion/reconciliation pipeline, LLM + CVSS enrichment, and an operations CLI.

---

## Core idea

The tracking unit is the **`candidate`**, which **can exist before there is a
CVE**. A ZDI advisory (`ZDI-CAN-…`), a CERT/CC note (`VU#…`) or a security commit
in a popular repo (`GHCOMMIT:owner/repo@sha`) create a candidate that is later
**reconciled** with the CVE when it appears. On top of that we compute the flagship
KPI: **`days_ahead_vs_nvd_present`** — how much earlier we saw the signal versus the
first time *we* observed the CVE in NVD (robust against NVD date backfill).

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md).

## Architecture (docker-compose)

| Service | Role |
|---|---|
| `postgres` | Postgres 16 — canonical state and signal |
| `redis` | cache / rate-limit |
| `migrate` | applies Alembic migrations and exits (workers wait for it to finish) |
| `baseline-worker` | syncs cvelistV5 + NVD 2.0 + EPSS |
| `sources-worker` | runs the fetchers on their cadences and ingests the mentions |

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
    CLI["CLI cveradar"]
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
# Bring everything up: postgres + redis + migrations + workers
docker compose up --build

# Infrastructure only, for development
docker compose up -d postgres redis
docker compose run --rm migrate            # apply migrations
```

Operation with the CLI (`cveradar`, inside any project image):

```bash
cveradar sources sync                       # registers the fetchers in the DB
cveradar sources list                       # source status
cveradar sources run redhat_csaf            # run a fetcher once
cveradar baseline sync                      # force cvelist+NVD+EPSS sync
cveradar emerging list --since 24h --tier 1 --min-mentions 2
cveradar cve show CVE-2026-12345            # timeline + enrichment
cveradar enrich CVE-2026-12345              # LLM + CVSS
cveradar stats                              # lead days per source
cveradar pending --kind product             # vulns tied to software with NO official CVE yet
                                            # (kind: product | distro | malware | all)
cveradar trend --kind product               # pending vulns by month/year (growth / hockey-stick)
```

The **flagship question** this project answers — *"how many identified,
software-associated vulnerabilities have no official public CVE, and which
software has the most pending?"* — is `cveradar pending`:

```text
CVEs without official publication: 14630 (14614 with identifiable software)
  breakdown: 13597 without cve_id (pre-CVE) · 1033 with reserved/unpublished cve_id
 software                     cves_pending
 npm:openclaw                 216
 langchain-ai/langgraph       26
 ...
```

## Implemented sources (11)

| Source | Tier | Method | Signal |
|---|---|---|---|
| `cisa_kev` | 1 | api | CISA Known Exploited Vulnerabilities — flags candidates with `in_kev` |
| `vulncheck_kev` | 1 | api | VulnCheck KEV (broader/earlier exploited catalog; needs free token) |
| `certcc_vu` | 1 | rss | CERT/CC Vulnerability Notes (VU#) |
| `redhat_csaf` | 2 | api | Red Hat Security Data (authoritative CVSS) |
| `nessus` | 3 | scrape | Tenable plugins (reserved CVE cited by scanner; needs browser profile) |
| `nuclei_templates` | 3 | api | ProjectDiscovery nuclei-templates commits (exploit template = early signal) |
| `metasploit` | 3 | api | Rapid7 metasploit-framework commits (new exploit module) |
| `github_advisories` | 4 | api | GitHub Security Advisories (GHSA + packages, paginated) |
| `github_commits` | 4 | api | **Top-N repos + N-month changelog** (reserved CVE / pre-CVE security fix) |
| `osv` | 4 | api | OSV.dev ecosystem advisories (PyPI, Go, crates.io, RubyGems, Packagist…) |
| `thehackernews` | 5 | rss | Active-exploitation news |

`cisa_kev` / `vulncheck_kev` don't just create mentions: they set `in_kev` on the
candidate (exploited-in-the-wild signal, and ground truth for the prediction
layer). See [`docs/SOURCES.md`](docs/SOURCES.md).

`github_commits` watches the **top-N repos** (`CVERADAR_GITHUB_TOP_N`, default
10,000, scalable to 100,000+) and scans their commits from the last N months. It is
**cached and incremental**: the repo list is cached (weekly rebuild), processed
in batches with a rotating cursor, and each repo keeps a *watermark*
(last scanned commit date). It detects commits that cite a CVE (often
reserved) and security fixes without a CVE, which become pre-CVE candidates.
See [`docs/SOURCES.md`](docs/SOURCES.md).

## Enrichment (Layer 3)

The LLM (configurable: `mock`/`openai`/`anthropic`/`ollama`, mock by default without
an API key) extracts **structured metadata, not a CVSS number**. CVSS follows a
3-level precedence: **authoritative** (vector extracted from the source text) →
**derived** (computed from metrics with the `cvss` library) →
qualitative **`severity_hint`**. See [`docs/ENRICHMENT.md`](docs/ENRICHMENT.md).

## Tests

```bash
# 49 tests (unit + integration against a real Postgres)
docker compose up -d postgres && docker compose run --rm migrate
docker compose run --rm --no-deps \
  -e DATABASE_URL=postgresql+psycopg://cveradar:cveradar@postgres:5432/cveradar \
  -v "$PWD":/app -w /app sources-worker \
  bash -lc "uv pip install --system -q pytest pytest-asyncio respx && pytest -q"
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — overview and data flow
- [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) — schema and per-table decisions
- [`docs/INGESTION.md`](docs/INGESTION.md) — ingestion and reconciliation pipeline
- [`docs/SOURCES.md`](docs/SOURCES.md) — fetchers and how to add one
- [`docs/ENRICHMENT.md`](docs/ENRICHMENT.md) — LLM + CVSS + normalization
- [`docs/BASELINE.md`](docs/BASELINE.md) — cvelistV5 + NVD + EPSS
- [`docs/CLI.md`](docs/CLI.md) — command reference
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — deployment and operation
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — non-obvious decisions

## Stack

Python 3.12, SQLModel/SQLAlchemy 2, Alembic, Postgres 16, Redis, httpx, feedparser,
selectolax, APScheduler, Playwright (optional), Typer, structlog. Docker + docker-compose.
