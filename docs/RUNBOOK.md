# Foreshock — Operations Runbook

End-to-end guide to start, load, operate, and recover the whole system. Everything
runs in Docker. This is the single source of truth for **running** Foreshock; for
design see `ARCHITECTURE.md`, for the data model `DATA_MODEL.md`, for sources
`SOURCES.md`.

---

## 1. What the system is made of

`docker-compose.yml` defines six services (each service builds its **own** image
from `docker/Dockerfile` — see the pitfall in §9):

| Service | Role | Notes |
|---|---|---|
| `postgres` | Database (Postgres 16) | Persistent volume `pgdata` |
| `redis` | Worker state / scheduling backend | |
| `migrate` | Runs `alembic upgrade head` and exits | Others wait for it to finish |
| `baseline-worker` | Scheduler for the **baseline**: cvelistV5 + NVD + EPSS | The "finish line" data |
| `sources-worker` | Scheduler for the **12 radar sources** | The "race" — early signals |
| `api` | FastAPI + static dashboard on `:8000` | Read-only |

### Two data layers (never confuse them)

- **Baseline** (`published_cves`, `epss_scores`): official, published truth. Expensive
  to build (~367k CVEs + ~349k EPSS), **not corrupted by radar work**, and therefore
  **preserved** across radar re-ingests.
- **Radar** (`candidates`, `identifiers`, `mentions`, `cvss_scores`,
  `affected_products`, `affected_version_ranges`, `cve_soft_references`): the
  early-warning signal, correlated into `candidate`s. This is the layer that a
  re-ingest truncates and rebuilds.

---

## 2. Prerequisites

- Docker + `docker compose`.
- Optional tokens in a gitignored `.env` (never committed — verified with
  `git check-ignore .env`):

  ```
  FORESHOCK_GITHUB_TOKEN=ghp_xxx        # raises GitHub rate limit + clone limits
  FORESHOCK_VULNCHECK_TOKEN=vulncheck_xxx
  FORESHOCK_NVD_API_KEY=xxx             # speeds up the NVD full sync
  ```

Without tokens the system still runs; token-gated sources just fetch less.

---

## 3. Quick start

```bash
./scripts/start.sh            # migrate -> workers -> api (normal operation)
./scripts/start.sh --build    # rebuild ALL images first, then start
./scripts/start.sh --status   # show service + dashboard status
./scripts/start.sh --stop-workers   # pause ONLY the schedulers (safe for re-ingest)
```

Dashboard/API: <http://localhost:8000>.

`docker compose up -d` (what `start.sh` runs) starts `migrate` first; the workers
and `api` wait for migrations to complete, then the schedulers begin fetching on
each source's cadence. **No per-source action is needed** — enabling/scheduling is
automatic and new sources register themselves on worker start.

---

## 4. First-time full load

For a fresh database you want the complete baseline plus a full-history radar load:

```bash
./scripts/start.sh --full-load
```

This: starts the system, **pauses the schedulers** (so nothing races), runs the NVD
and EPSS full syncs, truncates the radar layer, and launches the historical
re-ingest in the background. When it finishes, re-enable the schedulers with a plain
`./scripts/start.sh`.

Manual equivalent (if you prefer step-by-step):

```bash
docker compose up -d
docker compose stop sources-worker baseline-worker
docker compose run --rm sources-worker foreshock baseline nvd-full
docker compose run --rm sources-worker foreshock baseline epss-full
# then the re-ingest procedure in §6
```

---

## 5. The scheduler model

`sources-worker` and `baseline-worker` run APScheduler. On start they call
`sync_registry_to_db()` (registers every source in code into the `sources` table)
and schedule each **enabled** source at its `cadence_seconds`. Enable/disable and
cadence changes are picked up **hot** (re-reconciled every 60 s):

```bash
docker compose run --rm sources-worker foreshock sources list
docker compose run --rm sources-worker foreshock sources disable <name>
docker compose run --rm sources-worker foreshock sources enable  <name>
```

While the workers are **stopped**, nothing scheduled runs — this is intentional
during a manual re-ingest.

---

## 6. Full radar re-ingest (safe procedure)

Rebuilds the radar layer from scratch with full history, reusing the artifact cache
(`/data/cache`: OSV zips, etc.). The baseline is untouched.

> ### ⚠️ The one rule: only ONE re-ingest at a time
> Running two re-ingests concurrently (e.g. a leftover background job + a new one)
> **interleaves writes and can fire a stray `TRUNCATE`**, corrupting the result and
> causing lock contention. Before starting:
> 1. **Stop the schedulers**: `./scripts/start.sh --stop-workers`.
> 2. **Verify nothing else is ingesting**:
>    ```bash
>    docker ps --filter name=sources-worker-run          # should be empty
>    docker compose exec -T postgres psql -U cveradar -d cveradar -c \
>      "SELECT pid,state,left(query,40) FROM pg_stat_activity WHERE datname='cveradar' AND state='active';"
>    ```
>    Kill any stray runner: `docker ps --filter name=sources-worker-run -q | xargs -r docker kill`.
>    If a previous background re-ingest task still exists, stop it (`TaskStop`, or kill
>    its host process) — a stopped orchestrator can leave one in-flight container that
>    finishes on its own, but must not keep spawning new ones.

Procedure:

```bash
# 1. Stop schedulers (see above) and confirm no runners.
# 2. Rebuild ALL images if code changed (see §9 — NOT just `migrate`):
docker compose build
# 3. Apply migrations (safe only when nothing else is writing):
docker compose run --rm migrate
# 4. Truncate ONLY the radar layer (baseline preserved):
docker compose exec -T postgres psql -U cveradar -d cveradar -c "
  TRUNCATE candidates, candidate_links, identifiers, mentions, cvss_scores,
           affected_products, affected_version_ranges, cve_soft_references
  RESTART IDENTITY CASCADE;"
# 5. Launch the single controlled re-ingest (background):
docker compose run --rm -d -v "$(pwd)/scripts:/app/scripts" \
  sources-worker bash /app/scripts/reingest_full.sh
# 6. Follow progress:
docker compose run --rm sources-worker tail -f /data/reingest.log
# 7. When DONE, verify (see §8) and re-enable schedulers:
./scripts/start.sh
```

`scripts/reingest_full.sh` runs, in order: `sources sync` → OSV full history per
ecosystem → the other signal sources → `github_commits` (blobless clone) →
`baseline enrich-nvd`.

---

## 7. The 22 sources

**API / git / KEV (the original 11):**

| Tier | Source | What it brings |
|---|---|---|
| 1 | `cisa_kev` | US-gov exploited-in-the-wild list |
| 1 | `vulncheck_kev` | Broader/earlier KEV (token) |
| 1 | `certcc_vu` | CERT/CC VU notes |
| 2 | `redhat_csaf` | Red Hat CVE data (CVSS/severity) |
| 3 | `metasploit` | Exploit modules |
| 3 | `nuclei_templates` | Detection/PoC templates |
| 3 | `nessus` | Plugin advisories |
| 4 | `osv` | The backbone: ~13 package ecosystems (carries the full GHSA catalog via aliases) |
| 4 | `github_advisories` | Freshest GHSA (≈3k, mostly dup of OSV) |
| 4 | `github_commits` | **Blobless clone + `git log`** of top-N + watchlist repos; commits citing a CVE |
| 5 | `thehackernews` | News |

**RSS/Atom fetchers (`feeds_rss.py`, 11 new):**

| Tier | Source | What it brings |
|---|---|---|
| 1 | `zdi_published` | ZDI published advisories (many CVEs) |
| 1 | `zdi_upcoming` | ZDI upcoming — **pre-CVE via ZDI-CAN** (no CVE yet) |
| 1 | `certeu` | CERT-EU advisories |
| 2 | `siemens_cert` | Siemens ProductCERT (ICS/OT) |
| 2 | `paloalto` | Palo Alto Networks PSIRT |
| 2 | `spring_security` | Spring advisories |
| 2 | `fortiguard_psirt` | Fortinet PSIRT |
| 2 | `veeam` | Veeam advisories |
| 3 | `fulldisclosure` | Full Disclosure mailing list |
| 3 | `oss_security` | oss-security mailing list |
| 5 | `zdi_blog` | ZDI blog roundups (high CVE volume) |

The RSS framework converts each entry to mentions safely: **1 CVE** → one mention bundling
its non-CVE aliases; **multiple CVEs** → one mention per CVE (no over-merge); **ZDI-CAN
only** → anchored pre-CVE; no recognized code → dropped.

### The commit source

`github_commits`: top-10k popular repos, commits since `FORESHOCK_GITHUB_COMMITS_SINCE`
(fixed `2026-05-01`). It uses `git clone --filter=blob:none --shallow-since=… --no-checkout`
+ `git log` (no REST rate limit; only commit metadata transferred). It anchors the commit
to the CVE it cites; **extra CVEs mentioned in the message are stored as soft
references** (§8), not as identity.

> A previous "expand-all" source using GH Archive was removed: GitHub no longer includes
> commit messages in the Events API `PushEvent` payload, so GH Archive cannot supply the
> commit text to scan. A global commit scan would need the GitHub Commit Search API.

**git-log cache (bug recovery without re-cloning).** Each scan writes the *relevant*
commits (those citing a CVE or security-fix language) of every repo to a gzipped cache at
`/data/cache/gitlog/<owner__repo>.log.gz` — tiny (text only, 99% of commits dropped) and
*lossless* for the parser. If the extraction logic is fixed later, re-run it over the
cache **without cloning anything**:

```bash
docker compose run --rm sources-worker foreshock sources reextract-commits
```

This mirrors OSV's cached-zip pattern: raw signal is archived so a parser fix never
requires re-downloading.

---

## 8. Data model notes that drive the product goal

### Identity & the anti-over-merge rule
A mention only forms/merges a `candidate` via **declared** identifiers (structured
fields: `cve_id`, `native_id`, OSV/GHSA aliases). CVEs merely **mentioned in prose**
never merge candidates — otherwise a "batch fixes 15 CVEs" commit would collapse 15
unrelated vulns into one (this really happened; it is fixed). Recognized identifier
schemes: `CVE, ZDI-CAN, ZDI, VU, GHSA, MSRC, OSV`. A mention that resolves to **no**
recognized code (e.g. a bare commit) is **dropped** — nothing is stored without a
CVE or equivalent code.

### Soft references (`cve_soft_references`)
CVEs cited in a note's prose but not its own code are recorded here — **not** anchored,
**not** merged, **not** in `identifiers`. Countable context ("this CVE is referenced
here") for CVEs that may not be published yet.

### "Published" = NVD with data
A candidate is `published` only when its CVE exists in `published_cves` **with
`nvd_published_at` set**. A CVE that is reserved / only in MITRE without an NVD date
is **pre-published** (the target signal). Query the pre-published universe:

```sql
WITH cve_ids AS (
  SELECT DISTINCT i.value AS cve FROM identifiers i JOIN candidates c ON c.id=i.candidate_id
  WHERE i.scheme='CVE' AND c.status<>'merged')
SELECT COUNT(*) FILTER (WHERE p.id IS NULL OR p.nvd_published_at IS NULL) AS pre_published,
       COUNT(*) FILTER (WHERE p.nvd_published_at IS NOT NULL)             AS published
FROM cve_ids ci LEFT JOIN published_cves p ON p.id=ci.cve;
```

### NVD enrichment
`foreshock baseline enrich-nvd` derives, from `published_cves.raw_json` (CVE JSON 5.0),
structured `cve_cvss` / `cve_cwe` / `cve_cpe` / `cve_reference` tables plus
denormalized `published_cves` columns (`primary_cvss_*`, `primary_cwe`,
`has_exploit_ref`, `ssvc_*`, …). Idempotent; re-runnable.

### Post-re-ingest verification

```bash
docker compose exec -T postgres psql -U cveradar -d cveradar -c "
  SELECT (SELECT COUNT(*) FROM candidates WHERE status<>'merged') AS live,
         (SELECT COUNT(*) FROM mentions)  AS mentions,
         (SELECT MAX(n) FROM (SELECT COUNT(*) n FROM identifiers
            WHERE scheme='CVE' GROUP BY candidate_id) t) AS max_cves_per_candidate;"
```
`max_cves_per_candidate` should be small (single digits). A value in the dozens means
an over-merge — investigate before trusting the data.

---

## 9. Pitfalls learned (read before operating)

- **Each compose service has its OWN image.** `docker compose build migrate` rebuilds
  only `migrate`; the workers keep stale code. After changing app code, run
  `docker compose build` (no service arg) so `sources-worker`/`baseline-worker`/`api`
  are rebuilt too. Symptom of a stale worker: `sources sync` registers the wrong count.
- **Never migrate prod while a heavy ingest runs.** A schema `ALTER` needs an exclusive
  lock and will queue behind a long ingest transaction, blocking every query on that
  table. Migrate when idle (schedulers stopped, no runners).
- **Never run two re-ingests at once** (§6).
- **Tests truncate the DB in `DATABASE_URL`.** The integration test fixture
  `TRUNCATE`s (including `published_cves`). Always run tests against an isolated DB:
  ```bash
  docker compose exec -T postgres psql -U cveradar -d cveradar -c "CREATE DATABASE foreshock_test;"
  docker compose run --rm -e DATABASE_URL=postgresql+psycopg://cveradar:cveradar@postgres:5432/foreshock_test \
    -v "$(pwd)/migrations:/app/migrations" migrate
  docker compose run --rm -e DATABASE_URL=postgresql+psycopg://cveradar:cveradar@postgres:5432/foreshock_test \
    -v "$(pwd)/tests:/app/tests" -v "$(pwd)/pyproject.toml:/app/pyproject.toml" \
    migrate bash -lc "uv pip install --system --no-cache pytest pytest-asyncio respx && pytest /app/tests -q"
  ```

---

## 10. Migrations

Hand-written, reversible, in `migrations/versions/` (`0001`…`0009`). Head is
applied by the `migrate` service. To apply without a full image rebuild, mount the
folder: `docker compose run --rm -v "$(pwd)/migrations:/app/migrations" migrate`.

| Rev | Adds |
|---|---|
| 0001–0005 | Core schema, affected products, soft CVE ref, KEV flags, rich fields |
| 0006 | NVD enrichment: `cve_cvss/cwe/cpe/reference` + denormalized `published_cves` columns |
| 0007 | `cve_soft_references` (prose-mentioned CVEs) |
| 0008 | `sources.method` allows `git` |
| 0009 | Widened `sources.tier` range to 1..9 |
```
