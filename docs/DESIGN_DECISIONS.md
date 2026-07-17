# Design decisions

A record of CVERadar's non-obvious decisions and their rationale. Each one points
to the code that implements it.

---

## 1. The `candidate` is decoupled from the CVE

**Decision**: the tracking unit is `candidates`, not the CVE. A candidate can
exist **before** its CVE exists, anchored by a native identifier (`ZDI-CAN`,
`VU#`, `GHCOMMIT`, …).

**Why**: the radar's premise is to capture the early signal. Many signals (ZDI
reservations, CERT/CC notes, commit fixes) precede the public CVE assignment. If
the primary key were the CVE, there would be nowhere to record that window. When
the CVE appears, reconciliation merges the candidates.

*Code*: `app/core/models.py::Candidate`, `app/ingest/reconcile.py`.

---

## 2. `content_hash` over the extract, not the raw HTML

**Decision**: mention idempotency (`UNIQUE(source_id, content_hash)`) is computed
by hashing `cve + native + title + snippet + canonical url` normalized, **not**
the page HTML.

**Why**: raw HTML changes on every fetch (timestamps, ads, CSRF tokens), which
would create a new mention every time. The semantic extract is stable across
identical re-listings and only changes when the real content changes, which does
deserve a new timeline entry.

*Code*: `app/ingest/hashing.py`.

---

## 3. CVSS is computed, not guessed

**Decision**: the LLM returns the CVSS **base metrics**; the score is computed
with the `cvss` library. Authoritative vectors are extracted by regex from the
source text. The LLM is never asked for a number.

**Why**: a CVSS score is deterministic given its vector. Asking the LLM for the
number introduces hallucination and makes the result irreproducible. Separating
"extract metrics" (judgment) from "compute score" (arithmetic) yields auditable
results: `provenance='authoritative'` (verbatim vector) or `'derived'` (LLM
metrics), and a qualitative `severity_hint` only when there is no number.

*Code*: `app/enrichment/cvss.py`, `app/enrichment/schema.py`,
`app/enrichment/service.py`.

---

## 4. `days_ahead` vs own observation (`present`)

**Decision**: three edge deltas are stored, but the reference metric is
`days_ahead_vs_nvd_present`, measured against `nvd_first_observed_at` (when
CVERadar first saw the CVE in NVD), not against `nvd_published_at`.

**Why**: NVD does *backfill* — it publishes CVEs with retroactive dates or
rewrites timestamps. A delta against `nvd_published_at` would be distorted.
`nvd_first_observed_at` is ground truth from our own clock, sealed a single time
with `COALESCE` and immune to backfill.

*Code*: `app/baseline/nvd.py::upsert_nvd`,
`app/ingest/service.py::compute_days_ahead`.

---

## 5. Canonicalization: the LLM as a *linker*, not a corrector

**Decision**: to canonicalize product names, the LLM **chooses among existing
candidates** from the catalog (or "none"); it never rewrites free text. Confirmed
resolutions are stored as `product_aliases` so they resolve deterministically
next time.

**Why**: an LLM correcting names hallucinates nonexistent products and produces
non-reproducible outputs, poison for the dedup and the `cluster_fingerprint`.
Constraining it to a bounded choice keeps the result deterministic and makes the
system **learn** (each hit becomes a cheap Layer 1 alias).

*Code*: `app/enrichment/normalize.py`, `app/enrichment/service.py::_resolve_alias`,
migration `0002` (`product_catalog`, `product_aliases`).

---

## 6. Soft FK on `candidates.cve_id`

**Decision**: `candidates.cve_id` has **no** FK to `published_cves`. The
migration `0003_soft_cve_ref.py` drops the `candidates_cve_id_fkey` constraint.

**Why**: a candidate may reference a CVE that is only RESERVED and not yet
ingested by the baseline (or that MITRE/NVD have not published yet). A hard FK
would reject the INSERT and block precisely the early signal that is the
project's reason to exist. Reconciliation is done via *lookup*
(`session.get(PublishedCVE, cve_id)`), not via referential integrity. The
`idx_cand_cve` index backs that lookup.

*Code*: `migrations/versions/0003_soft_cve_ref.py`.

---

## 7. Reversible merge (union-find with tombstone) vs proposed fuzzy link

**Decision**: two different correlation mechanisms.
- **Deterministic** (same `(scheme, value)`): a real union-find merge; the loser
  is kept as a *tombstone* (`merged_into`, `status='merged'`), **not deleted** →
  reversible.
- **Fuzzy** (similar names/fingerprints): `candidate_links` only **proposes** a
  link (`status='suggested'`), it merges nothing.

**Why**: deterministic evidence (a shared identifier) justifies a merge; fuzzy
similarity does not, because a false positive would blend two distinct vulns in a
way that is hard to undo. Keeping the merge reversible and separating the fuzzy
part as a suggestion protects data integrity.

*Code*: `app/ingest/reconcile.py::merge_candidates`, migration `0001`
(`candidate_links`).

---

## 8. Reversible, hand-written migrations

**Decision**: the Alembic migrations are the schema's **source of truth**,
written by hand, with a complete `downgrade()`. `env.py` uses
`target_metadata=None` (no autogenerate). The SQLModel models are just an ORM
mapping.

**Why**: writing the DDL by hand allows Postgres features that autogenerate does
not handle well (partial indexes, `NULLS NOT DISTINCT`, views, CHECKs with
expressions). Having the models not drive the schema prevents an accidental ORM
change from "creating" or altering tables. Each migration is reversible so a
clean rollback is possible.

*Code*: `migrations/versions/*.py`, `migrations/env.py`,
`app/core/models.py` (docstring).

---

## 9. Isolation of fetcher and source failures

**Decision**: a fetcher that raises an exception **does not take down the
worker**. `run_source` catches the `fetch` exception, logs it, records
`last_error`/`last_error_at` in `sources` and returns empty metrics. The baseline
isolates its three sources the same way; the github scan isolates per repo.

**Why**: with many heterogeneous sources (APIs that change, HTML that breaks,
rate limits), the failure of one must not interrupt collection of the rest. The
worker stays alive and the broken source is flagged for diagnosis.

*Code*: `app/sources/runner.py::run_source`,
`app/baseline/service.py::run_baseline_async`,
`app/sources/github_commits.py` (try/except per repo),
`app/sources/__main__.py` (double safety net).
