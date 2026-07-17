# Design decisions

A record of CVERadar's non-obvious decisions and their rationale. Each one points
to the code that implements it.

---

## 1. The `candidate` is decoupled from the CVE

**Decision**: the tracking unit is `candidates`, not the CVE. A candidate can
exist **before** its CVE exists, anchored by a native identifier (`ZDI-CAN`,
`VU#`, `GHSA`, `GHCOMMIT`, an OSV id, …).

**Why**: the radar's premise is to capture the early signal. Many signals (ZDI
reservations, CERT/CC notes, commit fixes, ecosystem advisories) precede the
public CVE assignment. If the primary key were the CVE, there would be nowhere to
record that window. When the CVE later appears (in a mention or in the baseline),
reconciliation fills `candidates.cve_id` by lookup and, if it was tracked under a
different anchor, merges the candidates.

*Code*: `app/core/models.py::Candidate`, `app/ingest/reconcile.py`,
`app/ingest/service.py::compute_days_ahead`.

---

## 2. Deterministic linking: union-find with tombstone that survives UNIQUE collisions

**Decision**: Stage A of correlation is deterministic: a `(scheme, value)` pair
belongs to exactly one candidate (`UNIQUE(scheme, value)` on `identifiers`). When
a mention brings identifiers that already point to **different** candidates,
`resolve_candidate` merges them into one winner (`_pick_winner`: the one with a
CVE wins; ties broken by oldest `first_seen_at`). The loser is kept as a
**tombstone** (`merged_into = winner.id`, `status='merged'`) — never deleted — so
the merge is reversible, and `find_root` follows the chain to the live root.

**The subtle part — UNIQUE collisions on merge.** `identifiers` and `mentions`
have **global** UNIQUE constraints that do not include `candidate_id`, so their
rows can be reassigned to the winner with a blind `UPDATE`. But `cvss_scores`
(`UNIQUE(candidate_id, version, provenance, source)`) and `affected_products`
(`UNIQUE(candidate_id, vendor, product, ecosystem)`) include `candidate_id` in
their UNIQUE key. Two candidates being merged can therefore hold **colliding**
rows; a blind reassignment would raise `IntegrityError` and abort the entire
ingest. `merge_candidates` handles this per row: for each loser row, if an
equivalent row already exists on the winner it **deletes the loser duplicate**,
otherwise it reassigns it. This bug (aborting ingestion whenever two enriched
candidates merged) was found and fixed in the code review — see `CODE_REVIEW.md`.

`candidate_links` (fuzzy suggestions) are **not** reassigned: their canonical
`a < b` UNIQUE would collide and they are reversible suggestions anyway; they
stay pointing at the tombstone for a future cleanup pass.

*Code*: `app/ingest/reconcile.py::merge_candidates`, `find_root`, `_pick_winner`,
migration `0001` (`identifiers`, `mentions`, `cvss_scores`, `affected_products`
UNIQUE constraints).

---

## 3. `content_hash` over the extract, not the raw HTML

**Decision**: mention idempotency (`UNIQUE(source_id, content_hash)`) hashes
`cve + native + normalized(title) + normalized(snippet) + canonical(url)` — not
the page HTML.

**Why**: raw HTML changes on every fetch (timestamps, ads, CSRF tokens), which
would create a new mention every time. The semantic extract is stable across
identical re-listings and only changes when the real content changes, which does
deserve a new timeline entry. `canonical_url` strips fragments and tracking
params (`utm_*`, `mc_*` by prefix; `fbclid`, `gclid`, `ref`, `source`, `mkt_tok`
by exact match) and sorts the query so cosmetic URL variants collapse.

*Code*: `app/ingest/hashing.py`, migration `0001` (`uq_mentions_source_hash`).

---

## 4. Soft FK on `candidates.cve_id`

**Decision**: `candidates.cve_id` has **no** FK to `published_cves`. Migration
`0003_soft_cve_ref.py` drops `candidates_cve_id_fkey`.

**Why**: a candidate may reference a CVE that is only RESERVED and not yet
ingested by the baseline (or that MITRE/NVD have not published yet). A hard FK
would reject the INSERT and block exactly the early signal the project exists to
capture. Reconciliation is done by *lookup* (`session.get(PublishedCVE,
cve_id)`), not referential integrity; `idx_cand_cve` backs that lookup.

*Code*: `migrations/versions/0003_soft_cve_ref.py`,
`app/ingest/service.py::compute_days_ahead`.

---

## 5. CVSS is computed, not guessed — three provenance levels

**Decision**: a CVSS number is never asked from an LLM. Scores come from three
paths, in decreasing authority:

1. **Authoritative** — a `CVSS:3.0/3.1/4.0/...` vector is extracted **verbatim**
   from source text (or structured OSV/GHSA severity) and scored with the `cvss`
   library. `provenance='authoritative'`.
2. **Derived** — only if the LLM supplies **all 8** base metrics, a `CVSS:3.1`
   vector is assembled and scored. If any metric is missing, no vector is built.
   `provenance='derived'`.
3. **`severity_hint`** — a qualitative label (`likely-critical/high/medium/low`)
   from cheap proxies (vuln type weight + attack vector + PoC), set **only** when
   no numeric score of any provenance exists.

**Why**: a CVSS score is deterministic given its vector; asking an LLM for the
number introduces hallucination and irreproducibility. Separating "extract
metrics" (judgment) from "compute score" (arithmetic) yields auditable results.

*Code*: `app/enrichment/cvss.py` (`parse_authoritative`, `derive_from_metrics`,
`severity_hint`), `app/ingest/affected.py::persist_cvss_vectors`,
`app/enrichment/service.py::enrich_candidate`.

---

## 6. `days_ahead` vs own NVD observation (`present`), not NVD's self-reported date

**Decision**: three deltas are stored, but the reference metric is
`days_ahead_vs_nvd_present`, measured against `nvd_first_observed_at` (when
CVERadar first saw the CVE in the NVD delta), not against `nvd_published_at`.

**Why**: NVD *backfills* — it publishes CVEs with retroactive `published` dates or
rewrites timestamps, which can distort or even make negative a delta against
`nvd_published_at`. `nvd_first_observed_at` is ground truth from **our own
clock**: sealed once with `COALESCE(existing, observed_at)` the first time we see
the CVE and never overwritten, so it is immune to backfill.
`nvd_first_analyzed_observed_at` is the analogous seal for the first time we see
the CVE in `Analyzed` state.

*Code*: `app/baseline/nvd.py::upsert_nvd`,
`app/ingest/service.py::compute_days_ahead`, migration `0001`
(`nvd_first_observed_at`, `nvd_first_analyzed_observed_at`).

---

## 7. OSV filtered by `published`, not `modified`

**Decision**: the OSV source keeps advisories whose `published` date falls within
`osv_months`, with `modified` only as a fallback when `published` is absent.

**Why**: `modified` changes every time an advisory is touched (a reference added,
a range corrected), so filtering by `modified` re-surfaces old advisories as if
new and pollutes both the ingest window and the `first_seen_at`/`trend` signal.
`published` is the real appearance date, which is what "early radar" and the
pending-trend series care about. This was corrected in commit `e46bff9` ("use
`published` not `modified` for date/window").

*Code*: `app/sources/osv.py::_to_mention` (`date_str = rec.get("published") or
rec.get("modified")`).

---

## 8. Rich persistence of OSV (and GHSA) structured data

**Decision**: OSV advisories are mined for everything useful, not just the CVE
id: all `aliases` → `identifiers`; `severity` CVSS vectors (top-level and
per-`affected`) → **authoritative** `cvss_scores`; `affected[].package` + `purl`
+ version `ranges` → `affected_products` + `affected_version_ranges`;
`database_specific.cwe_ids` → `candidates.cwe_ids`; `references` →
`candidates.reference_urls`; `withdrawn` → `candidates.withdrawn`.

**Why**: OSV is a high-quality structured feed; discarding its severity, affected
ranges, CWEs and references would force re-deriving them (worse) from free text
later. These extras are applied idempotently through the same upserts on both the
new-mention and the duplicate-mention path (see decision 11).

*Code*: `app/sources/osv.py`, `app/ingest/affected.py` (`persist_affected`,
`persist_cvss_vectors`), migration `0005_rich_fields.py` (`affected_products.kind`,
`candidates.cwe_ids/reference_urls/withdrawn`).

---

## 9. Canonicalization: the LLM as a *linker*, not a corrector

**Decision**: to canonicalize product names the LLM **chooses among existing
catalog candidates** (or "none"); it never rewrites free text. Confirmed
resolutions are stored as `product_aliases` so the next occurrence resolves
deterministically (Stage 1) without another LLM call.

**Why**: an LLM correcting names invents nonexistent products and produces
non-reproducible output — poison for dedup and `cluster_fingerprint`. Bounding it
to a choice keeps results deterministic and makes the system **learn** (each hit
becomes a cheap alias). `_resolve_alias` looks up `product_aliases` by
`normalize_key(...)`; a hit sets `catalog_id` with `normalization_method='alias'`,
a miss leaves it `'unresolved'`.

*Code*: `app/enrichment/service.py::_resolve_alias`, `_upsert_affected`,
`app/enrichment/normalize.py`, migration `0002` (`product_catalog`,
`product_aliases`).

---

## 10. Ecosystem canonicalization and product/distro/malware classification

**Decision**: a single source of truth (`app/ingest/affected.py`) canonicalizes
ecosystem aliases (`pip`→`pypi`, `cargo`/`rust`/`crates`→`crates.io`,
`gem`→`rubygems`, `composer`→`packagist`, …) and classifies each affected
software into `kind ∈ {product, distro, malware}` (`classify_kind`): `malware`
if the OSV id is `MAL-*`, `distro` if the ecosystem starts with a known
distro/OS token, else `product`.

**Why**: OSV mixes real package advisories, per-distro security notes and malware
records under one feed. Without a `kind`, the `pending` ranking would blend a
Python library with "ubuntu" and a malware package. Canonical ecosystems also
prevent `pip` and `PyPI` from splitting one product into two rows.

*Code*: `app/ingest/affected.py` (`ECO_ALIAS`, `DISTRO`, `canonical_ecosystem`,
`classify_kind`), migration `0005` (`affected_products.kind`), `app/cli.py`
(`pending`, `trend`).

---

## 11. Candidate-level extras apply on the duplicate-mention path too

**Decision**: when a mention is a content-hash duplicate, the mention row is not
re-inserted, but `_apply_candidate_updates` still runs — flags (`in_kev`, …),
authoritative CVSS, affected products, CWEs, references, `withdrawn` are applied
to the **candidate**.

**Why**: flags and structured data belong to the candidate, not the mention. A
re-emission of an already-seen advisory that now adds `in_kev=True` or a fixed
version must still update the candidate; dropping it on the duplicate path (the
original bug, fixed in the code review) meant KEV membership or new product data
could be silently lost.

*Code*: `app/ingest/service.py::ingest_mention` (duplicate branch),
`_apply_candidate_updates`, `_apply_flags` (`_FLAG_WHITELIST = {in_kev, kev_date,
kev_source, has_public_poc}`).

---

## 12. KEV as a candidate flag and as prediction ground truth

**Decision**: CISA KEV and VulnCheck KEV do not only produce mentions — they set
`candidates.in_kev = True` (+ `kev_date`, `kev_source`) via the flag whitelist.

**Why**: "known exploited in the wild" is the highest-priority signal and the
**ground truth label** for the (future) prediction of *P(enters KEV in N days)*.
Modelling it as a boolean flag on the candidate (indexed partial index
`idx_cand_in_kev WHERE in_kev`) makes both prioritization queries and future
label extraction trivial, while the KEV feeds' rich fields still flow through the
normal mention timeline.

*Code*: `app/sources/cisa_kev.py`, `app/sources/vulncheck_kev.py`, migration
`0004_kev_flags.py`, `app/ingest/service.py::_apply_flags`.

---

## 13. Failure isolation at three granularities

**Decision**: failures are contained so that one bad unit never loses the rest.

- **Per source**: a fetcher that raises does not take down the worker.
  `run_source` catches the `fetch` exception, logs it, records
  `last_error`/`last_error_at`, and returns empty metrics.
  `app/sources/__main__.py` adds a second safety net around each scheduled run.
- **Per mention**: ingestion of each mention runs inside `session.begin_nested()`
  (a savepoint), so one malformed mention rolls back only itself and increments
  `errors`, keeping the valid ones in the batch.
- **Per NVD row**: `sync_nvd_delta` wraps each `upsert_nvd` in a savepoint, so a
  single corrupt record does not abort the page **and every following page**.
- **Per baseline source / per repo / per ecosystem**: `run_baseline_async`
  isolates cvelist/NVD/EPSS from each other; the GitHub scan isolates per repo;
  OSV isolates per ecosystem.

**Why**: with many heterogeneous, flaky sources, robustness comes from
compartmentalizing failure. The per-mention and per-NVD-row savepoints were added
in the code review after finding that a single bad row aborted whole batches.

*Code*: `app/sources/runner.py::run_source`, `app/sources/__main__.py`,
`app/baseline/nvd.py::sync_nvd_delta`, `app/baseline/service.py`,
`app/sources/github_commits.py`, `app/sources/osv.py`.

---

## 14. Mentions kept per source on purpose (corroboration) while candidates dedupe

**Decision**: idempotency is scoped **per source** (`UNIQUE(source_id,
content_hash)`), so the same CVE reported by CISA, Red Hat and The Hacker News
produces three distinct mentions — but all three attach to **one** candidate
(deduped by shared identifier).

**Why**: multiple independent sources reporting the same vuln is *corroboration*
signal (it drives `source_count` and the lead stats), not noise. Collapsing
cross-source mentions would erase that signal. Deduplication belongs at the
candidate layer (identity), while the mention layer preserves the multi-source
timeline. `stats` explicitly de-duplicates per `(source, candidate)` so a chatty
source does not skew the average lead.

*Code*: `app/ingest/service.py` (`_refresh_aggregates`, `content_hash` per
source), `app/cli.py::stats`, migration `0001` (`uq_mentions_source_hash`).

---

## 15. Reversible, hand-written migrations

**Decision**: the Alembic migrations are the schema's **source of truth**,
written by hand with a complete `downgrade()`. `env.py` uses
`target_metadata=None` (no autogenerate); the SQLModel models are only an ORM
mapping.

**Why**: hand-written DDL enables Postgres features autogenerate handles poorly
(partial indexes, `NULLS NOT DISTINCT` on `product_catalog`/`affected_products`,
views `radar`/`cvss_selected`/`epss_current`, CHECK constraints with
expressions). Not having the models drive the schema prevents an accidental ORM
change from silently altering tables, and every migration is reversible for a
clean rollback.

*Code*: `migrations/versions/*.py`, `migrations/env.py`, `app/core/models.py`.
