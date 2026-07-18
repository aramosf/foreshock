# Ingestion pipeline

The ingestion pipeline (`app/ingest/`) turns a **mention** captured by a fetcher
into rows in `mentions` / `candidates` / `identifiers` (plus structured
`cvss_scores` / `affected_products`), **idempotently**. It is the deterministic
correlation stage (Stage A): identifiers anchor mentions to candidates, and
candidates that share identifiers are merged with a reversible union-find.

Entry point: `ingest_mention(session, source_id, m)` in
`app/ingest/service.py`. It requires an open session and **does not commit** —
the runner wraps each mention in a `session.begin_nested()` savepoint (see
`SOURCES.md`).

---

## 1. `ingest_mention` step by step

```python
def ingest_mention(session, source_id, m: FetchedMention) -> IngestResult
```

1. **Normalize `seen_at`**: `m.seen_at or now(UTC)`; if naive, force
   `tzinfo=UTC`. Everything downstream is timezone-aware to avoid naive/aware
   mixing.
2. **Establish identity — declared ids only.** The candidate's identity comes
   **only** from what the source *declares*: `extract_identifiers(m.cve_id,
   m.native_id, *m.extra_ids)`. These anchor and merge (union-find). Bare CVEs
   merely cited in `title`/`snippet` are **not** used to merge — a commit that
   "fixes 21 CVEs" or a news post listing several must not collapse distinct
   vulnerabilities into one candidate. If the source declared **nothing**, it
   falls back to the **first** identifier found in the text (`text_ids[:1]`), not
   all of them. If still empty → dropped (`ingest.skip_no_identifier`), returns
   `IngestResult(created=False, duplicate=False)`.
3. **Drop if no recognized scheme.** If none of the identity ids is in
   `RECOGNIZED_SCHEMES` (`{CVE, ZDI-CAN, ZDI, VU, GHSA, MSRC, OSV}`), the mention
   is **dropped** (`ingest.skip_unrecognized`) — nothing is stored without a CVE
   or equivalent official code. A synthetic `GHCOMMIT` anchor is not enough and is
   discarded here.
4. **Pick CVE / native**: `cve = m.cve_id or primary_cve(ids)`;
   `native = m.native_id or primary_native(ids)`.
5. **Content hash** (§3): `chash = content_hash(cve, native, title, snippet, url)`.
6. **Dedup** by `(source_id, content_hash)`:
   - **Hit (duplicate path)**: fetch the candidate the existing mention points
     at and re-apply `_apply_candidate_updates` (§6) — a re-emission that now
     carries `in_kev`, products, CVSS, CWEs, etc. must still land on the
     candidate even though the mention row is unchanged. Returns
     `duplicate=True`.
   - **Miss (new path)**: continue.
7. **Resolve candidate** (§4–5): `candidate = resolve_candidate(session, ids)` —
   finds/creates and merges candidates, attaches missing identifiers, sets
   `cve_id` if a CVE appears.
8. **Apply candidate updates** (§6): flags + structured data.
9. **Persist raw HTML** (`_persist_raw`): if `m.raw_html` is set, write it to
   `{raw_html_dir}/{source_id}/{chash}.html` (skip if the file already exists);
   store the path on the mention.
10. **Insert the `mentions` row** (`extracted_cve`, `extracted_native`, `url`,
    `title`, `snippet`, `raw_html_path`, `seen_at`, `content_hash`), `flush`.
11. **Record soft references** (§6.1): CVEs cited in the note's prose that are
    **not** the anchored CVE → `cve_soft_references` (not anchored, not merged).
12. **Refresh aggregates** (§7) and **recompute days-ahead** (§8), `flush`.
13. Return `IngestResult(candidate_id, mention_id, created=True, duplicate=False)`.

---

## 2. `extract_identifiers` (`app/ingest/identifiers.py`)

Extracts native vulnerability identifiers from one or more texts, preserving a
**priority order** and deduplicating. The blob is the newline-join of all
non-empty inputs; each scheme's regex is run with `finditer`.

| Scheme | Regex (case-insensitive unless noted) |
|--------|----------------------------------------|
| `CVE` | `\bCVE-\d{4}-\d{4,}\b` |
| `ZDI-CAN` | `\bZDI-CAN-\d{3,6}\b` |
| `ZDI` | `\bZDI-\d{2}-\d{3,5}\b` |
| `VU` | `\bVU#\d{5,7}\b` |
| `GHSA` | `\bGHSA-<b4>-<b4>-<b4>\b` where `<b4>` = `[23456789cfghjmpqrvwx]{4}` (base32 body) |
| `MSRC` | `\bADV\d{6}\b` |
| `GHCOMMIT` | `\bGHCOMMIT:[\w.-]+/[\w.-]+@[0-9a-fA-F]{7,40}\b` (synthetic pre-CVE anchor, **not** case-folded) |
| `OSV` | `\b(?:PYSEC-\d{4}-\d+\|GO-\d{4}-\d+\|RUSTSEC-\d{4}-\d{4}\|GSD-\d{4}-\d+\|MAL-\d{4}-\d+\|OSV-\d{4}-\d+)\b` |

**Canonicalization** (`_canon`):

- `GHSA` → `GHSA-` prefix upper, body lowercased (e.g. `GHSA-jfh8-c2jp-5v3q`).
- `GHCOMMIT` → left as-is (owner/repo and SHA are case-sensitive).
- everything else → uppercased.

The **first scheme in the list is the preferred "native"** when there is no CVE.
Helpers:

- `primary_cve(ids)` → first `CVE`, else `None`.
- `primary_native(ids)` → first non-`CVE` identifier, else `None`.

**`RECOGNIZED_SCHEMES`** (`frozenset({CVE, ZDI-CAN, ZDI, VU, GHSA, MSRC, OSV})`) is
the product policy gate. A mention that resolves to **no** recognized scheme is
dropped at ingest (§1 step 3) — Foreshock stores nothing without a CVE or an
equivalent official code. `GHCOMMIT` is a **defined** scheme but is deliberately
**not** in `RECOGNIZED_SCHEMES`: a bare security-fix commit with no assigned code
is not anchored or stored. Together with `github_synthesize_candidates=False`
(default), `github_commits` therefore emits **only** commits that cite a real CVE.

---

## 3. `content_hash` (`app/ingest/hashing.py`)

Identity of a mention for idempotency. **The raw HTML is deliberately not
hashed** — timestamps, ads, CSRF tokens would change the hash and spawn a new
row every fetch. Instead the **semantic extract** is hashed:

```python
content_hash(cve, native, title, snippet, url) -> sha256 hex
```

The payload is the `\x1f`-joined tuple:

```
[ cve.upper(), native.upper(), normalize_text(title), normalize_text(snippet), canonical_url(url) ]
```

- `normalize_text(s)`: collapse whitespace runs to single spaces, strip,
  lowercase. Stable for hashing.
- `canonical_url(url)`:
  - lowercase scheme + netloc; strip fragment; path with a single trailing `/`
    removed (`/` kept if empty);
  - drop **tracking parameters**: by exact key
    `{fbclid, gclid, ref, source, mkt_tok}` and by prefix `utm_`, `mc_`;
  - keep remaining query params (blank values preserved) **sorted** for
    stability.

Consequence: an identical re-listing → same hash → no duplicate; a real content
change → new hash → new mention (a legitimate new point on the timeline).

---

## 4. `resolve_candidate` (`app/ingest/reconcile.py`)

Maps a mention's identifiers to the candidate they belong to.

1. For each identifier, look up its `Identifier` row and follow it to the live
   root via `find_root` (§5). Collect the distinct roots.
2. **No known root** → create a new `Candidate(status="candidate")`.
3. **One root** → use it.
4. **Several roots** → `_pick_winner` chooses one and merges the rest into it.
5. **Attach missing identifiers**: any `(scheme, value)` not yet on the
   candidate is inserted as an `Identifier`.
6. If a CVE is present and `candidate.cve_id is None`, set it.

`_pick_winner`: sort key `(0 if cve_id else 1, first_seen_at or +inf)` — the
candidate that already has a CVE wins; on a tie, the earliest-seen wins.

---

## 5. Union-find merge (`merge_candidates`, `find_root`)

`find_root(session, candidate_id)`: walk the `merged_into` chain to the live
winner. It keeps a `seen` set and stops if `merged_into` re-enters it, so a
cycle cannot loop forever.

`merge_candidates(session, winner, loser)` reassigns **all** of loser's children
to winner, tombstones the loser, and is reversible:

- **Globally-UNIQUE child tables** (`Identifier`, `Mention` — their UNIQUE has
  no `candidate_id`): bulk `UPDATE ... SET candidate_id = winner` — always safe.
- **Tables whose UNIQUE *includes* `candidate_id`** (`CVSSScore` on
  `(version, provenance, source)`; `AffectedProduct` on
  `(vendor, product, ecosystem)`): two candidates may hold **colliding** rows, so
  a blind reassign would raise `IntegrityError`. For each loser row, the code
  checks whether the winner already has a row with the same key columns:
  - **collision** → `session.delete(loser_row)` (winner's copy wins, duplicate
    discarded);
  - **no collision** → reassign `loser_row.candidate_id = winner.id`.
- **`candidate_links` are not reassigned**: their canonical UNIQUE (`a<b`) would
  collide, and they are reversible suggestions; they stay pointing at the
  tombstone for future cleanup.
- **Tombstone**: `UPDATE candidates SET merged_into = winner, status = 'merged'`
  for the loser. If the winner has no CVE but the loser does, the winner inherits
  it. The merge is reversible because the loser row survives with a
  `merged_into` pointer rather than being deleted.

---

## 6. `_apply_candidate_updates`

Applies a mention's flags and structured data to the candidate. **Called on both
the new-mention path and the duplicate path**, so re-emissions still update the
candidate.

- **Flags** (`_apply_flags`): only keys in the whitelist `{in_kev, kev_date,
  kev_source, has_public_poc}` with a non-`None` value are `setattr`-ed onto the
  candidate.
- **CVSS vectors** (`m.cvss_vectors`) → `persist_cvss_vectors(..., source="osv")`
  → **authoritative** `cvss_scores` (upsert on
  `uq_cvss_candidate_version_prov_source`).
- **Affected** (`m.affected`) → `persist_affected(...)`: upsert
  `affected_products` on `uq_affected_candidate_product`, and **replace** the
  row's `affected_version_ranges` (delete existing, insert new).
- **CWE / references / withdrawn**: `candidate.cwe_ids = m.cwe_ids`;
  `candidate.reference_urls = m.reference_urls[:50]`; `candidate.withdrawn =
  m.withdrawn` (only when not `None`).

All the upserts are idempotent, so applying them repeatedly (duplicate path) does
not duplicate anything.

### 6.1 Soft references (`_record_soft_references`)

After the `mentions` row is inserted (new path only), the pipeline scans the
note's prose (`extract_identifiers(title, snippet, url)`) for **CVEs that are not
the anchored CVE** and records each in `cve_soft_references`
(`{cve_id, mention_id, source_id, from_candidate_id, context}`). These are
**counted, not merged**: a GHSA body or commit message that cites other CVEs must
not pull those distinct vulnerabilities into this candidate. The cited CVE may not
even be published yet — that is the interesting case. Idempotent via
`ON CONFLICT DO NOTHING` on `uq_soft_ref_mention_cve`. See `DATA_MODEL.md`.

---

## 7. Aggregates (`_refresh_aggregates`)

Recomputes, over the candidate's mentions:

- `mention_count` = count of mentions;
- `source_count` = count of **distinct** `source_id`;
- `first_seen_at` = `min(seen_at)`, `last_seen_at` = `max(seen_at)`.

Promotion: a `candidate` with `mention_count >= 1` is bumped to `emerging`.

---

## 8. `compute_days_ahead`

Computes the radar's edge against NVD, only when the candidate has a reconciled
`cve_id`, a `first_seen_at`, and a matching `published_cves` row:

- `days_ahead_vs_nvd_published` = `_days(pub.nvd_published_at, first_seen_at)`
- `days_ahead_vs_nvd_present`   = `_days(pub.nvd_first_observed_at, first_seen_at)`
- `days_ahead_vs_nvd_analyzed`  = `_days(pub.nvd_first_analyzed_observed_at, first_seen_at)`

`_days(a, b)` returns `round((a - b).total_seconds() / 86400)` — **`round`, not
`timedelta.days`**, because `.days` floors and would return `-1` for small
negative deltas. Both operands are timezone-aware.

**Promotion means "NVD has data".** If `pub.nvd_published_at IS NOT NULL` and the
candidate is `candidate`/`emerging`, it is promoted to `published` and `promoted_at`
is stamped once. Note this is gated on the **NVD publication date**, not merely
cvelist `state='PUBLISHED'`: a CVE that is reserved or lacks an NVD date stays
pre-published, which is exactly the early window Foreshock measures.

---

## 9. Idempotency guarantees

- **Same mention re-fetched** → same `content_hash` → dedup hit, no new row; only
  candidate-level upserts (all idempotent) re-run.
- **CVSS / affected** upserts are keyed on UNIQUE constraints; re-applying them
  is a no-op update.
- **Merges** are reversible (tombstone, not delete) and cycle-safe
  (`find_root`'s `seen` guard).
- The runner's per-mention savepoint means a single failing mention increments
  `errors` and is skipped without rolling back the batch.
