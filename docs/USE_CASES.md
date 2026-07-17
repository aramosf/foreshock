# Use cases — questions CVERadar answers that MITRE / NVD / OSV cannot

**Framing.** MITRE, NVD, OSV and the KEV catalogs are the **finish line**: they
record a vulnerability once it has an assigned, published, scored identifier.
CVERadar watches the **race** — the interval between the first public signal that
a vulnerability exists (a commit, a ZDI reservation, a CERT/CC note, an ecosystem
advisory, an exploit module) and the moment the official catalog catches up. The
catalogs cannot answer "what is emerging right now and how far ahead of NVD are
we?" because, by construction, they only contain what already crossed the line.

Each section below states a concrete question, the command/query that answers it
today, and why the catalogs structurally cannot. Sections marked **FUTURE WORK**
describe questions the data model already supports but for which the analytics
are not yet implemented — they are called out explicitly, never presented as
shipped features.

---

## 1. What vulnerabilities have no official CVE *right now*?

**Answer today** — `cveradar pending`.

A candidate is **pending** when it is live (`merged_into IS NULL`) and either has
no `cve_id`, or its `cve_id` is **not `PUBLISHED`** in our baseline:

```sql
-- app/cli.py :: _PENDING_AP_SQL
SELECT c.id, c.first_seen_at, a.product, a.kind
FROM candidates c
LEFT JOIN affected_products a ON a.candidate_id = c.id
WHERE c.merged_into IS NULL
  AND ( c.cve_id IS NULL
     OR NOT EXISTS (SELECT 1 FROM published_cves p
                    WHERE p.id = c.cve_id AND p.state = 'PUBLISHED') );
```

```bash
cveradar pending --kind all --format json
cveradar emerging list --since 24h --min-mentions 2     # live view, newest first
```

**Why the catalogs can't**: NVD/MITRE only list *assigned and published* CVEs; an
advisory that is only RESERVED, or a fix commit with no CVE at all, does not exist
for them. CVERadar tracks it under a native or synthetic anchor (`ZDI-CAN`, `VU#`,
`GHSA`, `GHCOMMIT:owner/repo@sha`, OSV id) from `first_seen_at`.

---

## 2. How many days of lead does each source give us over NVD?

**Answer today** — `cveradar stats`.

```bash
cveradar stats --format json
```

Reports, per source, the average `days_ahead_vs_nvd_present` — the gap between our
first signal (`candidate.first_seen_at`) and the moment we first observed the CVE
in NVD (`nvd_first_observed_at`, our own backfill-immune clock), de-duplicated per
`(source, candidate)` and excluding merged candidates. Plus the promotion rate
(share of candidates that reached `status='published'`).

**Why the catalogs can't**: NVD knows its own `published`/`lastModified` dates but
has no notion of "when did an external radar first see this", and its
self-reported dates are subject to backfill. The lead metric only exists because
CVERadar stamps its own observation time.

---

## 3. Which software accumulates the most vulnerabilities with no official CVE?

**Answer today** — `cveradar pending --kind product`.

```bash
cveradar pending --kind product --top 30
cveradar pending --kind distro     # per-distro security notes
cveradar pending --kind malware    # OSV MAL-* records
```

Ranks product names by the number of pending candidates naming them, split by
`affected_products.kind` so a real library, a distro advisory, and a malware
package are never conflated. `cveradar trend --kind product --months 12` shows the
same set as a monthly time series bucketed by `first_seen_at` (hockey-stick
detection).

**Why the catalogs can't**: they can rank *published* CVEs per product, but not
the *pre-publication backlog* — the software with many advisories still working
through reservation/assignment. That backlog is CVERadar-only.

---

## Threat anticipation (the core value)

The catalogs answer "what happened". CVERadar is built to answer "what is *about
to* happen". The following are the anticipation use cases.

### 4. Exploit before CVE — code exists to attack something not yet cataloged

**Answer today** — cross the exploit-tooling sources against reserved/unpublished
CVEs.

The Tier-3 sources `nuclei_templates` (ProjectDiscovery) and `metasploit`
(Rapid7) scan their repos for commits that cite a CVE; a new nuclei template or
Metasploit module is a strong signal of imminent or active mass exploitation. A
PoC/exploit whose CVE is still only reserved — and **not yet in KEV** — is the
highest-value early warning.

```sql
-- Candidates seen by an exploit-tooling source whose CVE is NOT PUBLISHED
-- and NOT yet flagged as known-exploited.
SELECT c.id, c.cve_id, c.first_seen_at, c.mention_count, c.source_count
FROM candidates c
JOIN mentions m  ON m.candidate_id = c.id
JOIN sources  s  ON s.id = m.source_id
WHERE c.merged_into IS NULL
  AND s.name IN ('nuclei_templates', 'metasploit')
  AND COALESCE(c.in_kev, false) = false
  AND ( c.cve_id IS NULL
     OR NOT EXISTS (SELECT 1 FROM published_cves p
                    WHERE p.id = c.cve_id AND p.state = 'PUBLISHED') )
ORDER BY c.first_seen_at DESC;
```

`candidates.has_public_poc` (set via the flag whitelist / enrichment) is an
additional PoC signal to filter on.

**Why the catalogs can't**: NVD does not track exploit-tool availability, and KEV
only lists what CISA/VulnCheck have *already confirmed* as exploited — by then it
is no longer anticipation. The join of exploit-tooling commits × not-yet-published
CVE × not-in-KEV is exactly the pre-KEV exploit window.

### 5. Pre-KEV prediction — *P(enters KEV within 30 days)*

**FUTURE WORK (Layer 4, not implemented).** The schema is deliberately ready for
it but no model is trained or served yet.

- **Label / ground truth**: `candidates.in_kev`, `kev_date`, `kev_source` are set
  by the CISA/VulnCheck KEV sources (migration `0004_kev_flags.py`,
  `idx_cand_in_kev`). This is the supervised target — "did this candidate enter
  KEV, and when".
- **Features already available** per candidate: `days_ahead_vs_nvd_present`,
  `mention_count`, `source_count`, best `cvss_scores.base_score` /
  `base_severity`, latest `epss_scores.score` / `percentile` (FIRST.org's own
  30-day exploitation probability), `has_public_poc`, presence of
  `nuclei_templates` / `metasploit` mentions, `vuln_type`, `attack_vector`, and
  the affected-product `kind`.
- **Not yet built**: feature extraction job, model training/serving, and a
  `p_kev_30d` column or endpoint. There is no code path that computes this today.

**Why the catalogs can't**: KEV is a *lagging* record of confirmed exploitation.
EPSS predicts exploitation activity but is CVE-scoped and independent of the
radar's multi-source corroboration and lead signals. A radar-native pre-KEV model
would combine both, which neither catalog offers.

### 6. Velocity and acceleration of mention emergence

**Partly today (SQL), fuller version FUTURE WORK.**

The mention timeline (`mentions.seen_at` per candidate) already lets you measure
how fast corroboration is arriving — a burst across sources in hours is a
different threat posture than a lone commit.

```sql
-- Mentions in the last 24h vs the previous 24h, per candidate (velocity proxy).
SELECT c.id, c.cve_id,
       count(*) FILTER (WHERE m.seen_at >= now() - interval '24 hours')  AS last_24h,
       count(*) FILTER (WHERE m.seen_at <  now() - interval '24 hours'
                         AND m.seen_at >= now() - interval '48 hours')   AS prev_24h,
       min(m.seen_at) AS first_seen, max(m.seen_at) AS last_seen
FROM candidates c
JOIN mentions m ON m.candidate_id = c.id
WHERE c.merged_into IS NULL
GROUP BY c.id, c.cve_id
HAVING count(*) FILTER (WHERE m.seen_at >= now() - interval '24 hours') > 0
ORDER BY last_24h DESC;
```

**FUTURE WORK**: a first-class emergence-velocity / acceleration metric persisted
on the candidate (rate of mentions and its second derivative) and surfaced in the
CLI. Not implemented — the query above is the manual stand-in.

**Why the catalogs can't**: they carry no cross-source arrival timeline; there is
no "how fast is this being talked about" dimension in NVD/OSV.

### 7. Multi-signal crosses — pre-CVE × in_kev × cvss × exploit × affects-my-stack

**Answer today (SQL) for the available signals; watchlist part is FUTURE WORK.**

The point of the unified `candidates` model is that these signals live together
and can be intersected in one query. Example — high-severity, exploit-tooled,
known-exploited candidates that touch a product you care about, ranked by lead:

```sql
SELECT c.cve_id, c.first_seen_at, c.days_ahead_vs_nvd_present,
       cs.base_score, c.in_kev, ap.product
FROM candidates c
JOIN affected_products ap ON ap.candidate_id = c.id
LEFT JOIN cvss_selected  cs ON cs.candidate_id = c.id     -- view: best score/candidate
JOIN mentions m ON m.candidate_id = c.id
JOIN sources  s ON s.id = m.source_id
WHERE c.merged_into IS NULL
  AND ap.product IN ('openssl', 'nginx', 'tensorflow')     -- my stack
  AND (cs.base_score >= 8.0 OR c.in_kev)
  AND s.name IN ('nuclei_templates', 'metasploit')
ORDER BY c.days_ahead_vs_nvd_present DESC NULLS LAST;
```

The `radar` view (migration `0001`) pre-joins candidate + best CVSS
(`cvss_selected`) + current EPSS (`epss_current`) for the live set, so many of
these crosses can start from `SELECT * FROM radar WHERE …`.

**FUTURE WORK — alerts + watchlist.** There is no watchlist table, no alerting,
and no notification path yet. "Affects my stack" is expressed today by hand-listing
products in SQL; a persisted per-tenant watchlist (against
`product_catalog`/`product_aliases`) and an alert trigger on new multi-signal
matches are planned but unimplemented.

**Why the catalogs can't**: no catalog joins reservation status, KEV membership,
authoritative+derived CVSS, exploit-tool availability, EPSS and affected-product
canonicalization in one queryable place — that unification is the whole point of
the `candidates` model.

---

## Summary — available vs future

| Use case | Status | Entry point |
|---|---|---|
| 1. Vulns with no official CVE now | Available | `cveradar pending`, `emerging` |
| 2. Lead days per source | Available | `cveradar stats` |
| 3. Software with most pending CVEs | Available | `cveradar pending --kind`, `trend` |
| 4. Exploit-before-CVE (PoC × reserved × not-in-KEV) | Available (SQL) | nuclei/metasploit × pending × `in_kev` |
| 5. Pre-KEV prediction *P(KEV in 30d)* | **Future (Layer 4)** | label + features ready; no model |
| 6. Mention emergence velocity / acceleration | Partial (SQL) / Future | `mentions.seen_at` windows |
| 7. Multi-signal crosses | Available (SQL) | `radar` view + joins |
| 7b. Watchlist + alerts | **Future** | not implemented |
