# Modelo de datos

Las **migraciones Alembic escritas a mano son la fuente de verdad del esquema**
(`migrations/versions/0001_initial_schema.py`, `0002_affected_products.py`,
`0003_soft_cve_ref.py`). `app/core/models.py` es un mapeo ORM (SQLModel) sobre
esas tablas; `env.py` usa `target_metadata=None`, de modo que los modelos nunca
autogeneran ni crean tablas por su cuenta.

Migraciones posteriores: `0004_kev_flags` (`candidates.in_kev`, `kev_date`,
`kev_source`), `0005_rich_fields` (`affected_products.kind`; `candidates.cwe_ids`,
`reference_urls`, `withdrawn`), `0006_nvd_enrichment` (columnas de enriquecimiento
en `published_cves` + tablas hijas `cve_cvss`, `cve_cwe`, `cve_cpe`,
`cve_reference`), `0007_soft_cve_references` (`cve_soft_references`),
`0008_source_method_git` (amplía `CHECK ck_sources_method` con `'git'`),
`0009_source_tier_range` (amplía `CHECK ck_sources_tier` a `tier BETWEEN 1 AND 9`)
y `0010_github_repos_registry` (`github_repos`).

Postgres 16. Se aprovechan `gen_random_uuid()`, `TIMESTAMP WITH TIME ZONE`,
`JSONB`, `ARRAY(Text)` e índices parciales.

---

## Baseline

### `published_cves`
Estado canónico de cada CVE (cvelistV5 + NVD 2.0). PK `id` = `CVE-YYYY-NNNN`
(`Text`).

| Columna | Tipo | Notas |
|---|---|---|
| `id` | Text PK | `CVE-YYYY-NNNN` |
| `state` | Text | `RESERVED` / `PUBLISHED` / `REJECTED` (CHECK `ck_pubcves_state`) |
| `cvelist_published_at`, `cvelist_updated_at` | timestamptz | Fechas auto-reportadas por cvelistV5. |
| `nvd_published_at`, `nvd_last_modified_at` | timestamptz | Fechas auto-reportadas por NVD (**pueden venir con backfill**). |
| `nvd_vuln_status` | Text | p.ej. `Analyzed`, `Awaiting Analysis`. |
| `nvd_first_observed_at` | timestamptz | **Observación propia**: cuándo lo vimos por primera vez en NVD (inmune a backfill). |
| `nvd_first_analyzed_observed_at` | timestamptz | Cuándo lo vimos por primera vez en estado `Analyzed`. |
| `cna`, `assigner_short_name` | Text | Autoría del registro. |
| `raw_json` | JSONB | Registro CVE JSON 5.0 original (cvelistV5: contenedores CNA + CISA-ADP). |
| `ingested_at` | timestamptz | `server_default now()`. |
| `description_en` | Text | (`0006`) Descripción en inglés del contenedor CNA. |
| `primary_cvss_version` | Text | (`0006`) Versión del CVSS primario (`2.0/3.0/3.1/4.0`). |
| `primary_cvss_score` | Float | (`0006`) Base score del CVSS primario. |
| `primary_cvss_severity` | Text | (`0006`) Severidad del CVSS primario (mayúsculas). |
| `primary_cvss_vector` | Text | (`0006`) Vector del CVSS primario. |
| `primary_cwe` | Text | (`0006`) Primera debilidad `CWE-…`. |
| `has_exploit_ref` | Boolean | (`0006`) Alguna referencia con tag `Exploit`. |
| `has_patch_ref` | Boolean | (`0006`) Alguna referencia con tag `Patch`. |
| `ssvc_exploitation` | Text | (`0006`) SSVC `Exploitation` (contenedor CISA-ADP "Vulnrichment"). |
| `ssvc_automatable` | Text | (`0006`) SSVC `Automatable` (CISA-ADP). |
| `ssvc_technical_impact` | Text | (`0006`) SSVC `Technical Impact` (CISA-ADP). |
| `enriched_at` | timestamptz | (`0006`) Cuándo `enrich-nvd` derivó estas columnas. |

Todas las columnas `0006` son nullable. Son **atajos denormalizados** para
filtrar/joinear; el detalle completo vive en las tablas hijas `cve_cvss` /
`cve_cwe` / `cve_cpe` / `cve_reference`. Las puebla `foreshock baseline enrich-nvd`
(`app/baseline/enrich.py`), un batch derivado e idempotente (ver `ENRICHMENT.md`).

Los campos `cvelist_*` los rellena `app/baseline/cvelist.py`; los `nvd_*`,
`app/baseline/nvd.py`. Ninguno pisa al otro (upserts disjuntos por columnas).
Las columnas `nvd_first_*` se sellan una sola vez vía `COALESCE` — son el
**ground truth de observación** que hace robusta la métrica `days_ahead_present`.

### `sources`
Registro de fetchers. `name` único;
`method IN ('api','rss','scrape','browser','git')` (CHECK `ck_sources_method`,
ampliado con `'git'` en `0008`); `tier BETWEEN 1 AND 9` (CHECK `ck_sources_tier`,
ampliado en `0009`; en uso `1..5`).
Guarda `enabled`, `cadence_seconds`, `last_success_at`, `last_error`,
`last_error_at`. Índice parcial `idx_sources_enabled WHERE enabled`.

---

## Rastreo

### `candidates` — la unidad de rastreo
Un candidate existe **con o sin CVE**. PK `id` UUID (`gen_random_uuid()`).

- `status` — `candidate` / `emerging` / `published` / `rejected` / `merged`
  (CHECK `ck_cand_status`). `published` significa que el CVE tiene **datos NVD**
  (`published_cves.nvd_published_at IS NOT NULL`), no solo un cvelist `PUBLISHED`:
  un CVE RESERVADO o sin fecha NVD permanece pre-publicado.
- **`cve_id` (Text) — referencia BLANDA, SIN FK.** La migración `0003` elimina
  el constraint `candidates_cve_id_fkey`. Motivo: un candidate puede referenciar
  un CVE solo RESERVADO y aún no ingerido por el baseline (o que MITRE/NVD no
  publican todavía). Forzar el FK impediría registrar la señal temprana, que es
  la premisa de Foreshock. La reconciliación se hace por *lookup*
  (`compute_days_ahead` hace `session.get(PublishedCVE, cve_id)`), no por
  integridad referencial. Índice `idx_cand_cve`.
- `merged_into` — self-FK para el union-find de fusiones (tombstone). Índice
  parcial `idx_cand_merged_into WHERE merged_into IS NOT NULL`.
- `cluster_fingerprint` — huella para dedup difuso.
- Agregados de menciones: `first_seen_at`, `last_seen_at`, `mention_count`,
  `source_count` (recalculados por `_refresh_aggregates`).
- Reconciliación con NVD: `promoted_at`, `days_ahead_vs_nvd_published`,
  `days_ahead_vs_nvd_present`, `days_ahead_vs_nvd_analyzed`.
- Enriquecimiento (Capa 3): `affected_product`, `affected_versions`,
  `vuln_type`, `attack_vector` (CHECK `network/adjacent/local/physical`),
  `requires_auth`, `requires_interaction`, `has_public_poc`, `poc_urls[]`,
  `severity_hint` (CHECK `likely-critical/high/medium/low`),
  `enrichment_confidence` (CHECK 0..1), `enrichment_method`,
  `enrichment_updated_at`.

### `identifiers` — enlace determinista
Cada `(scheme, value)` ancla a **un solo** candidate.
`UNIQUE(scheme, value)` (`uq_identifiers_scheme_value`) es la clave del enlace
determinista (Etapa A de la correlación). FK `candidate_id` con
`ON DELETE CASCADE`. Esquemas definidos: `CVE`, `ZDI-CAN`, `ZDI`, `VU`, `GHSA`,
`MSRC`, `OSV` (ids de ecosistema: `PYSEC`/`GO`/`RUSTSEC`/`GSD`/`MAL`/`OSV`) y
`GHCOMMIT` (ver `INGESTION.md`).

**Política de reconocimiento.** `RECOGNIZED_SCHEMES = {CVE, ZDI-CAN, ZDI, VU,
GHSA, MSRC, OSV}`. La ingesta **descarta** cualquier mención que no ancle en al
menos un esquema reconocido — nada se almacena sin un CVE o un código oficial
equivalente. `GHCOMMIT` está **definido pero NO reconocido** (fuera de
`RECOGNIZED_SCHEMES`): una mención anclada solo por `GHCOMMIT` se descarta en la
ingesta y ya no existen filas `GHCOMMIT` en `identifiers`.

### `mentions` — observaciones crudas
Cada aparición de una vulnerabilidad en una fuente. FKs a `candidates`
(CASCADE) y `sources`.

- **Idempotencia por `content_hash`**: `UNIQUE(source_id, content_hash)`
  (`uq_mentions_source_hash`). El hash se calcula sobre el **extracto semántico**
  (CVE + nativo + título + snippet + URL canónica normalizados), **no** sobre el
  HTML crudo. Un re-listado idéntico → mismo hash → no duplica; un cambio real
  de contenido → hash nuevo → mención nueva legítima en el timeline. Ver
  `app/ingest/hashing.py`. La identidad del CVE va **dentro** del hash, por eso
  la restricción no incluye `cve_id`.
- `extracted_cve`, `extracted_native`, `url`, `title`, `snippet`,
  `raw_html_path` (ruta en disco al HTML crudo persistido), `seen_at`.

### `candidate_links` — dedup difuso PROPUESTO, no destructivo
Enlaces difusos entre candidates que **se sugieren pero no fusionan**. PK
compuesta `(a, b)` con CHECK `a < b` (par canónico, `ck_links_canonical_pair`).

- `method IN ('fingerprint','embedding','llm')` (CHECK `ck_links_method`).
- `confidence` 0..1; `status IN ('suggested','confirmed','rejected')`
  (default `suggested`).
- `rationale` para auditoría. Índice parcial
  `idx_links_status WHERE status = 'suggested'`.

Es no destructivo: a diferencia del union-find de `identifiers` (que fusiona de
verdad por evidencia determinista), aquí solo se propone un enlace para revisión.

### `cvss_scores` — v3/v4, autoritativo vs derivado, multi-fuente
Varias filas por candidate. `UNIQUE(candidate_id, version, provenance, source)`
(`uq_cvss_candidate_version_prov_source`).

- `version IN ('3.0','3.1','4.0')` (CHECK `ck_cvss_version`).
- `vector` (verbatim o construido), `base_score` (0..10), `base_severity`
  (`NONE/LOW/MEDIUM/HIGH/CRITICAL`).
- **`provenance IN ('authoritative','derived')`** (CHECK `ck_cvss_provenance`):
  `authoritative` = vector extraído verbatim del texto de la fuente y puntuado
  con la librería `cvss`; `derived` = calculado desde las métricas inferidas por
  el LLM.
- `source` — origen textual (`source-text`, `llm-derived`, …).
- `inferred_metrics[]` y `confidence` — solo para `derived`.

Ver `ENRICHMENT.md` para la precedencia de selección.

### `epss_scores` — histórico
PK compuesta `(cve_id, scored_date)` (`pk_epss_scores`) → cada snapshot diario
del modelo se conserva; se ve la evolución del score. `score` y `percentile`
0..1. **Sin FK a `published_cves`**: EPSS puede referir un CVE aún no ingerido.

---

## Canonicalización de software (migración `0002`)

### `product_catalog`
Vocabulario canónico (sembrado de CPE-dict / OSV / manual). La "verdad" contra
la que se enlazan los nombres sucios. Campos `vendor`, `product` (NOT NULL),
`ecosystem` (PyPI/npm/Go…; NULL en software clásico), `cpe23`, `purl`, `source`.
`UNIQUE(vendor, product, ecosystem)` con **`NULLS NOT DISTINCT`** (PG15+): dos
filas con `ecosystem NULL` también deduplican (sin esa cláusula, `NULL != NULL`
permitiría duplicados). Igual en `affected_products.uq_affected_candidate_product`.

### `product_aliases`
Clave normalizada → entrada canónica. `UNIQUE(alias_normalized)`: un alias
resuelve de forma **determinista** a UNA entrada. Crece con lo que confirma el
LLM/humano; la próxima vez resuelve en Capa 1 sin volver a llamar al LLM.
`source IN ('seed','llm','manual')`, `confidence` 0..1.

### `affected_products`
Productos afectados por candidate (multi-fila). Guarda el **raw extraído**
(`raw`, `product`, `vendor`, `ecosystem`, `cpe23`, `purl`, `exact_versions[]`,
`default_status`) **más** el enlace canónico `catalog_id` (FK
`ON DELETE SET NULL`) y la trazabilidad de la canonicalización:
`normalization_method IN ('exact','alias','fuzzy','llm','unresolved')`,
`normalization_confidence`. Índice parcial `idx_affected_unresolved WHERE
catalog_id IS NULL` = cola de pendientes de resolver.

### `affected_version_ranges`
Rangos estructurados por producto afectado (estilo OSV / CVE-5.0):
`introduced`, `fixed` (exclusivo), `last_affected` (inclusivo), `version_type`
(semver/rpm/custom…), `raw` (p.ej. `< 7.4.3`). FK a `affected_products` CASCADE.

---

## Enriquecimiento NVD (migración `0006`)

Cuatro **tablas hijas normalizadas** derivadas de `published_cves.raw_json`
(CVE JSON 5.0). `cve_id` es una **referencia blanda** a `published_cves.id`
(SIN FK: un CVE puede enriquecerse desde un contenedor ADP antes de que exista su
fila baseline). `enrich_all` (`app/baseline/enrich.py`, `foreshock baseline
enrich-nvd`) es idempotente vía **delete-by-cve + insert**. Ver `ENRICHMENT.md`.

### `cve_cvss`
Cada métrica CVSS hallada en los contenedores CNA y ADP (multi-fila por CVE).

| Columna | Tipo | Notas |
|---|---|---|
| `id` | BigInteger PK | autoincrement |
| `cve_id` | Text | Ref blanda a `published_cves.id`. |
| `version` | Text | `2.0` / `3.0` / `3.1` / `4.0`. |
| `source` | Text | `shortName` del CNA, o `cisa-adp`. |
| `type` | Text | `Primary` / `Secondary`. |
| `vector` | Text | Vector CVSS. |
| `base_score` | Float | Base score. |
| `base_severity` | Text | Severidad (mayúsculas). |
| `exploitability_score` | Float | Sub-score. |
| `impact_score` | Float | Sub-score. |
| `recorded_at` | timestamptz | Insert (`now()`). |

Índices `idx_cve_cvss_cve (cve_id)`, `idx_cve_cvss_score (base_score)`.

### `cve_cwe`
Debilidades declaradas (multi-fila por CVE).

| Columna | Tipo | Notas |
|---|---|---|
| `id` | BigInteger PK | autoincrement |
| `cve_id` | Text | Ref blanda. |
| `cwe_id` | Text | `CWE-79` o texto libre si no hay id. |
| `description` | Text | Texto de la debilidad (si había `cweId`). |
| `source` | Text | Contenedor de origen. |
| `recorded_at` | timestamptz | Insert (`now()`). |

Índices `idx_cve_cwe_cve (cve_id)`, `idx_cve_cwe_cwe (cwe_id)`.

### `cve_cpe`
Productos afectados como cadenas CPE 2.3 (multi-fila por CVE).

| Columna | Tipo | Notas |
|---|---|---|
| `id` | BigInteger PK | autoincrement |
| `cve_id` | Text | Ref blanda. |
| `cpe23` | Text | Cadena CPE 2.3. |
| `vulnerable` | Boolean | `False` si el `defaultStatus` del contenedor es `unaffected`. |
| `version_start` / `version_start_type` | Text | (reservados; actualmente NULL). |
| `version_end` / `version_end_type` | Text | (reservados; actualmente NULL). |
| `source` | Text | Contenedor de origen. |
| `recorded_at` | timestamptz | Insert (`now()`). |

Índices `idx_cve_cpe_cve (cve_id)`, `idx_cve_cpe_cpe (cpe23)`.

### `cve_reference`
URLs de referencia con sus tags (multi-fila por CVE; deduplicadas por URL entre
contenedores).

| Columna | Tipo | Notas |
|---|---|---|
| `id` | BigInteger PK | autoincrement |
| `cve_id` | Text | Ref blanda. |
| `url` | Text | URL de referencia. |
| `tags` | ARRAY(Text) | p.ej. `Exploit`, `Patch`, `Vendor Advisory`. |
| `source` | Text | Contenedor de origen. |
| `recorded_at` | timestamptz | Insert (`now()`). |

Índices `idx_cve_ref_cve (cve_id)`, GIN `idx_cve_ref_tags (tags)`.

---

## Referencias CVE blandas (migración `0007`)

### `cve_soft_references`
Un CVE **citado en la prosa** de una nota (cuerpo de un GHSA, mensaje de commit,
noticia) que **no** es el CVE anclado propio de la nota. Deliberadamente
desacoplado de la identidad: **no** ancla, **no** fusiona y **no** está en
`identifiers` ni en el union-find. Existe para *contar y contextualizar* CVEs
(a menudo aún no publicados) sin colapsar vulnerabilidades distintas. Lo puebla
`_record_soft_references` en `app/ingest/service.py`.

| Columna | Tipo | Notas |
|---|---|---|
| `id` | BigInteger PK | autoincrement |
| `cve_id` | Text | El CVE citado (**ref blanda**, sin FK — puede estar sin publicar). |
| `mention_id` | BigInteger | FK → `mentions.id` `ON DELETE CASCADE`. |
| `source_id` | Integer | FK → `sources.id`. |
| `from_candidate_id` | UUID | FK → `candidates.id` `ON DELETE SET NULL` — candidate de la nota. |
| `context` | Text | Snippet/título de la nota (≤500 chars). |
| `seen_at` | timestamptz | Insert (`now()`). |

`UNIQUE(mention_id, cve_id)` (`uq_soft_ref_mention_cve`, clave de idempotencia);
índices `idx_soft_ref_cve (cve_id)`, `idx_soft_ref_source (source_id)`.

---

## Registro de repos GitHub (migración `0010`)

### `github_repos`
Watchlist unificada de repositorios GitHub escaneados por `github_commits`
(`app/sources/repo_registry.py`). La PK `full_name` deduplica un repo añadido por
varias estrategias de descubrimiento; el `watermark` hace incremental cada escaneo
(ningún repo se re-escanea ni duplica). Reemplaza los antiguos archivos de estado
JSON.

| Columna | Tipo | Notas |
|---|---|---|
| `full_name` | Text PK | `owner/repo`. |
| `origin` | Text | `top_n` / `reference` / `past_cve` / `criticality` / `downloads` / `manual`. |
| `stars` | Integer | Estrellas (de la Search API / top-N). |
| `priority` | Integer | Prioridad de escaneo (default `0`; sube a `GREATEST` en conflicto). |
| `watermark` | Text | ISO de la fecha de commit más reciente ya escaneada. |
| `first_seen_at` | timestamptz | Creación (`now()`). |
| `last_scanned_at` | timestamptz | Último escaneo (NULL = nunca → se escanea primero). |

Índices `idx_ghrepos_scan (last_scanned_at, priority, stars)` (orden de escaneo:
no escaneados primero, luego prioridad, luego estrellas), `idx_ghrepos_origin
(origin)`. **Sin FK** — el registro es independiente de las tablas de rastreo
(aunque se *puebla* desde `mentions` / `cve_reference` /
`candidates.reference_urls`).

---

## Vistas de conveniencia

Definidas en `0001_initial_schema.py`:

- **`epss_current`** — `DISTINCT ON (cve_id) … ORDER BY cve_id, scored_date DESC`:
  el snapshot EPSS más reciente por CVE sobre el histórico.
- **`cvss_selected`** — `DISTINCT ON (candidate_id)` con orden de precedencia:
  `provenance = 'authoritative'` primero, luego versión más alta
  (`4.0 > 3.1 > 3.0`), luego `base_score DESC NULLS LAST`. Selecciona el "mejor"
  CVSS por candidate.
- **`radar`** — vista principal de consumo: `candidates` LEFT JOIN
  `cvss_selected` LEFT JOIN `epss_current`, filtrando
  `status IN ('candidate','emerging','published') AND merged_into IS NULL`.
  Expone `days_ahead_vs_nvd_present` y `days_ahead_vs_nvd_analyzed`, el CVSS
  seleccionado, `severity_hint` y el EPSS actual.
