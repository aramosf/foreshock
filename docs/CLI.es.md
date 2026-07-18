# CLI — `foreshock`

CLI de operación y consulta (Typer + Rich), definida en `app/cli.py` y expuesta
como script `foreshock` (`pyproject.toml [project.scripts]`). Dentro del
contenedor se invoca igual (`foreshock …`) o con `python -m app.cli`.

Estructura de subcomandos: `db`, `sources`, `baseline`, más los comandos de
consulta de primer nivel `emerging`, `cve`, `enrich`, `stats`.

---

## `db` — base de datos / migraciones

```bash
foreshock db init          # alembic upgrade head
```

`db init` ejecuta `alembic upgrade head` y propaga el código de salida.

---

## `sources` — gestión de fuentes

```bash
foreshock sources sync                 # registra los fetchers del código en la tabla sources
foreshock sources list                 # lista fuentes y su estado
foreshock sources enable <name>        # activa una fuente
foreshock sources disable <name>       # desactiva una fuente
foreshock sources run <name>           # ejecuta un fetcher una vez e imprime métricas
foreshock sources harvest-repos        # (re)puebla la watchlist github_repos
foreshock sources reextract-commits    # re-extrae github_commits desde la caché de git-log
```

- `sources sync` → `sync_registry_to_db()` (crea/actualiza filas; no pisa
  `cadence_seconds`).
- `sources list` muestra `name / tier / method / enabled / cadence /
  last_success / last_error`. `method` incluye `api` / `rss` / `scrape` /
  `browser` / `git`; `tier` con CHECK 1–9 (1–5 en uso).
- `sources run` → `run_source(name)` (async) e imprime
  `{"fetched", "created", "duplicate"}`.

```bash
foreshock sources run redhat_csaf
# {'fetched': 100, 'created': 12, 'duplicate': 88}
```

- `sources harvest-repos` → `repo_registry.harvest_all(client, settings)` e
  imprime el dict de conteos por estrategia. (Re)puebla la watchlist
  `github_repos` que consume `github_commits`. Estrategias `reference` /
  `past_cve` (repos citados en URLs de referencia; el que ya tiene CVE pasa a
  `past_cve`) y `top_n` (top-N por estrellas vía GitHub Search) **siempre
  corren**; `criticality` (opt-in `FORESHOCK_CRITICALITY_CSV_URL`) y `downloads`
  (opt-in `FORESHOCK_PYPI_DOWNLOADS_TOP_N`) son opcionales. `github_commits`
  también hace bootstrap del registro si está vacío, así que este comando sirve
  para **refrescar/ampliar** la watchlist o activar las estrategias opt-in.
- `sources reextract-commits` → re-extrae menciones de `github_commits` desde la
  **caché comprimida de git-log** (`{cache_dir}/gitlog/<owner__repo>.log.gz`)
  **sin clonar** (`reextract_from_cache` → `ingest_prefetched`, con el mismo
  aislamiento por savepoint por mención). Cero red; para recuperarse de un bug
  de parseo de commits sobre la caché ya capturada.

```bash
foreshock sources harvest-repos
# {'reference': 812, 'past_cve': 96, 'top_n': 10000, 'criticality': 0, 'downloads': 0}

foreshock sources reextract-commits
# menciones re-extraídas de caché: 1843
# {'fetched': 1843, 'created': 210, 'duplicate': 1633, 'errors': 0}
```

---

## `baseline` — sincronización del estado canónico

```bash
foreshock baseline sync                        # cvelistV5 + NVD + EPSS, una pasada
foreshock baseline sync --nvd-hours 6          # ventana del delta NVD (default 3)
foreshock baseline sync --full-cvelist         # reprocesa todo cvelistV5 (default False)
foreshock baseline nvd-full                     # backfill completo de NVD 2.0 (~270k CVEs, sin ventana)
foreshock baseline epss-full                    # dump completo del CSV de EPSS (todos los scores actuales)
foreshock baseline enrich-nvd                   # deriva CVSS/CWE/CPE/refs/SSVC desde raw_json
foreshock baseline enrich-nvd --batch 5000      # tamaño de página keyset (default 2000)
```

- `baseline sync` → `run_baseline_once(nvd_hours=…, force_full_cvelist=…)` e
  imprime las métricas por fuente.
- `baseline nvd-full` → `asyncio.run(sync_nvd_full())` — pagina **todo** el
  dataset de NVD 2.0 (~270k CVEs, sin ventana `lastMod`). Para un backfill en
  frío; después el delta programado lo mantiene al día.
- `baseline epss-full` → `asyncio.run(sync_epss_full())` — descarga el CSV
  completo de EPSS (todos los scores actuales) en vez del delta diario.
- `baseline enrich-nvd` → `enrich_all(batch_size=batch)` — **deriva** datos
  estructurados desde `published_cves.raw_json` (CVE JSON 5.0): filas
  `cve_cvss` / `cve_cwe` / `cve_cpe` / `cve_reference` más las columnas
  desnormalizadas de `published_cves` (CVSS/CWE primarios, flags de
  exploit/patch, SSVC). Sin red e **idempotente** (delete-by-cve + insert).
  `--batch` es el tamaño de página keyset sobre `published_cves.id` (default
  2000).

---

## `emerging` — candidates emergentes (con filtros)

```bash
foreshock emerging list
foreshock emerging list --since 24h --tier 1 --min-mentions 2
foreshock emerging list --source certcc_vu --limit 100
```

| Opción | Efecto |
|---|---|
| `--since` | Ventana relativa `Nh`/`Nd`/`Nw` (p.ej. `24h`, `7d`, `2w`) sobre `last_seen_at`. |
| `--source` | Filtra por `sources.name` (join con `mentions`). |
| `--tier` | Filtra por `sources.tier`. |
| `--min-mentions` | Mínimo de `mention_count` (default `1`). |
| `--limit` | Máximo de filas (default `50`). |

Solo lista candidates vivos (`merged_into IS NULL`), ordenados por
`last_seen_at DESC`. Columnas: `cve/id`, `status`, `vuln`, `sev` (mejor
`base_score` o `severity_hint`), `mentions`, `sources`, `days_ahead`
(`days_ahead_vs_nvd_present`), `last_seen`.

> Nota: el argumento posicional `action` solo acepta `list`.

---

## `cve show` — timeline y enriquecimiento

```bash
foreshock cve show CVE-2026-12345
foreshock cve show 3f8e...-uuid        # también acepta un UUID de candidate
```

`_find_candidate` busca por `cve_id` (uppercased) y, si no, interpreta la clave
como UUID de candidate. Imprime: status, enriquecimiento (`vuln`, `vector`,
`poc`, `hint`), `days_ahead` present/analyzed, lista de `identifiers`, tabla de
`cvss_scores` (version/score/sev/provenance/source), último EPSS y el
**timeline** de menciones (`seen_at`, source, title, url).

---

## `enrich` — enriquecer un candidate

```bash
foreshock enrich CVE-2026-12345
foreshock enrich <uuid-candidate>
```

Localiza el candidate y ejecuta `enrich_candidate` (LLM + CVSS). Imprime
`enriquecido` o `sin datos`. El proveedor LLM depende de `FORESHOCK_LLM_PROVIDER`
(default `mock`, sin red).

---

## `stats` — métricas de ventaja

```bash
foreshock stats
```

Imprime:
- Total de candidates, promovidos (`status='published'`) y tasa de promoción.
- **Días de ventaja medios por fuente** (vs NVD *present*): `AVG(
  days_ahead_vs_nvd_present)` agrupado por `sources.name`, ordenado
  descendente, con el nº de candidates distintos por fuente.
