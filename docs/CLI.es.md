# CLI — `cveradar`

CLI de operación y consulta (Typer + Rich), definida en `app/cli.py` y expuesta
como script `cveradar` (`pyproject.toml [project.scripts]`). Dentro del
contenedor se invoca igual (`cveradar …`) o con `python -m app.cli`.

Estructura de subcomandos: `db`, `sources`, `baseline`, más los comandos de
consulta de primer nivel `emerging`, `cve`, `enrich`, `stats`.

---

## `db` — base de datos / migraciones

```bash
cveradar db init          # alembic upgrade head
```

`db init` ejecuta `alembic upgrade head` y propaga el código de salida.

---

## `sources` — gestión de fuentes

```bash
cveradar sources sync                 # registra los fetchers del código en la tabla sources
cveradar sources list                 # lista fuentes y su estado
cveradar sources enable <name>        # activa una fuente
cveradar sources disable <name>       # desactiva una fuente
cveradar sources run <name>           # ejecuta un fetcher una vez e imprime métricas
```

- `sources sync` → `sync_registry_to_db()` (crea/actualiza filas; no pisa
  `cadence_seconds`).
- `sources list` muestra `name / tier / method / enabled / cadence /
  last_success / last_error`.
- `sources run` → `run_source(name)` (async) e imprime
  `{"fetched", "created", "duplicate"}`.

```bash
cveradar sources run redhat_csaf
# {'fetched': 100, 'created': 12, 'duplicate': 88}
```

---

## `baseline` — sincronización del estado canónico

```bash
cveradar baseline sync                        # cvelistV5 + NVD + EPSS, una pasada
cveradar baseline sync --nvd-hours 6          # ventana del delta NVD (default 3)
cveradar baseline sync --full-cvelist         # reprocesa todo cvelistV5 (default False)
```

Llama a `run_baseline_once(nvd_hours=…, force_full_cvelist=…)` e imprime las
métricas por fuente.

---

## `emerging` — candidates emergentes (con filtros)

```bash
cveradar emerging list
cveradar emerging list --since 24h --tier 1 --min-mentions 2
cveradar emerging list --source certcc_vu --limit 100
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
cveradar cve show CVE-2026-12345
cveradar cve show 3f8e...-uuid        # también acepta un UUID de candidate
```

`_find_candidate` busca por `cve_id` (uppercased) y, si no, interpreta la clave
como UUID de candidate. Imprime: status, enriquecimiento (`vuln`, `vector`,
`poc`, `hint`), `days_ahead` present/analyzed, lista de `identifiers`, tabla de
`cvss_scores` (version/score/sev/provenance/source), último EPSS y el
**timeline** de menciones (`seen_at`, source, title, url).

---

## `enrich` — enriquecer un candidate

```bash
cveradar enrich CVE-2026-12345
cveradar enrich <uuid-candidate>
```

Localiza el candidate y ejecuta `enrich_candidate` (LLM + CVSS). Imprime
`enriquecido` o `sin datos`. El proveedor LLM depende de `CVERADAR_LLM_PROVIDER`
(default `mock`, sin red).

---

## `stats` — métricas de ventaja

```bash
cveradar stats
```

Imprime:
- Total de candidates, promovidos (`status='published'`) y tasa de promoción.
- **Días de ventaja medios por fuente** (vs NVD *present*): `AVG(
  days_ahead_vs_nvd_present)` agrupado por `sources.name`, ordenado
  descendente, con el nº de candidates distintos por fuente.
