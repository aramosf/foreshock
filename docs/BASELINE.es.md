# Baseline — estado canónico

El baseline mantiene la **verdad canónica** contra la que se mide la ventaja del
radar: `published_cves` (cvelistV5 + NVD 2.0) y `epss_scores` (FIRST.org). Lo
orquesta el `baseline-worker` (`app/baseline/__main__.py`) con APScheduler, y
`app/baseline/service.py` ofrece una pasada única encadenada.

Las tres fuentes son **idempotentes** (`INSERT … ON CONFLICT`) y están
**aisladas**: el fallo de una no impide las demás.

```python
# app/baseline/service.py
async def run_baseline_async(nvd_hours=3, force_full_cvelist=False) -> dict
def run_baseline_once(nvd_hours=3, force_full_cvelist=False) -> dict  # asyncio.run(...)
```

`sync_cvelist` es síncrona (git + BD) y se corre en un hilo
(`asyncio.to_thread`); NVD y EPSS son async.

---

## cvelistV5 (`app/baseline/cvelist.py`)

Clon **git superficial** (`--depth 1`) del repo oficial
`CVEProject/cvelistV5`. En cada ejecución hace `git pull --ff-only` y procesa
**solo los JSON cambiados** entre la revisión previa y la nueva (delta barato);
en el primer clon, o con `force_full`, procesa todos.

```python
def sync_cvelist(force_full: bool = False) -> dict[str, int]
def parse_cve_record(raw: dict) -> dict        # PURA: JSON CVE 5.x -> columnas
def upsert_published(session, record) -> None  # ON CONFLICT (id) DO UPDATE
```

- `parse_cve_record` es **pura y testeable** (sin red ni BD): extrae `id`,
  `state`, `cvelist_published_at`, `cvelist_updated_at`, `assigner_short_name`,
  `cna`, `raw_json`. **Nunca** toca campos `nvd_*`.
- `_changed_json_files` usa `git diff --name-only HEAD@{1} HEAD` filtrando
  `cves/**.json`. Si no hay revisión previa, cae a `_all_json_files` (rglob de
  `CVE-*.json`).
- `upsert_published` actualiza estado/fechas de cvelist/cna/raw_json/ingested_at
  y **no pisa** los `nvd_*`. Un JSON malo no tumba el sync
  (`cvelist.parse_error`).

Cadencia: `FORESHOCK_CVELIST_SYNC_SECONDS` (default `900` = 15 min). Directorio:
`FORESHOCK_CVELIST_REPO_DIR` (default `/data/cvelistV5`).

---

## NVD 2.0 delta + observación propia (`app/baseline/nvd.py`)

Consulta la API NVD 2.0 filtrando por ventana de última modificación
(`lastModStartDate`/`lastModEndDate`) para traer los CVE tocados en las últimas
`hours` horas, paginando de a 2000 (`resultsPerPage`/`startIndex`).

```python
async def sync_nvd_delta(hours: int = 3) -> dict[str, int]
def parse_nvd_vuln(vuln: dict) -> dict          # PURA: item -> campos nvd_*
def upsert_nvd(session, record, observed_at) -> None
```

- `parse_nvd_vuln` (**pura**) extrae `id`, `nvd_published_at`,
  `nvd_last_modified_at`, `nvd_vuln_status`. Acepta tanto `{"cve": {...}}` como
  el objeto `cve` directo.
- **Ground truth de observación** — el valor diferencial del radar:
  - `nvd_first_observed_at = COALESCE(existing, observed_at)`: se fija la
    **primera** vez que vemos el CVE en NVD y **no se pisa** después. Inmune al
    backfill de fechas de NVD.
  - `nvd_first_analyzed_observed_at`: igual, pero solo se sella cuando
    observamos `vulnStatus == 'Analyzed'`.
  - `observed_at = end` (ahora) es nuestro propio reloj.
- Si el CVE aún no existe en `published_cves`, se crea con `state='PUBLISHED'`.
- Sin `apiKey`, respeta el rate limit público con pausa de `6s` entre páginas
  (`_RATE_LIMIT_SLEEP`); con `FORESHOCK_NVD_API_KEY` envía la cabecera `apiKey` y
  no espera.

Cadencia: `FORESHOCK_NVD_DELTA_SECONDS` (default `7200` = 2 h). Estos timestamps
alimentan `days_ahead_vs_nvd_present` / `_analyzed` (ver `ARCHITECTURE.md`).

---

## EPSS (`app/baseline/epss.py`)

Ingesta scores EPSS de FIRST.org **con histórico**: la PK de `epss_scores` es
`(cve_id, scored_date)`, de modo que cada snapshot diario se conserva y se ve la
evolución del score.

```python
async def sync_epss(cve_ids: list[str] | None = None) -> dict[str, int]
def parse_epss_row(row: dict) -> dict           # PURA: fila data[] -> columnas
def upsert_epss(session, record, model_version) -> None
```

- `parse_epss_row` (**pura**) extrae `cve_id`, `score`, `percentile`,
  `scored_date`.
- Con `cve_ids`: consulta filtrando por `?cve=…` en lotes de 100
  (`_BATCH_SIZE`). Sin ellos: primera página de los de mayor EPSS
  (`?order=!epss&limit=200`, `_RECENT_LIMIT`).
- `upsert_epss` hace `ON CONFLICT (cve_id, scored_date) DO UPDATE`; como la PK
  incluye la fecha, acumula snapshots en lugar de sobrescribir.

Cadencia: `FORESHOCK_EPSS_SYNC_SECONDS` (default `86400` = diario). La vista
`epss_current` expone el snapshot más reciente por CVE.
