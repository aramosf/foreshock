# Fuentes (fetchers)

Cada fetcher vive en `app/sources/<nombre>.py`, declara una subclase de
`BaseSource` decorada con `@register` y devuelve `list[FetchedMention]`. **No
escribe en BD** (de eso se encarga la ingesta) y **se aísla ante fallos**: si un
fetcher lanza excepción, el worker la captura, la loguea, registra
`last_error`/`last_error_at` en `sources` y sigue con el resto.

---

## El contrato `BaseSource` (`app/sources/base.py`)

```python
class BaseSource(abc.ABC):
    name: str = ""            # identificador único (== sources.name)
    kind: str = ""            # descripción legible del origen
    method: str = "api"       # api | rss | scrape | browser
    tier: int = 5             # 1..5 (prioridad de señal temprana)
    cadence_seconds: int = 3600

    @abc.abstractmethod
    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]: ...

    def seed_row(self) -> dict: ...   # fila para la tabla `sources`
```

`FetchContext` inyecta los recursos compartidos: `http` (`httpx.AsyncClient`),
`settings` y `browser` (`BrowserPool | None`).

Registro y carga:
- `@register` valida que la clase tenga `name`, rechaza duplicados y la añade a
  `REGISTRY`.
- `load_all()` importa todos los módulos de `app/sources/` (excepto `base`,
  `browser`, `runner`, `robots`) para poblar `REGISTRY`.
- `sync_registry_to_db()` (`app/sources/runner.py`) crea/actualiza la fila de
  `sources` de cada fetcher. **`cadence_seconds` no se pisa** al re-sincronizar:
  puede haberse ajustado en operación.

### Los 4 métodos (`method`)

| `method` | Transporte | Librería |
|---|---|---|
| `api` | API JSON/XML | `httpx` |
| `rss` | Feed RSS/Atom | `feedparser` |
| `scrape` | HTML estático | `httpx` + `selectolax` |
| `browser` | Requiere JS | `BrowserPool` (Playwright, opcional) |

---

## Los 6 fetchers

| Fetcher (`name`) | Tier | `method` | Fuente / URL | Señal |
|---|---|---|---|---|
| `certcc_vu` | 1 | rss | `https://www.kb.cert.org/vuls/atomfeed/` | Notas VU# de CERT/CC; suelen preceder al CVE. |
| `redhat_csaf` | 2 | api | `https://access.redhat.com/hydra/rest/securitydata/cve.json` | CVE JSON de Red Hat; CVSS **autoritativo**. `lookback_days = 3`. |
| `nessus` | 3 | scrape | `https://www.tenable.com/plugins/nessus/newest` | Plugins Nessus que citan CVEs a veces solo RESERVADOS. |
| `github_advisories` | 4 | api | `https://api.github.com/advisories` | GHSA con `cve_id` + paquetes afectados estructurados. |
| `github_commits` | 4 | api | `https://api.github.com` (top-N repos) | Commits que citan CVE o son fix de seguridad sin CVE. |
| `thehackernews` | 5 | rss | `https://feeds.feedburner.com/TheHackersNews` | Noticias; a veces mencionan CVEs pronto (explotación activa). |

Los fetchers `rss`/`scrape` filtran a menudo por presencia de `CVE-` en el texto
antes de emitir la mención (la ingesta vuelve a filtrar igual).
`redhat_csaf` y `github_advisories` aportan `cve_id`/`native_id` cuando los
conocen, ahorrando trabajo a la regex de ingesta.

El **tier** codifica la prioridad de señal temprana (1 = fuente que suele
adelantarse más al CVE público). Se usa para filtrar en la CLI (`emerging
--tier`) y para atribuir ventaja media por fuente (`stats`).

---

## `github_commits` en detalle (`app/sources/github_commits.py`)

Vigila los **top-N repos** de GitHub por estrellas y escanea sus commits de los
últimos N meses buscando dos señales:

1. **CVE citado** en el mensaje de commit (a menudo reservado, aún no público) →
   mención con ese `cve_id`.
2. **Fix de seguridad sin CVE** (regex `_SECFIX`: `security fix`,
   `vulnerabilit…`, `rce`, `xss`, `sqli`, `auth bypass`, `ssrf`, `deserializ`,
   `path traversal`, `buffer overflow`, `use-after-free`, `privilege
   escalation`, `out-of-bounds`…) → si `github_synthesize_candidates` está
   activo, se ancla como **candidate pre-CVE** con
   `native_id = "GHCOMMIT:owner/repo@sha12"`, que la reconciliación fusionará con
   el CVE cuando aparezca.

**Escala e incrementalidad** (settings con prefijo `CVERADAR_`):

- `github_top_n` (default `10000`, escalable a 100k+): nº de repos a vigilar.
- **Caché de la lista de repos** (`{data_dir}/github_top_repos.json`): se
  construye con `_build_repo_list` (Search API con ventanas descendentes de
  estrellas, porque la Search API tope 1000 resultados por consulta) y se
  **reconstruye semanalmente** (rebuild si `built_at` > 7 días).
- **Cursor rotatorio** (`{data_dir}/github_commits_cursor.txt`): en cada
  ejecución se procesa un lote de `github_repos_per_run` (default `150`) repos;
  el cursor avanza en módulo y hace *wrap*, de modo que el crawl recorre toda la
  lista en varias pasadas respetando el rate limit.
- **Watermark por repo** (`{data_dir}/github_repo_state.json`): `full_name → ISO
  del último commit escaneado`. El `since` de cada repo es el máximo entre el
  corte de N meses (`github_commits_months`, default `5`) y el watermark →
  escaneo **incremental**. Escritura atómica (`.tmp` + `os.replace`).
- `github_token` (PAT) sube el rate limit a 5000 req/h.

Un repo que falla no tumba el lote (`github.repo_error` y continúa).

---

## `BrowserPool` (`app/sources/browser.py`)

Pool de contextos Playwright **seguro ante concurrencia** para fetchers
`method=browser`. Playwright es dependencia **opcional** (extra `browser`);
importar el módulo no falla si no está instalada — solo falla al construir el
pool.

Diseño y motivos:

- **Un contexto persistente por fuente** (`launch_persistent_context` con
  `user-data-dir` propio bajo `{data_dir}/browser/<source>`): cookies/sesión
  durables y aislamiento entre fuentes.
- **Lock por fuente** (`asyncio.Lock` en `self._locks[source]`): nunca dos
  fetches concurrentes sobre el mismo contexto (los contextos Playwright **no**
  son seguros para uso concurrente).
- **Semáforo global** (`asyncio.Semaphore(browser_max_concurrent)`, default `3`):
  acota páginas simultáneas → memoria acotada.
- **Reciclado** (`browser_recycle_after`, default `50`): tras N usos, o ante
  crash al abrir una página, el contexto se cierra y renace en el próximo intento
  (los contextos leakean memoria con el tiempo).

`page(source)` es un `asynccontextmanager` que combina lock + semáforo, cede una
`Page` exclusiva y garantiza cierre + conteo de usos en el `finally`.

---

## HTTP educado (`app/sources/http.py`)

- **User-Agent identificable** desde `settings.user_agent`
  (`CVERadar/0.1 (+…; early-CVE research)`), sin rotar IP.
- **`robots.txt`** respetado (`respect_robots`, default `True`) y **cacheado**
  por host (`_robots_cache`). Si no hay robots accesible → se permite.
- **Retries con backoff exponencial** (`tenacity`: `stop_after_attempt(3)`,
  `wait_exponential(min=1, max=20)`) sobre `TransportError`/`HTTPStatusError`.
- `follow_redirects=True`, timeout `http_timeout_seconds` (default `30s`).
- `get()` comprueba robots, hace `raise_for_status()` y reintenta.

---

## Cómo añadir un fetcher

1. Crea `app/sources/mi_fuente.py`.
2. Subclasa `BaseSource`, decórala con `@register`, define atributos de clase e
   implementa `fetch`.
3. Devuelve `list[FetchedMention]`; **no** toques la BD.
4. Registra en la tabla: `cveradar sources sync` (o el arranque del
   `sources-worker` lo hace). Ejecútalo con `cveradar sources run mi_fuente`.

```python
# app/sources/example_json.py
from __future__ import annotations

from app.sources.base import BaseSource, FetchContext, register
from app.sources.http import get
from app.ingest.service import FetchedMention

API = "https://example.org/api/recent-vulns.json"


@register
class ExampleSource(BaseSource):
    name = "example_json"
    kind = "Example vuln feed (JSON API)"
    method = "api"
    tier = 3
    cadence_seconds = 3600

    async def fetch(self, ctx: FetchContext) -> list[FetchedMention]:
        resp = await get(ctx.http, API)
        out: list[FetchedMention] = []
        for item in resp.json():
            out.append(
                FetchedMention(
                    url=item.get("url"),
                    title=item.get("title"),
                    snippet=(item.get("description") or "")[:2000],
                    cve_id=item.get("cve"),        # si lo conoces
                )
            )
        return out
```

La idempotencia y la correlación las garantiza el pipeline de ingesta; el
fetcher solo tiene que devolver menciones limpias.
