"""Configuración central de Foreshock (pydantic-settings).

Todo se parametriza por variables de entorno (12-factor). Los defaults
apuntan al docker-compose local. Nunca se hardcodean secretos.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FORESHOCK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Base de datos / infra ---
    database_url: str = Field(
        default="postgresql+psycopg://foreshock:foreshock@localhost:5432/foreshock",
        validation_alias="DATABASE_URL",
    )
    # --- Almacenamiento de datos crudos y clon de cvelistV5 ---
    data_dir: str = Field(default="/data")  # raw_html, cache
    raw_html_dir: str = Field(default="/data/raw")
    cvelist_repo_dir: str = Field(default="/data/cvelistV5")

    # --- Cache de artefactos crudos (para recrear sin volver a la fuente) ---
    cache_dir: str = Field(default="/data/cache")
    cache_raw: bool = Field(default=True)          # archiva cada respuesta HTTP (write-through)
    cache_reuse_ttl_seconds: int = Field(default=43200)  # reusar binarios grandes (OSV) si < 12h

    # --- Baseline ---
    cvelist_repo_url: str = Field(default="https://github.com/CVEProject/cvelistV5.git")
    cvelist_sync_seconds: int = Field(default=900)  # 15 min
    nvd_delta_seconds: int = Field(default=7200)  # 2 h
    nvd_api_base: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str | None = Field(default=None)
    epss_sync_seconds: int = Field(default=86400)  # diario
    # Enriquecimiento incremental: solo toca filas sucias (sin sellar o
    # re-tocadas por cvelist), así que es barato encadenarlo al ritmo del
    # espejo en vez de dejar los campos derivados un día por detrás.
    enrich_sync_seconds: int = Field(default=7200)  # 2 h
    epss_api_base: str = Field(default="https://api.first.org/data/v1/epss")

    # --- Fuente GitHub commits (top-N repos, changelog últimos N meses) ---
    github_api_base: str = Field(default="https://api.github.com")
    github_token: str | None = Field(default=None)  # PAT: sube el rate limit a 5000/h
    github_top_n: int = Field(default=1000)           # nº de repos más populares a vigilar
    github_commits_months: int = Field(default=5)     # ventana relativa (fallback)
    # Cutoff FIJO de commits (YYYY-MM-DD). Si se fija, se usa en vez de la ventana
    # relativa y NO rueda con el tiempo -> el borde inferior queda anclado.
    github_commits_since: str = Field(default="2026-05-01")
    github_repos_per_run: int = Field(default=150)    # repos por ejecución (crawl incremental)
    # Política: NO sintetizar candidates GHCOMMIT desnudos (commit de seguridad sin
    # CVE/código). La ingesta los descartaría (RECOGNIZED_SCHEMES), así que no se
    # emiten. Un commit que cita un CVE/GHSA real sí entra por ese código.
    github_synthesize_candidates: bool = Field(default=False)
    github_advisories_max_pages: int = Field(default=30)  # paginación GHSA (100/pág -> ~3000)
    # Fetcher github_repo_advisories: escanea /security-advisories y /releases de
    # CADA repo del registro (los ~10k) vía REST, por lotes con marca de escaneo
    # propia (adv_last_scanned_at). per_run controla el rate limit (2 llamadas/repo
    # -> per_run*2 req/ejecución; con token el límite es 5000/h). window_days acota
    # qué se emite en el PRIMER escaneo de un repo (sin adv_watermark aún).
    # per_run: repos por ejecución. La contención de locks que antes obligaba a
    # lotes pequeños se resolvió en el runner con COMMIT PERIÓDICO
    # (_COMMIT_CHUNK en _persist_mentions): la transacción ya no retiene los locks
    # de affected_products durante todo el lote, así que un lote grande es seguro.
    # 500 repos (~5-6k menciones) cubren los ~10k del registro en ~1 día.
    github_repo_scan_per_run: int = Field(default=500)
    github_repo_scan_window_days: int = Field(default=365)
    github_repo_scan_releases_per_repo: int = Field(default=30)   # releases recientes por repo

    # --- Watchlist de repos (estrategias de relevancia más allá de las estrellas) ---
    # 1+2 (referencias de advisories / CVE previo) y 3 (distros vía refs) se derivan
    # de datos propios (siempre activas). 4 y 5 requieren fuente externa y son opt-in:
    criticality_csv_url: str | None = Field(default=None)   # CSV OpenSSF Criticality Score
    pypi_downloads_top_n: int = Field(default=0)            # >0 => top-N PyPI por descargas

    # --- VulnCheck (token gratis en vulncheck.com) ---
    vulncheck_token: str | None = Field(default=None)
    vulncheck_api_base: str = Field(default="https://api.vulncheck.com/v3")
    vulncheck_max_pages: int = Field(default=50)

    # --- Wordfence Intelligence (WP; API key gratuita en wordfence.com) ---
    wordfence_api_key: str | None = Field(default=None)

    # --- OSV.dev (ecosistemas de paquetes) ---
    osv_ecosystems: str = Field(default="PyPI,Go,crates.io,RubyGems,Packagist")
    osv_months: int = Field(default=5)          # <=0 => histórico COMPLETO (sin ventana)
    osv_max_per_ecosystem: int = Field(default=3000)  # <=0 => sin cap

    # --- Red Hat Security Data ---
    redhat_lookback_days: int = Field(default=3)  # días hacia atrás (sube para histórico)

    # --- Fetchers / scraping educado ---
    user_agent: str = Field(
        default="Foreshock/0.1 (+https://github.com/foreshock; early-CVE research)"
    )
    http_timeout_seconds: float = Field(default=30.0)
    max_retries: int = Field(default=3)
    respect_robots: bool = Field(default=True)
    browser_max_concurrent: int = Field(default=3)
    browser_recycle_after: int = Field(default=50)

    # --- Concurrencia de sources-worker ---
    # Límite de punta para el ciclo COMPLETO de una fuente (fetch + parse +
    # persistencia), no solo para la escritura en BD.
    sources_max_concurrent: int = Field(default=4, ge=1)
    # Los fetchers git crean procesos externos y compiten por disco/red.
    sources_git_max_concurrent: int = Field(default=1, ge=1)
    # Fuentes que construyen/ingieren lotes grandes (OSV, Wordfence, repos...).
    sources_heavy_max_concurrent: int = Field(default=1, ge=1)
    # Reparte la primera ejecución de las fuentes al arrancar el worker. Las
    # habilitadas en caliente siguen ejecutándose de inmediato.
    sources_startup_spread_seconds: int = Field(default=3600, ge=0)

    # --- Enriquecimiento LLM ---
    llm_provider: Literal["mock", "openai", "anthropic", "ollama"] = Field(default="mock")
    llm_model: str = Field(default="mock-model")
    llm_api_key: str | None = Field(default=None)
    llm_base_url: str | None = Field(default=None)  # p.ej. Ollama http://ollama:11434
    llm_max_tokens: int = Field(default=1024)
    enrichment_reenrich_hours: int = Field(default=24)
    enrichment_reenrich_min_mentions: int = Field(default=3)

    # --- Promoción / reconciliación ---
    emerging_min_mentions: int = Field(default=1)

    # --- Logging ---
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)


@lru_cache
def get_settings() -> Settings:
    """Settings cacheados (una sola lectura de entorno por proceso)."""
    return Settings()
