"""Configuración central de CVERadar (pydantic-settings).

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
        env_prefix="CVERADAR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Base de datos / infra ---
    database_url: str = Field(
        default="postgresql+psycopg://cveradar:cveradar@localhost:5432/cveradar",
        validation_alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")

    # --- Almacenamiento de datos crudos y clon de cvelistV5 ---
    data_dir: str = Field(default="/data")  # raw_html, cache
    raw_html_dir: str = Field(default="/data/raw")
    cvelist_repo_dir: str = Field(default="/data/cvelistV5")

    # --- Baseline ---
    cvelist_repo_url: str = Field(default="https://github.com/CVEProject/cvelistV5.git")
    cvelist_sync_seconds: int = Field(default=900)  # 15 min
    nvd_delta_seconds: int = Field(default=7200)  # 2 h
    nvd_api_base: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str | None = Field(default=None)
    epss_sync_seconds: int = Field(default=86400)  # diario
    epss_api_base: str = Field(default="https://api.first.org/data/v1/epss")

    # --- Fuente GitHub commits (top-N repos, changelog últimos N meses) ---
    github_api_base: str = Field(default="https://api.github.com")
    github_token: str | None = Field(default=None)  # PAT: sube el rate limit a 5000/h
    github_top_n: int = Field(default=10000)          # nº de repos más populares a vigilar
    github_commits_months: int = Field(default=5)     # ventana de changelog a escanear
    github_repos_per_run: int = Field(default=150)    # repos por ejecución (crawl incremental)
    github_synthesize_candidates: bool = Field(default=True)  # candidate pre-CVE en fixes sin CVE

    # --- Fetchers / scraping educado ---
    user_agent: str = Field(
        default="CVERadar/0.1 (+https://github.com/cveradar; early-CVE research)"
    )
    http_timeout_seconds: float = Field(default=30.0)
    max_retries: int = Field(default=3)
    respect_robots: bool = Field(default=True)
    browser_max_concurrent: int = Field(default=3)
    browser_recycle_after: int = Field(default=50)

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
