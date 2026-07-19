"""Proveedor LLM configurable para el enriquecimiento (Capa 3).

Diseño provider-neutral (mock | openai | anthropic | ollama) sobre httpx, para
no acoplar el proyecto a un SDK concreto. El default es 'mock': funciona sin
API key y produce una extracción determinista por heurística, para desarrollo
y tests. Toda salida se valida contra EnrichmentOut (Pydantic estricto).
"""

from __future__ import annotations

import abc
import json
import re

import httpx

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.enrichment.prompts import SYSTEM_PROMPT, build_user_prompt
from app.enrichment.schema import EnrichmentOut

log = get_logger(__name__)


class LLMProvider(abc.ABC):
    """Devuelve texto (idealmente JSON) a partir de system+user."""

    @abc.abstractmethod
    async def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class MockProvider(LLMProvider):
    """Extracción heurística determinista (sin red). Útil sin API key y en tests."""

    # \b en AMBAS ramas de cada alternancia: sin él, "mysqli" casaba _SQLI y
    # cualquier sufijo tipo "xss..." casaba _XSS por precedencia de la alternancia.
    _RCE = re.compile(r"\b(rce|remote code execution|code execution)\b", re.I)
    _SQLI = re.compile(r"\b(?:sql[\s-]?injection|sqli)\b", re.I)
    _XSS = re.compile(r"\b(?:xss|cross[\s-]?site scripting)\b", re.I)
    _AUTHB = re.compile(r"\bauth(entication)?\s*bypass\b", re.I)
    _POC = re.compile(r"\b(poc|proof[\s-]?of[\s-]?concept|exploit)\b", re.I)
    _URL = re.compile(r"https?://\S+")

    async def complete(self, system: str, user: str) -> str:
        text = user
        vuln_type = None
        if self._RCE.search(text):
            vuln_type = "RCE"
        elif self._AUTHB.search(text):
            vuln_type = "AuthBypass"
        elif self._SQLI.search(text):
            vuln_type = "SQLi"
        elif self._XSS.search(text):
            vuln_type = "XSS"
        has_poc = bool(self._POC.search(text))
        # heurística de vector: "remote"/"network" -> network
        av = "network" if re.search(r"\b(remote|network|unauthenticated)\b", text, re.I) else None
        out = {
            "affected_products": [],
            "vuln_type": vuln_type,
            "attack_vector": av,
            "requires_auth": False if re.search(r"unauthenticated", text, re.I) else None,
            "requires_interaction": None,
            "has_public_poc": has_poc,
            "poc_urls": self._URL.findall(text)[:5],
            "cvss_metrics": None,
            "summary": None,
            "confidence": 0.35,  # baja: es heurística, no un LLM real
        }
        return json.dumps(out)


class OpenAIProvider(LLMProvider):
    def __init__(self, settings: Settings):
        self._s = settings

    async def complete(self, system: str, user: str) -> str:
        base = self._s.llm_base_url or "https://api.openai.com/v1"
        async with httpx.AsyncClient(timeout=self._s.http_timeout_seconds) as client:
            resp = await client.post(
                f"{base}/chat/completions",
                headers={"Authorization": f"Bearer {self._s.llm_api_key}"},
                json={
                    "model": self._s.llm_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "response_format": {"type": "json_object"},
                    "max_tokens": self._s.llm_max_tokens,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


class AnthropicProvider(LLMProvider):
    """Messages API de Anthropic (https://api.anthropic.com/v1/messages)."""

    def __init__(self, settings: Settings):
        self._s = settings

    async def complete(self, system: str, user: str) -> str:
        base = self._s.llm_base_url or "https://api.anthropic.com"
        async with httpx.AsyncClient(timeout=self._s.http_timeout_seconds) as client:
            resp = await client.post(
                f"{base}/v1/messages",
                headers={
                    "x-api-key": self._s.llm_api_key or "",
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self._s.llm_model,
                    "max_tokens": self._s.llm_max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
            )
            resp.raise_for_status()
            # content es una lista de bloques; tomamos el primer texto.
            for block in resp.json().get("content", []):
                if block.get("type") == "text":
                    return block["text"]
            return "{}"


class OllamaProvider(LLMProvider):
    """Ollama local (http://host:11434). Formato JSON forzado."""

    def __init__(self, settings: Settings):
        self._s = settings

    async def complete(self, system: str, user: str) -> str:
        base = self._s.llm_base_url or "http://localhost:11434"
        async with httpx.AsyncClient(timeout=self._s.http_timeout_seconds) as client:
            resp = await client.post(
                f"{base}/api/chat",
                json={
                    "model": self._s.llm_model,
                    "format": "json",
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]


def get_provider(settings: Settings | None = None) -> LLMProvider:
    settings = settings or get_settings()
    match settings.llm_provider:
        case "openai":
            return OpenAIProvider(settings)
        case "anthropic":
            return AnthropicProvider(settings)
        case "ollama":
            return OllamaProvider(settings)
        case _:
            return MockProvider()


def _extract_json(text: str) -> dict:
    """Extrae el primer objeto JSON del texto (tolera envoltorios de markdown)."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?|\n?```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise


async def enrich(cve_id: str | None, snippets: list[str],
                 provider: LLMProvider | None = None) -> tuple[EnrichmentOut, str]:
    """Ejecuta el enriquecimiento. Devuelve (resultado validado, método)."""
    settings = get_settings()
    if provider is None:
        provider = get_provider(settings)
        method = f"{settings.llm_provider}:{settings.llm_model}"
    else:
        # Provider inyectado (tests, CLI): etiqueta con el provider REAL usado,
        # no con el de settings, para que enrichment_method no mienta.
        method = provider.__class__.__name__.removesuffix("Provider").lower()
    raw = await provider.complete(SYSTEM_PROMPT, build_user_prompt(cve_id, snippets))
    data = _extract_json(raw)
    return EnrichmentOut.model_validate(data), method
