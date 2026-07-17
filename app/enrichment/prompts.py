"""Plantillas de prompt para el enriquecimiento por LLM (Capa 3).

El LLM extrae METADATOS estructurados (no un score CVSS). Devuelve JSON estricto
validable contra app.enrichment.schema.EnrichmentOut.
"""

from __future__ import annotations

SYSTEM_PROMPT = """Eres un analista de vulnerabilidades. A partir de las menciones \
recopiladas sobre un CVE (o vuln aún sin CVE), extrae metadatos estructurados.

Reglas ESTRICTAS:
- Responde SOLO con un objeto JSON válido, sin texto adicional, sin markdown.
- NO inventes un score CVSS numérico. Si puedes inferir las métricas base CVSS \
(attack_vector, attack_complexity, privileges_required, user_interaction, scope, \
confidentiality, integrity, availability), inclúyelas en "cvss_metrics"; si no, \
omítelas o ponlas a null.
- Extrae productos afectados con vendor/product/ecosystem cuando se conozcan.
- "confidence" ∈ [0,1] refleja tu certeza global sobre la extracción.
- Si un dato no consta, usa null (o lista vacía). No adivines.

Esquema de salida (todas las claves opcionales salvo el objeto raíz):
{
  "affected_products": [{"vendor": str|null, "product": str, "ecosystem": str|null,
                          "versions_raw": str|null, "fixed_version": str|null}],
  "vuln_type": str|null,
  "attack_vector": "network"|"adjacent"|"local"|"physical"|null,
  "requires_auth": bool|null,
  "requires_interaction": bool|null,
  "has_public_poc": bool|null,
  "poc_urls": [str],
  "cvss_metrics": {
     "attack_vector": "network"|"adjacent"|"local"|"physical"|null,
     "attack_complexity": "low"|"high"|null,
     "privileges_required": "none"|"low"|"high"|null,
     "user_interaction": "none"|"required"|null,
     "scope": "unchanged"|"changed"|null,
     "confidentiality": "none"|"low"|"high"|null,
     "integrity": "none"|"low"|"high"|null,
     "availability": "none"|"low"|"high"|null
  }|null,
  "summary": str|null,
  "confidence": float
}
"""


def build_user_prompt(cve_id: str | None, snippets: list[str]) -> str:
    header = f"CVE: {cve_id}\n" if cve_id else "CVE: (aún sin asignar)\n"
    body = "\n\n---\n\n".join(s.strip() for s in snippets if s and s.strip())
    return (
        f"{header}\n"
        f"Menciones recopiladas ({len(snippets)}):\n\n{body}\n\n"
        "Extrae los metadatos en JSON según el esquema."
    )
