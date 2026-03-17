"""
Phase 2 AI Enhancement: improves the converted ELK rule to reduce
false positives and improve detection fidelity.
"""
import logging
from app.services.ai_provider import AIProvider

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert detection engineer specializing in ELK/Elasticsearch SIEM rules.
Your task is to analyze and improve detection rules to maximize signal quality while minimizing false positives.
Be concise and technical. Output valid JSON or plain text as instructed."""

ENHANCEMENT_PROMPT = """You are reviewing a detection rule converted from SIGMA format to Elasticsearch Lucene query.

SIGMA Rule (original):
{sigma_content}

Converted ELK Query:
{elk_query}

Rule Title: {title}
Severity: {severity}
MITRE Techniques: {mitre_ids}

Please analyze this rule and provide:
1. Assessment of the query quality (false positive risk, coverage gaps)
2. Specific improvements to the Lucene query if needed (return improved query or state "no changes")
3. Recommended tuning notes for analysts implementing this rule

Respond in this exact JSON format:
{{
  "improved_query": "<improved lucene query or null if no changes>",
  "quality_score": <1-10>,
  "false_positive_risk": "low|medium|high",
  "enhancement_notes": "<concise technical notes>",
  "tuning_recommendations": "<practical tuning advice for analysts>"
}}"""


async def enhance_rule(
    sigma_content: str,
    elk_query: str,
    title: str,
    severity: str,
    mitre_ids: list[str],
) -> dict:
    """
    Use AI to enhance a converted ELK rule.
    Returns a dict with improved_query, enhancement_notes, etc.
    """
    provider = AIProvider()
    prompt = ENHANCEMENT_PROMPT.format(
        sigma_content=sigma_content,
        elk_query=elk_query,
        title=title,
        severity=severity,
        mitre_ids=", ".join(mitre_ids) if mitre_ids else "N/A",
    )
    try:
        response = await provider.complete(prompt, system=SYSTEM_PROMPT)
        import json
        # Strip markdown code fences if present
        cleaned = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return json.loads(cleaned)
    except Exception as e:
        logger.error(f"AI enhancement failed: {e}")
        return {
            "improved_query": None,
            "quality_score": 5,
            "false_positive_risk": "medium",
            "enhancement_notes": f"AI enhancement unavailable: {e}",
            "tuning_recommendations": "Manual review recommended.",
        }
