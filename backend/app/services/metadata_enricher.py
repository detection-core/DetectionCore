"""
AI-powered metadata enrichment: extracts/verifies MITRE techniques,
adds author attribution, criticality rationale, and public reference URLs.
"""
import logging
import json
from app.services.ai_provider import AIProvider

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a threat intelligence analyst with deep knowledge of MITRE ATT&CK framework.
Analyze detection rules and extract accurate metadata."""

ENRICHMENT_PROMPT = """Analyze this detection rule and extract/verify metadata.

Rule Title: {title}
SIGMA Content:
{sigma_content}

Existing MITRE Technique IDs: {mitre_ids}
Existing threat actors: {threat_actors}
Existing targeted industries: {industries}

Provide enriched metadata in this exact JSON format:
{{
  "verified_mitre_ids": ["T1059.001", "T1053"],
  "mitre_tactic": "Execution",
  "criticality_rationale": "<why this severity makes sense>",
  "detection_author": "DetectionCore",
  "public_references": ["<url1>", "<url2>"],
  "false_negative_risk": "low|medium|high",
  "deployment_notes": "<important notes for deploying this rule>"
}}

Only include verified MITRE technique IDs that match the detection logic.
Only include real, public URLs if you are certain they exist."""


async def enrich_metadata(
    title: str,
    sigma_content: str,
    mitre_ids: list[str],
    threat_actors: list[str],
    targeted_industries: list[str],
) -> dict:
    """Use AI to enrich and verify rule metadata."""
    provider = AIProvider()
    prompt = ENRICHMENT_PROMPT.format(
        title=title,
        sigma_content=sigma_content,
        mitre_ids=", ".join(mitre_ids) if mitre_ids else "None",
        threat_actors=", ".join(threat_actors) if threat_actors else "Unknown",
        industries=", ".join(targeted_industries) if targeted_industries else "Unknown",
    )
    try:
        response = await provider.complete(prompt, system=SYSTEM_PROMPT)
        cleaned = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return json.loads(cleaned)
    except Exception as e:
        logger.error(f"Metadata enrichment failed for '{title}': {e}")
        return {
            "verified_mitre_ids": mitre_ids,
            "mitre_tactic": None,
            "criticality_rationale": "Requires manual review",
            "detection_author": "DetectionCore",
            "public_references": [],
            "false_negative_risk": "medium",
            "deployment_notes": "AI enrichment unavailable - manual review required",
        }
