"""
Generates unit test attack simulation commands for detection rules.
Unit tests are executable commands (PowerShell, bash, curl, etc.) that
when run against the target environment, should produce log events that
trigger the converted ELK detection rule.
"""
import logging
import json
from app.services.ai_provider import AIProvider
from app.models.rule import UnitTest, TestType

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a red team operator and detection engineer.
Your job is to generate realistic attack simulation commands that test whether
a SIEM detection rule fires correctly. Commands must be safe for use in isolated
lab environments and accurately simulate the described attack technique.
Do NOT generate commands that could cause irreversible damage (e.g., rm -rf /, format disk).
Favor PowerShell for Windows techniques, bash for Linux, and curl for network-based detections."""

TEST_GEN_PROMPT = """Generate unit test attack simulation commands for this detection rule.

Rule Title: {title}
Severity: {severity}
MITRE Techniques: {mitre_ids}
ELK Query: {elk_query}

SIGMA Detection Logic:
{sigma_content}

Generate 2-3 test cases that would trigger this rule when executed in a lab environment.
Each test should be a realistic attack simulation that produces the log events the rule detects.

Respond in this exact JSON format:
{{
  "tests": [
    {{
      "test_type": "powershell|bash|curl|python|manual",
      "command": "<the exact command to run>",
      "description": "<what attack this simulates and what log event it creates>",
      "expected_alert_fired": true
    }}
  ]
}}

If the technique cannot be safely simulated, use type "manual" and provide step-by-step instructions."""


async def generate_unit_tests(
    title: str,
    sigma_content: str,
    elk_query: str,
    severity: str,
    mitre_ids: list[str],
) -> list[UnitTest]:
    """Generate AI-powered unit test attack commands for a rule."""
    provider = AIProvider()
    prompt = TEST_GEN_PROMPT.format(
        title=title,
        sigma_content=sigma_content,
        elk_query=elk_query,
        severity=severity,
        mitre_ids=", ".join(mitre_ids) if mitre_ids else "N/A",
    )
    try:
        response = await provider.complete(prompt, system=SYSTEM_PROMPT)
        cleaned = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        data = json.loads(cleaned)
        tests = []
        for t in data.get("tests", []):
            test_type_str = t.get("test_type", "manual").lower()
            test_type = TestType(test_type_str) if test_type_str in TestType.__members__.values() else TestType.MANUAL
            tests.append(UnitTest(
                test_type=test_type,
                command=t.get("command", ""),
                description=t.get("description", ""),
                expected_alert_fired=t.get("expected_alert_fired", True),
            ))
        return tests
    except Exception as e:
        logger.error(f"Unit test generation failed for '{title}': {e}")
        return [UnitTest(
            test_type=TestType.MANUAL,
            command="# AI generation unavailable - manual test required",
            description=f"Manual testing required. Rule detects: {title}",
            expected_alert_fired=True,
        )]
