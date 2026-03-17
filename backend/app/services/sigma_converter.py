"""
Converts SIGMA rules to ELK (Elasticsearch) queries using pySigma.
"""
import logging
import yaml
from typing import Optional

logger = logging.getLogger(__name__)


class SigmaConversionResult:
    def __init__(
        self,
        elk_query: Optional[str] = None,
        elk_rule_json: Optional[dict] = None,
        error: Optional[str] = None,
    ):
        self.elk_query = elk_query
        self.elk_rule_json = elk_rule_json
        self.error = error
        self.success = error is None and elk_query is not None


def convert_sigma_to_elk(sigma_yaml: str) -> SigmaConversionResult:
    """
    Convert a SIGMA rule YAML string to ELK query + full alert rule JSON.
    Uses pySigma with the Elasticsearch backend.
    """
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.processing.resolver import ProcessingPipelineResolver

        # Parse and convert
        rules = SigmaCollection.from_yaml(sigma_yaml)
        backend = LuceneBackend()
        queries = backend.convert(rules)

        if not queries:
            return SigmaConversionResult(error="Conversion produced no output")

        elk_query = queries[0] if isinstance(queries[0], str) else str(queries[0])

        # Parse SIGMA YAML to extract metadata for ELK rule JSON
        parsed = yaml.safe_load(sigma_yaml)
        elk_rule_json = _build_elk_alert_rule(parsed, elk_query)

        return SigmaConversionResult(elk_query=elk_query, elk_rule_json=elk_rule_json)

    except ImportError:
        # pySigma not installed - fallback to basic conversion
        logger.warning("pySigma not available, using fallback converter")
        return _fallback_convert(sigma_yaml)
    except Exception as e:
        logger.error(f"SIGMA conversion error: {e}")
        return SigmaConversionResult(error=str(e))


def _build_elk_alert_rule(parsed: dict, elk_query: str) -> dict:
    """Build an Elasticsearch detection alert rule JSON."""
    name = parsed.get("title", "Untitled Detection Rule")
    description = parsed.get("description", "")
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "low",
    }
    raw_level = str(parsed.get("level", "medium")).lower()
    severity = severity_map.get(raw_level, "medium")

    log_source = parsed.get("logsource", {})
    index_patterns = _resolve_index_patterns(log_source)

    tags = parsed.get("tags", []) or []
    threat_entries = _build_threat_entries(tags)

    return {
        "name": name,
        "description": description,
        "risk_score": _severity_to_risk_score(severity),
        "severity": severity,
        "enabled": False,  # Start disabled, analyst enables after review
        "type": "query",
        "language": "lucene",
        "query": elk_query,
        "index": index_patterns,
        "interval": "5m",
        "from": "now-6m",
        "max_signals": 100,
        "tags": tags,
        "threat": threat_entries,
        "references": parsed.get("references", []) or [],
        "author": _ensure_list(parsed.get("author", "DetectionCore")),
        "license": "DRL",
        "rule_id": f"dc-{__import__('uuid').uuid4().hex[:8]}",
        "version": 1,
    }


def _resolve_index_patterns(log_source: dict) -> list[str]:
    """Map SIGMA logsource to ELK index patterns."""
    product = str(log_source.get("product", "")).lower()
    category = str(log_source.get("category", "")).lower()
    service = str(log_source.get("service", "")).lower()

    patterns = []

    if product == "windows":
        if category == "process_creation":
            patterns = ["winlogbeat-*", "logs-endpoint.events.process-*"]
        elif category == "file_event":
            patterns = ["winlogbeat-*", "logs-endpoint.events.file-*"]
        elif category == "network_connection":
            patterns = ["winlogbeat-*", "logs-endpoint.events.network-*"]
        elif service == "security":
            patterns = ["winlogbeat-*", "logs-system.security-*"]
        elif service == "sysmon":
            patterns = ["winlogbeat-*"]
        else:
            patterns = ["winlogbeat-*", "logs-windows.*"]
    elif product == "linux":
        patterns = ["auditbeat-*", "logs-endpoint.events.*"]
    elif product == "azure":
        patterns = ["logs-azure.*"]
    elif product == "aws":
        patterns = ["logs-aws.*"]
    elif category == "webserver":
        patterns = ["filebeat-*", "logs-nginx.*", "logs-apache.*"]
    else:
        patterns = ["*"]

    return patterns


def _severity_to_risk_score(severity: str) -> int:
    return {"critical": 99, "high": 73, "medium": 47, "low": 21}.get(severity, 47)


def _ensure_list(value) -> list:
    if isinstance(value, list):
        return value
    return [value] if value else ["DetectionCore"]


def _build_threat_entries(tags: list[str]) -> list[dict]:
    """Build ECS threat entries from SIGMA ATT&CK tags."""
    technique_ids = [
        t.replace("attack.", "").upper()
        for t in tags
        if t.lower().startswith("attack.t")
    ]
    tactic_tags = [
        t.replace("attack.", "").replace("_", " ").title()
        for t in tags
        if t.lower().startswith("attack.") and not t.lower().replace("attack.", "").startswith("t")
    ]
    tactic_name = tactic_tags[0] if tactic_tags else "Defense Evasion"
    tactic_id = tactic_name.lower().replace(" ", "-")

    if not technique_ids:
        return []
    return [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": tactic_id,
                "name": tactic_name,
                "reference": f"https://attack.mitre.org/tactics/{tactic_id}/",
            },
            "technique": [{"id": tid, "name": tid, "reference": f"https://attack.mitre.org/techniques/{tid}/"}],
        }
        for tid in technique_ids
    ]


def _fallback_convert(sigma_yaml: str) -> SigmaConversionResult:
    """Minimal fallback when pySigma is unavailable — extracts keywords."""
    try:
        parsed = yaml.safe_load(sigma_yaml)
        detection = parsed.get("detection", {})
        # Extract simple keyword searches
        keywords = []
        for key, val in detection.items():
            if key == "condition":
                continue
            if isinstance(val, list):
                keywords.extend([str(v) for v in val])
            elif isinstance(val, dict):
                for field, fval in val.items():
                    if isinstance(fval, list):
                        keywords.extend([f"{field}:{v}" for v in fval])
                    else:
                        keywords.append(f"{field}:{fval}")

        query = " OR ".join(keywords[:10]) if keywords else "*"
        elk_rule_json = _build_elk_alert_rule(parsed, query)
        return SigmaConversionResult(elk_query=query, elk_rule_json=elk_rule_json)
    except Exception as e:
        return SigmaConversionResult(error=f"Fallback conversion failed: {e}")
