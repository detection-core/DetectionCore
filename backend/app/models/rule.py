from beanie import Document
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum


class PipelineStatus(str, Enum):
    SYNCED = "synced"
    CONVERTED = "converted"
    ENHANCED = "enhanced"
    TESTED = "tested"
    SCORED = "scored"
    QUEUED = "queued"
    IMPLEMENTED = "implemented"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class TestType(str, Enum):
    POWERSHELL = "powershell"
    BASH = "bash"
    CURL = "curl"
    PYTHON = "python"
    MANUAL = "manual"


class TestResult(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"


class UnitTest(BaseModel):
    test_id: str = Field(default_factory=lambda: __import__("uuid").uuid4().hex[:8])
    test_type: TestType
    command: str
    description: str
    expected_alert_fired: bool = True
    last_run_at: Optional[datetime] = None
    last_run_result: TestResult = TestResult.NOT_RUN
    last_run_output: Optional[str] = None


class ScoringResult(BaseModel):
    total_score: float = 0.0
    log_availability: float = 0.0
    industry_match: float = 0.0
    region_match: float = 0.0
    severity_score: float = 0.0
    threat_actor_score: float = 0.0
    asset_type_score: float = 0.0
    computed_at: Optional[datetime] = None
    manually_overridden: bool = False
    override_value: Optional[float] = None


class ELKDeployment(BaseModel):
    deployed: bool = False
    rule_id_elk: Optional[str] = None
    index_pattern: Optional[str] = None
    deployed_at: Optional[datetime] = None
    last_error: Optional[str] = None


class DetectionRule(Document):
    # Source metadata
    sigma_rule_id: str  # ID from DetectionHub
    title: str
    description: Optional[str] = None
    tags: list[str] = []

    # Rule content
    sigma_content: str  # Raw SIGMA YAML
    elk_query: Optional[str] = None  # Converted ELK query (KQL/Lucene)
    elk_rule_json: Optional[dict] = None  # Full ELK alert rule JSON

    # Pipeline
    pipeline_status: PipelineStatus = PipelineStatus.SYNCED
    pipeline_error: Optional[str] = None

    # Classification
    severity: Severity = Severity.MEDIUM
    mitre_technique_ids: list[str] = []
    mitre_tactic: Optional[str] = None

    # Log source
    log_source_category: Optional[str] = None
    log_source_product: Optional[str] = None
    log_source_service: Optional[str] = None
    log_source_available: bool = False  # Resolved against uploaded log sources
    log_source_match_type: Optional[str] = None  # "exact", "partial", "product", or None

    # Threat context (from DetectionHub)
    threat_actors: list[str] = []
    malware_families: list[str] = []
    targeted_industries: list[str] = []
    targeted_regions: list[str] = []
    reference_urls: list[str] = []

    # AI outputs
    ai_enhancement_notes: Optional[str] = None
    unit_tests: list[UnitTest] = []
    ai_metadata_author: Optional[str] = None

    # Scoring
    scoring: ScoringResult = Field(default_factory=ScoringResult)

    # ELK deployment
    elk_deployment: ELKDeployment = Field(default_factory=ELKDeployment)

    # Timestamps
    synced_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "detection_rules"
        indexes = [
            "sigma_rule_id",
            "pipeline_status",
            "severity",
            "mitre_technique_ids",
            "scoring.total_score",
        ]
