"""
Scoring engine: calculates a relevance score for each rule
based on client context and rule metadata.
Score range: 0.0 - 100.0
"""
import logging
from datetime import datetime, timezone
from app.models.rule import DetectionRule, ScoringResult, Severity
from app.models.scoring_config import ScoringConfig
from app.models.log_source import LogSource

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 75.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 25.0,
    Severity.INFORMATIONAL: 5.0,
}


async def score_rule(rule: DetectionRule) -> ScoringResult:
    """Calculate a weighted relevance score for a rule."""
    config = await ScoringConfig.find_one()
    if not config:
        config = ScoringConfig()

    # Don't override manual overrides
    if rule.scoring.manually_overridden and rule.scoring.override_value is not None:
        result = rule.scoring
        result.total_score = rule.scoring.override_value
        return result

    # 1. Log availability (30% by default)
    log_availability = await _score_log_availability(rule)

    # 2. Industry match (20%)
    industry_match = _score_industry(rule, config)

    # 3. Region match (15%)
    region_match = _score_region(rule, config)

    # 4. Severity (20%)
    severity_score = SEVERITY_SCORES.get(rule.severity, 50.0)

    # 5. Threat actor relevance (10%)
    threat_actor_score = _score_threat_actor(rule, config)

    # 6. Asset type (5%)
    asset_type_score = _score_asset_type(rule, config)

    # Weighted total
    total = (
        log_availability * (config.weight_log_availability / 100)
        + industry_match * (config.weight_industry_match / 100)
        + region_match * (config.weight_region_match / 100)
        + severity_score * (config.weight_severity / 100)
        + threat_actor_score * (config.weight_threat_actor / 100)
        + asset_type_score * (config.weight_asset_type / 100)
    )
    total = min(100.0, max(0.0, total))

    return ScoringResult(
        total_score=round(total, 2),
        log_availability=round(log_availability, 2),
        industry_match=round(industry_match, 2),
        region_match=round(region_match, 2),
        severity_score=round(severity_score, 2),
        threat_actor_score=round(threat_actor_score, 2),
        asset_type_score=round(asset_type_score, 2),
        computed_at=datetime.now(timezone.utc),
        manually_overridden=False,
    )


async def _score_log_availability(rule: DetectionRule) -> float:
    """Check if the required log source is available in the client's ELK."""
    if not rule.log_source_category and not rule.log_source_product:
        return 50.0  # Unknown — neutral score

    filters = []
    if rule.log_source_category:
        filters.append(LogSource.category == rule.log_source_category)
    if rule.log_source_product:
        filters.append(LogSource.product == rule.log_source_product)

    log_source = await LogSource.find_one(LogSource.is_available == True, *filters)
    if log_source:
        return 100.0
    # Check if it exists but is marked unavailable
    any_source = await LogSource.find_one(*filters)
    return 0.0 if any_source else 50.0


def _score_industry(rule: DetectionRule, config: ScoringConfig) -> float:
    if not config.client_industry or not rule.targeted_industries:
        return 50.0
    client_industry = config.client_industry.lower()
    for ind in rule.targeted_industries:
        if client_industry in ind.lower() or ind.lower() in client_industry:
            return 100.0
    return 10.0  # Not targeted at client industry but still relevant


def _score_region(rule: DetectionRule, config: ScoringConfig) -> float:
    if not config.client_regions or not rule.targeted_regions:
        return 50.0
    client_regions_lower = [r.lower() for r in config.client_regions]
    for region in rule.targeted_regions:
        if any(r in region.lower() or region.lower() in r for r in client_regions_lower):
            return 100.0
    return 10.0


def _score_threat_actor(rule: DetectionRule, config: ScoringConfig) -> float:
    if not config.threat_actor_watchlist or not rule.threat_actors:
        return 50.0
    watchlist_lower = [t.lower() for t in config.threat_actor_watchlist]
    for actor in rule.threat_actors:
        if actor.lower() in watchlist_lower:
            return 100.0
    return 25.0


def _score_asset_type(rule: DetectionRule, config: ScoringConfig) -> float:
    # Asset type scoring based on log source product matching asset types
    if not config.client_asset_types:
        return 50.0
    product = (rule.log_source_product or "").lower()
    for asset in config.client_asset_types:
        if asset.lower() in product or product in asset.lower():
            return 100.0
    return 25.0
