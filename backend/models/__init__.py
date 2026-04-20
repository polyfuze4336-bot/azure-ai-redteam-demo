"""
Pydantic models for the Azure AI Red Team API.
"""

from .schemas import (
    AttackCategory,
    Severity,
    VerdictResult,
    Outcome,
    VerdictDetail,
    AttackScenario,
    AttackRequest,
    CampaignRequest,
    AttackResult,
    CampaignResult,
    HealthResponse,
    HistoryResponse,
    # Purview Governance Event Models
    PurviewEventType,
    PurviewPolicyAction,
    PurviewEventStatus,
    PurviewEventSource,
    PurviewGovernanceEvent,
    PurviewEventFilter,
    PurviewEventResponse,
    PurviewIngestionStatus,
    PurviewCorrelationStats,
    # Purview Correlation Models
    PurviewCorrelationMethod,
    PurviewEventCorrelation,
    LinkedPurviewEvent,
    PurviewCorrelationRequest,
    PurviewCorrelationResult,
    # Shared Correlation Models
    CorrelationConfidence,
    # Unified Run Details View Models
    AgentContextSnapshot,
    PolicyProfileSnapshot,
    PurviewGovernanceSnapshot,
    RuntimeResultSnapshot,
    LinkedAlertSummary,
    LinkedGovernanceEventSummary,
    StorylineSummary,
    UnifiedRunDetails,
)

__all__ = [
    "AttackCategory",
    "Severity",
    "VerdictResult",
    "Outcome",
    "VerdictDetail",
    "AttackScenario",
    "AttackRequest",
    "CampaignRequest",
    "AttackResult",
    "CampaignResult",
    "HealthResponse",
    "HistoryResponse",
    # Purview Governance Event Models
    "PurviewEventType",
    "PurviewPolicyAction",
    "PurviewEventStatus",
    "PurviewEventSource",
    "PurviewGovernanceEvent",
    "PurviewEventFilter",
    "PurviewEventResponse",
    "PurviewIngestionStatus",
    "PurviewCorrelationStats",
    # Purview Correlation Models
    "PurviewCorrelationMethod",
    "PurviewEventCorrelation",
    "LinkedPurviewEvent",
    "PurviewCorrelationRequest",
    "PurviewCorrelationResult",
    # Shared Correlation Models
    "CorrelationConfidence",
    # Unified Run Details View Models
    "AgentContextSnapshot",
    "PolicyProfileSnapshot",
    "PurviewGovernanceSnapshot",
    "RuntimeResultSnapshot",
    "LinkedAlertSummary",
    "LinkedGovernanceEventSummary",
    "StorylineSummary",
    "UnifiedRunDetails",
]
