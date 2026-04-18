"""
Lightweight demo agents for observability, explanation, and storytelling.

This module provides narrow-purpose agents that can be invoked, monitored,
and traced as part of the Azure AI Red Team demo experience.
"""

from .models import (
    AgentType,
    InputType,
    AgentStatus,
    InvocationStatus,
    AgentDefinition,
    AgentInvocation,
    AgentInvocationRequest,
)
from .registry import get_agent_registry, AgentRegistry
from .store import get_agent_store, AgentInvocationStore
from .service import get_agent_service, AgentService
from .executors import (
    AttackObserverExecutor,
    get_attack_observer_executor,
    TelemetryAnalystExecutor,
    get_telemetry_analyst_executor,
    PolicyExplainerExecutor,
    get_policy_explainer_executor,
    CampaignReporterExecutor,
    get_campaign_reporter_executor,
)
from .executors.attack_observer import AttackObservation
from .executors.telemetry_analyst import TelemetrySummary, PatternInsight
from .executors.policy_explainer import PolicyExplanation, MitigationNote
from .executors.campaign_reporter import CampaignReport, KeyObservation

__all__ = [
    # Enums
    "AgentType",
    "InputType",
    "AgentStatus",
    "InvocationStatus",
    # Models
    "AgentDefinition",
    "AgentInvocation",
    "AgentInvocationRequest",
    # Registry
    "get_agent_registry",
    "AgentRegistry",
    # Store
    "get_agent_store",
    "AgentInvocationStore",
    # Service
    "get_agent_service",
    "AgentService",
    # Executors - Attack Observer
    "AttackObserverExecutor",
    "get_attack_observer_executor",
    "AttackObservation",
    # Executors - Telemetry Analyst
    "TelemetryAnalystExecutor",
    "get_telemetry_analyst_executor",
    "TelemetrySummary",
    "PatternInsight",
    # Executors - Policy Explainer
    "PolicyExplainerExecutor",
    "get_policy_explainer_executor",
    "PolicyExplanation",
    "MitigationNote",
    # Executors - Campaign Reporter
    "CampaignReporterExecutor",
    "get_campaign_reporter_executor",
    "CampaignReport",
    "KeyObservation",
]
