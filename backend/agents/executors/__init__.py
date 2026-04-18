"""
Agent executors package.

Contains the execution logic for each lightweight demo agent.
Each executor is responsible for processing input and generating output
using prompt-based LLM calls.
"""

from .attack_observer import AttackObserverExecutor, get_attack_observer_executor
from .telemetry_analyst import TelemetryAnalystExecutor, get_telemetry_analyst_executor
from .policy_explainer import PolicyExplainerExecutor, get_policy_explainer_executor
from .campaign_reporter import CampaignReporterExecutor, get_campaign_reporter_executor

__all__ = [
    "AttackObserverExecutor",
    "get_attack_observer_executor",
    "TelemetryAnalystExecutor",
    "get_telemetry_analyst_executor",
    "PolicyExplainerExecutor",
    "get_policy_explainer_executor",
    "CampaignReporterExecutor",
    "get_campaign_reporter_executor",
]
