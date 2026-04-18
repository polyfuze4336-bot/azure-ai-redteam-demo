"""
Agent registry containing predefined lightweight demo agents.

This module provides the canonical definitions for all demo agents
used in the Azure AI Red Team demo experience.
"""

from datetime import datetime
from typing import Dict, List, Optional

from .models import (
    AgentDefinition,
    AgentType,
    AgentStatus,
    InputType,
)


# =============================================================================
# PREDEFINED AGENTS
# =============================================================================

PREDEFINED_AGENTS: List[AgentDefinition] = [
    AgentDefinition(
        agent_id="agent-attack-observer-001",
        agent_name="Attack Observer",
        agent_type=AgentType.ATTACK_OBSERVER,
        purpose=(
            "Narrates what happened during an attack in plain language. "
            "Explains the attack type, whether defenses activated, and the outcome. "
            "Great for walking through results during live demos."
        ),
        supported_input_types=[InputType.RUN],
        status=AgentStatus.ACTIVE,
        version="1.0.0",
        tags=["narration", "demo", "real-time"],
        config={
            "max_output_tokens": 500,
            "narration_style": "technical",
            "include_timing": True,
        },
        created_at=datetime(2026, 4, 1, 0, 0, 0),
        updated_at=datetime(2026, 4, 18, 0, 0, 0),
    ),
    AgentDefinition(
        agent_id="agent-telemetry-analyst-001",
        agent_name="Telemetry Analyst",
        agent_type=AgentType.TELEMETRY_ANALYST,
        purpose=(
            "Analyzes patterns across attack runs. "
            "Identifies trends in outcomes, latency, and defense effectiveness. "
            "Useful for spotting anomalies in red team activity."
        ),
        supported_input_types=[InputType.RUN, InputType.CAMPAIGN],
        status=AgentStatus.ACTIVE,
        version="1.0.0",
        tags=["analytics", "patterns", "insights"],
        config={
            "trend_window_hours": 24,
            "anomaly_threshold": 2.0,
            "include_comparisons": True,
        },
        created_at=datetime(2026, 4, 1, 0, 0, 0),
        updated_at=datetime(2026, 4, 18, 0, 0, 0),
    ),
    AgentDefinition(
        agent_id="agent-policy-explainer-001",
        agent_name="Policy Explainer",
        agent_type=AgentType.POLICY_EXPLAINER,
        purpose=(
            "Explains why content was blocked or allowed. "
            "Provides business-friendly explanations of Content Safety decisions. "
            "Helps stakeholders understand the verdict for each attack."
        ),
        supported_input_types=[InputType.RUN],
        status=AgentStatus.ACTIVE,
        version="1.0.0",
        tags=["explainability", "policy", "compliance"],
        config={
            "explanation_depth": "detailed",
            "include_policy_references": True,
            "audience": "technical",
        },
        created_at=datetime(2026, 4, 1, 0, 0, 0),
        updated_at=datetime(2026, 4, 18, 0, 0, 0),
    ),
    AgentDefinition(
        agent_id="agent-campaign-reporter-001",
        agent_name="Campaign Reporter",
        agent_type=AgentType.CAMPAIGN_REPORTER,
        purpose=(
            "Generates an executive summary for a completed campaign. "
            "Summarizes outcomes, defense coverage, and key observations. "
            "Ready for stakeholder presentations."
        ),
        supported_input_types=[InputType.CAMPAIGN],
        status=AgentStatus.ACTIVE,
        version="1.0.0",
        tags=["reporting", "executive", "summary"],
        config={
            "report_format": "narrative",
            "include_recommendations": True,
            "executive_summary": True,
        },
        created_at=datetime(2026, 4, 1, 0, 0, 0),
        updated_at=datetime(2026, 4, 18, 0, 0, 0),
    ),
]


# =============================================================================
# AGENT REGISTRY
# =============================================================================

class AgentRegistry:
    """
    Registry of available lightweight demo agents.
    
    Provides access to agent definitions and supports
    querying by type, status, and input compatibility.
    """
    
    _instance: Optional["AgentRegistry"] = None
    
    def __init__(self):
        self._agents: Dict[str, AgentDefinition] = {}
        self._load_predefined_agents()
    
    def _load_predefined_agents(self) -> None:
        """Load all predefined agents into the registry."""
        for agent in PREDEFINED_AGENTS:
            self._agents[agent.agent_id] = agent
    
    def get_agent(self, agent_id: str) -> Optional[AgentDefinition]:
        """Get an agent by ID."""
        return self._agents.get(agent_id)
    
    def get_agent_by_type(self, agent_type: AgentType) -> Optional[AgentDefinition]:
        """Get the first agent of a given type."""
        for agent in self._agents.values():
            if agent.agent_type == agent_type:
                return agent
        return None
    
    def list_agents(
        self, 
        status: Optional[AgentStatus] = None,
        input_type: Optional[InputType] = None,
    ) -> List[AgentDefinition]:
        """
        List agents with optional filtering.
        
        Args:
            status: Filter by agent status
            input_type: Filter by supported input type
            
        Returns:
            List of matching agent definitions
        """
        agents = list(self._agents.values())
        
        if status is not None:
            agents = [a for a in agents if a.status == status]
        
        if input_type is not None:
            agents = [a for a in agents if input_type in a.supported_input_types]
        
        return agents
    
    def get_active_agents(self) -> List[AgentDefinition]:
        """Get all active agents."""
        return self.list_agents(status=AgentStatus.ACTIVE)
    
    def get_agents_for_run(self) -> List[AgentDefinition]:
        """Get agents that can process attack runs."""
        return self.list_agents(
            status=AgentStatus.ACTIVE, 
            input_type=InputType.RUN
        )
    
    def get_agents_for_campaign(self) -> List[AgentDefinition]:
        """Get agents that can process campaigns."""
        return self.list_agents(
            status=AgentStatus.ACTIVE, 
            input_type=InputType.CAMPAIGN
        )
    
    def count_active(self) -> int:
        """Count active agents."""
        return len(self.get_active_agents())
    
    def count_total(self) -> int:
        """Count total agents."""
        return len(self._agents)


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_registry_instance: Optional[AgentRegistry] = None


def get_agent_registry() -> AgentRegistry:
    """Get the singleton agent registry instance."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = AgentRegistry()
    return _registry_instance
