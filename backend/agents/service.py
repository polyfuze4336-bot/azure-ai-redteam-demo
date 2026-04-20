"""
Agent service for managing agent invocations.

Provides the service layer for invoking agents, tracking invocations,
and retrieving agent metadata.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import uuid

from models.schemas import AttackResult, CampaignResult
from telemetry import get_telemetry_service, get_logger

from .models import (
    AgentDefinition,
    AgentInvocation,
    AgentInvocationRequest,
    AgentType,
    AgentStatus,
    InputType,
    InvocationStatus,
    AgentListResponse,
    InvocationListResponse,
    InvocationSummary,
)
from .registry import get_agent_registry, AgentRegistry
from .store import get_agent_store, AgentInvocationStore
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
from .executors.telemetry_analyst import TelemetrySummary
from .executors.policy_explainer import PolicyExplanation
from .executors.campaign_reporter import CampaignReport


# Module-level logger for agent service
logger = get_logger("agents.service")


class AgentService:
    """
    Service for managing lightweight demo agents.
    
    Provides methods for listing agents, creating invocations,
    and querying invocation history.
    """
    
    _instance: Optional["AgentService"] = None
    
    def __init__(
        self, 
        registry: Optional[AgentRegistry] = None,
        store: Optional[AgentInvocationStore] = None,
    ):
        """
        Initialize the agent service.
        
        Args:
            registry: Agent registry (uses singleton if not provided)
            store: Invocation store (uses singleton if not provided)
        """
        self._registry = registry or get_agent_registry()
        self._store = store or get_agent_store()
    
    # =========================================================================
    # AGENT QUERIES
    # =========================================================================
    
    def get_agent(self, agent_id: str) -> Optional[AgentDefinition]:
        """Get an agent by ID."""
        return self._registry.get_agent(agent_id)
    
    def get_agent_by_type(self, agent_type: AgentType) -> Optional[AgentDefinition]:
        """Get an agent by type."""
        return self._registry.get_agent_by_type(agent_type)
    
    def list_agents(
        self,
        status: Optional[AgentStatus] = None,
        input_type: Optional[InputType] = None,
    ) -> AgentListResponse:
        """
        List available agents with optional filtering.
        
        Args:
            status: Filter by status
            input_type: Filter by supported input type
            
        Returns:
            List response with agents and counts
        """
        agents = self._registry.list_agents(status=status, input_type=input_type)
        active_count = sum(1 for a in agents if a.status == AgentStatus.ACTIVE)
        
        return AgentListResponse(
            agents=agents,
            total=len(agents),
            active_count=active_count,
        )
    
    def get_agents_for_run(self) -> List[AgentDefinition]:
        """Get agents that can process attack runs."""
        return self._registry.get_agents_for_run()
    
    def get_agents_for_campaign(self) -> List[AgentDefinition]:
        """Get agents that can process campaigns."""
        return self._registry.get_agents_for_campaign()
    
    # =========================================================================
    # INVOCATION MANAGEMENT
    # =========================================================================
    
    def create_invocation(
        self,
        request: AgentInvocationRequest,
        input_summary: Optional[str] = None,
    ) -> AgentInvocation:
        """
        Create a new agent invocation record.
        
        Args:
            request: The invocation request
            input_summary: Brief summary of the input
            
        Returns:
            The created invocation record
            
        Raises:
            ValueError: If agent not found or input invalid
        """
        # Validate agent exists
        agent = self._registry.get_agent(request.agent_id)
        if agent is None:
            raise ValueError(f"Agent not found: {request.agent_id}")
        
        # Validate agent is active
        if agent.status != AgentStatus.ACTIVE:
            raise ValueError(f"Agent is not active: {agent.agent_name}")
        
        # Validate input type compatibility
        if request.linked_run_id and InputType.RUN not in agent.supported_input_types:
            raise ValueError(f"Agent does not support run input: {agent.agent_name}")
        
        if request.linked_campaign_id and InputType.CAMPAIGN not in agent.supported_input_types:
            raise ValueError(f"Agent does not support campaign input: {agent.agent_name}")
        
        # Create the invocation record
        invocation = AgentInvocation(
            invocation_id=str(uuid.uuid4()),
            agent_id=agent.agent_id,
            agent_name=agent.agent_name,
            agent_type=agent.agent_type,
            linked_run_id=request.linked_run_id,
            linked_campaign_id=request.linked_campaign_id,
            input_summary=input_summary or "",
            input_data=request.input_data,
            correlation_id=request.correlation_id or str(uuid.uuid4()),
            status=InvocationStatus.PENDING,
        )
        
        # Store the invocation
        self._store.store(invocation)
        
        return invocation
    
    def start_invocation(self, invocation_id: str) -> Optional[AgentInvocation]:
        """
        Mark an invocation as running.
        
        Args:
            invocation_id: ID of the invocation
            
        Returns:
            Updated invocation or None if not found
        """
        invocation = self._store.get(invocation_id)
        if invocation:
            invocation.mark_running()
            self._store.update(invocation)
        return invocation
    
    def complete_invocation(
        self,
        invocation_id: str,
        output_summary: str,
        raw_output: str,
        structured_output: Optional[Dict[str, Any]] = None,
    ) -> Optional[AgentInvocation]:
        """
        Mark an invocation as completed with output.
        
        Args:
            invocation_id: ID of the invocation
            output_summary: Brief summary of the output
            raw_output: Raw output from the agent
            structured_output: Parsed/structured output
            
        Returns:
            Updated invocation or None if not found
        """
        invocation = self._store.get(invocation_id)
        if invocation:
            invocation.mark_completed(output_summary, raw_output)
            if structured_output:
                invocation.structured_output = structured_output
            self._store.update(invocation)
        return invocation
    
    def fail_invocation(
        self,
        invocation_id: str,
        error_details: str,
        error_code: Optional[str] = None,
    ) -> Optional[AgentInvocation]:
        """
        Mark an invocation as failed.
        
        Args:
            invocation_id: ID of the invocation
            error_details: Error message
            error_code: Error code
            
        Returns:
            Updated invocation or None if not found
        """
        invocation = self._store.get(invocation_id)
        if invocation:
            invocation.mark_failed(error_details, error_code)
            self._store.update(invocation)
        return invocation
    
    # =========================================================================
    # INVOCATION QUERIES
    # =========================================================================
    
    def get_invocation(self, invocation_id: str) -> Optional[AgentInvocation]:
        """Get an invocation by ID."""
        return self._store.get(invocation_id)
    
    def get_invocations_for_run(self, run_id: str) -> List[AgentInvocation]:
        """Get all invocations linked to a run."""
        return self._store.get_by_run(run_id)
    
    def get_invocations_for_campaign(self, campaign_id: str) -> List[AgentInvocation]:
        """Get all invocations linked to a campaign."""
        return self._store.get_by_campaign(campaign_id)
    
    def get_invocations_by_correlation(self, correlation_id: str) -> List[AgentInvocation]:
        """Get all invocations with a correlation ID."""
        return self._store.get_by_correlation(correlation_id)
    
    def list_invocations(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[InvocationStatus] = None,
        agent_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> InvocationListResponse:
        """
        List invocations with optional filtering.
        
        Args:
            limit: Maximum number to return
            offset: Number to skip
            status: Filter by status
            agent_id: Filter by agent
            since: Only include invocations after this time
            
        Returns:
            Paginated list response
        """
        return self._store.list_recent(
            limit=limit,
            offset=offset,
            status=status,
            agent_id=agent_id,
            since=since,
        )
    
    def get_invocation_summary(
        self, 
        since: Optional[datetime] = None
    ) -> InvocationSummary:
        """
        Get summary statistics for invocations.
        
        Args:
            since: Only include invocations after this time
            
        Returns:
            Summary statistics
        """
        return self._store.get_summary(since=since)
    
    # =========================================================================
    # AGENT EXECUTION
    # =========================================================================
    
    async def invoke_attack_observer(
        self,
        attack_result: AttackResult,
        correlation_id: Optional[str] = None,
    ) -> Tuple[AgentInvocation, AttackObservation]:
        """
        Invoke the Attack Observer Agent on an attack result.
        
        Creates an invocation record, executes the agent, and stores
        the observation. Handles success and failure states.
        
        Args:
            attack_result: The attack run to analyze
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            Tuple of (invocation record, observation)
            
        Raises:
            ValueError: If agent not found
        """
        correlation_id = correlation_id or attack_result.correlation_id
        
        # Get the attack observer agent by type
        agent = self._registry.get_agent_by_type(AgentType.ATTACK_OBSERVER)
        if agent is None:
            raise ValueError("Attack Observer Agent not found in registry")
        
        # Create the invocation request
        request = AgentInvocationRequest(
            agent_id=agent.agent_id,
            linked_run_id=attack_result.run_id,
            correlation_id=correlation_id,
            input_data={
                "run_id": attack_result.run_id,
                "scenario_name": attack_result.scenario_name,
                "attack_category": attack_result.attack_category.value,
                "outcome": attack_result.outcome.value,
            },
        )
        
        # Create the invocation record
        input_summary = f"Analyzing {attack_result.attack_category.value} attack: {attack_result.scenario_name}"
        invocation = self.create_invocation(request, input_summary=input_summary)
        
        # Mark as running and log telemetry start
        self.start_invocation(invocation.invocation_id)
        
        telemetry = get_telemetry_service()
        await telemetry.track_agent_invoke_start(
            invocation_id=invocation.invocation_id,
            agent_name=agent.agent_name,
            agent_type=agent.agent_type.value,
            correlation_id=correlation_id,
            linked_run_id=attack_result.run_id,
            input_summary=input_summary,
            metadata={
                "scenario_name": attack_result.scenario_name,
                "attack_category": attack_result.attack_category.value,
            }
        )
        
        try:
            # Execute the agent
            executor = get_attack_observer_executor()
            observation = await executor.execute(attack_result, correlation_id)
            
            # Mark as completed with structured output
            self.complete_invocation(
                invocation_id=invocation.invocation_id,
                output_summary=observation.summary,
                raw_output=observation.client_narrative,
                structured_output=observation.to_dict(),
            )
            
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry completion
            await telemetry.track_agent_invoke_complete(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                status=invocation.status.value,
                latency_ms=invocation.latency_ms,
                linked_run_id=attack_result.run_id,
                output_summary=observation.summary,
                metadata={
                    "risk_level": str(observation.risk_level) if observation.risk_level else "unknown",
                }
            )
            
            return invocation, observation
            
        except Exception as e:
            # Mark as failed
            self.fail_invocation(
                invocation_id=invocation.invocation_id,
                error_details=str(e),
                error_code="EXECUTION_ERROR",
            )
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry error
            await telemetry.track_agent_invoke_error(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                latency_ms=invocation.latency_ms,
                linked_run_id=attack_result.run_id,
            )
            
            raise RuntimeError(f"Attack Observer Agent failed: {e}") from e
    
    async def invoke_telemetry_analyst(
        self,
        runs: List[AttackResult],
        correlation_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
    ) -> Tuple[AgentInvocation, TelemetrySummary]:
        """
        Invoke the Telemetry Analyst Agent on recent run history.
        
        Creates an invocation record, executes the agent, and stores
        the summary. Handles success and failure states.
        
        Args:
            runs: List of recent attack results to analyze
            correlation_id: Optional correlation ID for tracing
            campaign_id: Optional campaign ID if analyzing a campaign
            
        Returns:
            Tuple of (invocation record, telemetry summary)
            
        Raises:
            ValueError: If agent not found
        """
        import uuid
        correlation_id = correlation_id or str(uuid.uuid4())
        
        # Get the telemetry analyst agent by type
        agent = self._registry.get_agent_by_type(AgentType.TELEMETRY_ANALYST)
        if agent is None:
            raise ValueError("Telemetry Analyst Agent not found in registry")
        
        # Create the invocation request
        # Link to campaign if provided, or to first run's campaign
        linked_campaign_id = campaign_id
        linked_run_id = None
        if not linked_campaign_id and runs:
            linked_campaign_id = runs[0].campaign_id
            if not linked_campaign_id:
                linked_run_id = runs[0].run_id
        
        request = AgentInvocationRequest(
            agent_id=agent.agent_id,
            linked_run_id=linked_run_id,
            linked_campaign_id=linked_campaign_id,
            correlation_id=correlation_id,
            input_data={
                "run_count": len(runs),
                "categories": list(set(r.attack_category.value for r in runs)) if runs else [],
            },
        )
        
        # Create the invocation record
        input_summary = f"Analyzing {len(runs)} recent attack runs"
        invocation = self.create_invocation(request, input_summary=input_summary)
        
        # Mark as running and log telemetry start
        self.start_invocation(invocation.invocation_id)
        
        telemetry = get_telemetry_service()
        await telemetry.track_agent_invoke_start(
            invocation_id=invocation.invocation_id,
            agent_name=agent.agent_name,
            agent_type=agent.agent_type.value,
            correlation_id=correlation_id,
            linked_run_id=linked_run_id,
            linked_campaign_id=linked_campaign_id,
            input_summary=input_summary,
            metadata={
                "run_count": len(runs),
                "categories": list(set(r.attack_category.value for r in runs)) if runs else [],
            }
        )
        
        try:
            # Execute the agent
            executor = get_telemetry_analyst_executor()
            summary = await executor.execute(runs, correlation_id)
            
            # Mark as completed with structured output
            self.complete_invocation(
                invocation_id=invocation.invocation_id,
                output_summary=summary.summary,
                raw_output=summary.client_narrative,
                structured_output=summary.to_dict(),
            )
            
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry completion
            await telemetry.track_agent_invoke_complete(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                status=invocation.status.value,
                latency_ms=invocation.latency_ms,
                linked_run_id=linked_run_id,
                linked_campaign_id=linked_campaign_id,
                output_summary=summary.summary,
                metadata={
                    "total_runs": summary.total_runs,
                    "anomaly_count": summary.anomaly_count,
                }
            )
            
            return invocation, summary
            
        except Exception as e:
            # Mark as failed
            self.fail_invocation(
                invocation_id=invocation.invocation_id,
                error_details=str(e),
                error_code="EXECUTION_ERROR",
            )
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry error
            await telemetry.track_agent_invoke_error(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                latency_ms=invocation.latency_ms,
                linked_run_id=linked_run_id,
                linked_campaign_id=linked_campaign_id,
            )
            
            raise RuntimeError(f"Telemetry Analyst Agent failed: {e}") from e
    
    async def invoke_policy_explainer(
        self,
        attack_result: AttackResult,
        correlation_id: Optional[str] = None,
    ) -> Tuple[AgentInvocation, PolicyExplanation]:
        """
        Invoke the Policy Explainer Agent on an attack result.
        
        Creates an invocation record, executes the agent, and stores
        the explanation. Handles success and failure states.
        
        Args:
            attack_result: The attack run to explain
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            Tuple of (invocation record, policy explanation)
            
        Raises:
            ValueError: If agent not found
        """
        correlation_id = correlation_id or attack_result.correlation_id
        
        # Get the policy explainer agent by type
        agent = self._registry.get_agent_by_type(AgentType.POLICY_EXPLAINER)
        if agent is None:
            raise ValueError("Policy Explainer Agent not found in registry")
        
        # Create the invocation request
        request = AgentInvocationRequest(
            agent_id=agent.agent_id,
            linked_run_id=attack_result.run_id,
            correlation_id=correlation_id,
            input_data={
                "run_id": attack_result.run_id,
                "scenario_name": attack_result.scenario_name,
                "attack_category": attack_result.attack_category.value,
                "outcome": attack_result.outcome.value,
                "shield_result": attack_result.shield_verdict.result.value,
            },
        )
        
        # Create the invocation record
        input_summary = f"Explaining {attack_result.attack_category.value} attack: {attack_result.scenario_name}"
        invocation = self.create_invocation(request, input_summary=input_summary)
        
        # Mark as running and log telemetry start
        self.start_invocation(invocation.invocation_id)
        
        telemetry = get_telemetry_service()
        await telemetry.track_agent_invoke_start(
            invocation_id=invocation.invocation_id,
            agent_name=agent.agent_name,
            agent_type=agent.agent_type.value,
            correlation_id=correlation_id,
            linked_run_id=attack_result.run_id,
            input_summary=input_summary,
            metadata={
                "scenario_name": attack_result.scenario_name,
                "attack_category": attack_result.attack_category.value,
                "shield_result": attack_result.shield_verdict.result.value,
            }
        )
        
        try:
            # Execute the agent
            executor = get_policy_explainer_executor()
            explanation = await executor.execute(attack_result, correlation_id)
            
            # Mark as completed with structured output
            self.complete_invocation(
                invocation_id=invocation.invocation_id,
                output_summary=explanation.summary[:200],
                raw_output=explanation.client_narrative,
                structured_output=explanation.to_dict(),
            )
            
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry completion
            await telemetry.track_agent_invoke_complete(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                status=invocation.status.value,
                latency_ms=invocation.latency_ms,
                linked_run_id=attack_result.run_id,
                output_summary=explanation.summary[:200],
                metadata={
                    "policy_triggered": explanation.policy_triggered,
                    "confidence": explanation.confidence,
                }
            )
            
            return invocation, explanation
            
        except Exception as e:
            # Mark as failed
            self.fail_invocation(
                invocation_id=invocation.invocation_id,
                error_details=str(e),
                error_code="EXECUTION_ERROR",
            )
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry error
            await telemetry.track_agent_invoke_error(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                latency_ms=invocation.latency_ms,
                linked_run_id=attack_result.run_id,
            )
            
            raise RuntimeError(f"Policy Explainer Agent failed: {e}") from e
    
    async def invoke_campaign_reporter(
        self,
        campaign: CampaignResult,
        correlation_id: Optional[str] = None,
    ) -> Tuple[AgentInvocation, CampaignReport]:
        """
        Invoke the Campaign Reporter Agent on a campaign result.
        
        Creates an invocation record, executes the agent, and stores
        the report. Handles success and failure states.
        
        Args:
            campaign: The completed campaign to report on
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            Tuple of (invocation record, campaign report)
            
        Raises:
            ValueError: If agent not found
        """
        correlation_id = correlation_id or campaign.correlation_id
        
        # Get the campaign reporter agent by type
        agent = self._registry.get_agent_by_type(AgentType.CAMPAIGN_REPORTER)
        if agent is None:
            raise ValueError("Campaign Reporter Agent not found in registry")
        
        # Create the invocation request
        request = AgentInvocationRequest(
            agent_id=agent.agent_id,
            linked_campaign_id=campaign.campaign_id,
            correlation_id=correlation_id,
            input_data={
                "campaign_id": campaign.campaign_id,
                "campaign_name": campaign.name,
                "total_attacks": campaign.total_attacks,
                "status": campaign.status.value,
            },
        )
        
        # Create the invocation record
        input_summary = f"Reporting on campaign: {campaign.name} ({campaign.total_attacks} scenarios)"
        invocation = self.create_invocation(request, input_summary=input_summary)
        
        # Mark as running and log telemetry start
        self.start_invocation(invocation.invocation_id)
        
        telemetry = get_telemetry_service()
        await telemetry.track_agent_invoke_start(
            invocation_id=invocation.invocation_id,
            agent_name=agent.agent_name,
            agent_type=agent.agent_type.value,
            correlation_id=correlation_id,
            linked_campaign_id=campaign.campaign_id,
            input_summary=input_summary,
            metadata={
                "campaign_name": campaign.name,
                "total_attacks": campaign.total_attacks,
                "blocked_count": campaign.blocked_count,
                "passed_count": campaign.passed_count,
            }
        )
        
        try:
            # Execute the agent
            executor = get_campaign_reporter_executor()
            report = await executor.execute(campaign, correlation_id)
            
            # Mark as completed with structured output
            self.complete_invocation(
                invocation_id=invocation.invocation_id,
                output_summary=report.headline,
                raw_output=report.executive_summary,
                structured_output=report.to_dict(),
            )
            
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry completion
            await telemetry.track_agent_invoke_complete(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                status=invocation.status.value,
                latency_ms=invocation.latency_ms,
                linked_campaign_id=campaign.campaign_id,
                output_summary=report.headline,
                metadata={
                    "recommendation_count": len(report.recommendations) if report.recommendations else 0,
                }
            )
            
            return invocation, report
            
        except Exception as e:
            # Mark as failed
            self.fail_invocation(
                invocation_id=invocation.invocation_id,
                error_details=str(e),
                error_code="EXECUTION_ERROR",
            )
            # Refresh invocation to get updated state
            invocation = self._store.get(invocation.invocation_id)
            
            # Log telemetry error
            await telemetry.track_agent_invoke_error(
                invocation_id=invocation.invocation_id,
                agent_name=agent.agent_name,
                agent_type=agent.agent_type.value,
                correlation_id=correlation_id,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                latency_ms=invocation.latency_ms,
                linked_campaign_id=campaign.campaign_id,
            )
            
            raise RuntimeError(f"Campaign Reporter Agent failed: {e}") from e


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_service_instance: Optional[AgentService] = None


def get_agent_service() -> AgentService:
    """Get the singleton agent service instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = AgentService()
    return _service_instance
