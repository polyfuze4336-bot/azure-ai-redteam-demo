"""
Agent API endpoints.

Provides endpoints for listing agents, invoking agents, and querying
invocation history for the lightweight demo agent system.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Path
from pydantic import BaseModel, Field

from agents import (
    get_agent_service,
    AgentType,
    AgentStatus,
    InputType,
    InvocationStatus,
    AgentDefinition,
    AgentInvocation,
    AgentInvocationRequest,
)
from agents.models import AgentListResponse, InvocationListResponse, InvocationSummary
from storage import get_store

router = APIRouter(prefix="/api/agents", tags=["agents"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class InvokeAgentRequest(BaseModel):
    """Request to invoke an agent."""
    linked_run_id: Optional[str] = Field(
        None, 
        description="ID of the attack run to analyze"
    )
    linked_campaign_id: Optional[str] = Field(
        None, 
        description="ID of the campaign to analyze"
    )
    correlation_id: Optional[str] = Field(
        None, 
        description="Correlation ID for tracing"
    )
    input_data: dict = Field(
        default_factory=dict, 
        description="Additional input data for the agent"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "linked_run_id": "run-abc123",
                "correlation_id": "corr-xyz789"
            }
        }


class InvokeAgentResponse(BaseModel):
    """Response from agent invocation."""
    invocation: AgentInvocation
    output: dict = Field(
        default_factory=dict, 
        description="Structured output from the agent"
    )


# =============================================================================
# AGENT LIST ENDPOINTS
# =============================================================================

@router.get("", response_model=AgentListResponse)
async def list_agents(
    status: Optional[AgentStatus] = Query(
        None, 
        description="Filter by agent status"
    ),
    input_type: Optional[InputType] = Query(
        None, 
        description="Filter by supported input type"
    ),
) -> AgentListResponse:
    """
    List all available lightweight agents.
    
    Returns the list of demo agents with their metadata, purpose, and status.
    Can be filtered by status (active/inactive) or supported input type (run/campaign).
    
    - **status**: Filter by agent status (active, inactive, maintenance)
    - **input_type**: Filter by supported input type (run, campaign)
    """
    service = get_agent_service()
    return service.list_agents(status=status, input_type=input_type)


# =============================================================================
# INVOCATION HISTORY ENDPOINTS (must come before /{agent_id} routes)
# =============================================================================

@router.get("/invocations", response_model=InvocationListResponse)
async def list_invocations(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum results"),
    offset: int = Query(default=0, ge=0, description="Results to skip"),
    status: Optional[InvocationStatus] = Query(None, description="Filter by status"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
) -> InvocationListResponse:
    """
    List agent invocation history.
    
    Returns paginated list of invocations with optional filtering.
    Useful for reviewing agent execution history and debugging.
    
    - **limit**: Maximum number of results (default: 50)
    - **offset**: Number of results to skip for pagination
    - **status**: Filter by invocation status (pending, running, completed, failed)
    - **agent_id**: Filter by specific agent
    """
    service = get_agent_service()
    return service.list_invocations(
        limit=limit,
        offset=offset,
        status=status,
        agent_id=agent_id,
    )


@router.get("/invocations/summary", response_model=InvocationSummary)
async def get_invocation_summary() -> InvocationSummary:
    """
    Get summary statistics for agent invocations.
    
    Returns aggregate metrics including total invocations,
    success/failure counts, average latency, and breakdowns by agent and status.
    """
    service = get_agent_service()
    return service.get_invocation_summary()


@router.get("/invocations/by-run/{run_id}", response_model=list[AgentInvocation])
async def get_invocations_by_run(
    run_id: str = Path(..., description="Attack run ID")
) -> list[AgentInvocation]:
    """
    Get all agent invocations linked to an attack run.
    
    - **run_id**: ID of the attack run
    """
    service = get_agent_service()
    return service.get_invocations_for_run(run_id)


@router.get("/invocations/by-campaign/{campaign_id}", response_model=list[AgentInvocation])
async def get_invocations_by_campaign(
    campaign_id: str = Path(..., description="Campaign ID")
) -> list[AgentInvocation]:
    """
    Get all agent invocations linked to a campaign.
    
    - **campaign_id**: ID of the campaign
    """
    service = get_agent_service()
    return service.get_invocations_for_campaign(campaign_id)


@router.get("/invocations/by-correlation/{correlation_id}", response_model=list[AgentInvocation])
async def get_invocations_by_correlation(
    correlation_id: str = Path(..., description="Correlation ID")
) -> list[AgentInvocation]:
    """
    Get all agent invocations with a specific correlation ID.
    
    Useful for tracing agent activity across a distributed request.
    
    - **correlation_id**: Correlation ID for tracing
    """
    service = get_agent_service()
    return service.get_invocations_by_correlation(correlation_id)


@router.get("/invocations/{invocation_id}", response_model=AgentInvocation)
async def get_invocation(
    invocation_id: str = Path(..., description="Invocation ID")
) -> AgentInvocation:
    """
    Get details of a specific agent invocation.
    
    Returns the full invocation record including input, output,
    timing, status, and tracing information.
    
    - **invocation_id**: Unique identifier of the invocation
    """
    service = get_agent_service()
    invocation = service.get_invocation(invocation_id)
    
    if invocation is None:
        raise HTTPException(
            status_code=404, 
            detail=f"Invocation not found: {invocation_id}"
        )
    
    return invocation


# =============================================================================
# AGENT DETAIL AND INVOKE ENDPOINTS
# =============================================================================

@router.get("/{agent_id}", response_model=AgentDefinition)
async def get_agent(
    agent_id: str = Path(..., description="Agent ID")
) -> AgentDefinition:
    """
    Get details of a specific agent.
    
    - **agent_id**: Unique identifier of the agent
    """
    service = get_agent_service()
    agent = service.get_agent(agent_id)
    
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
    
    return agent


@router.post("/{agent_id}/invoke", response_model=InvokeAgentResponse)
async def invoke_agent(
    agent_id: str = Path(..., description="Agent ID to invoke"),
    request: InvokeAgentRequest = ...,
) -> InvokeAgentResponse:
    """
    Invoke an agent against a linked run or campaign.
    
    The agent analyzes the linked data and produces structured output
    suitable for display in the frontend.
    
    - **agent_id**: ID of the agent to invoke
    - **linked_run_id**: Attack run to analyze (for run-based agents)
    - **linked_campaign_id**: Campaign to analyze (for campaign-based agents)
    - **correlation_id**: Optional correlation ID for tracing
    - **input_data**: Additional context data
    
    Returns the invocation record and structured output.
    """
    service = get_agent_service()
    store = get_store()
    
    # Validate agent exists
    agent = service.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")
    
    # Validate agent is active
    if agent.status != AgentStatus.ACTIVE:
        raise HTTPException(
            status_code=400, 
            detail=f"Agent is not active: {agent.agent_name}"
        )
    
    # Validate input type compatibility
    if request.linked_run_id and InputType.RUN not in agent.supported_input_types:
        raise HTTPException(
            status_code=400,
            detail=f"Agent does not support run input: {agent.agent_name}"
        )
    
    if request.linked_campaign_id and InputType.CAMPAIGN not in agent.supported_input_types:
        raise HTTPException(
            status_code=400,
            detail=f"Agent does not support campaign input: {agent.agent_name}"
        )
    
    # Validate at least one input is provided
    if not request.linked_run_id and not request.linked_campaign_id:
        raise HTTPException(
            status_code=400,
            detail="Either linked_run_id or linked_campaign_id must be provided"
        )
    
    try:
        # Route to the appropriate executor based on agent type
        if agent.agent_type == AgentType.ATTACK_OBSERVER:
            # Get the attack run
            if not request.linked_run_id:
                raise HTTPException(
                    status_code=400,
                    detail="Attack Observer requires linked_run_id"
                )
            
            run = store.get_result(request.linked_run_id)
            if run is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Attack run not found: {request.linked_run_id}"
                )
            
            invocation, observation = await service.invoke_attack_observer(
                attack_result=run,
                correlation_id=request.correlation_id,
            )
            
            return InvokeAgentResponse(
                invocation=invocation,
                output=observation.to_dict(),
            )
        
        elif agent.agent_type == AgentType.TELEMETRY_ANALYST:
            # Get the attack run
            if not request.linked_run_id:
                raise HTTPException(
                    status_code=400,
                    detail="Telemetry Analyst requires linked_run_id"
                )
            
            run = store.get_result(request.linked_run_id)
            if run is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Attack run not found: {request.linked_run_id}"
                )
            
            invocation, summary = await service.invoke_telemetry_analyst(
                attack_result=run,
                correlation_id=request.correlation_id,
            )
            
            return InvokeAgentResponse(
                invocation=invocation,
                output=summary.to_dict(),
            )
        
        elif agent.agent_type == AgentType.POLICY_EXPLAINER:
            # Get the attack run
            if not request.linked_run_id:
                raise HTTPException(
                    status_code=400,
                    detail="Policy Explainer requires linked_run_id"
                )
            
            run = store.get_result(request.linked_run_id)
            if run is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Attack run not found: {request.linked_run_id}"
                )
            
            invocation, explanation = await service.invoke_policy_explainer(
                attack_result=run,
                correlation_id=request.correlation_id,
            )
            
            return InvokeAgentResponse(
                invocation=invocation,
                output=explanation.to_dict(),
            )
        
        elif agent.agent_type == AgentType.CAMPAIGN_REPORTER:
            # Get the campaign
            if not request.linked_campaign_id:
                raise HTTPException(
                    status_code=400,
                    detail="Campaign Reporter requires linked_campaign_id"
                )
            
            campaign = store.get_campaign(request.linked_campaign_id)
            if campaign is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Campaign not found: {request.linked_campaign_id}"
                )
            
            invocation, report = await service.invoke_campaign_reporter(
                campaign=campaign,
                correlation_id=request.correlation_id,
            )
            
            return InvokeAgentResponse(
                invocation=invocation,
                output=report.to_dict(),
            )
        
        else:
            raise HTTPException(
                status_code=501,
                detail=f"Agent type not implemented: {agent.agent_type.value}"
            )
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
