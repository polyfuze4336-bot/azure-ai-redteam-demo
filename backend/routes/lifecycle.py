"""
Secure Agent Lifecycle API routes.

Provides REST endpoints for managing agent profiles, policy profiles,
and Purview governance contexts in the Secure Agent Lifecycle demo.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from lifecycle import (
    get_lifecycle_service,
    AgentProfileStatus,
    DataClassification,
)
from lifecycle.models import (
    AgentProfile,
    PolicyProfile,
    PurviewGovernanceContext,
    CreateAgentProfileRequest,
    CreatePolicyProfileRequest,
    CreatePurviewContextRequest,
    AgentProfileListResponse,
    PolicyProfileListResponse,
    PurviewContextListResponse,
)


router = APIRouter(prefix="/api/lifecycle", tags=["lifecycle"])


# =============================================================================
# AGENT PROFILE ENDPOINTS
# =============================================================================

@router.get("/agents", response_model=AgentProfileListResponse)
async def list_agent_profiles(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[AgentProfileStatus] = None,
    policy_profile_id: Optional[str] = None,
):
    """List all agent profiles with optional filtering."""
    service = get_lifecycle_service()
    return service.list_agent_profiles(
        limit=limit,
        offset=offset,
        status=status,
        policy_profile_id=policy_profile_id,
    )


@router.post("/agents", response_model=AgentProfile, status_code=201)
async def create_agent_profile(request: CreateAgentProfileRequest):
    """Create a new agent profile."""
    service = get_lifecycle_service()
    try:
        return service.create_agent_profile(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/agents/{agent_id}", response_model=AgentProfile)
async def get_agent_profile(
    agent_id: str,
    resolve: bool = Query(default=False, description="Resolve policy and Purview references"),
):
    """Get an agent profile by ID."""
    service = get_lifecycle_service()
    agent = service.get_agent_profile(agent_id, resolve_references=resolve)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent profile not found: {agent_id}")
    return agent


@router.patch("/agents/{agent_id}", response_model=AgentProfile)
async def update_agent_profile(agent_id: str, updates: dict):
    """Update an agent profile."""
    service = get_lifecycle_service()
    agent = service.update_agent_profile(agent_id, updates)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent profile not found: {agent_id}")
    return agent


@router.post("/agents/{agent_id}/transition", response_model=AgentProfile)
async def transition_agent_status(agent_id: str, new_status: AgentProfileStatus):
    """Transition an agent to a new lifecycle status."""
    service = get_lifecycle_service()
    try:
        agent = service.transition_agent_status(agent_id, new_status)
        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent profile not found: {agent_id}")
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/agents/{agent_id}", status_code=204)
async def delete_agent_profile(agent_id: str):
    """Delete an agent profile."""
    service = get_lifecycle_service()
    if not service.delete_agent_profile(agent_id):
        raise HTTPException(status_code=404, detail=f"Agent profile not found: {agent_id}")


@router.post("/agents/{agent_id}/provision", response_model=AgentProfile)
async def provision_agent(agent_id: str):
    """
    Provision an agent (simulate Foundry-backed deployment).
    
    Transitions the agent from DRAFT to PROVISIONING to ACTIVE status,
    simulating the provisioning of an AI agent in a Foundry environment.
    """
    service = get_lifecycle_service()
    try:
        return service.provision_agent(agent_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/agents/{agent_id}/governance")
async def get_agent_governance(agent_id: str):
    """Get the resolved governance context for an agent."""
    service = get_lifecycle_service()
    try:
        return service.resolve_agent_governance(agent_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/agents/{agent_id}/validate")
async def validate_agent_for_activation(agent_id: str):
    """Validate that an agent is ready for activation."""
    service = get_lifecycle_service()
    try:
        return service.validate_agent_for_activation(agent_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =============================================================================
# POLICY PROFILE ENDPOINTS
# =============================================================================

@router.get("/policies", response_model=PolicyProfileListResponse)
async def list_policy_profiles():
    """List all policy profiles."""
    service = get_lifecycle_service()
    return service.list_policy_profiles()


@router.post("/policies", response_model=PolicyProfile, status_code=201)
async def create_policy_profile(request: CreatePolicyProfileRequest):
    """Create a new policy profile."""
    service = get_lifecycle_service()
    return service.create_policy_profile(request)


@router.get("/policies/{policy_id}", response_model=PolicyProfile)
async def get_policy_profile(policy_id: str):
    """Get a policy profile by ID."""
    service = get_lifecycle_service()
    policy = service.get_policy_profile(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy profile not found: {policy_id}")
    return policy


@router.patch("/policies/{policy_id}", response_model=PolicyProfile)
async def update_policy_profile(policy_id: str, updates: dict):
    """Update a policy profile."""
    service = get_lifecycle_service()
    policy = service.update_policy_profile(policy_id, updates)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy profile not found: {policy_id}")
    return policy


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy_profile(policy_id: str):
    """Delete a policy profile."""
    service = get_lifecycle_service()
    try:
        if not service.delete_policy_profile(policy_id):
            raise HTTPException(status_code=404, detail=f"Policy profile not found: {policy_id}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# PURVIEW GOVERNANCE CONTEXT ENDPOINTS
# =============================================================================

@router.get("/purview", response_model=PurviewContextListResponse)
async def list_purview_contexts():
    """List all Purview governance contexts."""
    service = get_lifecycle_service()
    return service.list_purview_contexts()


@router.post("/purview", response_model=PurviewGovernanceContext, status_code=201)
async def create_purview_context(request: CreatePurviewContextRequest):
    """Create a new Purview governance context."""
    service = get_lifecycle_service()
    return service.create_purview_context(request)


@router.get("/purview/{context_id}", response_model=PurviewGovernanceContext)
async def get_purview_context(context_id: str):
    """Get a Purview governance context by ID."""
    service = get_lifecycle_service()
    context = service.get_purview_context(context_id)
    if not context:
        raise HTTPException(status_code=404, detail=f"Purview context not found: {context_id}")
    return context


@router.patch("/purview/{context_id}", response_model=PurviewGovernanceContext)
async def update_purview_context(context_id: str, updates: dict):
    """Update a Purview governance context."""
    service = get_lifecycle_service()
    context = service.update_purview_context(context_id, updates)
    if not context:
        raise HTTPException(status_code=404, detail=f"Purview context not found: {context_id}")
    return context


@router.delete("/purview/{context_id}", status_code=204)
async def delete_purview_context(context_id: str):
    """Delete a Purview governance context."""
    service = get_lifecycle_service()
    try:
        if not service.delete_purview_context(context_id):
            raise HTTPException(status_code=404, detail=f"Purview context not found: {context_id}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# =============================================================================
# SUMMARY AND CONTEXT ENDPOINTS
# =============================================================================

@router.get("/summary")
async def get_lifecycle_summary():
    """Get a summary of all lifecycle data."""
    service = get_lifecycle_service()
    return service.get_lifecycle_summary()


@router.get("/foundry-context")
async def get_foundry_context():
    """
    Get the current Foundry environment context from app configuration.
    
    Returns the Foundry resource name and deployment settings that will be
    used as defaults when creating new agents.
    """
    try:
        from config import get_settings
        settings = get_settings()
        return {
            "foundry_resource_name": settings.foundry_resource_name or "demo-foundry-resource",
            "deployment_name": settings.azure_openai_deployment_name,
            "endpoint": settings.azure_openai_endpoint or getattr(settings, 'foundry_endpoint', None),
            "run_mode": settings.run_mode.value,
            "api_version": settings.azure_openai_api_version,
            "configured": bool(settings.foundry_resource_name),
        }
    except Exception as e:
        return {
            "foundry_resource_name": "demo-foundry-resource",
            "deployment_name": None,
            "endpoint": None,
            "run_mode": "demo",
            "api_version": "2024-02-15-preview",
            "configured": False,
            "error": str(e),
        }
