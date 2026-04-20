"""
Microsoft Purview Governance Event endpoints.

Provides API routes for:
- Retrieving real Purview governance events
- Syncing events from Purview APIs
- Filtering and querying governance events
- Linking events to runs and agents
- Importing governance records through adapters
- Getting ingestion status
- Correlating events with attack runs
"""

from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Body

from models.schemas import (
    PurviewGovernanceEvent,
    PurviewEventType,
    PurviewPolicyAction,
    PurviewEventStatus,
    PurviewEventSource,
    PurviewEventFilter,
    PurviewEventResponse,
    PurviewIngestionStatus,
    PurviewCorrelationStats,
    # Correlation models
    CorrelationConfidence,
    PurviewCorrelationMethod,
    PurviewEventCorrelation,
    LinkedPurviewEvent,
    PurviewCorrelationRequest,
    PurviewCorrelationResult,
)
from services.purview_governance import get_purview_governance_service
from services.purview_correlation import get_purview_correlation_service
from storage import get_store

router = APIRouter(prefix="/api/purview", tags=["purview-governance"])


@router.get("/events", response_model=PurviewEventResponse)
async def get_events(
    limit: int = Query(default=50, ge=1, le=500, description="Maximum events to return"),
    offset: int = Query(default=0, ge=0, description="Number of events to skip"),
    event_type: Optional[List[PurviewEventType]] = Query(
        default=None, 
        description="Filter by event types"
    ),
    status: Optional[List[PurviewEventStatus]] = Query(
        default=None, 
        description="Filter by status values"
    ),
    policy_action: Optional[List[PurviewPolicyAction]] = Query(
        default=None, 
        description="Filter by policy actions"
    ),
    source: Optional[List[PurviewEventSource]] = Query(
        default=None, 
        description="Filter by event source"
    ),
    policy_name: Optional[str] = Query(
        default=None, 
        description="Filter by policy name (partial match)"
    ),
    classification: Optional[str] = Query(
        default=None, 
        description="Filter by classification level"
    ),
    correlation_id: Optional[str] = Query(
        default=None, 
        description="Filter by correlation ID"
    ),
    linked_run_id: Optional[str] = Query(
        default=None, 
        description="Filter by linked run ID"
    ),
    linked_agent_id: Optional[str] = Query(
        default=None, 
        description="Filter by linked agent ID"
    ),
    linked_campaign_id: Optional[str] = Query(
        default=None, 
        description="Filter by linked campaign ID"
    ),
    start_time: Optional[datetime] = Query(
        default=None, 
        description="Filter events after this time"
    ),
    end_time: Optional[datetime] = Query(
        default=None, 
        description="Filter events before this time"
    ),
) -> PurviewEventResponse:
    """
    Get Purview governance events with optional filtering.
    
    Returns real events from Microsoft Purview APIs when available.
    Falls back to adapter/imported events if real source is temporarily unavailable.
    """
    store = get_store()
    service = get_purview_governance_service()
    
    # Build filter
    filter_params = PurviewEventFilter(
        limit=limit,
        offset=offset,
        event_type=event_type,
        status=status,
        policy_action=policy_action,
        source=source,
        policy_name=policy_name,
        classification=classification,
        correlation_id=correlation_id,
        linked_run_id=linked_run_id,
        linked_agent_id=linked_agent_id,
        linked_campaign_id=linked_campaign_id,
        start_time=start_time,
        end_time=end_time,
    )
    
    # Get events from service (which manages caching and API access)
    events = await service.get_events(filter_params)
    
    # Store in memory for persistence during session
    store.save_purview_events(events)
    
    # Determine source status
    ingestion_status = service.get_ingestion_status()
    source_status = "adapter" if ingestion_status.adapter_mode else "real"
    
    total = service.count_events()
    
    return PurviewEventResponse(
        events=events,
        total=total,
        limit=limit,
        offset=offset,
        source_status=source_status,
    )


@router.post("/events/sync", response_model=PurviewEventResponse)
async def sync_events(
    filter_params: Optional[PurviewEventFilter] = Body(
        default=None, 
        description="Optional filter for sync"
    ),
) -> PurviewEventResponse:
    """
    Trigger a sync of governance events from Microsoft Purview APIs.
    
    Forces a fresh fetch from the real Purview APIs rather than returning cached data.
    Use this to get the latest events or after configuration changes.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Clear cache to force fresh fetch
    service.clear_cache()
    
    # Sync events from Purview
    events = await service.sync_events(filter_params)
    
    # Store in memory
    store.save_purview_events(events)
    
    ingestion_status = service.get_ingestion_status()
    source_status = "adapter" if ingestion_status.adapter_mode else "real"
    
    return PurviewEventResponse(
        events=events,
        total=len(events),
        limit=filter_params.limit if filter_params else 50,
        offset=filter_params.offset if filter_params else 0,
        source_status=source_status,
    )


@router.get("/events/{event_id}", response_model=PurviewGovernanceEvent)
async def get_event(event_id: str) -> PurviewGovernanceEvent:
    """
    Get a specific governance event by ID.
    """
    service = get_purview_governance_service()
    event = service.get_event(event_id)
    
    if not event:
        # Try storage
        store = get_store()
        event = store.get_purview_event(event_id)
    
    if not event:
        raise HTTPException(status_code=404, detail=f"Governance event not found: {event_id}")
    
    return event


@router.post("/events/import", response_model=PurviewGovernanceEvent, status_code=201)
async def import_event(
    event: PurviewGovernanceEvent = Body(..., description="Governance event to import"),
) -> PurviewGovernanceEvent:
    """
    Import a governance event through the adapter interface.
    
    Used when direct API access is limited but governance records
    are available through configured adapters or manual import.
    The source will be marked appropriately to distinguish from
    real-time API events.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Import through service (handles normalization and source tracking)
    imported = service.import_event(event)
    
    # Also save to store
    store.save_purview_event(imported)
    
    return imported


@router.post("/events/import/batch", response_model=dict, status_code=201)
async def import_events_batch(
    events: List[PurviewGovernanceEvent] = Body(..., description="Governance events to import"),
) -> dict:
    """
    Import multiple governance events at once.
    
    Batch import for efficiency when loading historical governance records
    or syncing from external adapters.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Import through service
    count = service.import_events_batch(events)
    
    # Also save to store
    store.save_purview_events(events)
    
    return {
        "imported": count,
        "message": f"Successfully imported {count} governance events"
    }


@router.post("/events/create-policy-evaluation", response_model=PurviewGovernanceEvent, status_code=201)
async def create_policy_evaluation(
    policy_name: str = Body(..., description="Name of the policy"),
    action: PurviewPolicyAction = Body(..., description="Policy action taken"),
    classification: Optional[str] = Body(None, description="Data classification"),
    linked_agent_id: Optional[str] = Body(None, description="Linked agent ID"),
    linked_run_id: Optional[str] = Body(None, description="Linked run ID"),
    compliance_state: str = Body("compliant", description="Compliance state"),
    description: Optional[str] = Body(None, description="Event description"),
) -> PurviewGovernanceEvent:
    """
    Create a policy evaluation event for demo scenarios.
    
    This endpoint is used when real Purview API is not available but
    governance context needs to be demonstrated. Events created this way
    are marked as adapter imports to distinguish from real API events.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    event = service.create_policy_evaluation_event(
        policy_name=policy_name,
        action=action,
        classification=classification,
        linked_agent_id=linked_agent_id,
        linked_run_id=linked_run_id,
        compliance_state=compliance_state,
        description=description,
    )
    
    # Also save to store
    store.save_purview_event(event)
    
    return event


@router.post("/events/{event_id}/link-run")
async def link_event_to_run(
    event_id: str,
    run_id: str = Body(..., embed=True, description="Attack run ID to link"),
    correlation_id: Optional[str] = Body(None, embed=True, description="Optional correlation ID"),
) -> PurviewGovernanceEvent:
    """
    Link a governance event to an attack run.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Try service first
    event = service.link_event_to_run(event_id, run_id, correlation_id)
    
    if not event:
        # Try store
        event = store.link_purview_event_to_run(event_id, run_id, correlation_id)
    
    if not event:
        raise HTTPException(status_code=404, detail=f"Governance event not found: {event_id}")
    
    return event


@router.post("/events/{event_id}/link-agent")
async def link_event_to_agent(
    event_id: str,
    agent_id: str = Body(..., embed=True, description="Agent profile ID to link"),
) -> PurviewGovernanceEvent:
    """
    Link a governance event to an agent profile.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Try service first
    event = service.link_event_to_agent(event_id, agent_id)
    
    if not event:
        # Try store
        event = store.link_purview_event_to_agent(event_id, agent_id)
    
    if not event:
        raise HTTPException(status_code=404, detail=f"Governance event not found: {event_id}")
    
    return event


@router.get("/events/for-run/{run_id}", response_model=List[PurviewGovernanceEvent])
async def get_events_for_run(run_id: str) -> List[PurviewGovernanceEvent]:
    """
    Get all governance events linked to a specific attack run.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Combine from service and store
    events = service.get_events_for_run(run_id)
    store_events = store.get_purview_events_for_run(run_id)
    
    # Deduplicate by event_id
    seen = {e.event_id for e in events}
    for e in store_events:
        if e.event_id not in seen:
            events.append(e)
    
    return events


@router.get("/events/for-agent/{agent_id}", response_model=List[PurviewGovernanceEvent])
async def get_events_for_agent(agent_id: str) -> List[PurviewGovernanceEvent]:
    """
    Get all governance events linked to a specific agent profile.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Combine from service and store
    events = service.get_events_for_agent(agent_id)
    store_events = store.get_purview_events_for_agent(agent_id)
    
    # Deduplicate by event_id
    seen = {e.event_id for e in events}
    for e in store_events:
        if e.event_id not in seen:
            events.append(e)
    
    return events


@router.get("/status", response_model=PurviewIngestionStatus)
async def get_status() -> PurviewIngestionStatus:
    """
    Get current status of the Purview governance ingestion service.
    
    Returns connection status, source availability, adapter mode flag,
    and ingestion statistics.
    """
    service = get_purview_governance_service()
    return service.get_ingestion_status()


@router.get("/stats", response_model=PurviewCorrelationStats)
async def get_stats() -> PurviewCorrelationStats:
    """
    Get statistics about governance event correlation.
    
    Returns counts of linked/unlinked events and breakdowns by action and compliance state.
    """
    service = get_purview_governance_service()
    return service.get_correlation_stats()


@router.delete("/events/{event_id}", status_code=204)
async def delete_event(event_id: str):
    """
    Delete a specific governance event.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    # Try service cache
    if event_id in service._event_cache:
        del service._event_cache[event_id]
    
    # Also try store
    store.delete_purview_event(event_id)
    
    return None


@router.delete("/events", status_code=204)
async def clear_all_events():
    """
    Clear all governance events from cache and storage.
    
    Use with caution - this removes all stored governance events.
    """
    service = get_purview_governance_service()
    store = get_store()
    
    service.clear_cache()
    store.clear_purview_events()
    
    return None


# =============================================================================
# CORRELATION ENDPOINTS
# =============================================================================

@router.post("/correlate", response_model=PurviewCorrelationResult)
async def correlate_events_to_runs(
    request: PurviewCorrelationRequest = Body(
        default=PurviewCorrelationRequest(), 
        description="Correlation request options"
    ),
) -> PurviewCorrelationResult:
    """
    Correlate Purview governance events with attack runs.
    
    Uses multiple correlation methods:
    - Correlation ID matching (highest confidence)
    - Agent context matching (same agent_id)
    - Timestamp proximity (events close in time to runs)
    - Classification matching (same data classification)
    - Policy context matching (policy attached to agent)
    - Resource matching (same Foundry resource)
    - Run metadata matching
    
    Returns correlation results with confidence scores:
    - HIGH (>=70%): Strong correlation, multiple signals match
    - MEDIUM (>=40%): Reasonable correlation
    - LOW (>=20%): Weak correlation, single signal
    - UNLINKED (<20%): No correlation found
    
    If auto_link is true (default), events meeting min_confidence threshold
    are automatically linked to runs.
    """
    correlation_service = get_purview_correlation_service()
    return correlation_service.correlate_events(request)


@router.post("/correlate/manual", response_model=PurviewEventCorrelation)
async def manually_link_event(
    event_id: str = Body(..., embed=True, description="Event ID to link"),
    run_id: str = Body(..., embed=True, description="Run ID to link to"),
    reason: str = Body(
        default="Manually linked by user", 
        embed=True, 
        description="Reason for manual link"
    ),
) -> PurviewEventCorrelation:
    """
    Manually link a governance event to an attack run.
    
    Creates a high-confidence correlation with MANUAL method.
    Use when automatic correlation didn't find a match but you know
    the event is related to a specific run.
    """
    correlation_service = get_purview_correlation_service()
    correlation = correlation_service.link_event_manually(
        event_id=event_id,
        run_id=run_id,
        reason=reason,
    )
    
    if not correlation:
        raise HTTPException(
            status_code=404, 
            detail=f"Event {event_id} or run {run_id} not found"
        )
    
    return correlation


@router.delete("/correlate/{event_id}")
async def unlink_event(event_id: str) -> dict:
    """
    Remove the correlation for a governance event.
    
    Unlinks the event from any run it was previously correlated with.
    """
    correlation_service = get_purview_correlation_service()
    success = correlation_service.unlink_event(event_id)
    
    if not success:
        raise HTTPException(
            status_code=404, 
            detail=f"Event {event_id} not found or not linked"
        )
    
    return {"message": f"Event {event_id} unlinked successfully"}


@router.get("/correlate/{event_id}", response_model=Optional[PurviewEventCorrelation])
async def get_event_correlation(event_id: str) -> Optional[PurviewEventCorrelation]:
    """
    Get the correlation details for a specific event.
    
    Returns the correlation metadata including confidence, methods used,
    and match details if the event has been correlated.
    """
    correlation_service = get_purview_correlation_service()
    correlation = correlation_service.get_correlation(event_id)
    
    if not correlation:
        # Check if the event exists but just isn't correlated
        store = get_store()
        event = store.get_purview_event(event_id)
        if not event:
            raise HTTPException(status_code=404, detail=f"Event not found: {event_id}")
        return None
    
    return correlation


@router.get("/runs/{run_id}/governance-events", response_model=List[LinkedPurviewEvent])
async def get_governance_events_for_run(run_id: str) -> List[LinkedPurviewEvent]:
    """
    Get all governance events linked to a specific attack run.
    
    Returns full event details along with correlation metadata showing
    how each event was linked to the run.
    """
    correlation_service = get_purview_correlation_service()
    events = correlation_service.get_linked_events_for_run(run_id)
    
    # Also check if run exists
    store = get_store()
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
    
    return events


@router.get("/correlation-methods", response_model=List[dict])
async def list_correlation_methods() -> List[dict]:
    """
    List all available correlation methods with descriptions.
    
    Returns information about each correlation method including its
    weight in the scoring algorithm.
    """
    from services.purview_correlation import CORRELATION_WEIGHTS
    
    methods = [
        {
            "method": PurviewCorrelationMethod.CORRELATION_ID.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.CORRELATION_ID],
            "description": "Exact correlation ID match between event and run (highest confidence)"
        },
        {
            "method": PurviewCorrelationMethod.AGENT_CONTEXT.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.AGENT_CONTEXT],
            "description": "Same agent ID in both event and run"
        },
        {
            "method": PurviewCorrelationMethod.TIMESTAMP_PROXIMITY.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.TIMESTAMP_PROXIMITY],
            "description": "Event timestamp close to run timestamp (within time window)"
        },
        {
            "method": PurviewCorrelationMethod.CLASSIFICATION_MATCH.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.CLASSIFICATION_MATCH],
            "description": "Matching data classification levels"
        },
        {
            "method": PurviewCorrelationMethod.POLICY_CONTEXT.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.POLICY_CONTEXT],
            "description": "Policy from agent profile matches event policy"
        },
        {
            "method": PurviewCorrelationMethod.RESOURCE_MATCH.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.RESOURCE_MATCH],
            "description": "Same Foundry resource name"
        },
        {
            "method": PurviewCorrelationMethod.RUN_METADATA.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.RUN_METADATA],
            "description": "Matching fields in run and event metadata"
        },
        {
            "method": PurviewCorrelationMethod.CAMPAIGN_LINK.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.CAMPAIGN_LINK],
            "description": "Event and run share the same campaign ID"
        },
        {
            "method": PurviewCorrelationMethod.MANUAL.value,
            "weight": CORRELATION_WEIGHTS[PurviewCorrelationMethod.MANUAL],
            "description": "Manually linked by user (always high confidence)"
        },
    ]
    
    return methods


@router.get("/confidence-thresholds", response_model=dict)
async def get_confidence_thresholds() -> dict:
    """
    Get the confidence thresholds used for correlation classification.
    
    Returns the score thresholds that determine HIGH, MEDIUM, LOW,
    and UNLINKED confidence levels.
    """
    from services.purview_correlation import CONFIDENCE_THRESHOLDS
    
    return {
        "thresholds": {
            level.value: threshold 
            for level, threshold in CONFIDENCE_THRESHOLDS.items()
        },
        "description": {
            "high": "Score >= 0.70 - Strong correlation with multiple matching signals",
            "medium": "Score >= 0.40 - Reasonable correlation",
            "low": "Score >= 0.20 - Weak correlation with single signal",
            "unlinked": "Score < 0.20 - No meaningful correlation found"
        }
    }
