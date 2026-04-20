"""
Microsoft Defender alert endpoints.

Provides API routes for:
- Retrieving real Defender alerts
- Syncing alerts from Defender APIs
- Filtering and querying alerts
- Linking alerts to runs and agents
- Getting ingestion status
"""

from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Body

from models.schemas import (
    DefenderAlert,
    DefenderAlertSeverity,
    DefenderAlertStatus,
    DefenderAlertSource,
    DefenderAlertFilter,
    DefenderAlertResponse,
    DefenderIngestionStatus,
)
from services.defender_alerts import get_defender_alert_service
from storage import get_store

router = APIRouter(prefix="/api/defender", tags=["defender-alerts"])


@router.get("/alerts", response_model=DefenderAlertResponse)
async def get_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Maximum alerts to return"),
    offset: int = Query(default=0, ge=0, description="Number of alerts to skip"),
    severity: Optional[List[DefenderAlertSeverity]] = Query(
        default=None, 
        description="Filter by severity levels"
    ),
    status: Optional[List[DefenderAlertStatus]] = Query(
        default=None, 
        description="Filter by status values"
    ),
    source: Optional[List[DefenderAlertSource]] = Query(
        default=None, 
        description="Filter by alert source"
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
    category: Optional[str] = Query(
        default=None, 
        description="Filter by alert category"
    ),
    start_time: Optional[datetime] = Query(
        default=None, 
        description="Filter alerts after this time"
    ),
    end_time: Optional[datetime] = Query(
        default=None, 
        description="Filter alerts before this time"
    ),
) -> DefenderAlertResponse:
    """
    Get Defender alerts with optional filtering.
    
    Returns real alerts from Microsoft Defender APIs when available.
    Falls back to stored alerts if real source is temporarily unavailable.
    """
    store = get_store()
    service = get_defender_alert_service()
    
    # Build filter
    filter_params = DefenderAlertFilter(
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        source=source,
        correlation_id=correlation_id,
        linked_run_id=linked_run_id,
        linked_agent_id=linked_agent_id,
        category=category,
        start_time=start_time,
        end_time=end_time,
    )
    
    # Get alerts from service (which manages caching and real API access)
    alerts = await service.get_alerts(filter_params)
    
    # Store in memory for persistence during session
    store.save_defender_alerts(alerts)
    
    # Determine source status
    ingestion_status = service.get_ingestion_status()
    source_status = "fallback" if ingestion_status.fallback_active else "real"
    
    total = service.count_alerts()
    
    return DefenderAlertResponse(
        alerts=alerts,
        total=total,
        limit=limit,
        offset=offset,
        source_status=source_status,
    )


@router.post("/alerts/sync", response_model=DefenderAlertResponse)
async def sync_alerts(
    filter_params: Optional[DefenderAlertFilter] = Body(
        default=None, 
        description="Optional filter for sync"
    ),
) -> DefenderAlertResponse:
    """
    Trigger a sync of alerts from Microsoft Defender APIs.
    
    Forces a fresh fetch from the real Defender APIs rather than returning cached data.
    Use this to get the latest alerts or after configuration changes.
    """
    service = get_defender_alert_service()
    store = get_store()
    
    # Clear cache to force fresh fetch
    service.clear_cache()
    
    # Sync alerts from Defender
    alerts = await service.sync_alerts(filter_params)
    
    # Store in memory
    store.save_defender_alerts(alerts)
    
    ingestion_status = service.get_ingestion_status()
    source_status = "fallback" if ingestion_status.fallback_active else "real"
    
    return DefenderAlertResponse(
        alerts=alerts,
        total=len(alerts),
        limit=filter_params.limit if filter_params else 50,
        offset=filter_params.offset if filter_params else 0,
        source_status=source_status,
    )


@router.get("/alerts/{alert_id}", response_model=DefenderAlert)
async def get_alert_by_id(alert_id: str) -> DefenderAlert:
    """
    Get a specific Defender alert by ID.
    """
    service = get_defender_alert_service()
    store = get_store()
    
    # Try service cache first
    alert = await service.get_alert_by_id(alert_id)
    
    # Fall back to store
    if not alert:
        alert = store.get_defender_alert(alert_id)
    
    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return alert


@router.patch("/alerts/{alert_id}/status", response_model=DefenderAlert)
async def update_alert_status(
    alert_id: str,
    status: DefenderAlertStatus = Body(..., embed=True, description="New alert status"),
) -> DefenderAlert:
    """
    Update the status of a Defender alert.
    
    This updates the local status tracking. Actual status in Defender
    may need to be updated separately through the Defender portal.
    """
    service = get_defender_alert_service()
    store = get_store()
    
    # Update in service
    alert = await service.update_alert_status(alert_id, status)
    
    # Update in store
    if not alert:
        alert = store.update_defender_alert_status(alert_id, status)
    else:
        store.save_defender_alert(alert)
    
    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return alert


@router.post("/alerts/{alert_id}/link-run", response_model=DefenderAlert)
async def link_alert_to_run(
    alert_id: str,
    run_id: str = Body(..., embed=True, description="Attack run ID to link"),
) -> DefenderAlert:
    """
    Link a Defender alert to a specific attack run.
    
    Use this to correlate alerts with attack runs for investigation.
    """
    service = get_defender_alert_service()
    store = get_store()
    
    # Verify run exists
    run = store.get_result(run_id)
    if not run:
        raise HTTPException(
            status_code=404,
            detail=f"Run with ID {run_id} not found"
        )
    
    # Link in service
    alert = await service.link_alert_to_run(alert_id, run_id)
    
    # Link in store
    if not alert:
        alert = store.link_alert_to_run(alert_id, run_id)
    else:
        store.save_defender_alert(alert)
    
    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return alert


@router.post("/alerts/{alert_id}/link-agent", response_model=DefenderAlert)
async def link_alert_to_agent(
    alert_id: str,
    agent_id: str = Body(..., embed=True, description="Agent profile ID to link"),
) -> DefenderAlert:
    """
    Link a Defender alert to a specific agent profile.
    
    Use this to correlate alerts with agent configurations for investigation.
    """
    service = get_defender_alert_service()
    store = get_store()
    
    # Link in service
    alert = await service.link_alert_to_agent(alert_id, agent_id)
    
    # Link in store
    if not alert:
        alert = store.link_alert_to_agent(alert_id, agent_id)
    else:
        store.save_defender_alert(alert)
    
    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return alert


@router.get("/status", response_model=DefenderIngestionStatus)
async def get_ingestion_status() -> DefenderIngestionStatus:
    """
    Get the status of the Defender alert ingestion service.
    
    Returns information about:
    - Whether ingestion is enabled and configured
    - Connection status to real Defender APIs
    - Whether fallback mode is active
    - Last sync timestamp
    - Alert counts
    """
    service = get_defender_alert_service()
    return service.get_ingestion_status()


@router.get("/alerts/by-correlation/{correlation_id}", response_model=DefenderAlertResponse)
async def get_alerts_by_correlation(
    correlation_id: str,
    limit: int = Query(default=50, ge=1, le=500),
) -> DefenderAlertResponse:
    """
    Get all Defender alerts with a specific correlation ID.
    
    Useful for finding alerts related to a specific attack run or session.
    """
    service = get_defender_alert_service()
    
    filter_params = DefenderAlertFilter(
        correlation_id=correlation_id,
        limit=limit,
    )
    
    alerts = await service.get_alerts(filter_params)
    
    ingestion_status = service.get_ingestion_status()
    source_status = "fallback" if ingestion_status.fallback_active else "real"
    
    return DefenderAlertResponse(
        alerts=alerts,
        total=len(alerts),
        limit=limit,
        offset=0,
        source_status=source_status,
    )


@router.get("/alerts/high-severity", response_model=DefenderAlertResponse)
async def get_high_severity_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    include_critical: bool = Query(default=True, description="Include critical severity"),
) -> DefenderAlertResponse:
    """
    Get high and critical severity Defender alerts.
    
    Convenience endpoint for quickly viewing important alerts.
    """
    service = get_defender_alert_service()
    
    severities = [DefenderAlertSeverity.HIGH]
    if include_critical:
        severities.append(DefenderAlertSeverity.CRITICAL)
    
    filter_params = DefenderAlertFilter(
        severity=severities,
        limit=limit,
    )
    
    alerts = await service.get_alerts(filter_params)
    
    ingestion_status = service.get_ingestion_status()
    source_status = "fallback" if ingestion_status.fallback_active else "real"
    
    return DefenderAlertResponse(
        alerts=alerts,
        total=len(alerts),
        limit=limit,
        offset=0,
        source_status=source_status,
    )


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str) -> dict:
    """
    Delete a Defender alert from local storage.
    
    Note: This only removes the alert from local storage, not from Microsoft Defender.
    """
    store = get_store()
    service = get_defender_alert_service()
    
    # Clear from service cache
    if alert_id in service._alert_cache:
        del service._alert_cache[alert_id]
    
    # Delete from store
    deleted = store.delete_defender_alert(alert_id)
    
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return {"deleted": True, "alert_id": alert_id}


@router.delete("/alerts")
async def clear_all_alerts() -> dict:
    """
    Clear all Defender alerts from local storage.
    
    Useful for resetting the demo environment.
    Note: This does not affect alerts in Microsoft Defender.
    """
    store = get_store()
    service = get_defender_alert_service()
    
    count = store.count_defender_alerts()
    
    # Clear service cache
    service.clear_cache()
    
    # Clear store
    store.clear_defender_alerts()
    
    return {"cleared": True, "count": count}


# =============================================================================
# CORRELATION ENDPOINTS
# =============================================================================

from models.schemas import (
    AlertCorrelation,
    CorrelationMethod,
    CorrelationConfidence,
    CorrelationRequest,
    CorrelationResult,
    AttackResult,
)
from services.defender_correlation import get_correlation_service


@router.post("/correlation/correlate", response_model=CorrelationResult)
async def correlate_alerts(
    request: CorrelationRequest = Body(
        default=CorrelationRequest(),
        description="Correlation parameters"
    ),
) -> CorrelationResult:
    """
    Correlate Defender alerts with attack runs.
    
    Analyzes alerts and runs using multiple correlation methods:
    - correlation_id: Exact match on correlation IDs
    - timestamp_proximity: Alert timestamp close to run timestamp
    - agent_context: Same agent ID
    - target_context: Same deployment/resource name
    - category_match: Alert category maps to attack category
    - resource_match: Same Foundry resource
    - metadata_match: Matching metadata fields
    
    By default, analyzes all unlinked alerts against recent runs.
    Use alert_ids/run_ids to scope to specific items.
    Set auto_link=True (default) to automatically link matches above threshold.
    """
    correlation_service = get_correlation_service()
    return correlation_service.correlate_alerts(request)


@router.post("/alerts/{alert_id}/correlate-to-run/{run_id}", response_model=AlertCorrelation)
async def correlate_alert_to_run(
    alert_id: str,
    run_id: str,
) -> AlertCorrelation:
    """
    Calculate correlation score between a specific alert and run.
    
    Does NOT automatically link - use this to preview correlation before linking.
    Returns the correlation details including confidence, score, and reasoning.
    """
    store = get_store()
    correlation_service = get_correlation_service()
    
    alert = store.get_defender_alert(alert_id)
    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    run = store.get_result(run_id)
    if not run:
        raise HTTPException(
            status_code=404,
            detail=f"Run with ID {run_id} not found"
        )
    
    return correlation_service.correlate_alert_to_run(alert, run)


@router.post("/alerts/{alert_id}/link-run-manual", response_model=AlertCorrelation)
async def manually_link_alert_to_run(
    alert_id: str,
    run_id: str = Body(..., embed=True, description="Run ID to link to"),
) -> AlertCorrelation:
    """
    Manually link an alert to a run, bypassing confidence checks.
    
    Use this when you know an alert is related to a run even if
    automatic correlation didn't find a strong match.
    Sets confidence to HIGH with MANUAL correlation method.
    """
    correlation_service = get_correlation_service()
    
    result = correlation_service.manually_link_alert_to_run(alert_id, run_id)
    
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Alert {alert_id} or run {run_id} not found"
        )
    
    return result


@router.delete("/alerts/{alert_id}/unlink")
async def unlink_alert_from_run(
    alert_id: str,
) -> dict:
    """
    Remove the link between an alert and its associated run.
    
    Clears the linked_run_id, linked_agent_id, and linked_campaign_id
    from the alert, and removes the alert from the run's linked_defender_alerts.
    """
    correlation_service = get_correlation_service()
    
    success = correlation_service.unlink_alert_from_run(alert_id)
    
    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    return {"unlinked": True, "alert_id": alert_id}


@router.get("/alerts/for-run/{run_id}", response_model=List[DefenderAlert])
async def get_alerts_for_run(
    run_id: str,
) -> List[DefenderAlert]:
    """
    Get all Defender alerts linked to a specific attack run.
    
    Returns alerts that were correlated (automatically or manually) to this run.
    """
    store = get_store()
    
    # Verify run exists
    run = store.get_result(run_id)
    if not run:
        raise HTTPException(
            status_code=404,
            detail=f"Run with ID {run_id} not found"
        )
    
    correlation_service = get_correlation_service()
    return correlation_service.get_alerts_for_run(run_id)


@router.get("/runs/for-alert/{alert_id}", response_model=List[AttackResult])
async def get_runs_for_alert(
    alert_id: str,
) -> List[AttackResult]:
    """
    Get attack runs linked to a specific Defender alert.
    
    Returns runs that were correlated (automatically or manually) to this alert.
    Typically returns one run, but could be multiple if manually linked.
    """
    store = get_store()
    
    # Verify alert exists
    alert = store.get_defender_alert(alert_id)
    if not alert:
        raise HTTPException(
            status_code=404,
            detail=f"Alert with ID {alert_id} not found"
        )
    
    correlation_service = get_correlation_service()
    return correlation_service.get_runs_for_alert(alert_id)


@router.get("/correlation/stats")
async def get_correlation_stats() -> dict:
    """
    Get statistics about alert-to-run correlations.
    
    Returns counts of linked/unlinked alerts, correlation method usage, etc.
    """
    store = get_store()
    
    all_alerts = store.get_all_defender_alerts(limit=10000)
    
    total = len(all_alerts)
    linked = sum(1 for a in all_alerts if a.linked_run_id)
    unlinked = total - linked
    
    # Count by severity
    severe_linked = sum(
        1 for a in all_alerts 
        if a.linked_run_id and a.severity in [DefenderAlertSeverity.HIGH, DefenderAlertSeverity.CRITICAL]
    )
    
    return {
        "total_alerts": total,
        "linked_alerts": linked,
        "unlinked_alerts": unlinked,
        "link_rate": round(linked / total, 3) if total > 0 else 0.0,
        "high_severity_linked": severe_linked,
    }
