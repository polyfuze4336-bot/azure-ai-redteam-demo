"""
Attack and campaign endpoints.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from models.schemas import (
    AttackRequest,
    AttackResult,
    CampaignRequest,
    CampaignResult,
    HistoryResponse,
)
from services import get_attack_runner
from storage import get_store

router = APIRouter(prefix="/api", tags=["attacks"])


@router.post("/run-attack", response_model=AttackResult)
async def run_attack(request: AttackRequest) -> AttackResult:
    """
    Execute a single attack against the target model.
    
    - **prompt**: The attack prompt to send
    - **scenario_id**: Optional ID of a curated scenario
    - **category**: Attack category (if not using a scenario)
    - **target**: Target model name
    - **shield_enabled**: Whether Azure AI Content Safety is enabled
    """
    runner = get_attack_runner()
    result = await runner.run_attack(request)
    return result


@router.post("/run-campaign", response_model=CampaignResult)
async def run_campaign(request: CampaignRequest) -> CampaignResult:
    """
    Execute a campaign of multiple attacks.
    
    - **name**: Campaign name
    - **scenario_ids**: List of scenario IDs to run
    - **categories**: Optional filter by category
    - **target**: Target model name
    - **shield_enabled**: Whether Azure AI Content Safety is enabled
    """
    if not request.scenario_ids:
        raise HTTPException(
            status_code=400,
            detail="At least one scenario_id is required"
        )
    
    runner = get_attack_runner()
    result = await runner.run_campaign(request)
    return result


@router.get("/history", response_model=HistoryResponse)
async def get_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    category: Optional[str] = Query(default=None),
    campaign_id: Optional[str] = Query(default=None),
) -> HistoryResponse:
    """
    Get attack history with optional filtering.
    
    - **limit**: Maximum number of results (default: 50)
    - **offset**: Number of results to skip
    - **category**: Filter by attack category
    - **campaign_id**: Filter by campaign
    """
    store = get_store()
    
    results = store.get_all_results(
        limit=limit,
        offset=offset,
        category=category,
        campaign_id=campaign_id,
    )
    total = store.count_results()
    
    return HistoryResponse(
        results=results,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/history/{run_id}", response_model=AttackResult)
async def get_attack_result(run_id: str) -> AttackResult:
    """
    Get a specific attack result by ID.
    """
    store = get_store()
    result = store.get_result(run_id)
    
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Attack result not found: {run_id}"
        )
    
    return result


@router.get("/campaigns", response_model=list[CampaignResult])
async def get_campaigns(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[CampaignResult]:
    """
    Get all campaigns.
    """
    store = get_store()
    return store.get_all_campaigns(limit=limit, offset=offset)


@router.get("/campaigns/{campaign_id}", response_model=CampaignResult)
async def get_campaign(campaign_id: str) -> CampaignResult:
    """
    Get a specific campaign by ID.
    """
    store = get_store()
    campaign = store.get_campaign(campaign_id)
    
    if not campaign:
        raise HTTPException(
            status_code=404,
            detail=f"Campaign not found: {campaign_id}"
        )
    
    return campaign


@router.get("/statistics")
async def get_statistics() -> dict:
    """
    Get overall attack statistics.
    """
    store = get_store()
    return store.get_statistics()
