"""
Scenario management endpoints.
Exposes curated attack packs and individual scenarios.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query

from models.schemas import AttackScenario, AttackCategory
from services import get_scenario_service

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


@router.get("", response_model=List[AttackScenario])
async def list_scenarios(
    category: Optional[str] = Query(default=None, description="Filter by category"),
) -> List[AttackScenario]:
    """
    List all available attack scenarios.
    
    - **category**: Optional filter by attack category (e.g., "jailbreak", "prompt-injection")
    """
    service = get_scenario_service()
    
    if category:
        try:
            cat_enum = AttackCategory(category)
            return service.get_scenarios_by_category(cat_enum)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid category: {category}. Valid categories: {[c.value for c in AttackCategory]}"
            )
    
    return service.get_all_scenarios()


@router.get("/packs", response_model=List[Dict[str, Any]])
async def list_attack_packs() -> List[Dict[str, Any]]:
    """
    List all attack packs with metadata.
    
    Returns detailed information about each attack pack including:
    - category: The attack category
    - name: Human-readable pack name
    - description: What this pack tests
    - count: Number of scenarios in the pack
    - severities: Breakdown by severity level
    """
    service = get_scenario_service()
    return service.get_categories()


@router.get("/categories")
async def list_categories() -> List[Dict[str, Any]]:
    """
    List all attack categories with scenario counts.
    
    Returns a list of category objects with:
    - category: The category identifier
    - name: Human-readable name
    - description: What the category tests
    - count: Number of scenarios
    - severities: Count by severity level
    """
    service = get_scenario_service()
    return service.get_categories()


@router.get("/categories/names")
async def list_category_names() -> List[str]:
    """
    List just the category identifiers.
    
    Returns a simple list of category strings that can be used for filtering.
    """
    service = get_scenario_service()
    return service.get_category_names()


@router.get("/stats")
async def get_stats() -> Dict[str, Any]:
    """
    Get overall statistics about the attack scenario library.
    """
    service = get_scenario_service()
    categories = service.get_categories()
    
    total_scenarios = service.count_scenarios()
    total_critical = sum(c.get("severities", {}).get("critical", 0) for c in categories)
    total_high = sum(c.get("severities", {}).get("high", 0) for c in categories)
    total_medium = sum(c.get("severities", {}).get("medium", 0) for c in categories)
    total_low = sum(c.get("severities", {}).get("low", 0) for c in categories)
    
    return {
        "total_scenarios": total_scenarios,
        "total_categories": len(categories),
        "severities": {
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
        },
        "categories": [c["category"] for c in categories],
    }


@router.get("/{scenario_id}", response_model=AttackScenario)
async def get_scenario(scenario_id: str) -> AttackScenario:
    """
    Get a specific scenario by ID.
    """
    service = get_scenario_service()
    scenario = service.get_scenario(scenario_id)
    
    if not scenario:
        raise HTTPException(
            status_code=404,
            detail=f"Scenario not found: {scenario_id}"
        )
    
    return scenario
