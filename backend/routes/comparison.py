"""
Comparison mode endpoints for side-by-side attack testing.
"""

from fastapi import APIRouter, HTTPException

from models.schemas import (
    ComparisonRequest,
    ComparisonResult,
    ComparisonConfigResponse,
)
from services import get_comparison_service

router = APIRouter(prefix="/api/comparison", tags=["comparison"])


@router.get("/config", response_model=ComparisonConfigResponse)
async def get_comparison_config() -> ComparisonConfigResponse:
    """
    Get current comparison mode configuration.
    
    Returns information about:
    - Whether both targets use the same Foundry resource
    - Baseline and guarded deployment names
    - Shield settings for each target
    """
    service = get_comparison_service()
    return service.get_config()


@router.post("/run", response_model=ComparisonResult)
async def run_comparison(request: ComparisonRequest) -> ComparisonResult:
    """
    Run a side-by-side comparison attack.
    
    Executes the same attack prompt against:
    - **Baseline target**: Typically without shield protection
    - **Guarded target**: Typically with shield protection
    
    Returns detailed comparison including:
    - Response text from each target
    - Shield and evaluator verdicts
    - Attack success rate comparison
    - Latency difference
    """
    service = get_comparison_service()
    
    try:
        result = await service.run_comparison(request)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Comparison failed: {str(e)}")
