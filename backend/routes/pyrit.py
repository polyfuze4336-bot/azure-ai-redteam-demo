"""
PyRIT integration endpoints for automated red teaming.

These endpoints are optional - curated attacks remain the default path.
PyRIT-driven campaigns are clearly labeled as automated runs.
"""

from fastapi import APIRouter, HTTPException

from models.schemas import (
    PyRITCampaignRequest,
    PyRITCampaignResult,
    PyRITConfigResponse,
    PyRITStatus,
)
from services import get_pyrit_adapter

router = APIRouter(prefix="/api/pyrit", tags=["pyrit"])


@router.get("/config", response_model=PyRITConfigResponse)
async def get_pyrit_config() -> PyRITConfigResponse:
    """
    Get PyRIT integration status and configuration.
    
    Returns information about:
    - Whether PyRIT is installed and available
    - Available attack strategies
    - Default settings
    - Target endpoint configuration
    
    The application works fully without PyRIT - this endpoint
    helps the UI determine whether to show PyRIT options.
    """
    adapter = get_pyrit_adapter()
    return adapter.get_config()


@router.post("/campaign", response_model=PyRITCampaignResult)
async def run_pyrit_campaign(request: PyRITCampaignRequest) -> PyRITCampaignResult:
    """
    Run a PyRIT automated red teaming campaign.
    
    This endpoint runs automated attacks using PyRIT strategies.
    Results are:
    - Labeled with run_source='pyrit' for UI differentiation
    - Stored in both raw and normalized formats
    - Mapped to the platform's standard result schema
    
    **Note**: If PyRIT is not installed, returns simulated demo results
    showing the expected output format. The demo uses the same
    normalization logic as real PyRIT execution.
    
    Strategies available:
    - **jailbreak**: Persona-based jailbreak attempts
    - **prompt_injection**: Indirect prompt injection tests
    - **crescendo**: Multi-turn escalation attacks
    - **pair**: Prompt-adversarial pairing
    - **tap**: Tree-of-attacks prompt generation
    - **skeleton_key**: Master key bypass techniques
    """
    adapter = get_pyrit_adapter()
    config = adapter.get_config()
    
    # Allow running even if PyRIT is not installed (demo mode)
    # But warn if disabled entirely
    if config.status == PyRITStatus.DISABLED:
        raise HTTPException(
            status_code=400,
            detail="PyRIT integration is disabled. Set PYRIT_ENABLED=true to enable."
        )
    
    if config.status == PyRITStatus.MISCONFIGURED:
        raise HTTPException(
            status_code=400,
            detail="PyRIT configuration is incomplete. Check FOUNDRY_RESOURCE_NAME and endpoint settings."
        )
    
    try:
        result = await adapter.run_campaign(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PyRIT campaign failed: {str(e)}")


@router.get("/strategies")
async def list_strategies():
    """
    List available PyRIT attack strategies with descriptions.
    
    Returns detailed information about each strategy to help
    users understand what will be tested.
    """
    strategies = [
        {
            "id": "jailbreak",
            "name": "Jailbreak Attacks",
            "description": "Persona adoption and role-play based attempts to bypass safety guidelines",
            "severity": "critical",
            "multi_turn": True,
        },
        {
            "id": "prompt_injection", 
            "name": "Prompt Injection",
            "description": "Indirect injection attempts through embedded instructions",
            "severity": "high",
            "multi_turn": False,
        },
        {
            "id": "crescendo",
            "name": "Crescendo Attack",
            "description": "Gradual escalation toward restricted topics over multiple turns",
            "severity": "critical",
            "multi_turn": True,
        },
        {
            "id": "pair",
            "name": "PAIR (Prompt-Adversarial)",
            "description": "Automated jailbreak discovery using adversarial prompt pairing",
            "severity": "high",
            "multi_turn": True,
        },
        {
            "id": "tap",
            "name": "TAP (Tree of Attacks)",
            "description": "Tree-structured prompt generation for comprehensive testing",
            "severity": "high",
            "multi_turn": True,
        },
        {
            "id": "skeleton_key",
            "name": "Skeleton Key",
            "description": "Master key bypass techniques targeting system prompt overrides",
            "severity": "critical",
            "multi_turn": False,
        },
    ]
    
    return {"strategies": strategies}
