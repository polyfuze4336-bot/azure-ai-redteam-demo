"""
API routes module.
"""

from .attacks import router as attacks_router
from .health import router as health_router
from .scenarios import router as scenarios_router
from .comparison import router as comparison_router
from .pyrit import router as pyrit_router
from .agents import router as agents_router
from .lifecycle import router as lifecycle_router
from .defender_alerts import router as defender_alerts_router
from .purview_governance import router as purview_governance_router

__all__ = [
    "attacks_router", 
    "health_router", 
    "scenarios_router", 
    "comparison_router", 
    "pyrit_router",
    "agents_router",
    "lifecycle_router",
    "defender_alerts_router",
    "purview_governance_router",
]
