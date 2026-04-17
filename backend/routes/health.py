"""
Health check endpoint.
"""

from datetime import datetime
from typing import Any, Dict
from fastapi import APIRouter

from models.schemas import HealthResponse
from config import get_settings
from services import get_target_connector, get_safety_layer
from telemetry import get_telemetry_service

router = APIRouter(tags=["health"])


@router.get("/api/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.
    Returns service status and version information.
    """
    settings = get_settings()
    safety_layer = get_safety_layer()
    
    # Determine Azure OpenAI status based on configuration
    if settings.is_demo_mode:
        azure_openai_status = "demo"
    elif settings.is_azure_configured:
        azure_openai_status = "configured"
    else:
        azure_openai_status = "not_configured"
    
    # Determine Content Safety status
    if safety_layer.is_azure_available:
        content_safety_status = "azure"
    else:
        content_safety_status = "mock"
    
    return HealthResponse(
        status="ok",
        version="1.0.0",
        timestamp=datetime.utcnow(),
        services={
            "api": "running",
            "storage": "in-memory",
            "azure_openai": azure_openai_status,
            "content_safety": content_safety_status,
            "safety_provider": safety_layer.primary_provider_name,
            "run_mode": settings.run_mode.value,
        }
    )


@router.get("/api/config/status")
async def config_status() -> Dict[str, Any]:
    """
    Get current configuration status.
    
    Returns details about the Azure AI Foundry and OpenAI configuration,
    useful for debugging and verifying setup.
    
    Note: Sensitive values (API keys, secrets) are not exposed.
    """
    connector = get_target_connector()
    status = connector.get_configuration_status()
    settings = get_settings()
    safety_layer = get_safety_layer()
    safety_status = safety_layer.get_status()
    telemetry_svc = get_telemetry_service()
    telemetry_status = telemetry_svc.get_status()
    
    # Return non-sensitive configuration info
    return {
        "run_mode": status["run_mode"],
        "is_demo_mode": status["is_demo_mode"],
        "is_azure_configured": status["is_azure_configured"],
        "auth_mode": status["auth_mode"],
        "foundry_resource_name": status["foundry_resource_name"],
        "azure_ai_project_name": status["azure_ai_project_name"],
        "endpoint": status["endpoint"],
        "deployment_name": status["deployment_name"],
        "api_version": status["api_version"],
        "comparison_mode": {
            "baseline_deployment": status["baseline_deployment"],
            "guarded_deployment": status["guarded_deployment"],
        },
        "missing_config": status["missing_config"],
        "safety_layer": {
            "enabled": settings.safety_layer_enabled,
            "fallback_to_mock": settings.safety_layer_fallback_to_mock,
            "primary_provider": safety_status["primary_provider"],
            "azure_content_safety_configured": settings.is_content_safety_configured,
            "providers": {
                name: {
                    "name": info["name"],
                    "version": info["version"],
                    "is_available": info["is_available"],
                }
                for name, info in safety_status["providers"].items()
            },
        },
        "telemetry": {
            "enabled": settings.telemetry_enabled,
            "foundry_resource_name": telemetry_status["foundry_resource_name"],
            "deployment_name": telemetry_status["default_deployment_name"],
            "active_contexts": telemetry_status["active_contexts"],
            "adapters": [
                {
                    "name": a["name"],
                    "is_available": a["is_available"],
                }
                for a in telemetry_status["adapters"]
            ],
            "app_insights_configured": bool(settings.applicationinsights_connection_string),
        },
    }


@router.get("/")
async def root() -> dict:
    """Root endpoint - API information."""
    return {
        "name": "Azure AI Red Team Demo API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health",
    }
