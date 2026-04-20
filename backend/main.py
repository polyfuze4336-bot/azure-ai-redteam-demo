"""
Azure AI Red Team Demo API
Main FastAPI application entry point.
"""

import sys
from pathlib import Path

# Add backend to Python path for module resolution
sys.path.insert(0, str(Path(__file__).parent))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from routes import attacks_router, health_router, scenarios_router, comparison_router, pyrit_router, agents_router, lifecycle_router, defender_alerts_router, purview_governance_router
from telemetry import setup_logging, get_logger, get_telemetry_service, close_telemetry_service
from storage import get_store
from config import get_settings
from services import get_target_connector, close_target_connector, get_safety_layer, close_safety_layer, check_pyrit_availability

# Setup logging
setup_logging(level="INFO")
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting Azure AI Red Team Demo API...")
    
    # Load and log configuration
    settings = get_settings()
    logger.info(f"Run mode: {settings.run_mode.value}")
    logger.info(f"Foundry resource: {settings.foundry_resource_name or 'not configured'}")
    logger.info(f"Azure OpenAI endpoint: {settings.foundry_endpoint or 'not configured'}")
    logger.info(f"Authentication mode: {settings.auth_mode.value}")
    
    if settings.is_demo_mode:
        logger.info("Running in DEMO mode - using mock responses")
    else:
        if settings.is_azure_configured:
            logger.info(f"Azure OpenAI configured: deployment={settings.azure_openai_deployment_name}")
        else:
            missing = settings.validate_for_azure_mode()
            logger.warning(f"Azure mode requested but missing configuration: {missing}")
    
    # Initialize services
    store = get_store()
    logger.info(f"Storage initialized: {store.count_results()} results, {store.count_campaigns()} campaigns")
    
    # Initialize target connector
    connector = get_target_connector()
    config_status = connector.get_configuration_status()
    logger.info(f"Target connector initialized: demo_mode={config_status['is_demo_mode']}")
    
    # Initialize safety layer
    safety_layer = get_safety_layer()
    safety_status = safety_layer.get_status()
    logger.info(f"Safety layer initialized: provider={safety_status['primary_provider']}, azure_available={safety_layer.is_azure_available}")
    if settings.is_content_safety_configured:
        logger.info(f"Azure Content Safety configured: {settings.azure_content_safety_endpoint}")
    else:
        logger.info("Using mock safety provider (Azure Content Safety not configured)")
    
    # Initialize telemetry service
    telemetry_svc = get_telemetry_service()
    telemetry_status = telemetry_svc.get_status()
    logger.info(f"Telemetry service initialized: foundry={telemetry_status['foundry_resource_name'] or 'not set'}")
    logger.info(f"Telemetry adapters: {[a['name'] for a in telemetry_status['adapters']]}")
    if settings.applicationinsights_connection_string:
        logger.info("Application Insights configured")
    
    # Check PyRIT availability (optional addon)
    pyrit_available, pyrit_message = check_pyrit_availability()
    logger.info(f"PyRIT integration: enabled={settings.pyrit_enabled}, available={pyrit_available}")
    if settings.pyrit_enabled and not pyrit_available:
        logger.info(f"PyRIT not available: {pyrit_message}")
    
    yield
    
    # Cleanup
    logger.info("Shutting down API...")
    await close_telemetry_service()
    logger.info("Telemetry service closed")
    await close_safety_layer()
    logger.info("Safety layer closed")
    await close_target_connector()
    logger.info("Target connector closed")


# Create FastAPI application
app = FastAPI(
    title="Azure AI Red Team Demo API",
    description="""
    API for simulating adversarial attacks against Azure AI applications.
    
    ## Features
    
    - **Attack Execution**: Run individual attacks or full campaigns
    - **Curated Scenarios**: 25+ pre-built attack scenarios across 9 categories
    - **Mock Results**: Simulated Azure AI Content Safety verdicts
    - **History Tracking**: View past attacks and campaigns
    
    ## Categories
    
    - Jailbreak attempts
    - Prompt injection
    - Prompt extraction
    - Data exfiltration
    - Credential theft
    - Policy evasion
    - Indirect injection
    - Tool misuse
    - Code vulnerabilities
    
    ---
    
    **Note**: This is a demo API returning mock responses.
    Real Azure OpenAI and Content Safety integration coming soon.
    """,
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health_router)
app.include_router(attacks_router)
app.include_router(scenarios_router)
app.include_router(comparison_router)
app.include_router(pyrit_router)
app.include_router(agents_router)
app.include_router(lifecycle_router)
app.include_router(defender_alerts_router)
app.include_router(purview_governance_router)


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
