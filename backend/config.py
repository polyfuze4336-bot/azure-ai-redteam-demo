"""
Configuration module for Azure AI Foundry and Azure OpenAI integration.

Loads settings from environment variables with support for both local demo mode
and production Azure-hosted configuration.

Environment variables:
- FOUNDRY_RESOURCE_NAME: Azure AI Foundry resource name (e.g., mkhalib-4370-resource)
- AZURE_OPENAI_ENDPOINT: Azure OpenAI endpoint URL
- AZURE_OPENAI_API_KEY: API key for Azure OpenAI (use for key-based auth)
- AZURE_OPENAI_DEPLOYMENT_NAME: Model deployment name
- AZURE_OPENAI_API_VERSION: API version (default: 2024-02-15-preview)

Optional for Entra ID / Service Principal auth:
- AZURE_AI_PROJECT_NAME: AI project name within Foundry
- AZURE_TENANT_ID: Azure tenant ID
- AZURE_CLIENT_ID: Service principal client ID
- AZURE_CLIENT_SECRET: Service principal client secret
"""

import os
from enum import Enum
from typing import Optional
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class AuthMode(str, Enum):
    """Authentication mode for Azure services."""
    API_KEY = "api_key"
    ENTRA_ID = "entra_id"
    DEFAULT_CREDENTIAL = "default_credential"


class RunMode(str, Enum):
    """Application run mode."""
    DEMO = "demo"  # Local demo with mock responses
    AZURE = "azure"  # Connected to Azure AI Foundry


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Supports two modes:
    - DEMO: Returns mock responses (default, no Azure connection required)
    - AZURE: Connects to real Azure AI Foundry/OpenAI endpoints
    """
    
    # Application mode
    run_mode: RunMode = Field(
        default=RunMode.DEMO,
        description="Application run mode: 'demo' for mock responses, 'azure' for real API calls"
    )
    
    # Azure AI Foundry resource configuration
    foundry_resource_name: Optional[str] = Field(
        default=None,
        description="Azure AI Foundry resource name (e.g., mkhalib-4370-resource)"
    )
    
    azure_ai_project_name: Optional[str] = Field(
        default=None,
        description="Azure AI project name within the Foundry resource"
    )
    
    # Azure OpenAI endpoint configuration
    azure_openai_endpoint: Optional[str] = Field(
        default=None,
        description="Azure OpenAI endpoint URL"
    )
    
    azure_openai_api_key: Optional[str] = Field(
        default=None,
        description="Azure OpenAI API key (for key-based authentication)"
    )
    
    azure_openai_deployment_name: Optional[str] = Field(
        default=None,
        description="Azure OpenAI model deployment name"
    )
    
    azure_openai_api_version: str = Field(
        default="2024-02-15-preview",
        description="Azure OpenAI API version"
    )
    
    # Entra ID / Service Principal authentication
    azure_tenant_id: Optional[str] = Field(
        default=None,
        description="Azure tenant ID for Entra ID authentication"
    )
    
    azure_client_id: Optional[str] = Field(
        default=None,
        description="Azure client ID for service principal authentication"
    )
    
    azure_client_secret: Optional[str] = Field(
        default=None,
        description="Azure client secret for service principal authentication"
    )
    
    # Target comparison mode settings (for baseline vs guarded comparison)
    baseline_deployment_name: Optional[str] = Field(
        default=None,
        description="Baseline model deployment name for comparison mode"
    )
    
    guarded_deployment_name: Optional[str] = Field(
        default=None,
        description="Guarded model deployment name for comparison mode"
    )
    
    # Flexible comparison endpoints (optional - uses main endpoint if not set)
    baseline_azure_openai_endpoint: Optional[str] = Field(
        default=None,
        description="Baseline Azure OpenAI endpoint (optional, uses main endpoint if not set)"
    )
    
    guarded_azure_openai_endpoint: Optional[str] = Field(
        default=None,
        description="Guarded Azure OpenAI endpoint (optional, uses main endpoint if not set)"
    )
    
    # Comparison mode shield settings
    baseline_shield_enabled: bool = Field(
        default=False,
        description="Enable shield for baseline target (typically False)"
    )
    
    guarded_shield_enabled: bool = Field(
        default=True,
        description="Enable shield for guarded target (typically True)"
    )
    
    # Azure AI Content Safety configuration
    azure_content_safety_endpoint: Optional[str] = Field(
        default=None,
        description="Azure AI Content Safety endpoint URL"
    )
    
    azure_content_safety_key: Optional[str] = Field(
        default=None,
        description="Azure AI Content Safety API key"
    )
    
    azure_content_safety_api_version: str = Field(
        default="2024-02-15-preview",
        description="Azure AI Content Safety API version"
    )
    
    # Safety layer configuration
    safety_layer_enabled: bool = Field(
        default=True,
        description="Enable safety layer checks before target calls"
    )
    
    safety_layer_fallback_to_mock: bool = Field(
        default=True,
        description="Fall back to mock safety provider if Azure unavailable"
    )
    
    # Telemetry configuration
    applicationinsights_connection_string: Optional[str] = Field(
        default=None,
        description="Azure Application Insights connection string for telemetry"
    )
    
    telemetry_enabled: bool = Field(
        default=True,
        description="Enable structured telemetry logging"
    )
    
    telemetry_console_structured_json: bool = Field(
        default=False,
        description="Output telemetry as structured JSON (otherwise human-readable)"
    )
    
    # ==========================================================================
    # PyRIT Integration (Optional)
    # ==========================================================================
    
    pyrit_enabled: bool = Field(
        default=False,
        description="Enable PyRIT automated red teaming integration (optional addon)"
    )
    
    pyrit_attack_strategies: list[str] = Field(
        default_factory=lambda: ["jailbreak", "prompt_injection"],
        description="PyRIT attack strategies to run"
    )
    
    pyrit_max_turns: int = Field(
        default=5,
        description="Maximum conversation turns for multi-turn PyRIT attacks"
    )
    
    pyrit_parallel_attacks: int = Field(
        default=3,
        description="Number of parallel attack sequences to run"
    )
    
    pyrit_timeout_seconds: int = Field(
        default=120,
        description="Timeout for PyRIT attack sequences"
    )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"
    
    @property
    def auth_mode(self) -> AuthMode:
        """Determine the authentication mode based on available credentials."""
        if self.azure_openai_api_key:
            return AuthMode.API_KEY
        elif self.azure_client_id and self.azure_client_secret and self.azure_tenant_id:
            return AuthMode.ENTRA_ID
        else:
            return AuthMode.DEFAULT_CREDENTIAL
    
    @property
    def is_azure_configured(self) -> bool:
        """Check if Azure OpenAI is properly configured for API calls."""
        return bool(
            self.azure_openai_endpoint 
            and self.azure_openai_deployment_name
            and (self.azure_openai_api_key or self.azure_tenant_id)
        )
    
    @property
    def is_demo_mode(self) -> bool:
        """Check if running in demo mode with mock responses."""
        return self.run_mode == RunMode.DEMO
    
    @property
    def is_content_safety_configured(self) -> bool:
        """Check if Azure AI Content Safety is properly configured."""
        return bool(self.azure_content_safety_endpoint and self.azure_content_safety_key)
    
    @property
    def foundry_endpoint(self) -> Optional[str]:
        """
        Construct the Azure AI Foundry endpoint if resource name is provided.
        Falls back to azure_openai_endpoint if set.
        """
        if self.azure_openai_endpoint:
            return self.azure_openai_endpoint
        if self.foundry_resource_name:
            return f"https://{self.foundry_resource_name}.openai.azure.com"
        return None
    
    def get_endpoint_for_target(self, target: str = "default") -> Optional[str]:
        """
        Get the endpoint URL for a specific target.
        Supports 'baseline' and 'guarded' for comparison mode.
        """
        if target == "baseline" and self.baseline_azure_openai_endpoint:
            return self.baseline_azure_openai_endpoint
        elif target == "guarded" and self.guarded_azure_openai_endpoint:
            return self.guarded_azure_openai_endpoint
        # Fall back to main endpoint
        return self.foundry_endpoint
    
    def get_shield_enabled_for_target(self, target: str = "default") -> bool:
        """
        Get whether shield is enabled for a specific target.
        
        Args:
            target: 'default', 'baseline', or 'guarded'
        
        Returns:
            Whether shield is enabled for the target
        """
        if target == "baseline":
            return self.baseline_shield_enabled
        elif target == "guarded":
            return self.guarded_shield_enabled
        return self.safety_layer_enabled
    
    @property
    def is_same_resource_comparison(self) -> bool:
        """
        Check if baseline and guarded use the same Foundry resource.
        
        Returns:
            True if both targets use the same resource (different deployments only)
        """
        baseline_endpoint = self.get_endpoint_for_target("baseline")
        guarded_endpoint = self.get_endpoint_for_target("guarded")
        return baseline_endpoint == guarded_endpoint
    
    @property
    def comparison_mode_configured(self) -> bool:
        """
        Check if comparison mode is properly configured.
        
        Returns:
            True if at least one target has a deployment configured
        """
        return bool(
            self.baseline_deployment_name or 
            self.guarded_deployment_name or
            self.azure_openai_deployment_name
        )
    
    def get_deployment_for_target(self, target: str = "default") -> Optional[str]:
        """
        Get the deployment name for a specific target.
        
        Args:
            target: 'default', 'baseline', or 'guarded'
        
        Returns:
            Deployment name for the target
        """
        if target == "baseline" and self.baseline_deployment_name:
            return self.baseline_deployment_name
        elif target == "guarded" and self.guarded_deployment_name:
            return self.guarded_deployment_name
        return self.azure_openai_deployment_name
    
    def validate_for_azure_mode(self) -> list[str]:
        """
        Validate that all required settings are present for Azure mode.
        
        Returns:
            List of missing configuration items (empty if all valid)
        """
        missing = []
        
        if not self.foundry_endpoint:
            missing.append("AZURE_OPENAI_ENDPOINT or FOUNDRY_RESOURCE_NAME")
        
        if not self.azure_openai_deployment_name:
            missing.append("AZURE_OPENAI_DEPLOYMENT_NAME")
        
        if self.auth_mode == AuthMode.DEFAULT_CREDENTIAL:
            # Default credential requires Azure CLI login or managed identity
            pass
        elif self.auth_mode == AuthMode.ENTRA_ID:
            if not self.azure_tenant_id:
                missing.append("AZURE_TENANT_ID")
            if not self.azure_client_id:
                missing.append("AZURE_CLIENT_ID")
            if not self.azure_client_secret:
                missing.append("AZURE_CLIENT_SECRET")
        
        return missing
    
    @property
    def is_pyrit_configured(self) -> bool:
        """
        Check if PyRIT integration is enabled and properly configured.
        
        Returns:
            True if PyRIT is enabled and target endpoint is configured
        """
        return self.pyrit_enabled and bool(self.foundry_endpoint)


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached application settings.
    
    Returns:
        Settings instance loaded from environment variables
    """
    return Settings()


def reload_settings() -> Settings:
    """
    Force reload settings from environment (clears cache).
    
    Returns:
        Fresh Settings instance
    """
    get_settings.cache_clear()
    return get_settings()
