"""
Target connector service for Azure AI Foundry / Azure OpenAI endpoints.

This service handles:
- Connecting to Azure OpenAI compatible chat endpoints
- Multiple authentication methods (API key, Entra ID, Default Credential)
- Response parsing with timing and metadata
- Support for comparison mode (baseline vs guarded targets)
- Graceful fallback to mock responses in demo mode
"""

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
)

from config import Settings, get_settings, AuthMode, RunMode
from telemetry import get_logger, trace_operation

logger = get_logger("target_connector")


class TargetType(str, Enum):
    """Type of target for comparison mode."""
    DEFAULT = "default"
    BASELINE = "baseline"
    GUARDED = "guarded"


@dataclass
class TargetSettings:
    """Settings for a specific target endpoint."""
    name: str
    endpoint: str
    deployment_name: str
    api_version: str
    target_type: TargetType = TargetType.DEFAULT
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectorResponse:
    """Response from the target connector."""
    # Core response data
    response_text: str
    
    # Timing information
    latency_ms: int
    timestamp: datetime
    
    # Model metadata
    model: str
    deployment_name: str
    endpoint: str
    target_type: TargetType
    
    # Usage statistics (if available)
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    
    # Error details (if any)
    success: bool = True
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    # Additional metadata
    correlation_id: str = ""
    raw_response: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "response_text": self.response_text,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp.isoformat(),
            "model": self.model,
            "deployment_name": self.deployment_name,
            "endpoint": self.endpoint,
            "target_type": self.target_type.value,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "success": self.success,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "correlation_id": self.correlation_id,
        }


@dataclass
class ChatMessage:
    """Chat message for API calls."""
    role: str  # 'system', 'user', 'assistant'
    content: str
    
    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


class TargetConnector:
    """
    Connector service for Azure AI Foundry / Azure OpenAI endpoints.
    
    Supports:
    - Chat completions API
    - Multiple authentication methods
    - Comparison mode with baseline and guarded targets
    - Automatic fallback to demo mode
    """
    
    # Mock responses for demo mode
    MOCK_RESPONSES = [
        "I understand you're asking about this topic. Let me provide a helpful response while staying within appropriate guidelines.",
        "Thank you for your question. I'll do my best to assist while following safety protocols.",
        "I'm happy to help with that. Here's what I can tell you based on the information provided.",
        "That's an interesting question. Let me address it while being mindful of responsible AI practices.",
        "I can assist with that request. Here's a thoughtful response considering all relevant factors.",
    ]
    
    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize the target connector.
        
        Args:
            settings: Application settings. If None, loads from environment.
        """
        self._settings = settings or get_settings()
        self._http_client: Optional[httpx.AsyncClient] = None
        self._credential = None
        self._token_cache: Dict[str, tuple[str, float]] = {}
    
    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=10.0),
                follow_redirects=True,
            )
        return self._http_client
    
    async def close(self):
        """Close the HTTP client and cleanup resources."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None
    
    def _get_azure_credential(self):
        """Get the appropriate Azure credential based on settings."""
        if self._credential is not None:
            return self._credential
        
        auth_mode = self._settings.auth_mode
        
        if auth_mode == AuthMode.ENTRA_ID:
            logger.info("Using Entra ID (Service Principal) authentication")
            self._credential = ClientSecretCredential(
                tenant_id=self._settings.azure_tenant_id,
                client_id=self._settings.azure_client_id,
                client_secret=self._settings.azure_client_secret,
            )
        elif auth_mode == AuthMode.DEFAULT_CREDENTIAL:
            logger.info("Using DefaultAzureCredential (CLI/Managed Identity)")
            self._credential = DefaultAzureCredential()
        
        return self._credential
    
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API calls."""
        auth_mode = self._settings.auth_mode
        
        if auth_mode == AuthMode.API_KEY:
            return {"api-key": self._settings.azure_openai_api_key}
        
        # For Entra ID or Default Credential, get a bearer token
        credential = self._get_azure_credential()
        if credential is None:
            logger.warning("No credential available, authentication may fail")
            return {}
        
        # Token cache key
        cache_key = "azure_openai_token"
        
        # Check if we have a valid cached token (valid for at least 5 minutes)
        if cache_key in self._token_cache:
            token, expires_at = self._token_cache[cache_key]
            if time.time() < expires_at - 300:  # 5 minute buffer
                return {"Authorization": f"Bearer {token}"}
        
        try:
            # Get new token
            token = credential.get_token("https://cognitiveservices.azure.com/.default")
            # Cache for later use
            self._token_cache[cache_key] = (token.token, token.expires_on)
            return {"Authorization": f"Bearer {token.token}"}
        except Exception as e:
            logger.error(f"Failed to get Azure credential token: {e}")
            return {}
    
    def _get_target_settings(self, target_type: TargetType = TargetType.DEFAULT) -> Optional[TargetSettings]:
        """
        Get target settings for a specific target type.
        
        Args:
            target_type: Type of target (default, baseline, guarded)
        
        Returns:
            TargetSettings or None if not properly configured
        """
        endpoint = self._settings.foundry_endpoint
        deployment = self._settings.get_deployment_for_target(target_type.value)
        
        if not endpoint or not deployment:
            return None
        
        return TargetSettings(
            name=f"{self._settings.foundry_resource_name or 'azure-openai'}-{target_type.value}",
            endpoint=endpoint,
            deployment_name=deployment,
            api_version=self._settings.azure_openai_api_version,
            target_type=target_type,
            metadata={
                "foundry_resource": self._settings.foundry_resource_name,
                "project": self._settings.azure_ai_project_name,
            }
        )
    
    async def _call_azure_openai(
        self,
        messages: List[ChatMessage],
        target: TargetSettings,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        correlation_id: str = "",
    ) -> ConnectorResponse:
        """
        Make a chat completion call to Azure OpenAI.
        
        Args:
            messages: List of chat messages
            target: Target endpoint settings
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
            correlation_id: Correlation ID for tracing
        
        Returns:
            ConnectorResponse with result or error details
        """
        url = f"{target.endpoint.rstrip('/')}/openai/deployments/{target.deployment_name}/chat/completions"
        
        params = {"api-version": target.api_version}
        
        body = {
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        
        headers = {
            "Content-Type": "application/json",
            "x-ms-correlation-id": correlation_id,
        }
        headers.update(await self._get_auth_headers())
        
        start_time = time.perf_counter()
        timestamp = datetime.utcnow()
        
        try:
            client = await self._get_http_client()
            response = await client.post(url, json=body, headers=headers, params=params)
            
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract response content
                choices = data.get("choices", [])
                content = ""
                if choices:
                    content = choices[0].get("message", {}).get("content", "")
                
                # Extract usage statistics
                usage = data.get("usage", {})
                
                return ConnectorResponse(
                    response_text=content,
                    latency_ms=latency_ms,
                    timestamp=timestamp,
                    model=data.get("model", target.deployment_name),
                    deployment_name=target.deployment_name,
                    endpoint=target.endpoint,
                    target_type=target.target_type,
                    prompt_tokens=usage.get("prompt_tokens"),
                    completion_tokens=usage.get("completion_tokens"),
                    total_tokens=usage.get("total_tokens"),
                    success=True,
                    correlation_id=correlation_id,
                    raw_response=data,
                )
            else:
                # API error
                error_data = {}
                try:
                    error_data = response.json()
                except:
                    pass
                
                error_message = error_data.get("error", {}).get("message", response.text)
                error_code = error_data.get("error", {}).get("code", str(response.status_code))
                
                logger.warning(f"Azure OpenAI API error: {response.status_code} - {error_message}")
                
                return ConnectorResponse(
                    response_text="",
                    latency_ms=latency_ms,
                    timestamp=timestamp,
                    model=target.deployment_name,
                    deployment_name=target.deployment_name,
                    endpoint=target.endpoint,
                    target_type=target.target_type,
                    success=False,
                    error_code=error_code,
                    error_message=error_message,
                    correlation_id=correlation_id,
                )
                
        except httpx.TimeoutException as e:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Request timeout: {e}")
            return ConnectorResponse(
                response_text="",
                latency_ms=latency_ms,
                timestamp=timestamp,
                model=target.deployment_name,
                deployment_name=target.deployment_name,
                endpoint=target.endpoint,
                target_type=target.target_type,
                success=False,
                error_code="TIMEOUT",
                error_message=str(e),
                correlation_id=correlation_id,
            )
            
        except Exception as e:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Request failed: {e}")
            return ConnectorResponse(
                response_text="",
                latency_ms=latency_ms,
                timestamp=timestamp,
                model=target.deployment_name,
                deployment_name=target.deployment_name,
                endpoint=target.endpoint,
                target_type=target.target_type,
                success=False,
                error_code="CONNECTION_ERROR",
                error_message=str(e),
                correlation_id=correlation_id,
            )
    
    def _mock_response(
        self,
        prompt: str,
        target_type: TargetType,
        correlation_id: str,
    ) -> ConnectorResponse:
        """Generate a mock response for demo mode."""
        import random
        
        # Simulate some latency
        latency_ms = random.randint(100, 500)
        
        # Select a mock response
        response_text = random.choice(self.MOCK_RESPONSES)
        
        # Estimate token counts
        prompt_tokens = len(prompt.split()) * 2  # Rough estimate
        completion_tokens = len(response_text.split()) * 2
        
        return ConnectorResponse(
            response_text=response_text,
            latency_ms=latency_ms,
            timestamp=datetime.utcnow(),
            model="mock-gpt-4o",
            deployment_name="demo-deployment",
            endpoint="https://demo.local",
            target_type=target_type,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            success=True,
            correlation_id=correlation_id,
        )
    
    async def send_prompt(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        target_type: TargetType = TargetType.DEFAULT,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        correlation_id: Optional[str] = None,
    ) -> ConnectorResponse:
        """
        Send a prompt to the configured target endpoint.
        
        Args:
            prompt: The user prompt to send
            system_message: Optional system message
            target_type: Target type for comparison mode
            temperature: Sampling temperature
            max_tokens: Maximum response tokens
            correlation_id: Optional correlation ID for tracing
        
        Returns:
            ConnectorResponse with result or error details
        """
        correlation_id = correlation_id or str(uuid.uuid4())
        
        with trace_operation("send_prompt", correlation_id):
            # Check if we're in demo mode
            if self._settings.is_demo_mode:
                logger.info(f"Demo mode: generating mock response for {target_type.value} target")
                return self._mock_response(prompt, target_type, correlation_id)
            
            # Get target settings
            target = self._get_target_settings(target_type)
            
            if target is None:
                logger.error("Azure OpenAI not properly configured")
                return ConnectorResponse(
                    response_text="",
                    latency_ms=0,
                    timestamp=datetime.utcnow(),
                    model="unknown",
                    deployment_name="unknown",
                    endpoint="unknown",
                    target_type=target_type,
                    success=False,
                    error_code="NOT_CONFIGURED",
                    error_message="Azure OpenAI endpoint is not properly configured. Check AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT_NAME.",
                    correlation_id=correlation_id,
                )
            
            # Build messages
            messages: List[ChatMessage] = []
            
            if system_message:
                messages.append(ChatMessage(role="system", content=system_message))
            
            messages.append(ChatMessage(role="user", content=prompt))
            
            logger.info(f"Sending prompt to {target.name} ({target.deployment_name})")
            
            return await self._call_azure_openai(
                messages=messages,
                target=target,
                temperature=temperature,
                max_tokens=max_tokens,
                correlation_id=correlation_id,
            )
    
    async def send_prompt_comparison(
        self,
        prompt: str,
        system_message: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, ConnectorResponse]:
        """
        Send a prompt to both baseline and guarded targets for comparison.
        
        Args:
            prompt: The user prompt to send
            system_message: Optional system message
            temperature: Sampling temperature
            max_tokens: Maximum response tokens
            correlation_id: Optional correlation ID for tracing
        
        Returns:
            Dictionary with 'baseline' and 'guarded' ConnectorResponse objects
        """
        correlation_id = correlation_id or str(uuid.uuid4())
        
        # Send to both targets
        baseline_response = await self.send_prompt(
            prompt=prompt,
            system_message=system_message,
            target_type=TargetType.BASELINE,
            temperature=temperature,
            max_tokens=max_tokens,
            correlation_id=f"{correlation_id}-baseline",
        )
        
        guarded_response = await self.send_prompt(
            prompt=prompt,
            system_message=system_message,
            target_type=TargetType.GUARDED,
            temperature=temperature,
            max_tokens=max_tokens,
            correlation_id=f"{correlation_id}-guarded",
        )
        
        return {
            "baseline": baseline_response,
            "guarded": guarded_response,
        }
    
    def is_configured(self) -> bool:
        """Check if the connector is properly configured for Azure mode."""
        return self._settings.is_demo_mode or self._settings.is_azure_configured
    
    def get_configuration_status(self) -> Dict[str, Any]:
        """Get current configuration status for diagnostics."""
        return {
            "run_mode": self._settings.run_mode.value,
            "is_demo_mode": self._settings.is_demo_mode,
            "is_azure_configured": self._settings.is_azure_configured,
            "auth_mode": self._settings.auth_mode.value,
            "foundry_resource_name": self._settings.foundry_resource_name,
            "azure_ai_project_name": self._settings.azure_ai_project_name,
            "endpoint": self._settings.foundry_endpoint,
            "deployment_name": self._settings.azure_openai_deployment_name,
            "api_version": self._settings.azure_openai_api_version,
            "baseline_deployment": self._settings.baseline_deployment_name,
            "guarded_deployment": self._settings.guarded_deployment_name,
            "missing_config": self._settings.validate_for_azure_mode() if not self._settings.is_demo_mode else [],
        }


# Singleton instance
_connector_instance: Optional[TargetConnector] = None


def get_target_connector() -> TargetConnector:
    """Get the singleton target connector instance."""
    global _connector_instance
    if _connector_instance is None:
        _connector_instance = TargetConnector()
    return _connector_instance


async def close_target_connector():
    """Close the target connector and cleanup resources."""
    global _connector_instance
    if _connector_instance is not None:
        await _connector_instance.close()
        _connector_instance = None
