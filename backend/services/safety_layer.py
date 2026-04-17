"""
Pluggable safety layer service for Azure AI red teaming demo.

Provides an abstraction for safety evaluation with support for:
- Azure AI Content Safety Prompt Shields (when configured)
- Mock safety provider (fallback for demos)
- Future custom safety validators

Returns normalized shield verdicts: allowed, suspicious, blocked, unavailable
"""

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type

import httpx

from telemetry import get_logger

logger = get_logger("safety_layer")


# =============================================================================
# VERDICT DEFINITIONS
# =============================================================================

class ShieldVerdict(str, Enum):
    """Normalized shield verdict results."""
    ALLOWED = "allowed"       # Content is safe, no issues detected
    SUSPICIOUS = "suspicious"  # Content flagged but not blocked
    BLOCKED = "blocked"       # Content blocked by safety layer
    UNAVAILABLE = "unavailable"  # Safety check could not be performed


class SafetyCategory(str, Enum):
    """Categories of safety concerns detected."""
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    HARMFUL_CONTENT = "harmful_content"
    HATE_SPEECH = "hate_speech"
    VIOLENCE = "violence"
    SEXUAL_CONTENT = "sexual_content"
    SELF_HARM = "self_harm"
    INDIRECT_ATTACK = "indirect_attack"
    UNKNOWN = "unknown"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class SafetyCheckResult:
    """Result of a safety check from any provider."""
    # Core verdict
    verdict: ShieldVerdict
    
    # Provider information
    provider_name: str
    provider_version: str
    
    # Explanation
    reason: str
    explanation: str
    
    # Detected categories with severity scores
    categories_detected: List[SafetyCategory] = field(default_factory=list)
    category_scores: Dict[str, float] = field(default_factory=dict)
    
    # Timing
    check_latency_ms: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Metadata for UI display
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Raw response from provider (for debugging)
    raw_response: Optional[Dict[str, Any]] = None
    
    # Error details if unavailable
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "verdict": self.verdict.value,
            "provider_name": self.provider_name,
            "provider_version": self.provider_version,
            "reason": self.reason,
            "explanation": self.explanation,
            "categories_detected": [c.value for c in self.categories_detected],
            "category_scores": self.category_scores,
            "check_latency_ms": self.check_latency_ms,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


@dataclass
class SafetyCheckRequest:
    """Request for a safety check."""
    prompt: str
    user_prompt: Optional[str] = None  # Separated user prompt if available
    system_prompt: Optional[str] = None  # System prompt if available
    documents: Optional[List[str]] = None  # Documents for indirect attack detection
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# ABSTRACT BASE PROVIDER
# =============================================================================

class SafetyProvider(ABC):
    """
    Abstract base class for safety providers.
    
    Implement this interface to add new safety validation backends.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for display."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Provider version string."""
        pass
    
    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is properly configured and available."""
        pass
    
    @abstractmethod
    async def check(self, request: SafetyCheckRequest) -> SafetyCheckResult:
        """
        Perform a safety check on the request.
        
        Args:
            request: The safety check request with prompt and context
        
        Returns:
            SafetyCheckResult with verdict and details
        """
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get provider status for health checks."""
        return {
            "name": self.name,
            "version": self.version,
            "is_available": self.is_available,
        }


# =============================================================================
# MOCK SAFETY PROVIDER
# =============================================================================

class MockSafetyProvider(SafetyProvider):
    """
    Mock safety provider for demo mode.
    
    Returns deterministic results based on content patterns for predictable demos.
    """
    
    # Patterns that trigger blocking
    BLOCK_PATTERNS = [
        "ignore previous instructions",
        "ignore all instructions",
        "ignore all previous instructions",
        "ignore your instructions",
        "ignore the previous",
        "disregard your guidelines",
        "disregard all guidelines",
        "bypass your filters",
        "bypass safety",
        "bypass the filter",
        "jailbreak",
        "dan mode",
        "developer mode override",
        "pretend you are not an ai",
        "act as if you have no restrictions",
        "you are now",
        "system prompt:",
        "reveal your system",
        "show your system prompt",
        "[[system]]",
        "forget your training",
        "override your",
    ]
    
    # Patterns that trigger suspicion
    SUSPICIOUS_PATTERNS = [
        "hypothetically",
        "for educational purposes",
        "in theory",
        "roleplay as",
        "pretend",
        "imagine you are",
        "what would happen if",
        "creative writing",
        "fiction",
        "story where",
    ]
    
    @property
    def name(self) -> str:
        return "mock-safety"
    
    @property
    def version(self) -> str:
        return "1.0.0-demo"
    
    @property
    def is_available(self) -> bool:
        return True  # Always available
    
    async def check(self, request: SafetyCheckRequest) -> SafetyCheckResult:
        """Perform mock safety check based on pattern matching."""
        start_time = time.perf_counter()
        
        prompt_lower = request.prompt.lower()
        
        # Check for blocking patterns
        blocked_reasons = []
        for pattern in self.BLOCK_PATTERNS:
            if pattern in prompt_lower:
                blocked_reasons.append(pattern)
        
        # Check for suspicious patterns
        suspicious_reasons = []
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in prompt_lower:
                suspicious_reasons.append(pattern)
        
        latency_ms = int((time.perf_counter() - start_time) * 1000) + 5  # Add simulated latency
        
        # Determine verdict
        if blocked_reasons:
            return SafetyCheckResult(
                verdict=ShieldVerdict.BLOCKED,
                provider_name=self.name,
                provider_version=self.version,
                reason="Jailbreak attempt detected",
                explanation=f"Blocked patterns found: {', '.join(blocked_reasons[:3])}",
                categories_detected=[SafetyCategory.JAILBREAK, SafetyCategory.PROMPT_INJECTION],
                category_scores={
                    "jailbreak": 0.95,
                    "prompt_injection": 0.85,
                },
                check_latency_ms=latency_ms,
                metadata={
                    "blocked_patterns": blocked_reasons,
                    "mode": "demo",
                },
            )
        
        if suspicious_reasons:
            return SafetyCheckResult(
                verdict=ShieldVerdict.SUSPICIOUS,
                provider_name=self.name,
                provider_version=self.version,
                reason="Potentially evasive language detected",
                explanation=f"Suspicious patterns found: {', '.join(suspicious_reasons[:3])}",
                categories_detected=[SafetyCategory.PROMPT_INJECTION],
                category_scores={
                    "prompt_injection": 0.55,
                },
                check_latency_ms=latency_ms,
                metadata={
                    "suspicious_patterns": suspicious_reasons,
                    "mode": "demo",
                },
            )
        
        # Default: allowed
        return SafetyCheckResult(
            verdict=ShieldVerdict.ALLOWED,
            provider_name=self.name,
            provider_version=self.version,
            reason="No safety concerns detected",
            explanation="Content passed all safety checks",
            categories_detected=[],
            category_scores={},
            check_latency_ms=latency_ms,
            metadata={"mode": "demo"},
        )


# =============================================================================
# AZURE AI CONTENT SAFETY PROVIDER
# =============================================================================

class AzureContentSafetyProvider(SafetyProvider):
    """
    Azure AI Content Safety Prompt Shields provider.
    
    Calls the Azure AI Content Safety API for prompt shield analysis.
    Supports both jailbreak detection and indirect attack detection.
    """
    
    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        api_version: str = "2024-02-15-preview",
    ):
        self._endpoint = endpoint
        self._api_key = api_key
        self._api_version = api_version
        self._http_client: Optional[httpx.AsyncClient] = None
    
    @property
    def name(self) -> str:
        return "azure-content-safety"
    
    @property
    def version(self) -> str:
        return self._api_version
    
    @property
    def is_available(self) -> bool:
        return bool(self._endpoint and self._api_key)
    
    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
            )
        return self._http_client
    
    async def close(self):
        """Close HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None
    
    async def check(self, request: SafetyCheckRequest) -> SafetyCheckResult:
        """
        Perform safety check using Azure AI Content Safety Prompt Shields.
        """
        if not self.is_available:
            return SafetyCheckResult(
                verdict=ShieldVerdict.UNAVAILABLE,
                provider_name=self.name,
                provider_version=self.version,
                reason="Provider not configured",
                explanation="Azure AI Content Safety is not configured. Set AZURE_CONTENT_SAFETY_ENDPOINT and AZURE_CONTENT_SAFETY_KEY.",
                error_code="NOT_CONFIGURED",
                error_message="Missing endpoint or API key",
            )
        
        start_time = time.perf_counter()
        
        # Build request body for Prompt Shields API
        # https://learn.microsoft.com/en-us/azure/ai-services/content-safety/quickstart-jailbreak
        body = {
            "userPrompt": request.user_prompt or request.prompt,
        }
        
        if request.documents:
            body["documents"] = request.documents
        
        url = f"{self._endpoint.rstrip('/')}/contentsafety/text:shieldPrompt"
        params = {"api-version": self._api_version}
        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": self._api_key,
        }
        
        try:
            client = await self._get_http_client()
            response = await client.post(url, json=body, headers=headers, params=params)
            
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data, latency_ms)
            else:
                error_text = response.text
                logger.warning(f"Content Safety API error: {response.status_code} - {error_text}")
                
                return SafetyCheckResult(
                    verdict=ShieldVerdict.UNAVAILABLE,
                    provider_name=self.name,
                    provider_version=self.version,
                    reason="API error",
                    explanation=f"Content Safety API returned status {response.status_code}",
                    check_latency_ms=latency_ms,
                    error_code=str(response.status_code),
                    error_message=error_text[:200],
                )
                
        except httpx.TimeoutException as e:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Content Safety timeout: {e}")
            return SafetyCheckResult(
                verdict=ShieldVerdict.UNAVAILABLE,
                provider_name=self.name,
                provider_version=self.version,
                reason="Request timeout",
                explanation="Content Safety API request timed out",
                check_latency_ms=latency_ms,
                error_code="TIMEOUT",
                error_message=str(e),
            )
            
        except Exception as e:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Content Safety error: {e}")
            return SafetyCheckResult(
                verdict=ShieldVerdict.UNAVAILABLE,
                provider_name=self.name,
                provider_version=self.version,
                reason="Connection error",
                explanation="Failed to connect to Content Safety API",
                check_latency_ms=latency_ms,
                error_code="CONNECTION_ERROR",
                error_message=str(e),
            )
    
    def _parse_response(self, data: Dict[str, Any], latency_ms: int) -> SafetyCheckResult:
        """Parse Azure Content Safety Prompt Shields response."""
        # Extract attack detection results
        user_prompt_analysis = data.get("userPromptAnalysis", {})
        documents_analysis = data.get("documentsAnalysis", [])
        
        # Check jailbreak detection
        jailbreak_detected = user_prompt_analysis.get("attackDetected", False)
        
        # Check indirect attack in documents
        indirect_attack_detected = any(
            doc.get("attackDetected", False) for doc in documents_analysis
        )
        
        categories = []
        scores = {}
        
        if jailbreak_detected:
            categories.append(SafetyCategory.JAILBREAK)
            scores["jailbreak"] = 0.95
        
        if indirect_attack_detected:
            categories.append(SafetyCategory.INDIRECT_ATTACK)
            scores["indirect_attack"] = 0.90
        
        # Determine verdict
        if jailbreak_detected or indirect_attack_detected:
            verdict = ShieldVerdict.BLOCKED
            reason = "Attack detected"
            if jailbreak_detected and indirect_attack_detected:
                explanation = "Both jailbreak attempt and indirect attack detected in content"
            elif jailbreak_detected:
                explanation = "Jailbreak attempt detected in user prompt"
            else:
                explanation = "Indirect attack detected in documents"
        else:
            verdict = ShieldVerdict.ALLOWED
            reason = "No attacks detected"
            explanation = "Prompt passed all Prompt Shield checks"
        
        return SafetyCheckResult(
            verdict=verdict,
            provider_name=self.name,
            provider_version=self.version,
            reason=reason,
            explanation=explanation,
            categories_detected=categories,
            category_scores=scores,
            check_latency_ms=latency_ms,
            metadata={
                "jailbreak_detected": jailbreak_detected,
                "indirect_attack_detected": indirect_attack_detected,
                "documents_analyzed": len(documents_analysis),
            },
            raw_response=data,
        )


# =============================================================================
# SAFETY LAYER SERVICE
# =============================================================================

class SafetyLayerService:
    """
    Main safety layer service with pluggable providers.
    
    Manages safety providers and routes checks to the appropriate backend.
    Falls back to mock provider if Azure provider is not available.
    """
    
    def __init__(
        self,
        azure_endpoint: Optional[str] = None,
        azure_api_key: Optional[str] = None,
        azure_api_version: str = "2024-02-15-preview",
        enable_fallback: bool = True,
    ):
        """
        Initialize the safety layer.
        
        Args:
            azure_endpoint: Azure Content Safety endpoint
            azure_api_key: Azure Content Safety API key
            azure_api_version: API version to use
            enable_fallback: Whether to fall back to mock when Azure unavailable
        """
        self._providers: Dict[str, SafetyProvider] = {}
        self._primary_provider: Optional[str] = None
        self._enable_fallback = enable_fallback
        
        # Register mock provider (always available)
        self._mock_provider = MockSafetyProvider()
        self._providers["mock"] = self._mock_provider
        
        # Register Azure provider if configured
        if azure_endpoint and azure_api_key:
            self._azure_provider = AzureContentSafetyProvider(
                endpoint=azure_endpoint,
                api_key=azure_api_key,
                api_version=azure_api_version,
            )
            self._providers["azure"] = self._azure_provider
            self._primary_provider = "azure"
            logger.info("Azure Content Safety provider configured")
        else:
            self._azure_provider = None
            self._primary_provider = "mock"
            logger.info("Using mock safety provider (Azure Content Safety not configured)")
    
    def register_provider(self, name: str, provider: SafetyProvider):
        """
        Register a custom safety provider.
        
        Args:
            name: Provider identifier
            provider: SafetyProvider instance
        """
        self._providers[name] = provider
        logger.info(f"Registered safety provider: {name}")
    
    def set_primary_provider(self, name: str):
        """Set the primary provider to use for checks."""
        if name not in self._providers:
            raise ValueError(f"Unknown provider: {name}")
        self._primary_provider = name
        logger.info(f"Primary safety provider set to: {name}")
    
    def get_provider(self, name: Optional[str] = None) -> SafetyProvider:
        """Get a provider by name, or the primary provider."""
        provider_name = name or self._primary_provider
        if provider_name not in self._providers:
            raise ValueError(f"Unknown provider: {provider_name}")
        return self._providers[provider_name]
    
    async def check(
        self,
        prompt: str,
        user_prompt: Optional[str] = None,
        system_prompt: Optional[str] = None,
        documents: Optional[List[str]] = None,
        provider: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> SafetyCheckResult:
        """
        Perform a safety check.
        
        Args:
            prompt: The full prompt to check
            user_prompt: Separated user prompt (if available)
            system_prompt: System prompt (if available)
            documents: Documents for indirect attack detection
            provider: Specific provider to use (or primary)
            correlation_id: Correlation ID for tracing
        
        Returns:
            SafetyCheckResult with verdict and details
        """
        correlation_id = correlation_id or str(uuid.uuid4())
        
        request = SafetyCheckRequest(
            prompt=prompt,
            user_prompt=user_prompt,
            system_prompt=system_prompt,
            documents=documents,
            correlation_id=correlation_id,
        )
        
        # Get the target provider
        target_provider = self._providers.get(provider or self._primary_provider)
        
        if target_provider is None:
            return SafetyCheckResult(
                verdict=ShieldVerdict.UNAVAILABLE,
                provider_name="none",
                provider_version="0.0.0",
                reason="No provider available",
                explanation="No safety provider is configured or available",
                error_code="NO_PROVIDER",
            )
        
        # Check if primary provider is available
        if not target_provider.is_available and self._enable_fallback:
            logger.info(f"Primary provider {target_provider.name} unavailable, falling back to mock")
            target_provider = self._mock_provider
        
        logger.debug(f"Running safety check with provider: {target_provider.name}")
        
        result = await target_provider.check(request)
        
        # Add correlation ID to metadata
        result.metadata["correlation_id"] = correlation_id
        
        logger.info(
            f"Safety check complete: {result.verdict.value} "
            f"(provider={result.provider_name}, latency={result.check_latency_ms}ms)"
        )
        
        return result
    
    async def close(self):
        """Close all providers and cleanup resources."""
        if self._azure_provider:
            await self._azure_provider.close()
        logger.info("Safety layer closed")
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all providers."""
        return {
            "primary_provider": self._primary_provider,
            "fallback_enabled": self._enable_fallback,
            "providers": {
                name: provider.get_status()
                for name, provider in self._providers.items()
            },
        }
    
    @property
    def is_azure_available(self) -> bool:
        """Check if Azure Content Safety is available."""
        return self._azure_provider is not None and self._azure_provider.is_available
    
    @property
    def primary_provider_name(self) -> str:
        """Get the name of the primary provider."""
        return self._primary_provider or "none"


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_safety_layer_instance: Optional[SafetyLayerService] = None


def get_safety_layer() -> SafetyLayerService:
    """
    Get the singleton safety layer instance.
    
    Initializes from settings if not already created.
    """
    global _safety_layer_instance
    
    if _safety_layer_instance is None:
        # Import here to avoid circular dependency
        from config import get_settings
        
        settings = get_settings()
        
        _safety_layer_instance = SafetyLayerService(
            azure_endpoint=settings.azure_content_safety_endpoint,
            azure_api_key=settings.azure_content_safety_key,
            enable_fallback=True,
        )
    
    return _safety_layer_instance


def create_safety_layer(
    azure_endpoint: Optional[str] = None,
    azure_api_key: Optional[str] = None,
    enable_fallback: bool = True,
) -> SafetyLayerService:
    """
    Create a new safety layer instance with custom configuration.
    
    Use for testing or specialized scenarios.
    """
    return SafetyLayerService(
        azure_endpoint=azure_endpoint,
        azure_api_key=azure_api_key,
        enable_fallback=enable_fallback,
    )


async def close_safety_layer():
    """Close the singleton safety layer instance."""
    global _safety_layer_instance
    if _safety_layer_instance is not None:
        await _safety_layer_instance.close()
        _safety_layer_instance = None
