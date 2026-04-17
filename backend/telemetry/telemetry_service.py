"""
Structured telemetry service for attack and campaign runs.

Provides:
- Correlation ID generation and persistence
- Console logging with structured output
- Adapter pattern for future Application Insights integration
- Clean exposure of telemetry context to API responses
"""

import uuid
import time
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from .logger import get_logger

logger = get_logger("telemetry")


# =============================================================================
# ENUMS
# =============================================================================

class TelemetryEventType(str, Enum):
    """Types of telemetry events."""
    ATTACK_START = "attack_start"
    ATTACK_COMPLETE = "attack_complete"
    ATTACK_ERROR = "attack_error"
    CAMPAIGN_START = "campaign_start"
    CAMPAIGN_COMPLETE = "campaign_complete"
    CAMPAIGN_ERROR = "campaign_error"
    SAFETY_CHECK = "safety_check"
    TARGET_CALL = "target_call"
    EVALUATION = "evaluation"


class TelemetryStatus(str, Enum):
    """Status of telemetry capture for a run."""
    CAPTURED = "captured"  # Successfully logged
    PARTIAL = "partial"    # Some events failed to log
    FAILED = "failed"      # Telemetry capture failed
    DISABLED = "disabled"  # Telemetry disabled
    PENDING = "pending"    # Not yet finalized


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TelemetryContext:
    """
    Context for a single attack or campaign run.
    
    Generated at the start of a run and persisted through all telemetry events.
    """
    # Core identifiers
    correlation_id: str
    run_id: str
    campaign_id: Optional[str] = None
    
    # Foundry context
    foundry_resource_name: str = ""
    deployment_name: str = ""
    target_name: str = ""
    
    # Run context  
    scenario_id: str = ""
    scenario_name: str = ""
    attack_category: str = ""
    
    # Timing
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    
    # Status
    telemetry_status: TelemetryStatus = TelemetryStatus.PENDING
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "correlation_id": self.correlation_id,
            "run_id": self.run_id,
            "campaign_id": self.campaign_id,
            "foundry_resource_name": self.foundry_resource_name,
            "deployment_name": self.deployment_name,
            "target_name": self.target_name,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "attack_category": self.attack_category,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "telemetry_status": self.telemetry_status.value,
        }


@dataclass
class TelemetryEvent:
    """
    A single telemetry event for structured logging.
    """
    # Event identification
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: TelemetryEventType = TelemetryEventType.ATTACK_COMPLETE
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Correlation
    correlation_id: str = ""
    run_id: str = ""
    campaign_id: Optional[str] = None
    
    # Foundry context
    foundry_resource_name: str = ""
    deployment_name: str = ""
    
    # Attack context
    scenario_id: str = ""
    scenario_name: str = ""
    attack_category: str = ""
    target_name: str = ""
    
    # Results
    shield_verdict: str = ""  # blocked, allowed, flagged, n/a
    evaluator_outcome: str = ""  # safe, vulnerable, partial
    overall_outcome: str = ""
    
    # Performance
    latency_ms: int = 0
    
    # Model info
    model_name: str = ""
    tokens_used: Optional[int] = None
    
    # Error details
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "run_id": self.run_id,
            "campaign_id": self.campaign_id,
            "foundry_resource_name": self.foundry_resource_name,
            "deployment_name": self.deployment_name,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "attack_category": self.attack_category,
            "target_name": self.target_name,
            "shield_verdict": self.shield_verdict,
            "evaluator_outcome": self.evaluator_outcome,
            "overall_outcome": self.overall_outcome,
            "latency_ms": self.latency_ms,
            "model_name": self.model_name,
            "tokens_used": self.tokens_used,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "error_details": self.error_details,
            "metadata": self.metadata,
        }
    
    def to_log_line(self) -> str:
        """Format as a single structured log line."""
        parts = [
            f"[{self.event_type.value.upper()}]",
            f"correlation_id={self.correlation_id}",
            f"scenario={self.scenario_name or self.scenario_id or 'custom'}",
            f"category={self.attack_category}",
            f"target={self.target_name}",
            f"foundry={self.foundry_resource_name}",
            f"shield={self.shield_verdict}",
            f"outcome={self.overall_outcome}",
            f"latency={self.latency_ms}ms",
        ]
        
        if self.deployment_name:
            parts.append(f"deployment={self.deployment_name}")
        
        if self.error_message:
            parts.append(f"error={self.error_message}")
        
        return " | ".join(parts)


# =============================================================================
# ABSTRACT TELEMETRY ADAPTER
# =============================================================================

class TelemetryAdapter(ABC):
    """
    Abstract base class for telemetry adapters.
    
    Implement this interface to add new telemetry destinations
    (e.g., Application Insights, custom endpoints).
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter name for identification."""
        pass
    
    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the adapter is properly configured."""
        pass
    
    @abstractmethod
    async def track_event(self, event: TelemetryEvent) -> bool:
        """
        Track a telemetry event.
        
        Returns True if successfully sent, False otherwise.
        """
        pass
    
    @abstractmethod
    async def flush(self) -> None:
        """Flush any buffered events."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close the adapter and release resources."""
        pass


# =============================================================================
# CONSOLE ADAPTER
# =============================================================================

class ConsoleTelemetryAdapter(TelemetryAdapter):
    """
    Telemetry adapter that logs structured events to console.
    
    Primary adapter for demo mode and local development.
    """
    
    def __init__(self, structured_json: bool = False):
        """
        Initialize the console adapter.
        
        Args:
            structured_json: If True, output JSON; otherwise human-readable
        """
        self._structured_json = structured_json
        self._logger = get_logger("telemetry.console")
        self._event_count = 0
    
    @property
    def name(self) -> str:
        return "console"
    
    @property
    def is_available(self) -> bool:
        return True  # Always available
    
    async def track_event(self, event: TelemetryEvent) -> bool:
        """Log event to console."""
        try:
            self._event_count += 1
            
            if self._structured_json:
                # Output as JSON for structured logging
                self._logger.info(json.dumps(event.to_dict(), default=str))
            else:
                # Output human-readable line
                self._logger.info(event.to_log_line())
            
            return True
        except Exception as e:
            self._logger.error(f"Console telemetry error: {e}")
            return False
    
    async def flush(self) -> None:
        """No buffering, nothing to flush."""
        pass
    
    async def close(self) -> None:
        """Nothing to close."""
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get adapter statistics."""
        return {
            "name": self.name,
            "is_available": self.is_available,
            "events_logged": self._event_count,
            "structured_json": self._structured_json,
        }


# =============================================================================
# APPLICATION INSIGHTS ADAPTER (PLACEHOLDER)
# =============================================================================

class ApplicationInsightsTelemetryAdapter(TelemetryAdapter):
    """
    Telemetry adapter for Azure Application Insights.
    
    Requires APPLICATIONINSIGHTS_CONNECTION_STRING to be set.
    This is a placeholder implementation - full integration requires
    the opencensus-ext-azure or azure-monitor-opentelemetry package.
    """
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize Application Insights adapter.
        
        Args:
            connection_string: App Insights connection string
        """
        self._connection_string = connection_string
        self._logger = get_logger("telemetry.appinsights")
        self._client = None
        self._event_count = 0
        self._initialized = False
        
        if connection_string:
            self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize the Application Insights client."""
        try:
            # TODO: Integrate with actual App Insights SDK
            # from opencensus.ext.azure import AzureLogHandler
            # or from azure.monitor.opentelemetry import configure_azure_monitor
            self._logger.info("Application Insights adapter initialized (placeholder mode)")
            self._initialized = True
        except ImportError:
            self._logger.warning(
                "Application Insights SDK not installed. "
                "Install with: pip install azure-monitor-opentelemetry"
            )
            self._initialized = False
        except Exception as e:
            self._logger.error(f"Failed to initialize App Insights: {e}")
            self._initialized = False
    
    @property
    def name(self) -> str:
        return "application_insights"
    
    @property
    def is_available(self) -> bool:
        return bool(self._connection_string and self._initialized)
    
    async def track_event(self, event: TelemetryEvent) -> bool:
        """Track event to Application Insights."""
        if not self.is_available:
            return False
        
        try:
            self._event_count += 1
            
            # TODO: Send to actual App Insights
            # For now, log that we would send
            self._logger.debug(
                f"[AppInsights] Would track: {event.event_type.value} "
                f"correlation_id={event.correlation_id}"
            )
            
            return True
        except Exception as e:
            self._logger.error(f"App Insights track error: {e}")
            return False
    
    async def flush(self) -> None:
        """Flush buffered events to App Insights."""
        if self._client:
            # TODO: Implement actual flush
            pass
    
    async def close(self) -> None:
        """Close the App Insights client."""
        if self._client:
            # TODO: Implement actual close
            pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get adapter statistics."""
        return {
            "name": self.name,
            "is_available": self.is_available,
            "events_tracked": self._event_count,
            "connection_configured": bool(self._connection_string),
            "initialized": self._initialized,
        }


# =============================================================================
# TELEMETRY SERVICE
# =============================================================================

class TelemetryService:
    """
    Main telemetry service for attack and campaign runs.
    
    Manages:
    - Correlation ID generation
    - Telemetry context creation
    - Event routing to configured adapters
    - Status tracking for runs
    """
    
    def __init__(
        self,
        foundry_resource_name: str = "",
        default_deployment_name: str = "",
        app_insights_connection_string: Optional[str] = None,
        enable_console: bool = True,
        console_structured_json: bool = False,
    ):
        self._foundry_resource_name = foundry_resource_name
        self._default_deployment_name = default_deployment_name
        self._adapters: List[TelemetryAdapter] = []
        self._active_contexts: Dict[str, TelemetryContext] = {}
        self._logger = get_logger("telemetry.service")
        
        # Initialize adapters
        if enable_console:
            self._adapters.append(ConsoleTelemetryAdapter(structured_json=console_structured_json))
        
        if app_insights_connection_string:
            self._adapters.append(
                ApplicationInsightsTelemetryAdapter(connection_string=app_insights_connection_string)
            )
        
        self._logger.info(
            f"TelemetryService initialized: foundry={foundry_resource_name}, "
            f"adapters={[a.name for a in self._adapters]}"
        )
    
    # -------------------------------------------------------------------------
    # Context Management
    # -------------------------------------------------------------------------
    
    def create_context(
        self,
        run_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        scenario_id: str = "",
        scenario_name: str = "",
        attack_category: str = "",
        target_name: str = "",
        deployment_name: Optional[str] = None,
    ) -> TelemetryContext:
        """
        Create a new telemetry context for an attack or campaign run.
        
        Generates a new correlation ID and registers the context.
        """
        correlation_id = str(uuid.uuid4())
        run_id = run_id or str(uuid.uuid4())
        
        context = TelemetryContext(
            correlation_id=correlation_id,
            run_id=run_id,
            campaign_id=campaign_id,
            foundry_resource_name=self._foundry_resource_name,
            deployment_name=deployment_name or self._default_deployment_name,
            target_name=target_name,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            attack_category=attack_category,
            start_time=datetime.utcnow(),
            telemetry_status=TelemetryStatus.PENDING,
        )
        
        self._active_contexts[correlation_id] = context
        return context
    
    def get_context(self, correlation_id: str) -> Optional[TelemetryContext]:
        """Get an active telemetry context by correlation ID."""
        return self._active_contexts.get(correlation_id)
    
    def complete_context(
        self,
        correlation_id: str,
        status: TelemetryStatus = TelemetryStatus.CAPTURED,
    ) -> Optional[TelemetryContext]:
        """
        Mark a telemetry context as complete.
        
        Returns the updated context or None if not found.
        """
        context = self._active_contexts.get(correlation_id)
        if context:
            context.end_time = datetime.utcnow()
            context.telemetry_status = status
        return context
    
    def remove_context(self, correlation_id: str) -> None:
        """Remove a context from active tracking."""
        self._active_contexts.pop(correlation_id, None)
    
    # -------------------------------------------------------------------------
    # Event Tracking
    # -------------------------------------------------------------------------
    
    async def track_attack_start(
        self,
        context: TelemetryContext,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Track the start of an attack run."""
        event = TelemetryEvent(
            event_type=TelemetryEventType.ATTACK_START,
            correlation_id=context.correlation_id,
            run_id=context.run_id,
            campaign_id=context.campaign_id,
            foundry_resource_name=context.foundry_resource_name,
            deployment_name=context.deployment_name,
            scenario_id=context.scenario_id,
            scenario_name=context.scenario_name,
            attack_category=context.attack_category,
            target_name=context.target_name,
            metadata=metadata or {},
        )
        return await self._send_to_adapters(event)
    
    async def track_attack_complete(
        self,
        context: TelemetryContext,
        shield_verdict: str,
        evaluator_outcome: str,
        overall_outcome: str,
        latency_ms: int,
        model_name: str = "",
        tokens_used: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Track the completion of an attack run."""
        event = TelemetryEvent(
            event_type=TelemetryEventType.ATTACK_COMPLETE,
            correlation_id=context.correlation_id,
            run_id=context.run_id,
            campaign_id=context.campaign_id,
            foundry_resource_name=context.foundry_resource_name,
            deployment_name=context.deployment_name,
            scenario_id=context.scenario_id,
            scenario_name=context.scenario_name,
            attack_category=context.attack_category,
            target_name=context.target_name,
            shield_verdict=shield_verdict,
            evaluator_outcome=evaluator_outcome,
            overall_outcome=overall_outcome,
            latency_ms=latency_ms,
            model_name=model_name,
            tokens_used=tokens_used,
            metadata=metadata or {},
        )
        
        success = await self._send_to_adapters(event)
        
        # Update context status
        self.complete_context(
            context.correlation_id,
            TelemetryStatus.CAPTURED if success else TelemetryStatus.PARTIAL,
        )
        
        return success
    
    async def track_attack_error(
        self,
        context: TelemetryContext,
        error_code: str,
        error_message: str,
        error_details: Optional[Dict[str, Any]] = None,
        latency_ms: int = 0,
    ) -> bool:
        """Track an attack error."""
        event = TelemetryEvent(
            event_type=TelemetryEventType.ATTACK_ERROR,
            correlation_id=context.correlation_id,
            run_id=context.run_id,
            campaign_id=context.campaign_id,
            foundry_resource_name=context.foundry_resource_name,
            deployment_name=context.deployment_name,
            scenario_id=context.scenario_id,
            scenario_name=context.scenario_name,
            attack_category=context.attack_category,
            target_name=context.target_name,
            latency_ms=latency_ms,
            error_code=error_code,
            error_message=error_message,
            error_details=error_details,
        )
        
        success = await self._send_to_adapters(event)
        self.complete_context(context.correlation_id, TelemetryStatus.FAILED)
        return success
    
    async def track_campaign_start(
        self,
        context: TelemetryContext,
        campaign_name: str,
        total_attacks: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Track the start of a campaign."""
        event = TelemetryEvent(
            event_type=TelemetryEventType.CAMPAIGN_START,
            correlation_id=context.correlation_id,
            run_id=context.run_id,
            campaign_id=context.campaign_id,
            foundry_resource_name=context.foundry_resource_name,
            deployment_name=context.deployment_name,
            target_name=context.target_name,
            attack_category=context.attack_category,
            metadata={
                "campaign_name": campaign_name,
                "total_attacks": total_attacks,
                **(metadata or {}),
            },
        )
        return await self._send_to_adapters(event)
    
    async def track_campaign_complete(
        self,
        context: TelemetryContext,
        campaign_name: str,
        total_attacks: int,
        blocked_count: int,
        passed_count: int,
        flagged_count: int,
        latency_ms: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Track the completion of a campaign."""
        event = TelemetryEvent(
            event_type=TelemetryEventType.CAMPAIGN_COMPLETE,
            correlation_id=context.correlation_id,
            run_id=context.run_id,
            campaign_id=context.campaign_id,
            foundry_resource_name=context.foundry_resource_name,
            deployment_name=context.deployment_name,
            target_name=context.target_name,
            overall_outcome="completed",
            latency_ms=latency_ms,
            metadata={
                "campaign_name": campaign_name,
                "total_attacks": total_attacks,
                "blocked_count": blocked_count,
                "passed_count": passed_count,
                "flagged_count": flagged_count,
                "block_rate": round((blocked_count / total_attacks * 100) if total_attacks else 0, 1),
                **(metadata or {}),
            },
        )
        
        success = await self._send_to_adapters(event)
        self.complete_context(
            context.correlation_id,
            TelemetryStatus.CAPTURED if success else TelemetryStatus.PARTIAL,
        )
        return success
    
    # -------------------------------------------------------------------------
    # Internal Methods
    # -------------------------------------------------------------------------
    
    async def _send_to_adapters(self, event: TelemetryEvent) -> bool:
        """Send an event to all configured adapters."""
        if not self._adapters:
            return True  # No adapters configured is not an error
        
        results = []
        for adapter in self._adapters:
            try:
                if adapter.is_available:
                    result = await adapter.track_event(event)
                    results.append(result)
            except Exception as e:
                self._logger.error(f"Adapter {adapter.name} error: {e}")
                results.append(False)
        
        return all(results) if results else True
    
    async def flush(self) -> None:
        """Flush all adapters."""
        for adapter in self._adapters:
            try:
                await adapter.flush()
            except Exception as e:
                self._logger.error(f"Flush error for {adapter.name}: {e}")
    
    async def close(self) -> None:
        """Close all adapters and clean up."""
        await self.flush()
        for adapter in self._adapters:
            try:
                await adapter.close()
            except Exception as e:
                self._logger.error(f"Close error for {adapter.name}: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get telemetry service status."""
        return {
            "foundry_resource_name": self._foundry_resource_name,
            "default_deployment_name": self._default_deployment_name,
            "active_contexts": len(self._active_contexts),
            "adapters": [
                {
                    "name": a.name,
                    "is_available": a.is_available,
                }
                for a in self._adapters
            ],
        }


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_telemetry_service: Optional[TelemetryService] = None


def get_telemetry_service() -> TelemetryService:
    """Get the singleton telemetry service instance."""
    global _telemetry_service
    
    if _telemetry_service is None:
        from config import get_settings
        settings = get_settings()
        
        _telemetry_service = TelemetryService(
            foundry_resource_name=settings.foundry_resource_name or "",
            default_deployment_name=settings.azure_openai_deployment_name or "",
            app_insights_connection_string=getattr(
                settings, 'applicationinsights_connection_string', None
            ),
            enable_console=True,
            console_structured_json=False,
        )
    
    return _telemetry_service


def create_telemetry_service(
    foundry_resource_name: str = "",
    default_deployment_name: str = "",
    app_insights_connection_string: Optional[str] = None,
) -> TelemetryService:
    """Create a new telemetry service instance (for testing)."""
    global _telemetry_service
    
    _telemetry_service = TelemetryService(
        foundry_resource_name=foundry_resource_name,
        default_deployment_name=default_deployment_name,
        app_insights_connection_string=app_insights_connection_string,
    )
    
    return _telemetry_service


async def close_telemetry_service() -> None:
    """Close the singleton telemetry service."""
    global _telemetry_service
    
    if _telemetry_service:
        await _telemetry_service.close()
        _telemetry_service = None
