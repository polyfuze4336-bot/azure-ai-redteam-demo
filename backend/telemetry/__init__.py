"""
Telemetry module for observability and tracing.
"""

from .logger import get_logger, setup_logging
from .tracer import get_tracer, trace_operation
from .telemetry_service import (
    TelemetryService,
    TelemetryContext,
    TelemetryEvent,
    TelemetryEventType,
    TelemetryStatus,
    TelemetryAdapter,
    ConsoleTelemetryAdapter,
    ApplicationInsightsTelemetryAdapter,
    get_telemetry_service,
    create_telemetry_service,
    close_telemetry_service,
)

__all__ = [
    # Logger
    "get_logger",
    "setup_logging",
    # Tracer
    "get_tracer",
    "trace_operation",
    # Telemetry Service
    "TelemetryService",
    "TelemetryContext",
    "TelemetryEvent",
    "TelemetryEventType",
    "TelemetryStatus",
    "TelemetryAdapter",
    "ConsoleTelemetryAdapter",
    "ApplicationInsightsTelemetryAdapter",
    "get_telemetry_service",
    "create_telemetry_service",
    "close_telemetry_service",
]
