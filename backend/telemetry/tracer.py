"""
Distributed tracing support.
Placeholder for Azure Application Insights integration.
"""

import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, Dict, Any, Generator
from functools import wraps

from .logger import get_logger

logger = get_logger("tracer")


class Tracer:
    """
    Simple tracer for demo purposes.
    Replace with OpenTelemetry + Azure Monitor for production.
    """
    
    def __init__(self):
        self._spans: Dict[str, Dict[str, Any]] = {}
    
    def start_span(
        self, 
        name: str, 
        correlation_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None
    ) -> str:
        """Start a new trace span."""
        span_id = str(uuid.uuid4())
        self._spans[span_id] = {
            "name": name,
            "correlation_id": correlation_id or str(uuid.uuid4()),
            "start_time": datetime.utcnow(),
            "attributes": attributes or {},
            "events": [],
            "status": "running",
        }
        logger.debug(f"Started span: {name} ({span_id[:8]})")
        return span_id
    
    def end_span(
        self, 
        span_id: str, 
        status: str = "ok",
        error: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """End a trace span."""
        if span_id not in self._spans:
            return None
        
        span = self._spans[span_id]
        span["end_time"] = datetime.utcnow()
        span["status"] = status
        span["duration_ms"] = int(
            (span["end_time"] - span["start_time"]).total_seconds() * 1000
        )
        if error:
            span["error"] = error
        
        logger.debug(
            f"Ended span: {span['name']} ({span_id[:8]}) - "
            f"{span['duration_ms']}ms - {status}"
        )
        
        # In production, would export to Azure Monitor here
        return self._spans.pop(span_id)
    
    def add_event(self, span_id: str, name: str, attributes: Optional[Dict] = None) -> None:
        """Add an event to a span."""
        if span_id in self._spans:
            self._spans[span_id]["events"].append({
                "name": name,
                "timestamp": datetime.utcnow(),
                "attributes": attributes or {},
            })
    
    def set_attribute(self, span_id: str, key: str, value: Any) -> None:
        """Set an attribute on a span."""
        if span_id in self._spans:
            self._spans[span_id]["attributes"][key] = value


# Singleton tracer instance
_tracer: Optional[Tracer] = None


def get_tracer() -> Tracer:
    """Get the singleton tracer instance."""
    global _tracer
    if _tracer is None:
        _tracer = Tracer()
    return _tracer


@contextmanager
def trace_operation(
    name: str,
    correlation_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None
) -> Generator[str, None, None]:
    """
    Context manager for tracing an operation.
    
    Usage:
        with trace_operation("run_attack", correlation_id="abc") as span_id:
            # do work
            tracer.add_event(span_id, "checkpoint")
    """
    tracer = get_tracer()
    span_id = tracer.start_span(name, correlation_id, attributes)
    
    try:
        yield span_id
        tracer.end_span(span_id, status="ok")
    except Exception as e:
        tracer.end_span(span_id, status="error", error=str(e))
        raise


def traced(name: Optional[str] = None):
    """
    Decorator to trace a function.
    
    Usage:
        @traced("my_operation")
        async def my_function():
            pass
    """
    def decorator(func):
        operation_name = name or func.__name__
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            with trace_operation(operation_name):
                return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            with trace_operation(operation_name):
                return func(*args, **kwargs)
        
        # Return appropriate wrapper based on whether func is async
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator
