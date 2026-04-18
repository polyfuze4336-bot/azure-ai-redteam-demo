"""
Agent domain models and schemas.

Defines the data structures for lightweight demo agents including:
- Agent definitions (type, purpose, status)
- Agent invocation records (input, output, tracing)
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List, Union
from pydantic import BaseModel, Field
import uuid


# =============================================================================
# ENUMS
# =============================================================================

class AgentType(str, Enum):
    """Types of lightweight demo agents."""
    ATTACK_OBSERVER = "attack_observer"
    TELEMETRY_ANALYST = "telemetry_analyst"
    POLICY_EXPLAINER = "policy_explainer"
    CAMPAIGN_REPORTER = "campaign_reporter"


class InputType(str, Enum):
    """Supported input types for agents."""
    RUN = "run"
    CAMPAIGN = "campaign"


class AgentStatus(str, Enum):
    """Agent availability status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"


class InvocationStatus(str, Enum):
    """Status of an agent invocation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


# =============================================================================
# AGENT DEFINITION
# =============================================================================

class AgentDefinition(BaseModel):
    """
    Defines a lightweight demo agent.
    
    These agents are narrow-purpose, focused on observability,
    explanation, and storytelling for the red team demo.
    """
    agent_id: str = Field(
        ..., 
        description="Unique identifier for the agent"
    )
    agent_name: str = Field(
        ..., 
        description="Human-readable agent name"
    )
    agent_type: AgentType = Field(
        ..., 
        description="Type of agent"
    )
    purpose: str = Field(
        ..., 
        description="What this agent does and its role in the demo"
    )
    supported_input_types: List[InputType] = Field(
        ..., 
        description="Input types this agent can process (run, campaign)"
    )
    status: AgentStatus = Field(
        default=AgentStatus.ACTIVE, 
        description="Current availability status"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow, 
        description="When the agent was created"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow, 
        description="When the agent was last updated"
    )
    
    # Optional metadata
    version: str = Field(
        default="1.0.0", 
        description="Agent version"
    )
    tags: List[str] = Field(
        default_factory=list, 
        description="Tags for categorization"
    )
    config: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Agent-specific configuration"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "agent-attack-observer-001",
                "agent_name": "Attack Observer Agent",
                "agent_type": "attack_observer",
                "purpose": "Observes and narrates attack execution in real-time",
                "supported_input_types": ["run"],
                "status": "active",
                "version": "1.0.0"
            }
        }


# =============================================================================
# AGENT INVOCATION
# =============================================================================

class AgentInvocationRequest(BaseModel):
    """Request to invoke an agent."""
    agent_id: str = Field(
        ..., 
        description="ID of the agent to invoke"
    )
    linked_run_id: Optional[str] = Field(
        None, 
        description="ID of the attack run to process"
    )
    linked_campaign_id: Optional[str] = Field(
        None, 
        description="ID of the campaign to process"
    )
    input_data: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Additional input data for the agent"
    )
    correlation_id: Optional[str] = Field(
        None, 
        description="Correlation ID for tracing"
    )

    def validate_input_link(self) -> bool:
        """Ensure at least one link is provided."""
        return bool(self.linked_run_id or self.linked_campaign_id)


class AgentInvocation(BaseModel):
    """
    Record of an agent invocation.
    
    Captures the full lifecycle of an agent call including
    input, output, timing, and error details for observability.
    """
    invocation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), 
        description="Unique identifier for this invocation"
    )
    agent_id: str = Field(
        ..., 
        description="ID of the invoked agent"
    )
    agent_name: str = Field(
        ..., 
        description="Name of the invoked agent"
    )
    agent_type: AgentType = Field(
        ..., 
        description="Type of the invoked agent"
    )
    
    # Linked context
    linked_run_id: Optional[str] = Field(
        None, 
        description="ID of the linked attack run"
    )
    linked_campaign_id: Optional[str] = Field(
        None, 
        description="ID of the linked campaign"
    )
    
    # Input/Output
    input_summary: str = Field(
        default="", 
        description="Brief summary of the input"
    )
    input_data: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Full input data"
    )
    output_summary: str = Field(
        default="", 
        description="Brief summary of the output"
    )
    raw_output: str = Field(
        default="", 
        description="Raw output from the agent"
    )
    structured_output: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Parsed/structured output"
    )
    
    # Tracing
    correlation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), 
        description="Correlation ID for distributed tracing"
    )
    parent_span_id: Optional[str] = Field(
        None, 
        description="Parent span ID for nested tracing"
    )
    span_id: str = Field(
        default_factory=lambda: str(uuid.uuid4())[:16], 
        description="Span ID for this invocation"
    )
    
    # Timing
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, 
        description="When the invocation started"
    )
    completed_at: Optional[datetime] = Field(
        None, 
        description="When the invocation completed"
    )
    latency_ms: int = Field(
        default=0, 
        description="Total latency in milliseconds"
    )
    
    # Status
    status: InvocationStatus = Field(
        default=InvocationStatus.PENDING, 
        description="Current status of the invocation"
    )
    error_details: Optional[str] = Field(
        None, 
        description="Error message if failed"
    )
    error_code: Optional[str] = Field(
        None, 
        description="Error code if failed"
    )
    
    # Metadata
    metadata: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Additional metadata"
    )

    def mark_running(self) -> None:
        """Mark the invocation as running."""
        self.status = InvocationStatus.RUNNING
        self.timestamp = datetime.utcnow()

    def mark_completed(self, output_summary: str, raw_output: str) -> None:
        """Mark the invocation as completed with output."""
        self.status = InvocationStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.output_summary = output_summary
        self.raw_output = raw_output
        self.latency_ms = int(
            (self.completed_at - self.timestamp).total_seconds() * 1000
        )

    def mark_failed(self, error_details: str, error_code: Optional[str] = None) -> None:
        """Mark the invocation as failed with error details."""
        self.status = InvocationStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_details = error_details
        self.error_code = error_code
        self.latency_ms = int(
            (self.completed_at - self.timestamp).total_seconds() * 1000
        )

    class Config:
        json_schema_extra = {
            "example": {
                "invocation_id": "inv-abc123",
                "agent_id": "agent-attack-observer-001",
                "agent_name": "Attack Observer Agent",
                "agent_type": "attack_observer",
                "linked_run_id": "run-xyz789",
                "input_summary": "Observing jailbreak attack on gpt-4o",
                "output_summary": "Attack blocked by content safety shield",
                "correlation_id": "corr-123",
                "latency_ms": 245,
                "status": "completed"
            }
        }


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class AgentListResponse(BaseModel):
    """Response containing list of agents."""
    agents: List[AgentDefinition]
    total: int
    active_count: int


class InvocationListResponse(BaseModel):
    """Response containing list of invocations."""
    invocations: List[AgentInvocation]
    total: int
    page: int = 1
    page_size: int = 50


class InvocationSummary(BaseModel):
    """Summary statistics for invocations."""
    total_invocations: int
    completed_count: int
    failed_count: int
    pending_count: int
    average_latency_ms: float
    by_agent: Dict[str, int]
    by_status: Dict[str, int]
