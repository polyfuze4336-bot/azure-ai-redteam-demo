"""
Pydantic schemas for request/response models.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uuid


# =============================================================================
# ENUMS
# =============================================================================

class AttackCategory(str, Enum):
    """Attack category types."""
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt-injection"
    PROMPT_EXTRACTION = "prompt-extraction"
    DATA_EXFILTRATION = "data-exfiltration"
    CREDENTIAL_THEFT = "credential-theft"
    POLICY_EVASION = "policy-evasion"
    INDIRECT_INJECTION = "indirect-injection"
    TOOL_MISUSE = "tool-misuse"
    CODE_VULNERABILITY = "code-vulnerability"


class Severity(str, Enum):
    """Attack severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictResult(str, Enum):
    """Verdict result types."""
    BLOCKED = "blocked"
    ALLOWED = "allowed"
    FLAGGED = "flagged"
    NA = "n/a"


class Outcome(str, Enum):
    """Overall attack outcome."""
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    PARTIAL = "partial"


class CampaignStatus(str, Enum):
    """Campaign execution status."""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# =============================================================================
# VERDICT MODELS
# =============================================================================

class VerdictDetail(BaseModel):
    """Details of a single verdict."""
    result: VerdictResult = Field(..., description="Verdict result")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")
    categories_detected: List[str] = Field(default_factory=list, description="Categories detected")
    source: str = Field(default="unknown", description="Source of the verdict")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")


class Verdicts(BaseModel):
    """All three verdicts for an attack."""
    shield: VerdictDetail = Field(..., description="Azure AI Content Safety verdict")
    model: VerdictDetail = Field(..., description="Model's own safety response")
    evaluator: VerdictDetail = Field(..., description="Post-hoc evaluator verdict")


# =============================================================================
# SCENARIO MODELS
# =============================================================================

class AttackScenario(BaseModel):
    """Definition of an attack scenario."""
    id: str = Field(..., description="Unique scenario identifier")
    name: str = Field(..., description="Human-readable scenario name")
    category: AttackCategory = Field(..., description="Attack category")
    description: str = Field(..., description="What this attack does")
    prompt_template: str = Field(..., description="The attack prompt template")
    severity: Severity = Field(..., description="Severity level")
    expected_defense: str = Field(..., description="Expected security defense behavior")
    narrator_notes: Optional[str] = Field(None, description="Demo talking points")
    
    @property
    def prompt(self) -> str:
        """Alias for prompt_template for backward compatibility."""
        return self.prompt_template
    
    def model_dump(self, **kwargs) -> dict:
        """Override to include prompt in serialization."""
        data = super().model_dump(**kwargs)
        data["prompt"] = self.prompt_template  # Add prompt as alias
        return data


# =============================================================================
# REQUEST MODELS
# =============================================================================

class AttackRequest(BaseModel):
    """Request to run a single attack."""
    scenario_id: str = Field(..., description="ID of the scenario to run")
    target_model: str = Field(default="gpt-4o", description="Target model deployment")
    shield_enabled: bool = Field(default=True, description="Enable Azure AI Content Safety")
    custom_prompt: Optional[str] = Field(None, description="Override scenario prompt")
    category: Optional[str] = Field(None, description="Attack category (optional)")
    campaign_id: Optional[str] = Field(None, description="Parent campaign ID if part of campaign")
    agent_id: Optional[str] = Field(None, description="Optional agent profile ID to link this run")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "scenario_id": "jb-001",
                "target_model": "gpt-4o",
                "shield_enabled": True,
                "custom_prompt": None,
                "agent_id": "agent-abc123def456",
                "metadata": {"demo_session": "client-xyz"}
            }
        }


class CampaignRequest(BaseModel):
    """Request to run a campaign of multiple attacks."""
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    agent_id: Optional[str] = Field(None, description="Optional agent profile ID to link all runs")
    category: Optional[str] = Field(None, description="Filter by category, or run all")
    scenario_ids: Optional[List[str]] = Field(None, description="Specific scenarios to run")
    target_model: str = Field(default="gpt-4o", description="Target model deployment")
    shield_enabled: bool = Field(default=True, description="Enable Azure AI Content Safety")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Jailbreak Resilience Test",
                "category": "jailbreak",
                "scenario_ids": None,
                "target_model": "gpt-4o",
                "shield_enabled": True
            }
        }


# =============================================================================
# COMPARISON MODE MODELS
# =============================================================================

class ComparisonTargetType(str, Enum):
    """Type of comparison target."""
    BASELINE = "baseline"
    GUARDED = "guarded"


class ComparisonRequest(BaseModel):
    """Request to run a side-by-side comparison attack."""
    scenario_id: str = Field(..., description="ID of the scenario to run")
    custom_prompt: Optional[str] = Field(None, description="Override scenario prompt")
    
    # Optional overrides (uses config defaults if not specified)
    baseline_deployment: Optional[str] = Field(None, description="Override baseline deployment")
    guarded_deployment: Optional[str] = Field(None, description="Override guarded deployment")
    baseline_shield_enabled: Optional[bool] = Field(None, description="Override baseline shield setting")
    guarded_shield_enabled: Optional[bool] = Field(None, description="Override guarded shield setting")
    
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "scenario_id": "jb-001",
                "baseline_deployment": None,
                "guarded_deployment": None,
                "baseline_shield_enabled": False,
                "guarded_shield_enabled": True
            }
        }


class ComparisonTargetResult(BaseModel):
    """Result from a single target in a comparison."""
    # Target identification
    target_type: ComparisonTargetType = Field(..., description="Whether this is baseline or guarded")
    deployment_name: str = Field(..., description="Azure OpenAI deployment name")
    foundry_resource_name: str = Field(..., description="Azure AI Foundry resource name")
    endpoint_url: Optional[str] = Field(None, description="Target endpoint URL (masked)")
    shield_enabled: bool = Field(..., description="Whether shield was enabled")
    
    # Response
    response: str = Field(..., description="Model response text")
    latency_ms: int = Field(..., ge=0, description="Execution latency in milliseconds")
    tokens_used: Optional[int] = Field(None, description="Tokens consumed")
    
    # Verdicts
    shield_verdict: VerdictDetail = Field(..., description="Shield verdict")
    model_verdict: VerdictDetail = Field(..., description="Model verdict")
    evaluator_verdict: VerdictDetail = Field(..., description="Evaluator verdict")
    outcome: Outcome = Field(..., description="Overall attack outcome")
    
    # Telemetry
    correlation_id: str = Field(..., description="Correlation ID for this target run")


class ComparisonResult(BaseModel):
    """Result of a side-by-side comparison attack."""
    # Identifiers
    comparison_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique comparison ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Comparison timestamp")
    
    # Attack context
    scenario_id: str = Field(..., description="Scenario ID")
    scenario_name: str = Field(..., description="Scenario name")
    attack_category: AttackCategory = Field(..., description="Attack category")
    severity: Severity = Field(..., description="Severity level")
    prompt: str = Field(..., description="Attack prompt used")
    expected_defense: str = Field(..., description="Expected security behavior")
    
    # Comparison context
    is_same_resource: bool = Field(..., description="Whether both targets use same Foundry resource")
    comparison_type: str = Field(..., description="'same_resource_different_deployments' or 'different_environments'")
    
    # Results
    baseline: ComparisonTargetResult = Field(..., description="Baseline target result")
    guarded: ComparisonTargetResult = Field(..., description="Guarded target result")
    
    # Comparison metrics
    latency_difference_ms: int = Field(..., description="Guarded latency - baseline latency")
    baseline_attack_success: bool = Field(..., description="Whether attack succeeded on baseline")
    guarded_attack_success: bool = Field(..., description="Whether attack succeeded on guarded")
    shield_effectiveness: str = Field(..., description="Description of shield impact")
    
    class Config:
        json_schema_extra = {
            "example": {
                "comparison_id": "cmp-001",
                "scenario_id": "jb-001",
                "scenario_name": "DAN Jailbreak",
                "is_same_resource": True,
                "comparison_type": "same_resource_different_deployments"
            }
        }


class ComparisonConfigResponse(BaseModel):
    """Response showing current comparison mode configuration."""
    enabled: bool = Field(..., description="Whether comparison mode is available")
    is_same_resource: bool = Field(..., description="Whether both targets use same resource")
    comparison_type: str = Field(..., description="Type of comparison configured")
    foundry_resource_name: str = Field(..., description="Primary Foundry resource name")
    
    baseline: Dict[str, Any] = Field(..., description="Baseline target configuration")
    guarded: Dict[str, Any] = Field(..., description="Guarded target configuration")


# =============================================================================
# RESULT MODELS (Normalized Schema)
# =============================================================================

class TelemetryStatus(str, Enum):
    """Status of telemetry capture for a run."""
    CAPTURED = "captured"
    PARTIAL = "partial"
    FAILED = "failed"
    DISABLED = "disabled"
    PENDING = "pending"


class AttackResult(BaseModel):
    """
    Normalized result schema for a single attack execution.
    This is the core data model for all attack results.
    """
    # Identifiers
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique run identifier")
    campaign_id: Optional[str] = Field(None, description="Parent campaign ID if part of campaign")
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Correlation ID for tracing")
    run_source: str = Field(default="curated", description="Run source: 'curated', 'pyrit', or 'custom'")
    
    # Timing
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Execution timestamp")
    latency_ms: int = Field(..., ge=0, description="Total execution latency in milliseconds")
    
    # Attack Context
    attack_category: AttackCategory = Field(..., description="Category of the attack")
    scenario_name: str = Field(..., description="Name of the scenario executed")
    scenario_id: str = Field(..., description="ID of the scenario executed")
    severity: Severity = Field(..., description="Attack severity level")
    
    # Execution Details
    prompt: str = Field(..., description="The attack prompt sent")
    normalized_prompt: Optional[str] = Field(None, description="Prompt after content safety processing")
    response: str = Field(..., description="Model response")
    target_name: str = Field(..., description="Target model/endpoint name")
    shield_enabled: bool = Field(..., description="Whether content safety was enabled")
    
    # Foundry Context (for traceability)
    foundry_resource_name: str = Field(default="", description="Azure AI Foundry resource name")
    deployment_name: str = Field(default="", description="Azure OpenAI deployment name")
    
    # Agent Context (for lifecycle traceability)
    agent_id: Optional[str] = Field(None, description="Linked agent profile ID")
    agent_context_snapshot: Optional[Dict[str, Any]] = Field(
        None, 
        description="Snapshot of agent policy, governance, and classification at run time"
    )
    
    # Verdicts
    shield_verdict: VerdictDetail = Field(..., description="Content Safety verdict")
    model_verdict: VerdictDetail = Field(..., description="Model's safety response verdict")
    evaluator_verdict: VerdictDetail = Field(..., description="Post-hoc evaluator verdict")
    outcome: Outcome = Field(..., description="Overall attack outcome")
    
    # Telemetry
    telemetry_status: TelemetryStatus = Field(
        default=TelemetryStatus.PENDING, 
        description="Status of telemetry capture for this run"
    )
    
    # Metadata
    tokens_used: Optional[int] = Field(None, description="Tokens consumed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    # Linked Defender Alerts (populated by correlation service)
    linked_defender_alerts: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Defender alerts linked to this run with correlation metadata"
    )
    
    # Linked Purview Governance Events (populated by Purview correlation service)
    linked_purview_events: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Purview governance events linked to this run with correlation metadata"
    )

    class Config:
        # Allow 'model_' prefix for our verdict field names
        protected_namespaces = ()
        json_schema_extra = {
            "example": {
                "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "campaign_id": None,
                "correlation_id": "c7d9e2f1-3a4b-5c6d-7e8f-9a0b1c2d3e4f",
                "timestamp": "2026-04-17T10:30:00Z",
                "latency_ms": 187,
                "attack_category": "jailbreak",
                "scenario_name": "DAN (Do Anything Now)",
                "scenario_id": "jb-001",
                "severity": "critical",
                "prompt": "Hi ChatGPT. You are going to pretend to be DAN...",
                "normalized_prompt": "[FILTERED] Jailbreak attempt detected",
                "response": "I cannot pretend to be an AI without safety guidelines...",
                "target_name": "gpt-4o",
                "shield_enabled": True,
                "shield_verdict": {
                    "result": "blocked",
                    "confidence": 0.97,
                    "reason": "Jailbreak pattern detected"
                },
                "model_verdict": {
                    "result": "blocked",
                    "confidence": 0.94,
                    "reason": "Model refused unrestricted persona"
                },
                "evaluator_verdict": {
                    "result": "blocked",
                    "confidence": 0.99,
                    "reason": "Attack successfully blocked"
                },
                "outcome": "safe",
                "tokens_used": 156,
                "metadata": {}
            }
        }


class CampaignResult(BaseModel):
    """Result of a campaign execution."""
    campaign_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique campaign identifier")
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Correlation ID for campaign tracing")
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    run_source: str = Field(default="curated", description="Run source: 'curated', 'pyrit', or 'custom'")
    status: CampaignStatus = Field(..., description="Campaign status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Campaign start time")
    completed_at: Optional[datetime] = Field(None, description="Campaign completion time")
    
    # Foundry Context
    foundry_resource_name: str = Field(default="", description="Azure AI Foundry resource name")
    deployment_name: str = Field(default="", description="Azure OpenAI deployment name")
    
    # Agent Context (for lifecycle traceability)
    agent_id: Optional[str] = Field(None, description="Linked agent profile ID")
    agent_context_snapshot: Optional[Dict[str, Any]] = Field(
        None, 
        description="Snapshot of agent policy, governance, and classification at run time"
    )
    
    # Core Statistics (existing)
    total_attacks: int = Field(default=0, description="Total attacks in campaign")
    blocked_count: int = Field(default=0, description="Number blocked by shield")
    passed_count: int = Field(default=0, description="Number that bypassed all defenses (vulnerable)")
    flagged_count: int = Field(default=0, description="Number flagged for review")
    
    # Detailed Outcome Breakdown
    safe_refusal_count: int = Field(default=0, description="Model refused safely without shield")
    unsafe_success_count: int = Field(default=0, description="Attack succeeded - model complied")
    suspicious_success_count: int = Field(default=0, description="Partial compliance detected")
    error_count: int = Field(default=0, description="Errors during execution")
    
    # Computed Metrics
    attack_success_rate: float = Field(default=0.0, description="Percentage of successful attacks (vulnerable/total)")
    blocked_rate: float = Field(default=0.0, description="Percentage blocked by shield or model")
    average_latency_ms: float = Field(default=0.0, description="Average latency per attack in ms")
    total_latency_ms: int = Field(default=0, description="Total campaign execution time in ms")
    
    # Results
    results: List[AttackResult] = Field(default_factory=list, description="Individual attack results")
    
    # Metadata
    target_name: str = Field(..., description="Target model used")
    shield_enabled: bool = Field(..., description="Whether shield was enabled")
    categories: List[str] = Field(default_factory=list, description="Attack categories")
    
    # Telemetry
    telemetry_status: TelemetryStatus = Field(
        default=TelemetryStatus.PENDING,
        description="Status of telemetry capture for this campaign"
    )
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        protected_namespaces = ()

    @property
    def block_rate(self) -> float:
        """Calculate the block rate percentage (legacy property)."""
        return self.blocked_rate


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(default="healthy", description="Service status")
    version: str = Field(default="0.1.0", description="API version")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Current timestamp")
    services: Dict[str, str] = Field(default_factory=dict, description="Dependent service statuses")


class HistoryResponse(BaseModel):
    """Response containing attack history."""
    total: int = Field(..., description="Total number of results")
    limit: int = Field(..., description="Limit applied")
    offset: int = Field(..., description="Offset applied")
    results: List[AttackResult] = Field(..., description="Attack results")


# =============================================================================
# RUN SOURCE LABELS
# =============================================================================

class RunSource(str, Enum):
    """Source of the attack run (curated vs automated)."""
    CURATED = "curated"  # Manual curated attacks (default, most reliable)
    PYRIT = "pyrit"      # PyRIT automated red teaming
    CUSTOM = "custom"    # Custom user-provided prompts


# =============================================================================
# PYRIT INTEGRATION MODELS (Optional Addon)
# =============================================================================

class PyRITStrategy(str, Enum):
    """PyRIT attack strategy types."""
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    CRESCENDO = "crescendo"
    PAIR = "pair"
    TAP = "tap"
    SKELETON_KEY = "skeleton_key"
    CUSTOM = "custom"


class PyRITStatus(str, Enum):
    """Status of PyRIT integration."""
    AVAILABLE = "available"      # PyRIT is installed and configured
    NOT_INSTALLED = "not_installed"  # PyRIT package not found
    DISABLED = "disabled"        # PyRIT is disabled in config
    MISCONFIGURED = "misconfigured"  # Missing required configuration


class PyRITCampaignRequest(BaseModel):
    """Request to run a PyRIT automated campaign."""
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    
    # Attack configuration
    strategies: List[PyRITStrategy] = Field(
        default_factory=lambda: [PyRITStrategy.JAILBREAK, PyRITStrategy.PROMPT_INJECTION],
        description="PyRIT attack strategies to run"
    )
    
    # Target configuration
    target_model: str = Field(default="gpt-4o", description="Target model deployment")
    shield_enabled: bool = Field(default=True, description="Enable Azure AI Content Safety")
    
    # Execution settings
    max_turns: int = Field(default=5, ge=1, le=20, description="Max conversation turns")
    parallel_attacks: int = Field(default=3, ge=1, le=10, description="Parallel attack threads")
    timeout_seconds: int = Field(default=120, ge=30, le=600, description="Attack timeout")
    
    # Custom objectives (optional)
    custom_objectives: List[str] = Field(
        default_factory=list,
        description="Custom attack objectives to test"
    )
    
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "PyRIT Automated Jailbreak Test",
                "strategies": ["jailbreak", "prompt_injection"],
                "target_model": "gpt-4o",
                "shield_enabled": True,
                "max_turns": 5,
                "parallel_attacks": 3
            }
        }


class PyRITAttackResult(BaseModel):
    """Raw result from a single PyRIT attack sequence."""
    sequence_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique sequence ID")
    strategy: PyRITStrategy = Field(..., description="Attack strategy used")
    objective: str = Field(..., description="Attack objective")
    
    # Conversation turns
    turns: List[Dict[str, Any]] = Field(default_factory=list, description="Conversation turns")
    total_turns: int = Field(default=0, description="Number of turns in attack")
    
    # Raw PyRIT output
    success: bool = Field(..., description="Whether PyRIT reported success")
    success_score: float = Field(default=0.0, ge=0.0, le=1.0, description="PyRIT success score")
    raw_output: Dict[str, Any] = Field(default_factory=dict, description="Raw PyRIT output metadata")
    
    # Timing
    duration_ms: int = Field(..., ge=0, description="Total duration in milliseconds")
    
    # Error handling
    error: Optional[str] = Field(None, description="Error message if failed")


class PyRITCampaignResult(BaseModel):
    """Result of a PyRIT automated campaign - includes raw and normalized output."""
    # Campaign identification
    campaign_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique campaign ID")
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Correlation ID for tracing")
    
    name: str = Field(..., description="Campaign name")
    description: Optional[str] = Field(None, description="Campaign description")
    run_source: RunSource = Field(default=RunSource.PYRIT, description="Run source label")
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Campaign start time")
    completed_at: Optional[datetime] = Field(None, description="Campaign completion time")
    status: CampaignStatus = Field(..., description="Campaign status")
    
    # Target context
    foundry_resource_name: str = Field(default="", description="Azure AI Foundry resource name")
    deployment_name: str = Field(default="", description="Azure OpenAI deployment name")
    target_name: str = Field(..., description="Target model used")
    shield_enabled: bool = Field(..., description="Whether shield was enabled")
    
    # PyRIT-specific results
    strategies_run: List[PyRITStrategy] = Field(default_factory=list, description="Strategies that were run")
    pyrit_results: List[PyRITAttackResult] = Field(default_factory=list, description="Raw PyRIT attack results")
    
    # Normalized results (mapped to platform schema)
    normalized_results: List[AttackResult] = Field(default_factory=list, description="Normalized attack results")
    
    # Aggregate statistics
    total_sequences: int = Field(default=0, description="Total attack sequences run")
    successful_attacks: int = Field(default=0, description="Number of successful attacks (per PyRIT)")
    blocked_count: int = Field(default=0, description="Number blocked by shield")
    passed_count: int = Field(default=0, description="Number that bypassed defenses")
    flagged_count: int = Field(default=0, description="Number flagged for review")
    error_count: int = Field(default=0, description="Number of errors")
    
    # Computed metrics
    attack_success_rate: float = Field(default=0.0, description="Percentage of successful attacks")
    blocked_rate: float = Field(default=0.0, description="Percentage blocked by shield")
    average_duration_ms: float = Field(default=0.0, description="Average attack duration")
    total_duration_ms: int = Field(default=0, description="Total campaign duration")
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        protected_namespaces = ()


class PyRITConfigResponse(BaseModel):
    """Response showing PyRIT integration status and configuration."""
    status: PyRITStatus = Field(..., description="PyRIT integration status")
    enabled: bool = Field(..., description="Whether PyRIT is enabled in config")
    available: bool = Field(..., description="Whether PyRIT is installed and usable")
    
    # Configuration details (only shown if available)
    strategies: List[PyRITStrategy] = Field(default_factory=list, description="Available attack strategies")
    default_max_turns: int = Field(default=5, description="Default max conversation turns")
    default_parallel_attacks: int = Field(default=3, description="Default parallel attacks")
    default_timeout_seconds: int = Field(default=120, description="Default timeout")
    
    # Target info
    foundry_resource_name: str = Field(default="", description="Configured Foundry resource")
    endpoint_configured: bool = Field(..., description="Whether target endpoint is configured")
    
    message: str = Field(..., description="Human-readable status message")


# =============================================================================
# DEFENDER ALERT MODELS
# =============================================================================

class DefenderAlertSeverity(str, Enum):
    """Microsoft Defender alert severity levels."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DefenderAlertStatus(str, Enum):
    """Microsoft Defender alert status values."""
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    UNKNOWN = "unknown"


class DefenderAlertSource(str, Enum):
    """Source of the Defender alert."""
    DEFENDER_FOR_AI = "defender_for_ai"
    DEFENDER_FOR_CLOUD = "defender_for_cloud"
    CONTENT_SAFETY = "content_safety"
    SENTINEL = "sentinel"
    FALLBACK_SIMULATED = "fallback_simulated"  # Only used when real source unavailable


class DefenderAlert(BaseModel):
    """
    Internal model for Microsoft Defender alerts related to AI workloads.
    Normalized from various Defender sources into a consistent structure.
    """
    # Core identification
    alert_id: str = Field(..., description="Unique Defender alert identifier")
    title: str = Field(..., description="Alert title")
    description: str = Field(..., description="Detailed alert description")
    
    # Severity and status
    severity: DefenderAlertSeverity = Field(..., description="Alert severity level")
    status: DefenderAlertStatus = Field(default=DefenderAlertStatus.NEW, description="Alert status")
    
    # Timestamps
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Alert creation timestamp")
    detected_at: datetime = Field(default_factory=datetime.utcnow, description="When the threat was detected")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    
    # Correlation and linking
    correlation_id: Optional[str] = Field(None, description="Correlation ID linking to attack runs")
    linked_run_id: Optional[str] = Field(None, description="Resolved link to a specific attack run")
    linked_agent_id: Optional[str] = Field(None, description="Resolved link to an agent profile")
    linked_campaign_id: Optional[str] = Field(None, description="Resolved link to a campaign")
    
    # Source and context
    source: DefenderAlertSource = Field(..., description="Source of the alert")
    resource_name: Optional[str] = Field(None, description="Affected Azure resource name")
    resource_type: Optional[str] = Field(None, description="Type of affected resource")
    subscription_id: Optional[str] = Field(None, description="Azure subscription ID")
    
    # Alert details
    category: Optional[str] = Field(None, description="Alert category (e.g., 'JailbreakAttempt', 'PromptInjection')")
    tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    
    # Remediation
    remediation_steps: List[str] = Field(default_factory=list, description="Suggested remediation steps")
    is_incident: bool = Field(default=False, description="Whether this alert is part of an incident")
    incident_id: Optional[str] = Field(None, description="Parent incident ID if applicable")
    
    # Raw metadata from source
    raw_metadata: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Raw metadata from the Defender API response"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "da-12345-67890-abcdef",
                "title": "Jailbreak attempt detected on AI deployment",
                "description": "A prompt injection attack attempting to bypass content safety filters was detected.",
                "severity": "high",
                "status": "new",
                "timestamp": "2024-01-15T10:30:00Z",
                "correlation_id": "corr-abc123",
                "linked_run_id": "run-xyz789",
                "source": "defender_for_ai",
                "category": "JailbreakAttempt",
                "tactics": ["Initial Access", "Defense Evasion"],
                "techniques": ["T1189", "T1562"]
            }
        }


class DefenderAlertFilter(BaseModel):
    """Filter parameters for querying Defender alerts."""
    # Time filters
    start_time: Optional[datetime] = Field(None, description="Filter alerts after this time")
    end_time: Optional[datetime] = Field(None, description="Filter alerts before this time")
    
    # Status and severity filters
    severity: Optional[List[DefenderAlertSeverity]] = Field(None, description="Filter by severity levels")
    status: Optional[List[DefenderAlertStatus]] = Field(None, description="Filter by status values")
    
    # Correlation filters
    correlation_id: Optional[str] = Field(None, description="Filter by correlation ID")
    linked_run_id: Optional[str] = Field(None, description="Filter by linked run ID")
    linked_agent_id: Optional[str] = Field(None, description="Filter by linked agent ID")
    
    # Source filters
    source: Optional[List[DefenderAlertSource]] = Field(None, description="Filter by alert source")
    category: Optional[str] = Field(None, description="Filter by alert category")
    
    # Pagination
    limit: int = Field(default=50, ge=1, le=500, description="Maximum alerts to return")
    offset: int = Field(default=0, ge=0, description="Number of alerts to skip")

    class Config:
        json_schema_extra = {
            "example": {
                "severity": ["high", "critical"],
                "status": ["new", "in_progress"],
                "limit": 50,
                "offset": 0
            }
        }


class DefenderAlertResponse(BaseModel):
    """Response containing Defender alerts."""
    total: int = Field(..., description="Total number of matching alerts")
    limit: int = Field(..., description="Limit applied")
    offset: int = Field(..., description="Offset applied")
    source_status: str = Field(
        default="real", 
        description="'real' if from Defender API, 'fallback' if simulated"
    )
    alerts: List[DefenderAlert] = Field(..., description="Defender alerts")


class DefenderIngestionStatus(BaseModel):
    """Status of the Defender alert ingestion service."""
    enabled: bool = Field(..., description="Whether ingestion is enabled")
    source_available: bool = Field(..., description="Whether real Defender source is available")
    fallback_active: bool = Field(..., description="Whether fallback mode is active")
    last_sync_at: Optional[datetime] = Field(None, description="Last successful sync timestamp")
    last_error: Optional[str] = Field(None, description="Last error message if any")
    alerts_ingested: int = Field(default=0, description="Total alerts ingested this session")
    configured_resource: Optional[str] = Field(None, description="Configured Defender resource")
    message: str = Field(..., description="Human-readable status message")


# =============================================================================
# PURVIEW GOVERNANCE EVENT MODELS
# =============================================================================

class PurviewEventType(str, Enum):
    """Types of Purview governance events."""
    POLICY_EVALUATION = "policy_evaluation"
    CLASSIFICATION_APPLIED = "classification_applied"
    CLASSIFICATION_CHANGED = "classification_changed"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    RETENTION_TRIGGERED = "retention_triggered"
    COMPLIANCE_CHECK = "compliance_check"
    LABEL_CHANGE = "label_change"
    POLICY_VIOLATION = "policy_violation"
    DATA_LINEAGE = "data_lineage"
    AUDIT_LOG = "audit_log"


class PurviewPolicyAction(str, Enum):
    """Actions taken by Purview policies."""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    ENCRYPT = "encrypt"
    REDACT = "redact"
    WARN = "warn"
    FLAG_FOR_REVIEW = "flag_for_review"
    NOTIFY = "notify"
    BLOCK = "block"


class PurviewEventStatus(str, Enum):
    """Status of a Purview governance event."""
    PENDING = "pending"
    PROCESSED = "processed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_ACTION = "requires_action"
    COMPLETED = "completed"


class PurviewEventSource(str, Enum):
    """Source of the Purview governance event."""
    PURVIEW_COMPLIANCE_CENTER = "purview_compliance_center"
    PURVIEW_DATA_CATALOG = "purview_data_catalog"
    PURVIEW_DATA_MAP = "purview_data_map"
    PURVIEW_POLICY_ENGINE = "purview_policy_engine"
    AZURE_ACTIVITY_LOG = "azure_activity_log"
    GRAPH_SECURITY_API = "graph_security_api"
    ADAPTER_IMPORT = "adapter_import"
    MANUAL_ENTRY = "manual_entry"


class PurviewGovernanceEvent(BaseModel):
    """
    Internal model for Microsoft Purview governance events.
    
    Represents policy evaluations, compliance checks, classification changes,
    and other governance-related activities from Purview. Normalized from
    various Purview sources into a consistent structure for the demo.
    """
    # Core identification
    event_id: str = Field(
        default_factory=lambda: f"pgov-{uuid.uuid4().hex[:12]}",
        description="Unique governance event identifier"
    )
    event_type: PurviewEventType = Field(..., description="Type of governance event")
    
    # Policy context
    policy_name: str = Field(..., description="Name of the policy evaluated or applied")
    policy_id: Optional[str] = Field(None, description="Unique policy identifier if available")
    policy_action: PurviewPolicyAction = Field(..., description="Action taken by the policy")
    
    # Classification context
    classification: Optional[str] = Field(
        None, 
        description="Data classification level (e.g., confidential, internal, public)"
    )
    sensitivity_label: Optional[str] = Field(
        None, 
        description="Sensitivity label applied if any"
    )
    
    # Timestamps
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, 
        description="When the event occurred"
    )
    processed_at: Optional[datetime] = Field(
        None, 
        description="When the event was ingested/processed"
    )
    
    # Status
    status: PurviewEventStatus = Field(
        default=PurviewEventStatus.PROCESSED, 
        description="Current status of the event"
    )
    
    # Linking to runs and agents
    linked_run_id: Optional[str] = Field(
        None, 
        description="Resolved link to a specific attack run"
    )
    linked_agent_id: Optional[str] = Field(
        None, 
        description="Resolved link to an agent profile"
    )
    linked_campaign_id: Optional[str] = Field(
        None, 
        description="Resolved link to a campaign"
    )
    correlation_id: Optional[str] = Field(
        None, 
        description="Correlation ID for tracing across systems"
    )
    
    # Source and context
    source: PurviewEventSource = Field(..., description="Source of the governance event")
    resource_name: Optional[str] = Field(
        None, 
        description="Affected Azure resource name"
    )
    resource_type: Optional[str] = Field(
        None, 
        description="Type of affected resource"
    )
    purview_account_name: Optional[str] = Field(
        None, 
        description="Purview account name if applicable"
    )
    
    # Event details
    description: str = Field(
        default="", 
        description="Human-readable description of the event"
    )
    affected_entity: Optional[str] = Field(
        None, 
        description="Entity affected by this event (user, agent, data asset)"
    )
    additional_context: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Additional context specific to the event type"
    )
    
    # Compliance and audit
    compliance_state: Optional[str] = Field(
        None, 
        description="Compliance state (compliant, non_compliant, unknown)"
    )
    risk_level: Optional[str] = Field(
        None, 
        description="Risk level if applicable (low, medium, high, critical)"
    )
    remediation_guidance: Optional[str] = Field(
        None, 
        description="Suggested remediation if non-compliant"
    )
    
    # Raw metadata from source
    raw_metadata: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Raw metadata from the Purview source"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "pgov-abc123def456",
                "event_type": "policy_evaluation",
                "policy_name": "AI Agent Data Access Policy",
                "policy_action": "allow",
                "classification": "confidential",
                "timestamp": "2026-04-19T10:30:00Z",
                "status": "processed",
                "linked_agent_id": "agent-xyz789",
                "source": "purview_policy_engine",
                "description": "Policy evaluation for AI agent data access request",
                "compliance_state": "compliant"
            }
        }


class PurviewEventFilter(BaseModel):
    """Filter parameters for querying Purview governance events."""
    # Time filters
    start_time: Optional[datetime] = Field(None, description="Filter events after this time")
    end_time: Optional[datetime] = Field(None, description="Filter events before this time")
    
    # Type and status filters
    event_type: Optional[List[PurviewEventType]] = Field(
        None, 
        description="Filter by event types"
    )
    status: Optional[List[PurviewEventStatus]] = Field(
        None, 
        description="Filter by status values"
    )
    policy_action: Optional[List[PurviewPolicyAction]] = Field(
        None, 
        description="Filter by policy actions"
    )
    
    # Policy and classification filters
    policy_name: Optional[str] = Field(None, description="Filter by policy name (partial match)")
    classification: Optional[str] = Field(None, description="Filter by classification level")
    
    # Linking filters
    linked_run_id: Optional[str] = Field(None, description="Filter by linked run ID")
    linked_agent_id: Optional[str] = Field(None, description="Filter by linked agent ID")
    linked_campaign_id: Optional[str] = Field(None, description="Filter by linked campaign ID")
    correlation_id: Optional[str] = Field(None, description="Filter by correlation ID")
    
    # Source filter
    source: Optional[List[PurviewEventSource]] = Field(
        None, 
        description="Filter by event source"
    )
    
    # Pagination
    limit: int = Field(default=50, ge=1, le=500, description="Maximum events to return")
    offset: int = Field(default=0, ge=0, description="Number of events to skip")

    class Config:
        json_schema_extra = {
            "example": {
                "event_type": ["policy_evaluation", "access_denied"],
                "status": ["processed", "requires_action"],
                "classification": "confidential",
                "limit": 50,
                "offset": 0
            }
        }


class PurviewEventResponse(BaseModel):
    """Response containing Purview governance events."""
    total: int = Field(..., description="Total number of matching events")
    limit: int = Field(..., description="Limit applied")
    offset: int = Field(..., description="Offset applied")
    source_status: str = Field(
        default="real", 
        description="'real' if from Purview APIs, 'adapter' if from configured import"
    )
    events: List[PurviewGovernanceEvent] = Field(..., description="Governance events")


class PurviewIngestionStatus(BaseModel):
    """Status of the Purview governance event ingestion service."""
    enabled: bool = Field(..., description="Whether ingestion is enabled")
    source_available: bool = Field(..., description="Whether Purview source is reachable")
    adapter_mode: bool = Field(
        default=False, 
        description="Whether using adapter/import mode instead of direct API"
    )
    last_sync_at: Optional[datetime] = Field(None, description="Last successful sync timestamp")
    last_error: Optional[str] = Field(None, description="Last error message if any")
    events_ingested: int = Field(default=0, description="Total events ingested this session")
    configured_account: Optional[str] = Field(None, description="Configured Purview account")
    connection_method: str = Field(
        default="not_configured", 
        description="Connection method (purview_api, graph_api, adapter, manual)"
    )
    message: str = Field(..., description="Human-readable status message")


class PurviewCorrelationStats(BaseModel):
    """Statistics about governance event correlation with runs and agents."""
    total_events: int = Field(..., description="Total governance events")
    linked_to_runs: int = Field(..., description="Events linked to attack runs")
    linked_to_agents: int = Field(..., description="Events linked to agent profiles")
    unlinked: int = Field(..., description="Events not yet linked")
    
    # Breakdown by action
    allow_count: int = Field(default=0, description="Events with allow action")
    deny_count: int = Field(default=0, description="Events with deny action")
    audit_count: int = Field(default=0, description="Events with audit action")
    flag_count: int = Field(default=0, description="Events flagged for review")
    
    # Breakdown by compliance
    compliant_count: int = Field(default=0, description="Compliant events")
    non_compliant_count: int = Field(default=0, description="Non-compliant events")


# =============================================================================
# DEFENDER ALERT CORRELATION MODELS
# =============================================================================

class CorrelationMethod(str, Enum):
    """Methods used to correlate Defender alerts with attack runs."""
    CORRELATION_ID = "correlation_id"  # Exact correlation ID match
    TIMESTAMP_PROXIMITY = "timestamp_proximity"  # Alert timestamp close to run timestamp
    AGENT_CONTEXT = "agent_context"  # Same agent ID
    TARGET_CONTEXT = "target_context"  # Same target/deployment
    CATEGORY_MATCH = "category_match"  # Alert category matches attack category
    RESOURCE_MATCH = "resource_match"  # Same Foundry resource
    METADATA_MATCH = "metadata_match"  # Matching metadata fields
    MANUAL = "manual"  # Manually linked by user


class CorrelationConfidence(str, Enum):
    """Confidence level of alert-to-run correlation."""
    HIGH = "high"  # Strong match (e.g., exact correlation ID)
    MEDIUM = "medium"  # Reasonable match (multiple signals align)
    LOW = "low"  # Weak match (single weak signal)
    UNLINKED = "unlinked"  # No correlation found


class AlertCorrelation(BaseModel):
    """
    Represents a correlation between a Defender alert and an attack run.
    Stores the method used, confidence level, and reasoning.
    """
    alert_id: str = Field(..., description="Defender alert ID")
    run_id: str = Field(..., description="Attack run ID")
    
    # Correlation details
    confidence: CorrelationConfidence = Field(..., description="Confidence level of correlation")
    methods_used: List[CorrelationMethod] = Field(
        default_factory=list, 
        description="Methods that contributed to this correlation"
    )
    score: float = Field(
        default=0.0, 
        ge=0.0, 
        le=1.0, 
        description="Numeric correlation score (0-1)"
    )
    
    # Reasoning and metadata
    reason: str = Field(..., description="Human-readable explanation of correlation")
    match_details: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Details of what matched for each method"
    )
    
    # Timestamps
    correlated_at: datetime = Field(
        default_factory=datetime.utcnow, 
        description="When correlation was established"
    )
    
    # Optional links
    agent_id: Optional[str] = Field(None, description="Agent ID if matched via agent context")
    campaign_id: Optional[str] = Field(None, description="Campaign ID if run is part of campaign")

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "da-12345-67890",
                "run_id": "run-abc123",
                "confidence": "high",
                "methods_used": ["correlation_id", "timestamp_proximity"],
                "score": 0.95,
                "reason": "Exact correlation ID match with timestamp within 5 seconds",
                "match_details": {
                    "correlation_id": {"matched": True, "value": "corr-xyz"},
                    "timestamp_delta_seconds": 2.5
                }
            }
        }


class LinkedDefenderAlert(BaseModel):
    """
    A Defender alert linked to an attack run with correlation metadata.
    Stored on the AttackResult for easy access.
    """
    alert_id: str = Field(..., description="Defender alert ID")
    title: str = Field(..., description="Alert title for quick reference")
    severity: DefenderAlertSeverity = Field(..., description="Alert severity")
    category: Optional[str] = Field(None, description="Alert category")
    timestamp: datetime = Field(..., description="Alert timestamp")
    
    # Correlation info
    correlation: AlertCorrelation = Field(..., description="Correlation details")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "da-12345",
                "title": "Jailbreak attempt detected",
                "severity": "high",
                "category": "JailbreakAttempt",
                "timestamp": "2026-04-19T10:30:00Z",
                "correlation": {
                    "confidence": "high",
                    "score": 0.95,
                    "reason": "Exact correlation ID match"
                }
            }
        }


class CorrelationRequest(BaseModel):
    """Request to correlate alerts with runs."""
    alert_ids: Optional[List[str]] = Field(
        None, 
        description="Specific alert IDs to correlate (None = all unlinked)"
    )
    run_ids: Optional[List[str]] = Field(
        None, 
        description="Specific run IDs to consider (None = all recent)"
    )
    min_confidence: CorrelationConfidence = Field(
        default=CorrelationConfidence.LOW, 
        description="Minimum confidence to create link"
    )
    time_window_seconds: int = Field(
        default=300, 
        ge=1, 
        le=3600, 
        description="Time window for timestamp proximity matching"
    )
    auto_link: bool = Field(
        default=True, 
        description="Automatically link alerts meeting threshold"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "min_confidence": "medium",
                "time_window_seconds": 300,
                "auto_link": True
            }
        }


class CorrelationResult(BaseModel):
    """Result of a correlation operation."""
    total_alerts_processed: int = Field(..., description="Total alerts analyzed")
    total_runs_considered: int = Field(..., description="Total runs considered")
    correlations_found: int = Field(..., description="Number of correlations found")
    correlations_linked: int = Field(..., description="Number of correlations auto-linked")
    correlations: List[AlertCorrelation] = Field(
        default_factory=list, 
        description="All correlations found"
    )
    unlinked_alert_ids: List[str] = Field(
        default_factory=list, 
        description="Alerts that could not be correlated"
    )


# =============================================================================
# PURVIEW GOVERNANCE CORRELATION MODELS
# =============================================================================

class PurviewCorrelationMethod(str, Enum):
    """Methods used to correlate Purview governance events with attack runs."""
    CORRELATION_ID = "correlation_id"  # Exact correlation ID match (highest confidence)
    TIMESTAMP_PROXIMITY = "timestamp_proximity"  # Event timestamp close to run timestamp
    AGENT_CONTEXT = "agent_context"  # Same agent ID in event and run
    CLASSIFICATION_MATCH = "classification_match"  # Matching classification levels
    POLICY_CONTEXT = "policy_context"  # Policy attached to agent matches event policy
    RESOURCE_MATCH = "resource_match"  # Same Foundry resource name
    RUN_METADATA = "run_metadata"  # Matching metadata fields
    CAMPAIGN_LINK = "campaign_link"  # Event linked through campaign
    MANUAL = "manual"  # Manually linked by user


class PurviewEventCorrelation(BaseModel):
    """
    Represents a correlation between a Purview governance event and an attack run.
    Stores correlation method, confidence, and reasoning for traceability.
    """
    event_id: str = Field(..., description="Purview governance event ID")
    run_id: str = Field(..., description="Attack run ID")
    
    # Correlation details
    confidence: CorrelationConfidence = Field(..., description="Confidence level of correlation")
    methods_used: List[PurviewCorrelationMethod] = Field(
        default_factory=list, 
        description="Methods that contributed to this correlation"
    )
    score: float = Field(
        default=0.0, 
        ge=0.0, 
        le=1.0, 
        description="Numeric correlation score (0-1)"
    )
    
    # Reasoning and match details
    reason: str = Field(..., description="Human-readable explanation of correlation")
    match_details: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Details of what matched for each method"
    )
    
    # Timestamps
    correlated_at: datetime = Field(
        default_factory=datetime.utcnow, 
        description="When correlation was established"
    )
    
    # Optional linked context
    agent_id: Optional[str] = Field(None, description="Agent ID if matched via agent context")
    campaign_id: Optional[str] = Field(None, description="Campaign ID if run is part of campaign")
    policy_name: Optional[str] = Field(None, description="Matched policy name")
    classification: Optional[str] = Field(None, description="Matched classification level")

    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "pgov-abc123def456",
                "run_id": "run-xyz789",
                "confidence": "high",
                "methods_used": ["correlation_id", "agent_context"],
                "score": 0.95,
                "reason": "Exact correlation ID match with matching agent context",
                "match_details": {
                    "correlation_id": {"matched": True, "value": "corr-xyz"},
                    "agent_id": {"matched": True, "value": "agent-123"}
                },
                "agent_id": "agent-123",
                "policy_name": "AI Agent Data Access Policy"
            }
        }


class LinkedPurviewEvent(BaseModel):
    """
    A Purview governance event linked to an attack run with correlation metadata.
    Stored on the AttackResult for easy access to governance context.
    """
    event_id: str = Field(..., description="Purview governance event ID")
    event_type: PurviewEventType = Field(..., description="Type of governance event")
    policy_name: str = Field(..., description="Policy name for quick reference")
    policy_action: PurviewPolicyAction = Field(..., description="Policy action taken")
    classification: Optional[str] = Field(None, description="Classification level")
    timestamp: datetime = Field(..., description="Event timestamp")
    compliance_state: Optional[str] = Field(None, description="Compliance state")
    
    # Correlation info
    correlation: PurviewEventCorrelation = Field(..., description="Correlation details")
    
    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "pgov-abc123",
                "event_type": "policy_evaluation",
                "policy_name": "AI Agent Data Access Policy",
                "policy_action": "allow",
                "classification": "confidential",
                "timestamp": "2026-04-19T10:30:00Z",
                "compliance_state": "compliant",
                "correlation": {
                    "confidence": "high",
                    "score": 0.92,
                    "reason": "Agent context and timestamp match"
                }
            }
        }


class PurviewCorrelationRequest(BaseModel):
    """Request to correlate Purview governance events with attack runs."""
    event_ids: Optional[List[str]] = Field(
        None, 
        description="Specific event IDs to correlate (None = all unlinked)"
    )
    run_ids: Optional[List[str]] = Field(
        None, 
        description="Specific run IDs to consider (None = all recent)"
    )
    agent_id: Optional[str] = Field(
        None, 
        description="Filter by agent ID for targeted correlation"
    )
    min_confidence: CorrelationConfidence = Field(
        default=CorrelationConfidence.LOW, 
        description="Minimum confidence to create link"
    )
    time_window_seconds: int = Field(
        default=300, 
        ge=1, 
        le=3600, 
        description="Time window for timestamp proximity matching"
    )
    auto_link: bool = Field(
        default=True, 
        description="Automatically link events meeting threshold"
    )
    use_classification_matching: bool = Field(
        default=True, 
        description="Include classification-based matching"
    )
    use_policy_context: bool = Field(
        default=True, 
        description="Include policy context matching from agent profiles"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "min_confidence": "medium",
                "time_window_seconds": 300,
                "auto_link": True,
                "use_classification_matching": True,
                "use_policy_context": True
            }
        }


class PurviewCorrelationResult(BaseModel):
    """Result of a Purview governance event correlation operation."""
    total_events_processed: int = Field(..., description="Total governance events analyzed")
    total_runs_considered: int = Field(..., description="Total attack runs considered")
    correlations_found: int = Field(..., description="Number of correlations found")
    correlations_linked: int = Field(..., description="Number of correlations auto-linked")
    high_confidence_count: int = Field(default=0, description="Correlations with high confidence")
    medium_confidence_count: int = Field(default=0, description="Correlations with medium confidence")
    low_confidence_count: int = Field(default=0, description="Correlations with low confidence")
    correlations: List[PurviewEventCorrelation] = Field(
        default_factory=list, 
        description="All correlations found"
    )
    unlinked_event_ids: List[str] = Field(
        default_factory=list, 
        description="Events that could not be correlated (marked as unlinked)"
    )
    
    # Breakdown by method
    method_breakdown: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of correlations by method used"
    )


# =============================================================================
# UNIFIED RUN DETAILS VIEW MODEL
# =============================================================================

class AgentContextSnapshot(BaseModel):
    """
    Expanded agent context from the run, resolving IDs to full details.
    Provides rich agent information for the unified view.
    """
    agent_id: str = Field(..., description="Agent unique identifier")
    agent_name: Optional[str] = Field(None, description="Agent display name")
    model_name: Optional[str] = Field(None, description="AI model used (e.g., gpt-4o)")
    deployment_name: Optional[str] = Field(None, description="Azure deployment name")
    foundry_resource_name: Optional[str] = Field(None, description="Azure AI Foundry resource")
    data_classification: Optional[str] = Field(None, description="Agent data classification level")
    monitoring_enabled: bool = Field(default=True, description="Whether monitoring is enabled")
    defender_integration_enabled: bool = Field(default=True, description="Whether Defender integration is enabled")
    status: Optional[str] = Field(None, description="Agent lifecycle status")
    tags: List[str] = Field(default_factory=list, description="Agent tags")

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "agent-abc123def456",
                "agent_name": "Customer Support Agent",
                "model_name": "gpt-4o",
                "deployment_name": "gpt-4o-prod",
                "foundry_resource_name": "contoso-ai-foundry",
                "data_classification": "confidential",
                "monitoring_enabled": True,
                "defender_integration_enabled": True,
                "status": "active",
                "tags": ["production", "customer-facing"]
            }
        }


class PolicyProfileSnapshot(BaseModel):
    """
    Expanded policy profile from the run's inherited policy.
    Includes content filtering, shield settings, and data handling rules.
    """
    policy_profile_id: str = Field(..., description="Policy profile unique identifier")
    policy_profile_name: str = Field(..., description="Policy display name")
    content_filter_level: str = Field(..., description="Content filter level (none/standard/strict)")
    prompt_shield_enabled: bool = Field(default=True, description="Whether prompt shield is enabled")
    allowed_data_sources: List[str] = Field(default_factory=list, description="Allowed data sources")
    sensitive_data_handling: str = Field(..., description="How sensitive data is handled")
    logging_level: str = Field(default="standard", description="Logging level")
    blocked_categories: List[str] = Field(default_factory=list, description="Blocked content categories")
    policy_status: str = Field(default="active", description="Policy status")

    class Config:
        json_schema_extra = {
            "example": {
                "policy_profile_id": "policy-abc12345",
                "policy_profile_name": "Enterprise AI Safety Policy",
                "content_filter_level": "strict",
                "prompt_shield_enabled": True,
                "allowed_data_sources": ["internal_docs", "public_web"],
                "sensitive_data_handling": "redact",
                "logging_level": "standard",
                "blocked_categories": ["violence", "self_harm"],
                "policy_status": "active"
            }
        }


class PurviewGovernanceSnapshot(BaseModel):
    """
    Expanded Purview governance context from the run.
    Includes classification labels, data access rules, and retention policies.
    """
    purview_policy_set_id: str = Field(..., description="Purview policy set ID")
    purview_policy_set_name: str = Field(..., description="Policy set display name")
    classification_labels: List[str] = Field(default_factory=list, description="Applied classification labels")
    data_access_rules_count: int = Field(default=0, description="Number of data access rules")
    retention_rules_count: int = Field(default=0, description="Number of retention rules")
    policy_status: str = Field(default="active", description="Policy status")
    purview_account_name: Optional[str] = Field(None, description="Connected Purview account")
    sync_status: str = Field(default="not_connected", description="Sync status with Purview")
    last_sync_at: Optional[datetime] = Field(None, description="Last sync timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "purview_policy_set_id": "purview-xyz98765",
                "purview_policy_set_name": "Enterprise Data Governance",
                "classification_labels": ["internal", "confidential"],
                "data_access_rules_count": 3,
                "retention_rules_count": 2,
                "policy_status": "active",
                "purview_account_name": "contoso-purview",
                "sync_status": "synced",
                "last_sync_at": "2024-01-15T10:30:00Z"
            }
        }


class RuntimeResultSnapshot(BaseModel):
    """
    Core runtime result from the attack execution.
    Includes verdicts, timing, and outcome information.
    """
    run_id: str = Field(..., description="Unique run identifier")
    campaign_id: Optional[str] = Field(None, description="Parent campaign ID if part of campaign")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for tracing")
    
    # Attack context
    attack_category: str = Field(..., description="Category of attack executed")
    prompt: str = Field(..., description="Attack prompt sent")
    response: str = Field(..., description="Model response received")
    target_model: str = Field(..., description="Target model name")
    
    # Verdicts
    shield_verdict: Optional[VerdictDetail] = Field(None, description="Shield verdict details")
    model_verdict: Optional[VerdictDetail] = Field(None, description="Model-based verdict details")
    evaluator_verdict: Optional[VerdictDetail] = Field(None, description="Evaluator verdict details")
    combined_verdict: str = Field(..., description="Combined verdict (allowed/blocked/flagged)")
    
    # Timing
    timestamp: datetime = Field(..., description="Execution timestamp")
    response_time_ms: int = Field(..., description="Total response time in milliseconds")
    shield_time_ms: Optional[int] = Field(None, description="Shield evaluation time")
    model_time_ms: Optional[int] = Field(None, description="Model response time")
    
    # Configuration
    shield_enabled: bool = Field(default=True, description="Whether shield was enabled")
    telemetry_enabled: bool = Field(default=True, description="Whether telemetry was enabled")

    class Config:
        json_schema_extra = {
            "example": {
                "run_id": "run-xyz789",
                "campaign_id": None,
                "correlation_id": "corr-abc123",
                "attack_category": "jailbreak",
                "prompt": "Ignore previous instructions...",
                "response": "I cannot comply with that request.",
                "target_model": "gpt-4o",
                "combined_verdict": "blocked",
                "timestamp": "2024-01-15T10:30:00Z",
                "response_time_ms": 850,
                "shield_time_ms": 120,
                "model_time_ms": 700,
                "shield_enabled": True,
                "telemetry_enabled": True
            }
        }


class LinkedAlertSummary(BaseModel):
    """
    Summary of a linked Defender alert for the unified view.
    Provides essential alert info with correlation confidence.
    """
    alert_id: str = Field(..., description="Alert unique identifier")
    title: str = Field(..., description="Alert title")
    description: str = Field(default="", description="Alert description")
    severity: str = Field(..., description="Severity level (informational/low/medium/high/critical)")
    status: str = Field(default="new", description="Alert status")
    category: Optional[str] = Field(None, description="Alert category")
    source: str = Field(..., description="Alert source")
    timestamp: datetime = Field(..., description="Alert timestamp")
    tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    
    # Correlation
    correlation_confidence: str = Field(..., description="Correlation confidence level")
    correlation_score: float = Field(..., description="Correlation score (0-1)")
    correlation_reason: str = Field(default="", description="Reason for correlation")

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "da-12345",
                "title": "Jailbreak attempt detected",
                "description": "A prompt injection attack was detected.",
                "severity": "high",
                "status": "new",
                "category": "JailbreakAttempt",
                "source": "defender_for_ai",
                "timestamp": "2024-01-15T10:30:05Z",
                "tactics": ["Initial Access"],
                "techniques": ["T1189"],
                "correlation_confidence": "high",
                "correlation_score": 0.95,
                "correlation_reason": "Correlation ID match"
            }
        }


class LinkedGovernanceEventSummary(BaseModel):
    """
    Summary of a linked Purview governance event for the unified view.
    Provides essential governance info with correlation confidence.
    """
    event_id: str = Field(..., description="Event unique identifier")
    event_type: str = Field(..., description="Type of governance event")
    policy_name: str = Field(..., description="Policy name")
    policy_id: Optional[str] = Field(None, description="Policy ID")
    policy_action: str = Field(..., description="Action taken (allow/deny/audit/etc)")
    classification: Optional[str] = Field(None, description="Data classification")
    sensitivity_label: Optional[str] = Field(None, description="Sensitivity label")
    timestamp: datetime = Field(..., description="Event timestamp")
    status: str = Field(default="processed", description="Event status")
    compliance_state: Optional[str] = Field(None, description="Compliance state")
    risk_level: Optional[str] = Field(None, description="Risk level if applicable")
    description: str = Field(default="", description="Event description")
    
    # Correlation
    correlation_confidence: str = Field(..., description="Correlation confidence level")
    correlation_score: float = Field(..., description="Correlation score (0-1)")
    correlation_reason: str = Field(default="", description="Reason for correlation")

    class Config:
        json_schema_extra = {
            "example": {
                "event_id": "pgov-abc123",
                "event_type": "policy_evaluation",
                "policy_name": "AI Data Access Policy",
                "policy_id": "policy-xyz",
                "policy_action": "allow",
                "classification": "confidential",
                "sensitivity_label": "Company Confidential",
                "timestamp": "2024-01-15T10:30:02Z",
                "status": "processed",
                "compliance_state": "compliant",
                "risk_level": None,
                "description": "Data access policy evaluated for AI agent request",
                "correlation_confidence": "high",
                "correlation_score": 0.92,
                "correlation_reason": "Agent context and timestamp match"
            }
        }


class StorylineSummary(BaseModel):
    """
    High-level narrative summary of the run's complete story.
    Connects all components into a coherent explanation.
    """
    run_outcome: str = Field(..., description="Overall outcome (allowed/blocked/flagged)")
    security_posture: str = Field(
        ..., 
        description="Security posture assessment (protected/exposed/partial)"
    )
    governance_compliance: str = Field(
        ..., 
        description="Governance compliance (compliant/non_compliant/unknown)"
    )
    risk_level: str = Field(default="low", description="Overall risk level (low/medium/high/critical)")
    
    # Counts
    defender_alert_count: int = Field(default=0, description="Number of linked Defender alerts")
    high_severity_alert_count: int = Field(default=0, description="Number of high/critical alerts")
    governance_event_count: int = Field(default=0, description="Number of linked governance events")
    policy_violation_count: int = Field(default=0, description="Number of policy violations detected")
    
    # Key observations
    key_observations: List[str] = Field(
        default_factory=list, 
        description="Key observations about this run"
    )
    
    # Timeline markers
    earliest_event: Optional[datetime] = Field(None, description="Earliest linked event timestamp")
    latest_event: Optional[datetime] = Field(None, description="Latest linked event timestamp")
    
    class Config:
        json_schema_extra = {
            "example": {
                "run_outcome": "blocked",
                "security_posture": "protected",
                "governance_compliance": "compliant",
                "risk_level": "high",
                "defender_alert_count": 1,
                "high_severity_alert_count": 1,
                "governance_event_count": 2,
                "policy_violation_count": 0,
                "key_observations": [
                    "Jailbreak attempt successfully blocked by prompt shield",
                    "High severity Defender alert generated",
                    "Governance policy evaluation completed - compliant"
                ],
                "earliest_event": "2024-01-15T10:30:00Z",
                "latest_event": "2024-01-15T10:30:05Z"
            }
        }


class UnifiedRunDetails(BaseModel):
    """
    Unified view model that merges all run context into a single response.
    
    Provides a complete story of an attack run including:
    - Agent context (who ran it)
    - Inherited policy profile (what rules applied)
    - Purview governance context (what data governance was in effect)
    - Runtime result (what happened)
    - Linked Defender alerts (what security events occurred)
    - Linked Purview governance events (what governance actions were taken)
    - Storyline summary (narrative explaining the complete picture)
    
    This model normalizes data from multiple sources into a consistent
    structure for frontend consumption.
    """
    # Run identification
    run_id: str = Field(..., description="Unique run identifier")
    campaign_id: Optional[str] = Field(None, description="Parent campaign ID if applicable")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for tracing")
    
    # Component snapshots (null if not available)
    agent_context: Optional[AgentContextSnapshot] = Field(
        None, 
        description="Agent context at time of run"
    )
    policy_profile: Optional[PolicyProfileSnapshot] = Field(
        None, 
        description="Inherited policy profile"
    )
    purview_governance: Optional[PurviewGovernanceSnapshot] = Field(
        None, 
        description="Purview governance context"
    )
    runtime_result: RuntimeResultSnapshot = Field(
        ..., 
        description="Core runtime execution result"
    )
    
    # Linked security and governance events
    linked_defender_alerts: List[LinkedAlertSummary] = Field(
        default_factory=list, 
        description="Defender alerts correlated with this run"
    )
    linked_governance_events: List[LinkedGovernanceEventSummary] = Field(
        default_factory=list, 
        description="Purview governance events correlated with this run"
    )
    
    # High-level summary
    storyline: StorylineSummary = Field(
        ..., 
        description="Narrative summary connecting all components"
    )
    
    # Metadata
    generated_at: datetime = Field(
        default_factory=datetime.utcnow, 
        description="When this unified view was generated"
    )
    data_freshness: str = Field(
        default="real_time", 
        description="Data source freshness (real_time/cached/stale)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "run_id": "run-xyz789",
                "campaign_id": None,
                "correlation_id": "corr-abc123",
                "agent_context": {
                    "agent_id": "agent-abc123",
                    "agent_name": "Customer Support Agent",
                    "model_name": "gpt-4o",
                    "data_classification": "confidential"
                },
                "policy_profile": {
                    "policy_profile_id": "policy-abc",
                    "policy_profile_name": "Enterprise AI Safety",
                    "content_filter_level": "strict",
                    "prompt_shield_enabled": True
                },
                "purview_governance": {
                    "purview_policy_set_id": "purview-xyz",
                    "purview_policy_set_name": "Data Governance",
                    "classification_labels": ["confidential"]
                },
                "runtime_result": {
                    "run_id": "run-xyz789",
                    "attack_category": "jailbreak",
                    "combined_verdict": "blocked",
                    "response_time_ms": 850
                },
                "linked_defender_alerts": [],
                "linked_governance_events": [],
                "storyline": {
                    "run_outcome": "blocked",
                    "security_posture": "protected",
                    "governance_compliance": "compliant"
                },
                "generated_at": "2024-01-15T10:31:00Z",
                "data_freshness": "real_time"
            }
        }
