"""
Secure Agent Lifecycle domain models.

Defines the data structures for demonstrating secure AI agent development:
- AgentProfile: AI agent identity with policy and governance bindings
- PolicyProfile: Content filtering and safety policy configuration
- PurviewGovernanceContext: Data governance and compliance context

These models support the Secure Agent Lifecycle demo narrative showing
how AI agents inherit security policies, comply with data governance,
and operate within organizational controls.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid


# =============================================================================
# ENUMS
# =============================================================================

class DataClassification(str, Enum):
    """
    Data classification levels for sensitivity handling.
    
    Aligned with common enterprise data classification schemes
    and Microsoft Purview sensitivity labels.
    """
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class AgentProfileStatus(str, Enum):
    """Status of an agent profile in the lifecycle."""
    DRAFT = "draft"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


class PolicyStatus(str, Enum):
    """Status of a policy profile or governance context."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING_REVIEW = "pending_review"
    EXPIRED = "expired"


class ContentFilterLevel(str, Enum):
    """Content filter strictness levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CUSTOM = "custom"


class SensitiveDataHandling(str, Enum):
    """How sensitive data should be handled."""
    BLOCK = "block"
    REDACT = "redact"
    AUDIT = "audit"
    ALLOW_WITH_LOGGING = "allow_with_logging"


class LoggingLevel(str, Enum):
    """Logging verbosity for policy enforcement."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    VERBOSE = "verbose"
    DEBUG = "debug"


# =============================================================================
# POLICY PROFILE MODEL
# =============================================================================

class PolicyProfile(BaseModel):
    """
    Security and content policy profile for AI agents.
    
    Defines the runtime protection settings that an agent inherits
    when created in a Foundry-aligned environment. This includes
    content filtering, prompt shielding, and data handling rules.
    """
    policy_profile_id: str = Field(
        default_factory=lambda: f"policy-{uuid.uuid4().hex[:8]}",
        description="Unique identifier for the policy profile"
    )
    policy_profile_name: str = Field(
        ...,
        description="Human-readable policy profile name"
    )
    content_filter_level: ContentFilterLevel = Field(
        default=ContentFilterLevel.MEDIUM,
        description="Content filter strictness level"
    )
    prompt_shield_enabled: bool = Field(
        default=True,
        description="Whether Azure AI Prompt Shield is enabled"
    )
    allowed_data_sources: List[str] = Field(
        default_factory=list,
        description="List of approved data sources the agent can access"
    )
    sensitive_data_handling: SensitiveDataHandling = Field(
        default=SensitiveDataHandling.REDACT,
        description="How sensitive data should be handled"
    )
    logging_level: LoggingLevel = Field(
        default=LoggingLevel.STANDARD,
        description="Logging verbosity for policy enforcement"
    )
    description: Optional[str] = Field(
        None,
        description="Description of the policy profile and its purpose"
    )
    
    # Metadata
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the policy profile was created"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the policy profile was last updated"
    )
    
    # Additional settings
    custom_filter_rules: Dict[str, Any] = Field(
        default_factory=dict,
        description="Custom content filter rules if level is CUSTOM"
    )
    blocked_categories: List[str] = Field(
        default_factory=lambda: ["hate", "violence", "self-harm", "sexual"],
        description="Content categories to block"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "policy_profile_id": "policy-abc12345",
                "policy_profile_name": "Enterprise Standard Policy",
                "content_filter_level": "high",
                "prompt_shield_enabled": True,
                "allowed_data_sources": ["sharepoint", "internal-kb"],
                "sensitive_data_handling": "redact",
                "logging_level": "standard",
                "description": "Standard enterprise policy with high content filtering"
            }
        }


# =============================================================================
# PURVIEW GOVERNANCE CONTEXT MODEL
# =============================================================================

class DataAccessRule(BaseModel):
    """A single data access rule from Purview."""
    rule_id: str = Field(..., description="Unique rule identifier")
    rule_name: str = Field(..., description="Human-readable rule name")
    allowed_classifications: List[DataClassification] = Field(
        default_factory=list,
        description="Data classifications this rule allows access to"
    )
    conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional conditions for the rule"
    )
    action: str = Field(
        default="allow",
        description="Action when rule matches (allow, deny, audit)"
    )


class RetentionRule(BaseModel):
    """Data retention and handling rule from Purview."""
    rule_id: str = Field(..., description="Unique rule identifier")
    rule_name: str = Field(..., description="Human-readable rule name")
    retention_days: Optional[int] = Field(
        None,
        description="Number of days to retain data (None = indefinite)"
    )
    handling_instruction: str = Field(
        default="standard",
        description="Handling instruction (standard, encrypt, delete-after-use)"
    )
    applies_to_classifications: List[DataClassification] = Field(
        default_factory=list,
        description="Classifications this rule applies to"
    )


class PurviewGovernanceContext(BaseModel):
    """
    Microsoft Purview governance context for AI agents.
    
    Represents the data governance policies that apply to an agent,
    including classification labels, data access rules, and retention
    policies. This context is used to enforce organizational data
    governance during agent operations.
    """
    purview_policy_set_id: str = Field(
        default_factory=lambda: f"purview-{uuid.uuid4().hex[:8]}",
        description="Unique identifier for the Purview policy set"
    )
    purview_policy_set_name: str = Field(
        ...,
        description="Human-readable policy set name"
    )
    classification_labels: List[DataClassification] = Field(
        default_factory=list,
        description="Sensitivity labels this policy set recognizes"
    )
    data_access_rules: List[DataAccessRule] = Field(
        default_factory=list,
        description="Data access rules from Purview"
    )
    retention_rules: List[RetentionRule] = Field(
        default_factory=list,
        description="Retention and handling rules from Purview"
    )
    policy_status: PolicyStatus = Field(
        default=PolicyStatus.ACTIVE,
        description="Current status of the policy set"
    )
    description: Optional[str] = Field(
        None,
        description="Description of the governance context"
    )
    
    # Metadata
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the governance context was created"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the governance context was last updated"
    )
    
    # Purview integration metadata
    purview_account_name: Optional[str] = Field(
        None,
        description="Associated Purview account name if connected"
    )
    last_sync_at: Optional[datetime] = Field(
        None,
        description="Last time policies were synced from Purview"
    )
    sync_status: str = Field(
        default="not_connected",
        description="Sync status (not_connected, syncing, synced, error)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "purview_policy_set_id": "purview-xyz98765",
                "purview_policy_set_name": "Enterprise Data Governance",
                "classification_labels": ["internal", "confidential"],
                "data_access_rules": [],
                "retention_rules": [],
                "policy_status": "active",
                "description": "Standard enterprise data governance policies"
            }
        }


# =============================================================================
# AGENT PROFILE MODEL
# =============================================================================

class AgentProfile(BaseModel):
    """
    Secure AI agent profile for the lifecycle demo.
    
    Represents an AI agent created within a Foundry-aligned environment
    that inherits security policies and governance controls. This is
    distinct from the lightweight demo agents - this models the
    AI agent being developed and secured.
    """
    
    agent_id: str = Field(
        default_factory=lambda: f"agent-{uuid.uuid4().hex[:12]}",
        description="Unique identifier for the agent"
    )
    agent_name: str = Field(
        ...,
        description="Human-readable agent name"
    )
    description: Optional[str] = Field(
        None,
        description="Description of the agent's purpose"
    )
    
    # Model and deployment context
    model_name: str = Field(
        ...,
        description="Name of the AI model (e.g., gpt-4o, gpt-4o-mini)"
    )
    deployment_name: str = Field(
        ...,
        description="Azure AI deployment name"
    )
    foundry_resource_name: str = Field(
        ...,
        description="Azure AI Foundry resource name"
    )
    
    # Policy and governance bindings
    policy_profile_id: Optional[str] = Field(
        None,
        description="ID of the associated policy profile"
    )
    purview_policy_set_id: Optional[str] = Field(
        None,
        description="ID of the associated Purview governance context"
    )
    
    # Data classification
    data_classification: DataClassification = Field(
        default=DataClassification.INTERNAL,
        description="Data classification level for the agent"
    )
    
    # Operational settings
    monitoring_enabled: bool = Field(
        default=True,
        description="Whether monitoring/telemetry is enabled"
    )
    defender_integration_enabled: bool = Field(
        default=True,
        description="Whether Microsoft Defender integration is enabled"
    )
    
    # Status and timestamps
    status: AgentProfileStatus = Field(
        default=AgentProfileStatus.DRAFT,
        description="Current lifecycle status"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the agent profile was created"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the agent profile was last updated"
    )
    
    # Additional metadata
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )
    
    # Resolved policy references (populated at runtime)
    resolved_policy: Optional[PolicyProfile] = Field(
        None,
        description="Resolved policy profile (populated when loaded)"
    )
    resolved_purview_context: Optional[PurviewGovernanceContext] = Field(
        None,
        description="Resolved Purview context (populated when loaded)"
    )
    
    model_config = {
        "protected_namespaces": (),
        "json_schema_extra": {
            "example": {
                "agent_id": "agent-abc123def456",
                "agent_name": "Customer Support Agent",
                "description": "AI agent for handling customer inquiries",
                "model_name": "gpt-4o",
                "deployment_name": "gpt-4o",
                "foundry_resource_name": "mkhalib-4370-resource",
                "policy_profile_id": "policy-abc12345",
                "purview_policy_set_id": "purview-xyz98765",
                "data_classification": "confidential",
                "monitoring_enabled": True,
                "defender_integration_enabled": True,
                "status": "active"
            }
        }
    }


# =============================================================================
# API REQUEST/RESPONSE MODELS
# =============================================================================

class CreateAgentProfileRequest(BaseModel):
    """
    Request to create a new agent profile.
    
    This simulates provisioning a Foundry-backed AI agent that inherits
    runtime policy and governance context at creation time.
    """
    
    model_config = {"protected_namespaces": ()}
    
    # Required fields
    agent_name: str = Field(..., description="Human-readable agent name")
    model_name: str = Field(..., description="AI model name (e.g., gpt-4o)")
    deployment_name: str = Field(..., description="Azure AI deployment name")
    policy_profile_id: str = Field(..., description="Policy profile to inherit (required)")
    data_classification: DataClassification = Field(..., description="Data classification level (required)")
    
    # Optional fields
    description: Optional[str] = Field(None, description="Agent description and purpose")
    foundry_resource_name: Optional[str] = Field(
        None, 
        description="Foundry resource name (auto-filled from app config if not provided)"
    )
    purview_policy_set_id: Optional[str] = Field(
        None, 
        description="Purview governance context to apply (optional)"
    )
    monitoring_enabled: bool = Field(
        default=True, 
        description="Enable monitoring and telemetry collection"
    )
    defender_integration_enabled: bool = Field(
        default=True, 
        description="Enable Microsoft Defender integration"
    )
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")


class CreatePolicyProfileRequest(BaseModel):
    """Request to create a new policy profile."""
    policy_profile_name: str = Field(..., description="Policy profile name")
    content_filter_level: ContentFilterLevel = Field(default=ContentFilterLevel.MEDIUM)
    prompt_shield_enabled: bool = Field(default=True)
    allowed_data_sources: List[str] = Field(default_factory=list)
    sensitive_data_handling: SensitiveDataHandling = Field(default=SensitiveDataHandling.REDACT)
    logging_level: LoggingLevel = Field(default=LoggingLevel.STANDARD)
    description: Optional[str] = Field(None)


class CreatePurviewContextRequest(BaseModel):
    """Request to create a new Purview governance context."""
    purview_policy_set_name: str = Field(..., description="Policy set name")
    classification_labels: List[DataClassification] = Field(default_factory=list)
    description: Optional[str] = Field(None)
    purview_account_name: Optional[str] = Field(None)


class AgentProfileListResponse(BaseModel):
    """Response containing a list of agent profiles."""
    agents: List[AgentProfile] = Field(default_factory=list)
    total: int = Field(default=0)
    limit: int = Field(default=50)
    offset: int = Field(default=0)


class PolicyProfileListResponse(BaseModel):
    """Response containing a list of policy profiles."""
    policies: List[PolicyProfile] = Field(default_factory=list)
    total: int = Field(default=0)


class PurviewContextListResponse(BaseModel):
    """Response containing a list of Purview governance contexts."""
    contexts: List[PurviewGovernanceContext] = Field(default_factory=list)
    total: int = Field(default=0)
