"""
Secure Agent Lifecycle service layer.

Provides business logic for managing agent profiles, policy profiles,
and Purview governance contexts. Handles validation, lifecycle state
transitions, and policy resolution.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
import logging
import uuid

from .models import (
    AgentProfile,
    AgentProfileStatus,
    PolicyProfile,
    PurviewGovernanceContext,
    PolicyStatus,
    DataClassification,
    CreateAgentProfileRequest,
    CreatePolicyProfileRequest,
    CreatePurviewContextRequest,
    AgentProfileListResponse,
    PolicyProfileListResponse,
    PurviewContextListResponse,
)
from .store import LifecycleStore, get_lifecycle_store


logger = logging.getLogger(__name__)


class LifecycleService:
    """
    Service for Secure Agent Lifecycle operations.
    
    Provides:
    - Agent profile CRUD with lifecycle state management
    - Policy profile management
    - Purview governance context management
    - Policy inheritance and resolution
    """
    
    def __init__(self, store: Optional[LifecycleStore] = None):
        """
        Initialize the lifecycle service.
        
        Args:
            store: Optional store instance (uses singleton if not provided)
        """
        self._store = store or get_lifecycle_store()
    
    # =========================================================================
    # AGENT PROFILE OPERATIONS
    # =========================================================================
    
    def _get_foundry_context(self) -> Dict[str, Any]:
        """Get Foundry context from app configuration."""
        try:
            from config import get_settings
            settings = get_settings()
            return {
                "foundry_resource_name": settings.foundry_resource_name,
                "deployment_name": settings.azure_openai_deployment_name,
                "endpoint": settings.azure_openai_endpoint or settings.foundry_endpoint,
                "run_mode": settings.run_mode.value,
            }
        except Exception:
            return {
                "foundry_resource_name": None,
                "deployment_name": None,
                "endpoint": None,
                "run_mode": "demo",
            }
    
    def create_agent_profile(
        self,
        request: CreateAgentProfileRequest,
        foundry_resource_override: Optional[str] = None,
    ) -> AgentProfile:
        """
        Create a new agent profile simulating Foundry-backed provisioning.
        
        This simulates creating an AI agent in a Foundry-aligned environment
        that inherits runtime policy and governance context at creation time.
        
        Args:
            request: Agent creation request with required fields
            foundry_resource_override: Optional override for foundry resource name
        
        Returns:
            Created agent profile in DRAFT status
        
        Raises:
            ValueError: If policy profile or Purview context not found
        """
        # Validate policy profile reference (required)
        policy = self._store.get_policy_profile(request.policy_profile_id)
        if not policy:
            raise ValueError(f"Policy profile not found: {request.policy_profile_id}")
        
        # Validate Purview context reference if provided
        if request.purview_policy_set_id:
            purview = self._store.get_purview_context(request.purview_policy_set_id)
            if not purview:
                raise ValueError(f"Purview context not found: {request.purview_policy_set_id}")
        
        # Resolve foundry resource name from:
        # 1. Explicit override
        # 2. Request body
        # 3. App configuration
        foundry_context = self._get_foundry_context()
        foundry_resource = (
            foundry_resource_override
            or request.foundry_resource_name
            or foundry_context.get("foundry_resource_name")
            or "demo-foundry-resource"
        )
        
        # Generate provisioning context metadata
        provisioning_context = {
            "provisioned_at": datetime.utcnow().isoformat(),
            "provisioning_correlation_id": str(uuid.uuid4()),
            "inherited_policy": {
                "policy_id": policy.policy_profile_id,
                "policy_name": policy.policy_profile_name,
                "content_filter_level": policy.content_filter_level.value,
                "prompt_shield_enabled": policy.prompt_shield_enabled,
                "sensitive_data_handling": policy.sensitive_data_handling.value,
            },
            "foundry_context": {
                "resource_name": foundry_resource,
                "run_mode": foundry_context.get("run_mode", "demo"),
            },
        }
        
        # Add Purview context to provisioning metadata if present
        if request.purview_policy_set_id:
            purview = self._store.get_purview_context(request.purview_policy_set_id)
            if purview:
                provisioning_context["inherited_governance"] = {
                    "purview_id": purview.purview_policy_set_id,
                    "purview_name": purview.purview_policy_set_name,
                    "classification_labels": [c.value for c in purview.classification_labels],
                    "policy_status": purview.policy_status.value,
                }
        
        # Create agent profile
        agent = AgentProfile(
            agent_name=request.agent_name,
            description=request.description,
            model_name=request.model_name,
            deployment_name=request.deployment_name,
            foundry_resource_name=foundry_resource,
            policy_profile_id=request.policy_profile_id,
            purview_policy_set_id=request.purview_policy_set_id,
            data_classification=request.data_classification,
            monitoring_enabled=request.monitoring_enabled,
            defender_integration_enabled=request.defender_integration_enabled,
            tags=request.tags,
            status=AgentProfileStatus.DRAFT,
            metadata=provisioning_context,
        )
        
        saved = self._store.save_agent_profile(agent)
        
        logger.info(
            f"Created agent profile: {saved.agent_id} ({saved.agent_name})",
            extra={
                "agent_id": saved.agent_id,
                "foundry_resource": foundry_resource,
                "policy_profile_id": saved.policy_profile_id,
                "purview_policy_set_id": saved.purview_policy_set_id,
                "data_classification": saved.data_classification.value,
            }
        )
        
        return saved
    
    def provision_agent(self, agent_id: str) -> AgentProfile:
        """
        Simulate provisioning an agent (draft -> provisioning -> active).
        
        In a real implementation, this would trigger Azure resource provisioning.
        For demo purposes, this immediately transitions through states.
        
        Args:
            agent_id: Agent profile ID to provision
            
        Returns:
            Updated agent profile in ACTIVE status
        """
        agent = self._store.get_agent_profile(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        
        if agent.status != AgentProfileStatus.DRAFT:
            raise ValueError(f"Agent must be in DRAFT status to provision (current: {agent.status.value})")
        
        # Transition to provisioning
        agent.status = AgentProfileStatus.PROVISIONING
        agent.metadata["provisioning_started_at"] = datetime.utcnow().isoformat()
        self._store.save_agent_profile(agent)
        
        logger.info(f"Agent {agent_id} provisioning started")
        
        # Simulate provisioning completion (instant for demo)
        agent.status = AgentProfileStatus.ACTIVE
        agent.metadata["provisioning_completed_at"] = datetime.utcnow().isoformat()
        agent.metadata["provisioning_status"] = "completed"
        saved = self._store.save_agent_profile(agent)
        
        logger.info(
            f"Agent {agent_id} provisioned successfully",
            extra={
                "agent_id": agent_id,
                "status": saved.status.value,
                "foundry_resource": saved.foundry_resource_name,
            }
        )
        
        return saved
    
    def get_agent_profile(
        self,
        agent_id: str,
        resolve_references: bool = False
    ) -> Optional[AgentProfile]:
        """
        Get an agent profile by ID.
        
        Args:
            agent_id: Agent profile ID
            resolve_references: Whether to resolve policy/Purview references
        """
        if resolve_references:
            return self._store.get_agent_profile_with_resolved(agent_id)
        return self._store.get_agent_profile(agent_id)
    
    def list_agent_profiles(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[AgentProfileStatus] = None,
        policy_profile_id: Optional[str] = None,
    ) -> AgentProfileListResponse:
        """List agent profiles with optional filtering."""
        agents = self._store.list_agent_profiles(
            limit=limit,
            offset=offset,
            status=status,
            policy_profile_id=policy_profile_id,
        )
        total = self._store.count_agent_profiles()
        
        return AgentProfileListResponse(
            agents=agents,
            total=total,
            limit=limit,
            offset=offset,
        )
    
    def update_agent_profile(
        self,
        agent_id: str,
        updates: Dict[str, Any]
    ) -> Optional[AgentProfile]:
        """
        Update an agent profile.
        
        Validates that status transitions are valid and updates allowed fields.
        """
        agent = self._store.get_agent_profile(agent_id)
        if not agent:
            return None
        
        # Define allowed update fields
        allowed_fields = {
            "agent_name", "description", "policy_profile_id",
            "purview_policy_set_id", "data_classification",
            "monitoring_enabled", "defender_integration_enabled", "tags", "metadata"
        }
        
        for key, value in updates.items():
            if key in allowed_fields:
                setattr(agent, key, value)
        
        return self._store.save_agent_profile(agent)
    
    def transition_agent_status(
        self,
        agent_id: str,
        new_status: AgentProfileStatus
    ) -> Optional[AgentProfile]:
        """
        Transition an agent to a new lifecycle status.
        
        Validates that the transition is allowed based on current status.
        """
        agent = self._store.get_agent_profile(agent_id)
        if not agent:
            return None
        
        # Define valid transitions
        valid_transitions = {
            AgentProfileStatus.DRAFT: [AgentProfileStatus.PROVISIONING, AgentProfileStatus.DECOMMISSIONED],
            AgentProfileStatus.PROVISIONING: [AgentProfileStatus.ACTIVE, AgentProfileStatus.DRAFT],
            AgentProfileStatus.ACTIVE: [AgentProfileStatus.SUSPENDED, AgentProfileStatus.DECOMMISSIONED],
            AgentProfileStatus.SUSPENDED: [AgentProfileStatus.ACTIVE, AgentProfileStatus.DECOMMISSIONED],
            AgentProfileStatus.DECOMMISSIONED: [],  # Terminal state
        }
        
        if new_status not in valid_transitions.get(agent.status, []):
            raise ValueError(
                f"Invalid status transition: {agent.status.value} -> {new_status.value}"
            )
        
        agent.status = new_status
        saved = self._store.save_agent_profile(agent)
        
        logger.info(
            f"Agent {agent_id} transitioned to {new_status.value}",
            extra={"agent_id": agent_id, "new_status": new_status.value}
        )
        
        return saved
    
    def delete_agent_profile(self, agent_id: str) -> bool:
        """Delete an agent profile."""
        return self._store.delete_agent_profile(agent_id)
    
    # =========================================================================
    # POLICY PROFILE OPERATIONS
    # =========================================================================
    
    def create_policy_profile(self, request: CreatePolicyProfileRequest) -> PolicyProfile:
        """Create a new policy profile."""
        policy = PolicyProfile(
            policy_profile_name=request.policy_profile_name,
            content_filter_level=request.content_filter_level,
            prompt_shield_enabled=request.prompt_shield_enabled,
            allowed_data_sources=request.allowed_data_sources,
            sensitive_data_handling=request.sensitive_data_handling,
            logging_level=request.logging_level,
            description=request.description,
        )
        
        saved = self._store.save_policy_profile(policy)
        
        logger.info(
            f"Created policy profile: {saved.policy_profile_id} ({saved.policy_profile_name})"
        )
        
        return saved
    
    def get_policy_profile(self, policy_id: str) -> Optional[PolicyProfile]:
        """Get a policy profile by ID."""
        return self._store.get_policy_profile(policy_id)
    
    def list_policy_profiles(self) -> PolicyProfileListResponse:
        """List all policy profiles."""
        policies = self._store.list_policy_profiles()
        return PolicyProfileListResponse(
            policies=policies,
            total=len(policies),
        )
    
    def update_policy_profile(
        self,
        policy_id: str,
        updates: Dict[str, Any]
    ) -> Optional[PolicyProfile]:
        """Update a policy profile."""
        policy = self._store.get_policy_profile(policy_id)
        if not policy:
            return None
        
        allowed_fields = {
            "policy_profile_name", "content_filter_level", "prompt_shield_enabled",
            "allowed_data_sources", "sensitive_data_handling", "logging_level",
            "description", "custom_filter_rules", "blocked_categories"
        }
        
        for key, value in updates.items():
            if key in allowed_fields:
                setattr(policy, key, value)
        
        return self._store.save_policy_profile(policy)
    
    def delete_policy_profile(self, policy_id: str) -> bool:
        """Delete a policy profile."""
        # Check if any agents are using this policy
        agents = self._store.get_agents_by_policy(policy_id)
        if agents:
            raise ValueError(
                f"Cannot delete policy profile: {len(agents)} agent(s) are using it"
            )
        return self._store.delete_policy_profile(policy_id)
    
    # =========================================================================
    # PURVIEW GOVERNANCE CONTEXT OPERATIONS
    # =========================================================================
    
    def create_purview_context(
        self,
        request: CreatePurviewContextRequest
    ) -> PurviewGovernanceContext:
        """Create a new Purview governance context."""
        context = PurviewGovernanceContext(
            purview_policy_set_name=request.purview_policy_set_name,
            classification_labels=request.classification_labels,
            description=request.description,
            purview_account_name=request.purview_account_name,
            sync_status="simulated" if not request.purview_account_name else "not_connected",
        )
        
        saved = self._store.save_purview_context(context)
        
        logger.info(
            f"Created Purview context: {saved.purview_policy_set_id} ({saved.purview_policy_set_name})"
        )
        
        return saved
    
    def get_purview_context(self, context_id: str) -> Optional[PurviewGovernanceContext]:
        """Get a Purview governance context by ID."""
        return self._store.get_purview_context(context_id)
    
    def list_purview_contexts(self) -> PurviewContextListResponse:
        """List all Purview governance contexts."""
        contexts = self._store.list_purview_contexts()
        return PurviewContextListResponse(
            contexts=contexts,
            total=len(contexts),
        )
    
    def update_purview_context(
        self,
        context_id: str,
        updates: Dict[str, Any]
    ) -> Optional[PurviewGovernanceContext]:
        """Update a Purview governance context."""
        context = self._store.get_purview_context(context_id)
        if not context:
            return None
        
        allowed_fields = {
            "purview_policy_set_name", "classification_labels",
            "data_access_rules", "retention_rules", "policy_status",
            "description", "purview_account_name", "sync_status"
        }
        
        for key, value in updates.items():
            if key in allowed_fields:
                setattr(context, key, value)
        
        return self._store.save_purview_context(context)
    
    def delete_purview_context(self, context_id: str) -> bool:
        """Delete a Purview governance context."""
        # Check if any agents are using this context
        agents = self._store.get_agents_by_purview_context(context_id)
        if agents:
            raise ValueError(
                f"Cannot delete Purview context: {len(agents)} agent(s) are using it"
            )
        return self._store.delete_purview_context(context_id)
    
    # =========================================================================
    # RESOLUTION AND VALIDATION
    # =========================================================================
    
    def resolve_agent_governance(self, agent_id: str) -> Dict[str, Any]:
        """
        Resolve the full governance context for an agent.
        
        Returns a comprehensive view of all policies and governance
        rules that apply to the agent.
        """
        agent = self._store.get_agent_profile_with_resolved(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        
        result = {
            "agent_id": agent.agent_id,
            "agent_name": agent.agent_name,
            "data_classification": agent.data_classification.value,
            "status": agent.status.value,
            "policy": None,
            "purview": None,
            "effective_rules": {
                "content_filtering": "default",
                "prompt_shielding": True,
                "sensitive_data": "redact",
                "allowed_classifications": [DataClassification.PUBLIC.value, DataClassification.INTERNAL.value],
            }
        }
        
        # Resolve policy
        if agent.resolved_policy:
            policy = agent.resolved_policy
            result["policy"] = {
                "id": policy.policy_profile_id,
                "name": policy.policy_profile_name,
                "content_filter_level": policy.content_filter_level.value,
                "prompt_shield_enabled": policy.prompt_shield_enabled,
                "sensitive_data_handling": policy.sensitive_data_handling.value,
            }
            result["effective_rules"]["content_filtering"] = policy.content_filter_level.value
            result["effective_rules"]["prompt_shielding"] = policy.prompt_shield_enabled
            result["effective_rules"]["sensitive_data"] = policy.sensitive_data_handling.value
        
        # Resolve Purview context
        if agent.resolved_purview_context:
            purview = agent.resolved_purview_context
            result["purview"] = {
                "id": purview.purview_policy_set_id,
                "name": purview.purview_policy_set_name,
                "classification_labels": [c.value for c in purview.classification_labels],
                "policy_status": purview.policy_status.value,
                "sync_status": purview.sync_status,
            }
            result["effective_rules"]["allowed_classifications"] = [
                c.value for c in purview.classification_labels
            ]
        
        return result
    
    def validate_agent_for_activation(self, agent_id: str) -> Dict[str, Any]:
        """
        Validate that an agent is ready for activation.
        
        Checks policy bindings, Purview context, and configuration completeness.
        """
        agent = self._store.get_agent_profile(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        
        issues = []
        warnings = []
        
        # Check status
        if agent.status not in [AgentProfileStatus.DRAFT, AgentProfileStatus.PROVISIONING]:
            issues.append(f"Agent is in {agent.status.value} state, cannot activate")
        
        # Check policy binding
        if not agent.policy_profile_id:
            warnings.append("No policy profile bound - default policies will apply")
        else:
            policy = self._store.get_policy_profile(agent.policy_profile_id)
            if not policy:
                issues.append(f"Policy profile {agent.policy_profile_id} not found")
        
        # Check Purview binding
        if not agent.purview_policy_set_id:
            warnings.append("No Purview governance context bound - default governance will apply")
        else:
            purview = self._store.get_purview_context(agent.purview_policy_set_id)
            if not purview:
                issues.append(f"Purview context {agent.purview_policy_set_id} not found")
            elif purview.policy_status != PolicyStatus.ACTIVE:
                warnings.append(f"Purview policy set is {purview.policy_status.value}")
        
        # Check monitoring
        if not agent.monitoring_enabled:
            warnings.append("Monitoring is disabled - telemetry will not be collected")
        
        # Check Defender integration
        if not agent.defender_integration_enabled:
            warnings.append("Defender integration is disabled - threat detection will be limited")
        
        return {
            "agent_id": agent_id,
            "is_valid": len(issues) == 0,
            "can_activate": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
        }
    
    # =========================================================================
    # SUMMARY AND STATISTICS
    # =========================================================================
    
    def get_lifecycle_summary(self) -> Dict[str, Any]:
        """Get a summary of all lifecycle data."""
        return self._store.get_summary()


# Singleton accessor
_service_instance: Optional[LifecycleService] = None


def get_lifecycle_service() -> LifecycleService:
    """Get the singleton lifecycle service instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = LifecycleService()
    return _service_instance
