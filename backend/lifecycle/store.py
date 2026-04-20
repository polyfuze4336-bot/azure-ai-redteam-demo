"""
Secure Agent Lifecycle storage.

Provides in-memory storage for agent profiles, policy profiles,
and Purview governance contexts. Suitable for demo purposes.
"""

from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict
import threading

from .models import (
    AgentProfile,
    AgentProfileStatus,
    PolicyProfile,
    PurviewGovernanceContext,
    PolicyStatus,
    DataClassification,
    ContentFilterLevel,
    SensitiveDataHandling,
    LoggingLevel,
    DataAccessRule,
    RetentionRule,
)


class LifecycleStore:
    """
    In-memory store for Secure Agent Lifecycle data.
    
    Provides thread-safe storage for agent profiles, policy profiles,
    and Purview governance contexts used in the lifecycle demo.
    """
    
    _instance: Optional["LifecycleStore"] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern for shared state."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        
        # Storage dictionaries
        self._agent_profiles: Dict[str, AgentProfile] = {}
        self._policy_profiles: Dict[str, PolicyProfile] = {}
        self._purview_contexts: Dict[str, PurviewGovernanceContext] = {}
        
        # Index for quick lookups
        self._agents_by_policy: Dict[str, List[str]] = defaultdict(list)
        self._agents_by_purview: Dict[str, List[str]] = defaultdict(list)
        self._agents_by_status: Dict[AgentProfileStatus, List[str]] = defaultdict(list)
        
        # Thread locks
        self._agents_lock = threading.Lock()
        self._policies_lock = threading.Lock()
        self._purview_lock = threading.Lock()
        
        # Initialize with default data
        self._initialize_defaults()
        
        self._initialized = True
    
    def _initialize_defaults(self) -> None:
        """Initialize with seeded policy profiles and Purview contexts for demo."""
        
        # =================================================================
        # SEEDED POLICY PROFILES
        # =================================================================
        # These profiles demonstrate the spectrum from open/permissive to
        # strict/regulated, suitable for live demo storytelling.
        
        default_policies = [
            # -------------------------------------------------------------
            # 1. Open Demo Policy
            # Use case: Prototyping, hackathons, early exploration
            # Demo note: Show what happens with minimal guardrails
            # -------------------------------------------------------------
            PolicyProfile(
                policy_profile_id="policy-open-demo",
                policy_profile_name="Open Demo Policy",
                content_filter_level=ContentFilterLevel.LOW,
                prompt_shield_enabled=False,
                allowed_data_sources=["any", "public-web", "demo-data"],
                sensitive_data_handling=SensitiveDataHandling.ALLOW_WITH_LOGGING,
                logging_level=LoggingLevel.MINIMAL,
                description=(
                    "Permissive policy for demos and prototyping. "
                    "Content filtering is minimal, prompt shielding is off, "
                    "and sensitive data is allowed with logging. "
                    "Use this to show what happens without enterprise guardrails."
                ),
                blocked_categories=[],  # Nothing blocked
                custom_filter_rules={
                    "demo_mode": True,
                    "behavior_notes": "Demonstrates unprotected agent behavior for comparison"
                }
            ),
            
            # -------------------------------------------------------------
            # 2. Standard Enterprise Policy
            # Use case: General business applications, internal tools
            # Demo note: The baseline most organizations start with
            # -------------------------------------------------------------
            PolicyProfile(
                policy_profile_id="policy-standard-enterprise",
                policy_profile_name="Standard Enterprise Policy",
                content_filter_level=ContentFilterLevel.MEDIUM,
                prompt_shield_enabled=True,
                allowed_data_sources=["sharepoint", "internal-kb", "approved-apis", "crm"],
                sensitive_data_handling=SensitiveDataHandling.REDACT,
                logging_level=LoggingLevel.STANDARD,
                description=(
                    "Balanced enterprise policy for general business use. "
                    "Content filtering catches harmful content, prompt shielding "
                    "blocks injection attacks, and sensitive data is automatically redacted. "
                    "This is the recommended baseline for most internal AI agents."
                ),
                blocked_categories=["hate", "violence", "self-harm", "sexual"],
                custom_filter_rules={
                    "demo_mode": False,
                    "behavior_notes": "Demonstrates balanced protection suitable for most business scenarios"
                }
            ),
            
            # -------------------------------------------------------------
            # 3. Strict Regulated Policy
            # Use case: Financial services, healthcare, legal
            # Demo note: Show maximum protection for regulated industries
            # -------------------------------------------------------------
            PolicyProfile(
                policy_profile_id="policy-strict-regulated",
                policy_profile_name="Strict Regulated Policy",
                content_filter_level=ContentFilterLevel.HIGH,
                prompt_shield_enabled=True,
                allowed_data_sources=["approved-internal-only", "compliance-vetted"],
                sensitive_data_handling=SensitiveDataHandling.BLOCK,
                logging_level=LoggingLevel.VERBOSE,
                description=(
                    "Maximum protection policy for regulated industries. "
                    "High content filtering blocks edge cases, prompt shielding "
                    "is enabled, and any sensitive data access is blocked entirely. "
                    "All interactions are logged verbosely for compliance audit trails."
                ),
                blocked_categories=["hate", "violence", "self-harm", "sexual", "profanity", "controversial"],
                custom_filter_rules={
                    "demo_mode": False,
                    "strict_mode": True,
                    "behavior_notes": "Demonstrates maximum protection for compliance-sensitive environments"
                }
            ),
        ]
        
        for policy in default_policies:
            self._policy_profiles[policy.policy_profile_id] = policy
        
        # =================================================================
        # SEEDED PURVIEW GOVERNANCE CONTEXTS
        # =================================================================
        # These governance contexts represent different data sensitivity
        # tiers and compliance requirements, aligned with Microsoft Purview.
        
        default_purview_contexts = [
            # -------------------------------------------------------------
            # 1. Internal Collaboration Governance
            # For: Public and internal data, general collaboration
            # Demo note: Minimal restrictions, broad access
            # -------------------------------------------------------------
            PurviewGovernanceContext(
                purview_policy_set_id="purview-internal-collab",
                purview_policy_set_name="Internal Collaboration Governance",
                classification_labels=[
                    DataClassification.PUBLIC,
                    DataClassification.INTERNAL,
                ],
                data_access_rules=[
                    DataAccessRule(
                        rule_id="dar-collab-001",
                        rule_name="Public Data - Open Access",
                        allowed_classifications=[DataClassification.PUBLIC],
                        conditions={},
                        action="allow"
                    ),
                    DataAccessRule(
                        rule_id="dar-collab-002",
                        rule_name="Internal Data - Authenticated Access",
                        allowed_classifications=[DataClassification.INTERNAL],
                        conditions={"requires_authentication": True},
                        action="allow"
                    ),
                ],
                retention_rules=[
                    RetentionRule(
                        rule_id="ret-collab-001",
                        rule_name="Standard Business Retention",
                        retention_days=365,
                        handling_instruction="standard",
                        applies_to_classifications=[DataClassification.PUBLIC, DataClassification.INTERNAL]
                    ),
                ],
                policy_status=PolicyStatus.ACTIVE,
                description=(
                    "Governance for general internal collaboration scenarios. "
                    "Agents can access public and internal data with standard authentication. "
                    "Use this for productivity tools, internal chatbots, and team assistants."
                ),
                sync_status="simulated"
            ),
            
            # -------------------------------------------------------------
            # 2. Confidential Business Data Governance
            # For: Customer data, business strategies, internal reports
            # Demo note: Access requires justification, audit trail
            # -------------------------------------------------------------
            PurviewGovernanceContext(
                purview_policy_set_id="purview-confidential-business",
                purview_policy_set_name="Confidential Business Data Governance",
                classification_labels=[
                    DataClassification.INTERNAL,
                    DataClassification.CONFIDENTIAL,
                ],
                data_access_rules=[
                    DataAccessRule(
                        rule_id="dar-conf-001",
                        rule_name="Internal Data - Standard Access",
                        allowed_classifications=[DataClassification.INTERNAL],
                        conditions={},
                        action="allow"
                    ),
                    DataAccessRule(
                        rule_id="dar-conf-002",
                        rule_name="Confidential Data - Audited Access",
                        allowed_classifications=[DataClassification.CONFIDENTIAL],
                        conditions={
                            "requires_justification": True,
                            "audit_all_access": True
                        },
                        action="audit"
                    ),
                ],
                retention_rules=[
                    RetentionRule(
                        rule_id="ret-conf-001",
                        rule_name="Internal Data Retention",
                        retention_days=365,
                        handling_instruction="standard",
                        applies_to_classifications=[DataClassification.INTERNAL]
                    ),
                    RetentionRule(
                        rule_id="ret-conf-002",
                        rule_name="Confidential Data - Encrypt at Rest",
                        retention_days=730,  # 2 years
                        handling_instruction="encrypt",
                        applies_to_classifications=[DataClassification.CONFIDENTIAL]
                    ),
                ],
                policy_status=PolicyStatus.ACTIVE,
                description=(
                    "Governance for business-critical and customer-related data. "
                    "Confidential data access requires justification and is fully audited. "
                    "Use this for CRM agents, business intelligence tools, and customer support systems."
                ),
                sync_status="simulated"
            ),
            
            # -------------------------------------------------------------
            # 3. Restricted Regulated Data Governance
            # For: PII, financial records, healthcare data, legal holds
            # Demo note: Strict controls, many access requests denied
            # -------------------------------------------------------------
            PurviewGovernanceContext(
                purview_policy_set_id="purview-restricted-regulated",
                purview_policy_set_name="Restricted Regulated Data Governance",
                classification_labels=[
                    DataClassification.CONFIDENTIAL,
                    DataClassification.RESTRICTED,
                ],
                data_access_rules=[
                    DataAccessRule(
                        rule_id="dar-reg-001",
                        rule_name="Confidential - Elevated Access Required",
                        allowed_classifications=[DataClassification.CONFIDENTIAL],
                        conditions={
                            "requires_elevated_privileges": True,
                            "audit_all_access": True,
                            "time_limited": True
                        },
                        action="audit"
                    ),
                    DataAccessRule(
                        rule_id="dar-reg-002",
                        rule_name="Restricted - Deny by Default",
                        allowed_classifications=[DataClassification.RESTRICTED],
                        conditions={
                            "requires_explicit_approval": True,
                            "compliance_review": True
                        },
                        action="deny"
                    ),
                ],
                retention_rules=[
                    RetentionRule(
                        rule_id="ret-reg-001",
                        rule_name="Confidential - Compliance Retention",
                        retention_days=2555,  # ~7 years
                        handling_instruction="encrypt",
                        applies_to_classifications=[DataClassification.CONFIDENTIAL]
                    ),
                    RetentionRule(
                        rule_id="ret-reg-002",
                        rule_name="Restricted - Legal Hold Eligible",
                        retention_days=None,  # Indefinite / legal hold
                        handling_instruction="encrypt",
                        applies_to_classifications=[DataClassification.RESTRICTED]
                    ),
                ],
                policy_status=PolicyStatus.ACTIVE,
                description=(
                    "Governance for highly regulated and restricted data. "
                    "Restricted data is denied by default and requires explicit compliance approval. "
                    "Use this for financial services, healthcare, and legal applications with strict audit requirements."
                ),
                sync_status="simulated"
            ),
        ]
        
        for purview in default_purview_contexts:
            self._purview_contexts[purview.purview_policy_set_id] = purview
    
    # =========================================================================
    # AGENT PROFILE OPERATIONS
    # =========================================================================
    
    def save_agent_profile(self, agent: AgentProfile) -> AgentProfile:
        """Save or update an agent profile."""
        with self._agents_lock:
            # Update timestamp
            agent.updated_at = datetime.utcnow()
            
            # Remove from old indices if updating
            if agent.agent_id in self._agent_profiles:
                old_agent = self._agent_profiles[agent.agent_id]
                if old_agent.policy_profile_id:
                    self._agents_by_policy[old_agent.policy_profile_id] = [
                        a for a in self._agents_by_policy[old_agent.policy_profile_id]
                        if a != agent.agent_id
                    ]
                if old_agent.purview_policy_set_id:
                    self._agents_by_purview[old_agent.purview_policy_set_id] = [
                        a for a in self._agents_by_purview[old_agent.purview_policy_set_id]
                        if a != agent.agent_id
                    ]
                self._agents_by_status[old_agent.status] = [
                    a for a in self._agents_by_status[old_agent.status]
                    if a != agent.agent_id
                ]
            
            # Save agent
            self._agent_profiles[agent.agent_id] = agent
            
            # Update indices
            if agent.policy_profile_id:
                self._agents_by_policy[agent.policy_profile_id].append(agent.agent_id)
            if agent.purview_policy_set_id:
                self._agents_by_purview[agent.purview_policy_set_id].append(agent.agent_id)
            self._agents_by_status[agent.status].append(agent.agent_id)
        
        return agent
    
    def get_agent_profile(self, agent_id: str) -> Optional[AgentProfile]:
        """Get an agent profile by ID."""
        with self._agents_lock:
            return self._agent_profiles.get(agent_id)
    
    def get_agent_profile_with_resolved(self, agent_id: str) -> Optional[AgentProfile]:
        """Get an agent profile with resolved policy and Purview references."""
        agent = self.get_agent_profile(agent_id)
        if not agent:
            return None
        
        # Resolve policy profile
        if agent.policy_profile_id:
            agent.resolved_policy = self.get_policy_profile(agent.policy_profile_id)
        
        # Resolve Purview context
        if agent.purview_policy_set_id:
            agent.resolved_purview_context = self.get_purview_context(agent.purview_policy_set_id)
        
        return agent
    
    def list_agent_profiles(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[AgentProfileStatus] = None,
        policy_profile_id: Optional[str] = None,
    ) -> List[AgentProfile]:
        """List agent profiles with optional filtering."""
        with self._agents_lock:
            agents = list(self._agent_profiles.values())
        
        # Apply filters
        if status:
            agents = [a for a in agents if a.status == status]
        if policy_profile_id:
            agents = [a for a in agents if a.policy_profile_id == policy_profile_id]
        
        # Sort by created_at descending
        agents.sort(key=lambda a: a.created_at, reverse=True)
        
        # Apply pagination
        return agents[offset:offset + limit]
    
    def count_agent_profiles(self) -> int:
        """Count total agent profiles."""
        with self._agents_lock:
            return len(self._agent_profiles)
    
    def delete_agent_profile(self, agent_id: str) -> bool:
        """Delete an agent profile."""
        with self._agents_lock:
            if agent_id not in self._agent_profiles:
                return False
            
            agent = self._agent_profiles[agent_id]
            
            # Remove from indices
            if agent.policy_profile_id:
                self._agents_by_policy[agent.policy_profile_id] = [
                    a for a in self._agents_by_policy[agent.policy_profile_id]
                    if a != agent_id
                ]
            if agent.purview_policy_set_id:
                self._agents_by_purview[agent.purview_policy_set_id] = [
                    a for a in self._agents_by_purview[agent.purview_policy_set_id]
                    if a != agent_id
                ]
            self._agents_by_status[agent.status] = [
                a for a in self._agents_by_status[agent.status]
                if a != agent_id
            ]
            
            del self._agent_profiles[agent_id]
            return True
    
    # =========================================================================
    # POLICY PROFILE OPERATIONS
    # =========================================================================
    
    def save_policy_profile(self, policy: PolicyProfile) -> PolicyProfile:
        """Save or update a policy profile."""
        with self._policies_lock:
            policy.updated_at = datetime.utcnow()
            self._policy_profiles[policy.policy_profile_id] = policy
        return policy
    
    def get_policy_profile(self, policy_id: str) -> Optional[PolicyProfile]:
        """Get a policy profile by ID."""
        with self._policies_lock:
            return self._policy_profiles.get(policy_id)
    
    def list_policy_profiles(self) -> List[PolicyProfile]:
        """List all policy profiles."""
        with self._policies_lock:
            policies = list(self._policy_profiles.values())
        policies.sort(key=lambda p: p.policy_profile_name)
        return policies
    
    def count_policy_profiles(self) -> int:
        """Count total policy profiles."""
        with self._policies_lock:
            return len(self._policy_profiles)
    
    def delete_policy_profile(self, policy_id: str) -> bool:
        """Delete a policy profile."""
        with self._policies_lock:
            if policy_id not in self._policy_profiles:
                return False
            del self._policy_profiles[policy_id]
            return True
    
    # =========================================================================
    # PURVIEW GOVERNANCE CONTEXT OPERATIONS
    # =========================================================================
    
    def save_purview_context(self, context: PurviewGovernanceContext) -> PurviewGovernanceContext:
        """Save or update a Purview governance context."""
        with self._purview_lock:
            context.updated_at = datetime.utcnow()
            self._purview_contexts[context.purview_policy_set_id] = context
        return context
    
    def get_purview_context(self, context_id: str) -> Optional[PurviewGovernanceContext]:
        """Get a Purview context by ID."""
        with self._purview_lock:
            return self._purview_contexts.get(context_id)
    
    def list_purview_contexts(self) -> List[PurviewGovernanceContext]:
        """List all Purview governance contexts."""
        with self._purview_lock:
            contexts = list(self._purview_contexts.values())
        contexts.sort(key=lambda c: c.purview_policy_set_name)
        return contexts
    
    def count_purview_contexts(self) -> int:
        """Count total Purview contexts."""
        with self._purview_lock:
            return len(self._purview_contexts)
    
    def delete_purview_context(self, context_id: str) -> bool:
        """Delete a Purview governance context."""
        with self._purview_lock:
            if context_id not in self._purview_contexts:
                return False
            del self._purview_contexts[context_id]
            return True
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_agents_by_policy(self, policy_id: str) -> List[AgentProfile]:
        """Get all agents using a specific policy profile."""
        with self._agents_lock:
            agent_ids = self._agents_by_policy.get(policy_id, [])
            return [self._agent_profiles[aid] for aid in agent_ids if aid in self._agent_profiles]
    
    def get_agents_by_purview_context(self, context_id: str) -> List[AgentProfile]:
        """Get all agents using a specific Purview context."""
        with self._agents_lock:
            agent_ids = self._agents_by_purview.get(context_id, [])
            return [self._agent_profiles[aid] for aid in agent_ids if aid in self._agent_profiles]
    
    def get_summary(self) -> Dict:
        """Get a summary of all lifecycle data."""
        return {
            "agent_profiles": {
                "total": self.count_agent_profiles(),
                "by_status": {
                    status.value: len(self._agents_by_status[status])
                    for status in AgentProfileStatus
                }
            },
            "policy_profiles": {
                "total": self.count_policy_profiles(),
            },
            "purview_contexts": {
                "total": self.count_purview_contexts(),
            }
        }
    
    def clear(self) -> None:
        """Clear all stored data (for testing)."""
        with self._agents_lock:
            self._agent_profiles.clear()
            self._agents_by_policy.clear()
            self._agents_by_purview.clear()
            self._agents_by_status.clear()
        with self._policies_lock:
            self._policy_profiles.clear()
        with self._purview_lock:
            self._purview_contexts.clear()
        
        # Re-initialize defaults
        self._initialize_defaults()


# Singleton accessor
_store_instance: Optional[LifecycleStore] = None


def get_lifecycle_store() -> LifecycleStore:
    """Get the singleton lifecycle store instance."""
    global _store_instance
    if _store_instance is None:
        _store_instance = LifecycleStore()
    return _store_instance
