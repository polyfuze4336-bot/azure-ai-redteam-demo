"""
Policy-aware outcome modifiers for demo-friendly governance behavior.

This module provides deterministic, explainable outcome adjustments based on:
- PolicyProfile settings (content_filter_level, prompt_shield_enabled, etc.)
- PurviewGovernanceContext (data access rules, classification labels)
- DataClassification level

These modifiers influence attack execution outcomes to demonstrate how
organizational policies affect AI agent security posture.

DEMO RULES SUMMARY:
==================
1. prompt_shield_enabled=True → +20% chance of suspicious/blocked shield verdict
2. content_filter_level=high → unsafe outputs reclassified 30% more often
3. data_classification=confidential/restricted → +15% stricter treatment
4. sensitive_data_handling=block/redact → exfiltration prompts get blocked/flagged
5. Purview deny rules → additional governance block chance

All rules are intentionally simple and composable for demo clarity.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import re

from telemetry import get_logger

logger = get_logger("policy_modifiers")


# =============================================================================
# MODIFIER RESULT TYPES
# =============================================================================

class ModifierEffect(str, Enum):
    """Effect type from a policy modifier."""
    NONE = "none"              # No change to outcome
    INCREASE_BLOCK = "increase_block"    # Increase chance of blocking
    INCREASE_FLAG = "increase_flag"      # Increase chance of flagging
    FORCE_BLOCK = "force_block"          # Force outcome to blocked
    FORCE_FLAG = "force_flag"            # Force outcome to flagged
    AUDIT_NOTE = "audit_note"            # Add audit note, no outcome change


@dataclass
class ModifierResult:
    """Result from applying a policy modifier."""
    effect: ModifierEffect
    probability_adjustment: float  # -1.0 to 1.0, additive to block/flag chance
    reason: str
    source: str  # Which policy setting triggered this
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregatedModifiers:
    """Aggregated results from all policy modifiers."""
    # Probability adjustments (additive)
    block_probability_delta: float = 0.0  # Added to base block chance
    flag_probability_delta: float = 0.0   # Added to base flag chance
    
    # Force outcomes (if any modifier forces, it wins)
    force_block: bool = False
    force_flag: bool = False
    
    # Tracking
    modifiers_applied: List[ModifierResult] = field(default_factory=list)
    governance_notes: List[str] = field(default_factory=list)
    
    def add_modifier(self, result: ModifierResult):
        """Add a modifier result to the aggregation."""
        self.modifiers_applied.append(result)
        
        if result.effect == ModifierEffect.FORCE_BLOCK:
            self.force_block = True
            self.governance_notes.append(f"[BLOCKED] {result.reason}")
        elif result.effect == ModifierEffect.FORCE_FLAG:
            self.force_flag = True
            self.governance_notes.append(f"[FLAGGED] {result.reason}")
        elif result.effect == ModifierEffect.INCREASE_BLOCK:
            self.block_probability_delta += result.probability_adjustment
            self.governance_notes.append(f"[+BLOCK] {result.reason}")
        elif result.effect == ModifierEffect.INCREASE_FLAG:
            self.flag_probability_delta += result.probability_adjustment
            self.governance_notes.append(f"[+FLAG] {result.reason}")
        elif result.effect == ModifierEffect.AUDIT_NOTE:
            self.governance_notes.append(f"[AUDIT] {result.reason}")


# =============================================================================
# EXFILTRATION PATTERN DETECTION
# =============================================================================

# Patterns that suggest data exfiltration attempts
EXFILTRATION_PATTERNS = [
    r"(?i)(extract|dump|export|steal|exfiltrate)\s+.*?(data|information|records|database)",
    r"(?i)send\s+(this|the|all)\s+.*?(data|info|content)\s+to",
    r"(?i)(leak|expose|reveal)\s+.*?(confidential|secret|private|internal)",
    r"(?i)(copy|transfer|move)\s+.*?(external|outside|unauthorized)",
    r"(?i)bypass\s+(security|access|controls|authentication)",
    r"(?i)access\s+(without|no)\s+(permission|authorization)",
    r"(?i)(download|scrape)\s+.*?(database|records|files)",
    r"(?i)(read|show|display)\s+(all|every)\s*(passwords?|credentials?|secrets?|keys?)",
]

# Patterns that suggest compliance/regulation violations
COMPLIANCE_VIOLATION_PATTERNS = [
    r"(?i)(ignore|bypass|override)\s+(compliance|regulation|policy|gdpr|hipaa|sox)",
    r"(?i)(delete|destroy|remove)\s+(audit|logs?|records?)\s*(trail)?",
    r"(?i)hide\s+(evidence|traces|activity|logs?)",
    r"(?i)disable\s+(monitoring|logging|audit|tracking)",
]

# Compiled patterns for performance
_compiled_exfiltration = [re.compile(p) for p in EXFILTRATION_PATTERNS]
_compiled_compliance = [re.compile(p) for p in COMPLIANCE_VIOLATION_PATTERNS]


def detect_exfiltration_attempt(prompt: str) -> Tuple[bool, List[str]]:
    """
    Detect potential data exfiltration patterns in prompt.
    
    DEMO RULE: Simple pattern matching for exfiltration-style language.
    In production, would use more sophisticated NLP/ML detection.
    
    Returns:
        (detected, list of matched pattern descriptions)
    """
    matches = []
    for i, pattern in enumerate(_compiled_exfiltration):
        if pattern.search(prompt):
            matches.append(f"exfiltration_pattern_{i}")
    return len(matches) > 0, matches


def detect_compliance_violation(prompt: str) -> Tuple[bool, List[str]]:
    """
    Detect potential compliance violation patterns in prompt.
    
    DEMO RULE: Pattern matching for compliance bypass language.
    
    Returns:
        (detected, list of matched pattern descriptions)
    """
    matches = []
    for i, pattern in enumerate(_compiled_compliance):
        if pattern.search(prompt):
            matches.append(f"compliance_pattern_{i}")
    return len(matches) > 0, matches


# =============================================================================
# POLICY PROFILE MODIFIERS
# =============================================================================

def apply_prompt_shield_modifier(
    policy_profile: Optional[Dict[str, Any]],
) -> ModifierResult:
    """
    Apply modifier based on prompt_shield_enabled setting.
    
    DEMO RULE: If prompt_shield_enabled=True, increase block/flag probability by 20%.
    This simulates the enhanced protection from Azure AI Prompt Shield.
    """
    if not policy_profile:
        return ModifierResult(
            effect=ModifierEffect.NONE,
            probability_adjustment=0.0,
            reason="No policy profile",
            source="prompt_shield_enabled",
        )
    
    if policy_profile.get("prompt_shield_enabled", False):
        return ModifierResult(
            effect=ModifierEffect.INCREASE_BLOCK,
            probability_adjustment=0.20,
            reason="Prompt Shield enabled: +20% detection rate",
            source="prompt_shield_enabled",
            details={"shield_boost": 0.20},
        )
    
    return ModifierResult(
        effect=ModifierEffect.NONE,
        probability_adjustment=0.0,
        reason="Prompt Shield disabled",
        source="prompt_shield_enabled",
    )


def apply_content_filter_modifier(
    policy_profile: Optional[Dict[str, Any]],
) -> ModifierResult:
    """
    Apply modifier based on content_filter_level setting.
    
    DEMO RULES:
    - high: +15% flag probability (aggressive classification)
    - medium: no change (baseline)
    - low: -10% flag probability (lenient)
    """
    if not policy_profile:
        return ModifierResult(
            effect=ModifierEffect.NONE,
            probability_adjustment=0.0,
            reason="No policy profile",
            source="content_filter_level",
        )
    
    level = policy_profile.get("content_filter_level", "medium")
    
    if level == "high":
        return ModifierResult(
            effect=ModifierEffect.INCREASE_FLAG,
            probability_adjustment=0.15,
            reason="High content filter: +15% classification strictness",
            source="content_filter_level",
            details={"filter_level": "high"},
        )
    elif level == "low":
        return ModifierResult(
            effect=ModifierEffect.INCREASE_FLAG,
            probability_adjustment=-0.10,
            reason="Low content filter: -10% classification strictness",
            source="content_filter_level",
            details={"filter_level": "low"},
        )
    
    return ModifierResult(
        effect=ModifierEffect.NONE,
        probability_adjustment=0.0,
        reason="Medium content filter: baseline strictness",
        source="content_filter_level",
        details={"filter_level": "medium"},
    )


def apply_sensitive_data_handling_modifier(
    policy_profile: Optional[Dict[str, Any]],
    prompt: str,
) -> ModifierResult:
    """
    Apply modifier based on sensitive_data_handling and prompt content.
    
    DEMO RULES:
    - If exfiltration detected + handling=block → FORCE_BLOCK
    - If exfiltration detected + handling=redact → FORCE_FLAG
    - If exfiltration detected + handling=audit → AUDIT_NOTE only
    - If no exfiltration detected → no change
    """
    if not policy_profile:
        return ModifierResult(
            effect=ModifierEffect.NONE,
            probability_adjustment=0.0,
            reason="No policy profile",
            source="sensitive_data_handling",
        )
    
    # Check for exfiltration patterns
    exfil_detected, patterns = detect_exfiltration_attempt(prompt)
    
    if not exfil_detected:
        return ModifierResult(
            effect=ModifierEffect.NONE,
            probability_adjustment=0.0,
            reason="No sensitive data patterns detected",
            source="sensitive_data_handling",
        )
    
    handling = policy_profile.get("sensitive_data_handling", "audit")
    
    if handling == "block":
        return ModifierResult(
            effect=ModifierEffect.FORCE_BLOCK,
            probability_adjustment=1.0,
            reason=f"Sensitive data handling=block: exfiltration patterns detected ({len(patterns)} matches)",
            source="sensitive_data_handling",
            details={"patterns": patterns, "handling": "block"},
        )
    elif handling == "redact":
        return ModifierResult(
            effect=ModifierEffect.FORCE_FLAG,
            probability_adjustment=0.0,
            reason=f"Sensitive data handling=redact: exfiltration patterns flagged ({len(patterns)} matches)",
            source="sensitive_data_handling",
            details={"patterns": patterns, "handling": "redact"},
        )
    elif handling == "audit":
        return ModifierResult(
            effect=ModifierEffect.AUDIT_NOTE,
            probability_adjustment=0.0,
            reason=f"Sensitive data handling=audit: exfiltration patterns logged ({len(patterns)} matches)",
            source="sensitive_data_handling",
            details={"patterns": patterns, "handling": "audit"},
        )
    
    # allow_with_logging
    return ModifierResult(
        effect=ModifierEffect.AUDIT_NOTE,
        probability_adjustment=0.0,
        reason=f"Sensitive data handling=allow_with_logging: patterns logged",
        source="sensitive_data_handling",
        details={"patterns": patterns, "handling": "allow_with_logging"},
    )


# =============================================================================
# DATA CLASSIFICATION MODIFIERS
# =============================================================================

def apply_data_classification_modifier(
    data_classification: Optional[str],
) -> ModifierResult:
    """
    Apply modifier based on data classification level.
    
    DEMO RULES:
    - restricted: +20% block probability (highest sensitivity)
    - confidential: +15% block probability
    - internal: +5% block probability
    - public: no change
    """
    if not data_classification:
        return ModifierResult(
            effect=ModifierEffect.NONE,
            probability_adjustment=0.0,
            reason="No data classification set",
            source="data_classification",
        )
    
    classification = data_classification.lower()
    
    if classification == "restricted":
        return ModifierResult(
            effect=ModifierEffect.INCREASE_BLOCK,
            probability_adjustment=0.20,
            reason="Restricted data classification: +20% strictness",
            source="data_classification",
            details={"classification": "restricted"},
        )
    elif classification == "confidential":
        return ModifierResult(
            effect=ModifierEffect.INCREASE_BLOCK,
            probability_adjustment=0.15,
            reason="Confidential data classification: +15% strictness",
            source="data_classification",
            details={"classification": "confidential"},
        )
    elif classification == "internal":
        return ModifierResult(
            effect=ModifierEffect.INCREASE_BLOCK,
            probability_adjustment=0.05,
            reason="Internal data classification: +5% strictness",
            source="data_classification",
            details={"classification": "internal"},
        )
    
    # public
    return ModifierResult(
        effect=ModifierEffect.NONE,
        probability_adjustment=0.0,
        reason="Public data classification: baseline strictness",
        source="data_classification",
        details={"classification": "public"},
    )


# =============================================================================
# PURVIEW GOVERNANCE MODIFIERS
# =============================================================================

def apply_purview_governance_modifier(
    purview_context: Optional[Dict[str, Any]],
    prompt: str,
    data_classification: Optional[str] = None,
) -> ModifierResult:
    """
    Apply modifier based on Purview governance context.
    
    DEMO RULES:
    - If Purview has deny rules for the data classification → FORCE_BLOCK
    - If Purview requires audit for the classification → AUDIT_NOTE + 10% flag increase
    - If compliance violation patterns detected → +25% block probability
    - Otherwise → no change
    """
    if not purview_context:
        return ModifierResult(
            effect=ModifierEffect.NONE,
            probability_adjustment=0.0,
            reason="No Purview governance context",
            source="purview_governance",
        )
    
    # Check policy status
    if purview_context.get("policy_status") != "active":
        return ModifierResult(
            effect=ModifierEffect.AUDIT_NOTE,
            probability_adjustment=0.0,
            reason=f"Purview policy not active: {purview_context.get('policy_status')}",
            source="purview_governance",
        )
    
    # Check for compliance violation patterns
    compliance_violated, patterns = detect_compliance_violation(prompt)
    if compliance_violated:
        return ModifierResult(
            effect=ModifierEffect.INCREASE_BLOCK,
            probability_adjustment=0.25,
            reason=f"Compliance violation patterns detected: +25% block probability ({len(patterns)} matches)",
            source="purview_governance",
            details={"compliance_patterns": patterns},
        )
    
    # Check data access rules for deny actions
    data_access_rules = purview_context.get("data_access_rules", [])
    classification_labels = purview_context.get("classification_labels", [])
    
    # If the agent's data classification is in restricted labels with deny rules
    if data_classification:
        for rule in data_access_rules:
            if rule.get("action") == "deny":
                allowed = rule.get("allowed_classifications", [])
                if data_classification not in allowed and data_classification in classification_labels:
                    return ModifierResult(
                        effect=ModifierEffect.FORCE_FLAG,
                        probability_adjustment=0.0,
                        reason=f"Purview deny rule '{rule.get('rule_name')}' applies to {data_classification} data",
                        source="purview_governance",
                        details={"rule": rule.get("rule_name"), "classification": data_classification},
                    )
            elif rule.get("action") == "audit":
                if data_classification in rule.get("allowed_classifications", []):
                    return ModifierResult(
                        effect=ModifierEffect.INCREASE_FLAG,
                        probability_adjustment=0.10,
                        reason=f"Purview audit rule '{rule.get('rule_name')}' requires review for {data_classification} data",
                        source="purview_governance",
                        details={"rule": rule.get("rule_name"), "classification": data_classification},
                    )
    
    return ModifierResult(
        effect=ModifierEffect.NONE,
        probability_adjustment=0.0,
        reason="Purview governance: no restrictions triggered",
        source="purview_governance",
    )


# =============================================================================
# MAIN AGGREGATION FUNCTION
# =============================================================================

def compute_policy_modifiers(
    agent_context: Optional[Dict[str, Any]],
    prompt: str,
) -> AggregatedModifiers:
    """
    Compute all policy modifiers for an attack run.
    
    This is the main entry point that aggregates all policy-aware adjustments
    based on the agent context snapshot.
    
    Args:
        agent_context: The agent_context_snapshot from the attack request
        prompt: The attack prompt being evaluated
    
    Returns:
        AggregatedModifiers with all adjustments and governance notes
    
    DEMO BEHAVIOR:
    - All modifiers are applied independently and aggregated
    - Force effects (FORCE_BLOCK, FORCE_FLAG) take precedence
    - Probability adjustments are additive (clamped to 0.0-1.0 range)
    - Governance notes provide explainability for the UI
    """
    result = AggregatedModifiers()
    
    if not agent_context:
        result.governance_notes.append("[INFO] No agent context - using baseline behavior")
        return result
    
    # Extract policy profile and Purview context
    policy_profile = agent_context.get("policy_profile")
    purview_context = agent_context.get("purview_context")
    data_classification = agent_context.get("data_classification")
    
    logger.debug(
        f"Computing policy modifiers: "
        f"policy={policy_profile is not None}, "
        f"purview={purview_context is not None}, "
        f"classification={data_classification}"
    )
    
    # Apply all modifiers
    
    # 1. Prompt Shield modifier
    shield_mod = apply_prompt_shield_modifier(policy_profile)
    result.add_modifier(shield_mod)
    
    # 2. Content Filter Level modifier
    filter_mod = apply_content_filter_modifier(policy_profile)
    result.add_modifier(filter_mod)
    
    # 3. Sensitive Data Handling modifier
    sensitive_mod = apply_sensitive_data_handling_modifier(policy_profile, prompt)
    result.add_modifier(sensitive_mod)
    
    # 4. Data Classification modifier
    class_mod = apply_data_classification_modifier(data_classification)
    result.add_modifier(class_mod)
    
    # 5. Purview Governance modifier
    purview_mod = apply_purview_governance_modifier(purview_context, prompt, data_classification)
    result.add_modifier(purview_mod)
    
    # Log summary
    logger.info(
        f"Policy modifiers computed: "
        f"block_delta={result.block_probability_delta:+.2f}, "
        f"flag_delta={result.flag_probability_delta:+.2f}, "
        f"force_block={result.force_block}, "
        f"force_flag={result.force_flag}"
    )
    
    return result
