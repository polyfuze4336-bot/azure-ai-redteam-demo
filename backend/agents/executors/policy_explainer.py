"""
Policy Explainer Agent Executor.

Purpose:
- Take a flagged or blocked run
- Explain in simple business-friendly language why the run was considered unsafe
- Provide short suggested mitigation notes for the presenter

This agent is designed for client demos to provide clear explanations
of why content was blocked or flagged by Azure AI Content Safety.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from models.schemas import AttackResult, Outcome, VerdictResult, VerdictDetail, AttackCategory, Severity
from config import get_settings, RunMode
from telemetry import get_logger

logger = get_logger("policy_explainer_agent")


# =============================================================================
# OUTPUT MODEL
# =============================================================================

@dataclass
class MitigationNote:
    """A single mitigation suggestion."""
    priority: str  # high, medium, low
    action: str
    rationale: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "priority": self.priority,
            "action": self.action,
            "rationale": self.rationale,
        }


@dataclass
class PolicyExplanation:
    """Structured output from the Policy Explainer Agent."""
    
    # Core explanation
    summary: str
    why_flagged: str
    risk_category: str
    
    # Verdict breakdown
    shield_explanation: str
    model_explanation: str
    evaluator_explanation: str
    final_outcome_explanation: str
    
    # Business-friendly interpretation
    business_impact: str
    compliance_note: str
    
    # Mitigation guidance
    mitigations: List[MitigationNote]
    recommended_action: str
    
    # Demo narrative
    client_narrative: str
    presenter_talking_points: List[str]
    
    # Metadata
    confidence_level: str  # high, medium, low
    policy_references: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": self.summary,
            "why_flagged": self.why_flagged,
            "risk_category": self.risk_category,
            "shield_explanation": self.shield_explanation,
            "model_explanation": self.model_explanation,
            "evaluator_explanation": self.evaluator_explanation,
            "final_outcome_explanation": self.final_outcome_explanation,
            "business_impact": self.business_impact,
            "compliance_note": self.compliance_note,
            "mitigations": [m.to_dict() for m in self.mitigations],
            "recommended_action": self.recommended_action,
            "client_narrative": self.client_narrative,
            "presenter_talking_points": self.presenter_talking_points,
            "confidence_level": self.confidence_level,
            "policy_references": self.policy_references,
        }


# =============================================================================
# POLICY KNOWLEDGE BASE
# =============================================================================

CATEGORY_EXPLANATIONS = {
    "jailbreak": {
        "description": "Attempt to bypass the model's safety guidelines through role-play, personas, or instruction overrides",
        "risk": "Could allow unauthorized access to harmful content generation",
        "policy": "Azure AI Content Safety: Jailbreak Attack Detection",
        "business_impact": "Potential reputational damage if malicious content is generated",
    },
    "prompt-injection": {
        "description": "Attempt to inject malicious instructions that override the system's intended behavior",
        "risk": "Could manipulate the model to perform unintended actions",
        "policy": "Azure AI Content Safety: Prompt Injection Detection",
        "business_impact": "Could lead to data leakage or unauthorized operations",
    },
    "prompt-extraction": {
        "description": "Attempt to extract system prompts or confidential configuration",
        "risk": "Could expose proprietary instructions or sensitive business logic",
        "policy": "Azure AI Content Safety: Prompt Extraction Prevention",
        "business_impact": "Risk of intellectual property exposure",
    },
    "data-exfiltration": {
        "description": "Attempt to extract sensitive data from the model or connected systems",
        "risk": "Could lead to unauthorized data access or privacy violations",
        "policy": "Azure AI Content Safety: Data Protection Controls",
        "business_impact": "Potential data breach with regulatory implications",
    },
    "credential-theft": {
        "description": "Attempt to obtain authentication credentials or security tokens",
        "risk": "Could enable unauthorized system access",
        "policy": "Azure AI Content Safety: Credential Protection",
        "business_impact": "Security breach risk with potential compliance violations",
    },
    "policy-evasion": {
        "description": "Attempt to circumvent content policies through indirect methods",
        "risk": "Could generate content that violates organizational policies",
        "policy": "Azure AI Content Safety: Policy Enforcement",
        "business_impact": "Compliance and brand safety concerns",
    },
    "indirect-injection": {
        "description": "Malicious instructions embedded in external content processed by the model",
        "risk": "Could manipulate behavior through trusted data sources",
        "policy": "Azure AI Content Safety: Indirect Injection Detection",
        "business_impact": "Supply chain security risk",
    },
    "tool-misuse": {
        "description": "Attempt to misuse connected tools or function-calling capabilities",
        "risk": "Could trigger unauthorized operations in connected systems",
        "policy": "Azure AI Content Safety: Tool Use Controls",
        "business_impact": "Operational security and integrity risk",
    },
    "code-vulnerability": {
        "description": "Attempt to generate or execute malicious code",
        "risk": "Could introduce security vulnerabilities or execute harmful code",
        "policy": "Azure AI Content Safety: Code Security",
        "business_impact": "System security and infrastructure risk",
    },
}

VERDICT_EXPLANATIONS = {
    VerdictResult.BLOCKED: {
        "shield": "Azure AI Content Safety actively blocked this request before it reached the model",
        "model": "The model's built-in safety alignment refused to process this request",
        "evaluator": "Post-hoc evaluation determined the content should not be allowed",
    },
    VerdictResult.FLAGGED: {
        "shield": "Content Safety flagged this request for review but allowed it to proceed",
        "model": "The model processed the request but raised safety concerns",
        "evaluator": "Post-hoc evaluation flagged potential policy concerns",
    },
    VerdictResult.ALLOWED: {
        "shield": "Content Safety did not detect policy violations in this request",
        "model": "The model processed the request without triggering safety mechanisms",
        "evaluator": "Post-hoc evaluation found no significant policy concerns",
    },
}

OUTCOME_EXPLANATIONS = {
    Outcome.SAFE: "The system successfully defended against this attack. Defenses worked as intended.",
    Outcome.VULNERABLE: "The attack bypassed defenses. This indicates a potential gap in protection.",
    Outcome.PARTIAL: "The attack was partially successful. Some defenses triggered but the response may still contain concerning content.",
}


# =============================================================================
# ANALYSIS FUNCTIONS
# =============================================================================

def _explain_verdict(verdict: VerdictDetail, source: str) -> str:
    """Generate explanation for a single verdict."""
    result = verdict.result
    confidence = verdict.confidence
    
    base_explanation = VERDICT_EXPLANATIONS.get(result, {}).get(source, f"{source} returned {result.value}")
    
    confidence_qualifier = ""
    if confidence >= 0.9:
        confidence_qualifier = " with high confidence"
    elif confidence >= 0.7:
        confidence_qualifier = " with moderate confidence"
    else:
        confidence_qualifier = " with low confidence"
    
    categories = verdict.categories_detected
    if categories:
        category_text = f" Categories detected: {', '.join(categories)}."
    else:
        category_text = ""
    
    return f"{base_explanation}{confidence_qualifier}.{category_text}"


def _determine_risk_category(attack_result: AttackResult) -> str:
    """Determine the primary risk category."""
    category = attack_result.attack_category.value
    
    # Check detected categories from verdicts
    detected = []
    for verdict in [attack_result.shield_verdict, attack_result.model_verdict, attack_result.evaluator_verdict]:
        detected.extend(verdict.categories_detected)
    
    if detected:
        # Use most frequently detected category
        from collections import Counter
        common = Counter(detected).most_common(1)
        if common:
            return common[0][0]
    
    return category


def _generate_why_flagged(attack_result: AttackResult) -> str:
    """Generate explanation of why this run was flagged/blocked."""
    category = attack_result.attack_category.value
    category_info = CATEGORY_EXPLANATIONS.get(category, {})
    
    shield_result = attack_result.shield_verdict.result
    outcome = attack_result.outcome
    
    why = f"This request was flagged because it exhibits characteristics of a {category.replace('-', ' ')} attack. "
    why += category_info.get("description", "The content triggered safety detection mechanisms.") + ". "
    
    if shield_result == VerdictResult.BLOCKED:
        why += "Azure AI Content Safety proactively blocked this request."
    elif shield_result == VerdictResult.FLAGGED:
        why += "The request was flagged for review but allowed through for this test."
    elif outcome == Outcome.SAFE:
        why += "Although not blocked by Content Safety, the model safely refused the request."
    else:
        why += "The request bypassed initial filters but was caught by post-hoc evaluation."
    
    return why


def _generate_business_impact(attack_result: AttackResult) -> str:
    """Generate business impact statement."""
    category = attack_result.attack_category.value
    category_info = CATEGORY_EXPLANATIONS.get(category, {})
    outcome = attack_result.outcome
    
    base_impact = category_info.get("business_impact", "Potential security and compliance concerns.")
    
    if outcome == Outcome.SAFE:
        return f"Risk mitigated: {base_impact} However, defenses successfully prevented any actual impact."
    elif outcome == Outcome.VULNERABLE:
        return f"HIGH RISK: {base_impact} This attack succeeded and requires immediate attention."
    else:
        return f"MODERATE RISK: {base_impact} Partial success indicates defense gaps that need review."


def _generate_compliance_note(attack_result: AttackResult) -> str:
    """Generate compliance-related note."""
    category = attack_result.attack_category.value
    severity = attack_result.severity
    outcome = attack_result.outcome
    
    if outcome == Outcome.VULNERABLE:
        return f"This {severity.value}-severity {category} vulnerability may have compliance implications. Document findings and initiate remediation review."
    elif outcome == Outcome.PARTIAL:
        return f"Partial attack success detected. Review content policies for {category} scenarios and consider additional safeguards."
    else:
        return f"Defense effective. Continue monitoring {category} attack patterns and document successful mitigations."


def _generate_mitigations(attack_result: AttackResult) -> List[MitigationNote]:
    """Generate mitigation suggestions."""
    category = attack_result.attack_category.value
    outcome = attack_result.outcome
    shield_enabled = attack_result.shield_enabled
    
    mitigations = []
    
    # Outcome-based mitigations
    if outcome == Outcome.VULNERABLE:
        mitigations.append(MitigationNote(
            priority="high",
            action="Enable or strengthen Azure AI Content Safety filters",
            rationale="The attack bypassed current defenses. Enhanced filtering is recommended.",
        ))
        mitigations.append(MitigationNote(
            priority="high",
            action=f"Review system prompts for {category} attack vectors",
            rationale="Strengthen instructions to resist this attack pattern.",
        ))
    elif outcome == Outcome.PARTIAL:
        mitigations.append(MitigationNote(
            priority="medium",
            action="Fine-tune detection thresholds for this attack category",
            rationale="Partial success suggests thresholds may be too permissive.",
        ))
    
    # Shield-based mitigations
    if not shield_enabled:
        mitigations.append(MitigationNote(
            priority="high" if outcome != Outcome.SAFE else "medium",
            action="Enable Azure AI Content Safety for production deployments",
            rationale="Content Safety provides defense-in-depth against adversarial attacks.",
        ))
    
    # Category-specific mitigations
    category_mitigations = {
        "jailbreak": MitigationNote(
            priority="medium",
            action="Implement jailbreak-resistant system prompts with explicit boundaries",
            rationale="Clear role definitions reduce susceptibility to persona-based attacks.",
        ),
        "prompt-injection": MitigationNote(
            priority="medium",
            action="Use input sanitization and delimiter strategies",
            rationale="Separating user input from system instructions prevents injection.",
        ),
        "prompt-extraction": MitigationNote(
            priority="medium",
            action="Add explicit instructions to never reveal system configuration",
            rationale="Hardened prompts resist extraction attempts.",
        ),
        "data-exfiltration": MitigationNote(
            priority="high",
            action="Implement data classification and output filtering",
            rationale="Prevent sensitive data from appearing in model responses.",
        ),
    }
    
    if category in category_mitigations and outcome != Outcome.SAFE:
        mitigations.append(category_mitigations[category])
    
    # Always include monitoring
    if outcome == Outcome.SAFE:
        mitigations.append(MitigationNote(
            priority="low",
            action="Continue monitoring and logging attack patterns",
            rationale="Successful defense should be documented for compliance evidence.",
        ))
    
    return mitigations[:4]  # Limit to top 4 mitigations


def _generate_talking_points(attack_result: AttackResult, why_flagged: str) -> List[str]:
    """Generate presenter talking points for demo."""
    category = attack_result.attack_category.value
    outcome = attack_result.outcome
    shield_result = attack_result.shield_verdict.result
    confidence = attack_result.shield_verdict.confidence
    
    points = []
    
    # Opening context
    points.append(f"This demonstrates a {category.replace('-', ' ')} attack scenario.")
    
    # Defense outcome
    if shield_result == VerdictResult.BLOCKED:
        points.append(f"Azure AI Content Safety blocked this with {confidence:.0%} confidence - the attack never reached the model.")
    elif outcome == Outcome.SAFE:
        points.append("Even without immediate blocking, the model's alignment training led to a safe refusal.")
    elif outcome == Outcome.VULNERABLE:
        points.append("This shows why red teaming matters - the attack succeeded, revealing a gap to address.")
    else:
        points.append("The partial success here indicates an area where defenses could be strengthened.")
    
    # Business relevance
    points.append("This is exactly the kind of scenario organizations need to test before production deployment.")
    
    return points


def _generate_client_narrative(attack_result: AttackResult, mitigations: List[MitigationNote]) -> str:
    """Generate client-facing narrative."""
    category = attack_result.attack_category.value
    outcome = attack_result.outcome
    
    if outcome == Outcome.SAFE:
        narrative = f"This {category} attack was successfully defended. "
        narrative += "Azure AI Content Safety and the model's safety alignment worked together to prevent any harmful output. "
        narrative += "This demonstrates the defense-in-depth approach we recommend for production deployments."
    elif outcome == Outcome.VULNERABLE:
        narrative = f"This {category} attack bypassed current defenses, which is exactly what red teaming is designed to discover. "
        if mitigations:
            narrative += f"Our recommendation: {mitigations[0].action.lower()}. "
        narrative += "Finding these gaps before deployment prevents real-world incidents."
    else:
        narrative = f"This {category} attack was partially successful, indicating defenses are working but could be strengthened. "
        narrative += "This kind of insight helps prioritize security improvements for your AI deployment."
    
    return narrative


def _get_policy_references(attack_result: AttackResult) -> List[str]:
    """Get relevant policy references."""
    category = attack_result.attack_category.value
    refs = []
    
    # Content Safety documentation
    refs.append("Azure AI Content Safety: Prompt Shields Documentation")
    
    # Category-specific policy
    category_info = CATEGORY_EXPLANATIONS.get(category, {})
    if "policy" in category_info:
        refs.append(category_info["policy"])
    
    # Severity-based guidelines
    if attack_result.severity == Severity.CRITICAL:
        refs.append("Azure Responsible AI: Critical Severity Response Guidelines")
    elif attack_result.severity == Severity.HIGH:
        refs.append("Azure Responsible AI: High Severity Incident Response")
    
    return refs


def _determine_confidence_level(attack_result: AttackResult) -> str:
    """Determine confidence in the explanation based on verdict consistency."""
    verdicts = [
        attack_result.shield_verdict.result,
        attack_result.model_verdict.result,
        attack_result.evaluator_verdict.result,
    ]
    confidences = [
        attack_result.shield_verdict.confidence,
        attack_result.model_verdict.confidence,
        attack_result.evaluator_verdict.confidence,
    ]
    
    avg_confidence = sum(confidences) / len(confidences)
    
    # Check for consensus
    unique_verdicts = set(verdicts)
    
    if len(unique_verdicts) == 1 and avg_confidence >= 0.8:
        return "high"
    elif avg_confidence >= 0.6:
        return "medium"
    else:
        return "low"


# =============================================================================
# EXECUTOR CLASS
# =============================================================================

class PolicyExplainerExecutor:
    """
    Executor for the Policy Explainer Agent.
    
    Analyzes flagged or blocked runs and produces business-friendly
    explanations with mitigation guidance for demo presentations.
    """
    
    def __init__(self):
        self._settings = get_settings()
    
    async def execute(
        self,
        attack_result: AttackResult,
        correlation_id: Optional[str] = None,
    ) -> PolicyExplanation:
        """
        Execute the Policy Explainer Agent on an attack result.
        
        Args:
            attack_result: The attack run to explain
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            PolicyExplanation with structured explanation and mitigations
        """
        import uuid
        correlation_id = correlation_id or str(uuid.uuid4())
        
        logger.info(
            f"Policy Explainer analyzing run {attack_result.run_id[:8]}...",
            extra={"correlation_id": correlation_id}
        )
        
        # Generate all components
        risk_category = _determine_risk_category(attack_result)
        why_flagged = _generate_why_flagged(attack_result)
        
        shield_explanation = _explain_verdict(attack_result.shield_verdict, "shield")
        model_explanation = _explain_verdict(attack_result.model_verdict, "model")
        evaluator_explanation = _explain_verdict(attack_result.evaluator_verdict, "evaluator")
        final_outcome_explanation = OUTCOME_EXPLANATIONS.get(
            attack_result.outcome, 
            f"Outcome: {attack_result.outcome.value}"
        )
        
        business_impact = _generate_business_impact(attack_result)
        compliance_note = _generate_compliance_note(attack_result)
        
        mitigations = _generate_mitigations(attack_result)
        recommended_action = mitigations[0].action if mitigations else "Continue monitoring"
        
        talking_points = _generate_talking_points(attack_result, why_flagged)
        client_narrative = _generate_client_narrative(attack_result, mitigations)
        
        confidence_level = _determine_confidence_level(attack_result)
        policy_references = _get_policy_references(attack_result)
        
        # Generate summary
        category = attack_result.attack_category.value
        outcome = attack_result.outcome.value
        summary = f"{category.replace('-', ' ').title()} attack with {outcome} outcome. {why_flagged}"
        
        result = PolicyExplanation(
            summary=summary,
            why_flagged=why_flagged,
            risk_category=risk_category,
            shield_explanation=shield_explanation,
            model_explanation=model_explanation,
            evaluator_explanation=evaluator_explanation,
            final_outcome_explanation=final_outcome_explanation,
            business_impact=business_impact,
            compliance_note=compliance_note,
            mitigations=mitigations,
            recommended_action=recommended_action,
            client_narrative=client_narrative,
            presenter_talking_points=talking_points,
            confidence_level=confidence_level,
            policy_references=policy_references,
        )
        
        logger.info(
            f"Policy Explainer completed: category={risk_category}, confidence={confidence_level}",
            extra={"correlation_id": correlation_id}
        )
        
        return result


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_executor_instance: Optional[PolicyExplainerExecutor] = None


def get_policy_explainer_executor() -> PolicyExplainerExecutor:
    """Get the singleton Policy Explainer executor instance."""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = PolicyExplainerExecutor()
    return _executor_instance
