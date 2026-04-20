"""
Unified Run Details Service.

Assembles all run context into a single normalized response structure.
Merges:
- Agent context snapshot
- Inherited policy profile
- Purview governance context
- Runtime execution result
- Linked Defender alerts
- Linked Purview governance events
- Storyline narrative summary
"""

import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

from models.schemas import (
    AttackResult,
    UnifiedRunDetails,
    AgentContextSnapshot,
    PolicyProfileSnapshot,
    PurviewGovernanceSnapshot,
    RuntimeResultSnapshot,
    LinkedAlertSummary,
    LinkedGovernanceEventSummary,
    StorylineSummary,
    VerdictDetail,
)
from storage import get_store

logger = logging.getLogger(__name__)


class UnifiedRunDetailsService:
    """
    Service for assembling unified run details from multiple data sources.
    
    This service:
    1. Loads the base attack result
    2. Expands agent context snapshot into full details
    3. Resolves policy profile from agent context
    4. Resolves Purview governance context from agent context
    5. Formats runtime result
    6. Formats linked Defender alerts
    7. Formats linked Purview governance events
    8. Generates a storyline summary
    """
    
    def __init__(self):
        self._store = get_store()
    
    def get_unified_details(self, run_id: str) -> Optional[UnifiedRunDetails]:
        """
        Get unified run details for a specific run.
        
        Args:
            run_id: The run identifier
            
        Returns:
            UnifiedRunDetails or None if run not found
        """
        # Load base attack result
        result = self._store.get_result(run_id)
        if not result:
            logger.warning(f"Run not found: {run_id}")
            return None
        
        return self._assemble_unified_details(result)
    
    def _assemble_unified_details(self, result: AttackResult) -> UnifiedRunDetails:
        """
        Assemble unified details from an attack result.
        """
        # Extract component snapshots
        agent_context = self._extract_agent_context(result)
        policy_profile = self._extract_policy_profile(result)
        purview_governance = self._extract_purview_governance(result)
        runtime_result = self._extract_runtime_result(result)
        linked_alerts = self._format_linked_alerts(result)
        linked_events = self._format_linked_governance_events(result)
        
        # Generate storyline
        storyline = self._generate_storyline(
            result=result,
            agent_context=agent_context,
            policy_profile=policy_profile,
            linked_alerts=linked_alerts,
            linked_events=linked_events,
        )
        
        return UnifiedRunDetails(
            run_id=result.run_id,
            campaign_id=result.campaign_id,
            correlation_id=result.correlation_id,
            agent_context=agent_context,
            policy_profile=policy_profile,
            purview_governance=purview_governance,
            runtime_result=runtime_result,
            linked_defender_alerts=linked_alerts,
            linked_governance_events=linked_events,
            storyline=storyline,
            generated_at=datetime.utcnow(),
            data_freshness="real_time",
        )
    
    def _extract_agent_context(self, result: AttackResult) -> Optional[AgentContextSnapshot]:
        """
        Extract and expand agent context from the result.
        """
        snapshot = result.agent_context_snapshot
        if not snapshot:
            return None
        
        return AgentContextSnapshot(
            agent_id=snapshot.get("agent_id", result.agent_id or "unknown"),
            agent_name=snapshot.get("agent_name"),
            model_name=snapshot.get("model_name"),
            deployment_name=snapshot.get("deployment_name"),
            foundry_resource_name=snapshot.get("foundry_resource_name"),
            data_classification=snapshot.get("data_classification"),
            monitoring_enabled=snapshot.get("monitoring_enabled", True),
            defender_integration_enabled=snapshot.get("defender_integration_enabled", True),
            status=snapshot.get("status"),
            tags=snapshot.get("tags", []),
        )
    
    def _extract_policy_profile(self, result: AttackResult) -> Optional[PolicyProfileSnapshot]:
        """
        Extract and expand policy profile from the result.
        """
        snapshot = result.agent_context_snapshot
        if not snapshot:
            return None
        
        policy = snapshot.get("policy_profile")
        if not policy:
            return None
        
        return PolicyProfileSnapshot(
            policy_profile_id=policy.get("policy_profile_id", "unknown"),
            policy_profile_name=policy.get("policy_profile_name", "Unknown Policy"),
            content_filter_level=policy.get("content_filter_level", "standard"),
            prompt_shield_enabled=policy.get("prompt_shield_enabled", True),
            allowed_data_sources=policy.get("allowed_data_sources", []),
            sensitive_data_handling=policy.get("sensitive_data_handling", "redact"),
            logging_level=policy.get("logging_level", "standard"),
            blocked_categories=policy.get("blocked_categories", []),
            policy_status=policy.get("policy_status", "active"),
        )
    
    def _extract_purview_governance(self, result: AttackResult) -> Optional[PurviewGovernanceSnapshot]:
        """
        Extract and expand Purview governance context from the result.
        """
        snapshot = result.agent_context_snapshot
        if not snapshot:
            return None
        
        purview = snapshot.get("purview_context")
        if not purview:
            return None
        
        return PurviewGovernanceSnapshot(
            purview_policy_set_id=purview.get("purview_policy_set_id", "unknown"),
            purview_policy_set_name=purview.get("purview_policy_set_name", "Unknown Policy Set"),
            classification_labels=purview.get("classification_labels", []),
            data_access_rules_count=len(purview.get("data_access_rules", [])),
            retention_rules_count=len(purview.get("retention_rules", [])),
            policy_status=purview.get("policy_status", "active"),
            purview_account_name=purview.get("purview_account_name"),
            sync_status=purview.get("sync_status", "not_connected"),
            last_sync_at=purview.get("last_sync_at"),
        )
    
    def _extract_runtime_result(self, result: AttackResult) -> RuntimeResultSnapshot:
        """
        Extract runtime result from the attack result.
        """
        # Determine combined verdict
        combined_verdict = "allowed"
        if result.shield_verdict and result.shield_verdict.result.value in ["blocked", "denied"]:
            combined_verdict = "blocked"
        elif result.model_verdict and result.model_verdict.result.value in ["blocked", "denied"]:
            combined_verdict = "blocked"
        elif result.evaluator_verdict and result.evaluator_verdict.result.value == "harmful":
            combined_verdict = "flagged"
        
        return RuntimeResultSnapshot(
            run_id=result.run_id,
            campaign_id=result.campaign_id,
            correlation_id=result.correlation_id,
            attack_category=result.attack_category.value,
            prompt=result.prompt,
            response=result.response,
            target_model=result.target_model,
            shield_verdict=result.shield_verdict,
            model_verdict=result.model_verdict,
            evaluator_verdict=result.evaluator_verdict,
            combined_verdict=combined_verdict,
            timestamp=result.timestamp,
            response_time_ms=result.response_time_ms,
            shield_time_ms=result.shield_time_ms,
            model_time_ms=result.model_time_ms,
            shield_enabled=result.shield_enabled,
            telemetry_enabled=result.telemetry_enabled,
        )
    
    def _format_linked_alerts(self, result: AttackResult) -> List[LinkedAlertSummary]:
        """
        Format linked Defender alerts into summary objects.
        """
        alerts = []
        
        for alert_data in result.linked_defender_alerts:
            # Get correlation info from the correlation field if it exists
            correlation = alert_data.get("correlation", {})
            
            alerts.append(LinkedAlertSummary(
                alert_id=alert_data.get("alert_id", "unknown"),
                title=alert_data.get("title", "Unknown Alert"),
                description=alert_data.get("description", ""),
                severity=alert_data.get("severity", "medium"),
                status=alert_data.get("status", "new"),
                category=alert_data.get("category"),
                source=alert_data.get("source", "defender_for_ai"),
                timestamp=alert_data.get("timestamp", datetime.utcnow()),
                tactics=alert_data.get("tactics", []),
                techniques=alert_data.get("techniques", []),
                correlation_confidence=correlation.get("confidence", "low"),
                correlation_score=correlation.get("score", 0.0),
                correlation_reason=correlation.get("reason", ""),
            ))
        
        return alerts
    
    def _format_linked_governance_events(self, result: AttackResult) -> List[LinkedGovernanceEventSummary]:
        """
        Format linked Purview governance events into summary objects.
        """
        events = []
        
        for event_data in result.linked_purview_events:
            # Get correlation info from the correlation field if it exists
            correlation = event_data.get("correlation", {})
            
            events.append(LinkedGovernanceEventSummary(
                event_id=event_data.get("event_id", "unknown"),
                event_type=event_data.get("event_type", "policy_evaluation"),
                policy_name=event_data.get("policy_name", "Unknown Policy"),
                policy_id=event_data.get("policy_id"),
                policy_action=event_data.get("policy_action", "allow"),
                classification=event_data.get("classification"),
                sensitivity_label=event_data.get("sensitivity_label"),
                timestamp=event_data.get("timestamp", datetime.utcnow()),
                status=event_data.get("status", "processed"),
                compliance_state=event_data.get("compliance_state"),
                risk_level=event_data.get("risk_level"),
                description=event_data.get("description", ""),
                correlation_confidence=correlation.get("confidence", "low"),
                correlation_score=correlation.get("score", 0.0),
                correlation_reason=correlation.get("reason", ""),
            ))
        
        return events
    
    def _generate_storyline(
        self,
        result: AttackResult,
        agent_context: Optional[AgentContextSnapshot],
        policy_profile: Optional[PolicyProfileSnapshot],
        linked_alerts: List[LinkedAlertSummary],
        linked_events: List[LinkedGovernanceEventSummary],
    ) -> StorylineSummary:
        """
        Generate a narrative storyline summary from all components.
        """
        # Determine run outcome
        run_outcome = "allowed"
        if result.shield_verdict and result.shield_verdict.result.value in ["blocked", "denied"]:
            run_outcome = "blocked"
        elif result.model_verdict and result.model_verdict.result.value in ["blocked", "denied"]:
            run_outcome = "blocked"
        elif result.evaluator_verdict and result.evaluator_verdict.result.value == "harmful":
            run_outcome = "flagged"
        
        # Determine security posture
        high_severity_count = len([a for a in linked_alerts if a.severity in ["high", "critical"]])
        if run_outcome == "blocked" and high_severity_count == 0:
            security_posture = "protected"
        elif high_severity_count > 0:
            security_posture = "exposed"
        else:
            security_posture = "partial"
        
        # Determine governance compliance
        policy_violations = [e for e in linked_events if e.policy_action in ["deny", "block"]]
        if len(policy_violations) > 0:
            governance_compliance = "non_compliant"
        elif len(linked_events) > 0:
            governance_compliance = "compliant"
        else:
            governance_compliance = "unknown"
        
        # Determine risk level
        if high_severity_count >= 2 or len(policy_violations) >= 2:
            risk_level = "critical"
        elif high_severity_count >= 1 or len(policy_violations) >= 1:
            risk_level = "high"
        elif len(linked_alerts) > 0 or security_posture == "partial":
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Generate key observations
        observations = []
        
        # Outcome observation
        if run_outcome == "blocked":
            if result.shield_verdict:
                observations.append(f"Attack blocked by prompt shield ({result.attack_category.value})")
            else:
                observations.append(f"Attack blocked ({result.attack_category.value})")
        elif run_outcome == "flagged":
            observations.append(f"Attack flagged for review ({result.attack_category.value})")
        else:
            observations.append(f"Attack was allowed through ({result.attack_category.value})")
        
        # Alert observations
        if high_severity_count > 0:
            observations.append(f"{high_severity_count} high/critical severity Defender alert(s) generated")
        elif len(linked_alerts) > 0:
            observations.append(f"{len(linked_alerts)} Defender alert(s) linked to this run")
        
        # Governance observations
        if len(policy_violations) > 0:
            observations.append(f"{len(policy_violations)} governance policy violation(s) detected")
        elif len(linked_events) > 0:
            observations.append(f"{len(linked_events)} governance event(s) - all compliant")
        
        # Policy observation
        if policy_profile:
            if policy_profile.prompt_shield_enabled:
                observations.append(f"Prompt shield was enabled with {policy_profile.content_filter_level} content filtering")
        
        # Calculate timeline
        all_timestamps = [result.timestamp]
        all_timestamps.extend([a.timestamp for a in linked_alerts])
        all_timestamps.extend([e.timestamp for e in linked_events])
        earliest = min(all_timestamps)
        latest = max(all_timestamps)
        
        return StorylineSummary(
            run_outcome=run_outcome,
            security_posture=security_posture,
            governance_compliance=governance_compliance,
            risk_level=risk_level,
            defender_alert_count=len(linked_alerts),
            high_severity_alert_count=high_severity_count,
            governance_event_count=len(linked_events),
            policy_violation_count=len(policy_violations),
            key_observations=observations,
            earliest_event=earliest,
            latest_event=latest,
        )


# Singleton instance
_service_instance: Optional[UnifiedRunDetailsService] = None


def get_unified_run_details_service() -> UnifiedRunDetailsService:
    """Get the singleton unified run details service instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = UnifiedRunDetailsService()
    return _service_instance
