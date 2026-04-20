"""
Defender Alert Correlation Service.

Correlates Microsoft Defender alerts with attack runs and agents using
multiple correlation methods including correlation ID, timestamps,
agent context, target context, and metadata matching.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum

from models.schemas import (
    DefenderAlert,
    DefenderAlertSeverity,
    AttackResult,
    AlertCorrelation,
    LinkedDefenderAlert,
    CorrelationMethod,
    CorrelationConfidence,
    CorrelationRequest,
    CorrelationResult,
)
from storage import get_store

logger = logging.getLogger(__name__)


# =============================================================================
# Correlation Weights and Thresholds
# =============================================================================

# Weight for each correlation method (used in score calculation)
CORRELATION_WEIGHTS = {
    CorrelationMethod.CORRELATION_ID: 0.50,  # Strongest signal
    CorrelationMethod.TIMESTAMP_PROXIMITY: 0.15,
    CorrelationMethod.AGENT_CONTEXT: 0.15,
    CorrelationMethod.TARGET_CONTEXT: 0.10,
    CorrelationMethod.CATEGORY_MATCH: 0.05,
    CorrelationMethod.RESOURCE_MATCH: 0.05,
    CorrelationMethod.METADATA_MATCH: 0.05,
    CorrelationMethod.MANUAL: 1.0,  # Manual link is always full confidence
}

# Score thresholds for confidence levels
CONFIDENCE_THRESHOLDS = {
    CorrelationConfidence.HIGH: 0.70,
    CorrelationConfidence.MEDIUM: 0.40,
    CorrelationConfidence.LOW: 0.15,
}

# Category mapping from alert categories to attack categories
ALERT_TO_ATTACK_CATEGORY_MAP = {
    "jailbreakattempt": "jailbreak",
    "jailbreak": "jailbreak",
    "promptinjection": "prompt-injection",
    "prompt_injection": "prompt-injection",
    "contentabuse": "policy-evasion",
    "dataexfiltration": "data-exfiltration",
    "data_exfiltration": "data-exfiltration",
    "credentialtheft": "credential-theft",
    "indirectinjection": "indirect-injection",
    "toolmisuse": "tool-misuse",
    "codevulnerability": "code-vulnerability",
}


class DefenderAlertCorrelationService:
    """
    Service for correlating Microsoft Defender alerts with attack runs.
    
    Uses multiple correlation methods to find the best match:
    - Correlation ID: Exact match on correlation_id field
    - Timestamp Proximity: Alert timestamp close to run timestamp
    - Agent Context: Same agent ID
    - Target Context: Same deployment/resource name
    - Category Match: Alert category maps to attack category
    - Resource Match: Same Foundry resource
    - Metadata Match: Matching metadata fields
    """
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern for shared state."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        logger.info("DefenderAlertCorrelationService initialized")
    
    # -------------------------------------------------------------------------
    # Individual Correlation Methods
    # -------------------------------------------------------------------------
    
    def _match_correlation_id(
        self, 
        alert: DefenderAlert, 
        run: AttackResult
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check for exact correlation ID match.
        This is the strongest signal for correlation.
        """
        if not alert.correlation_id or not run.correlation_id:
            return False, {"matched": False, "reason": "Missing correlation ID"}
        
        matched = alert.correlation_id == run.correlation_id
        return matched, {
            "matched": matched,
            "alert_correlation_id": alert.correlation_id,
            "run_correlation_id": run.correlation_id,
        }
    
    def _match_timestamp_proximity(
        self, 
        alert: DefenderAlert, 
        run: AttackResult,
        window_seconds: int = 300
    ) -> Tuple[float, Dict[str, Any]]:
        """
        Check if alert timestamp is close to run timestamp.
        Returns a score based on proximity (closer = higher score).
        """
        # Use detected_at if available, otherwise timestamp
        alert_time = alert.detected_at or alert.timestamp
        run_time = run.timestamp
        
        delta = abs((alert_time - run_time).total_seconds())
        
        if delta > window_seconds:
            return 0.0, {
                "matched": False,
                "delta_seconds": delta,
                "window_seconds": window_seconds,
                "reason": "Outside time window"
            }
        
        # Score decreases linearly with distance (1.0 at 0s, 0.0 at window)
        score = 1.0 - (delta / window_seconds)
        
        return score, {
            "matched": True,
            "delta_seconds": round(delta, 2),
            "window_seconds": window_seconds,
            "proximity_score": round(score, 3),
        }
    
    def _match_agent_context(
        self, 
        alert: DefenderAlert, 
        run: AttackResult
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if alert and run relate to the same agent.
        """
        # Check linked agent ID
        if alert.linked_agent_id and run.agent_id:
            matched = alert.linked_agent_id == run.agent_id
            if matched:
                return True, {
                    "matched": True,
                    "agent_id": run.agent_id,
                    "match_type": "direct_agent_id"
                }
        
        # Check agent context snapshot
        if run.agent_context_snapshot:
            agent_name = run.agent_context_snapshot.get("agent_name", "")
            # Check if agent name appears in alert description or metadata
            if agent_name and (
                agent_name.lower() in alert.description.lower() or
                agent_name.lower() in str(alert.raw_metadata).lower()
            ):
                return True, {
                    "matched": True,
                    "agent_name": agent_name,
                    "match_type": "agent_name_in_description"
                }
        
        return False, {"matched": False}
    
    def _match_target_context(
        self, 
        alert: DefenderAlert, 
        run: AttackResult
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if alert and run relate to the same target/deployment.
        """
        matches = []
        
        # Check deployment name
        if run.deployment_name and alert.resource_name:
            if run.deployment_name.lower() in alert.resource_name.lower():
                matches.append(("deployment_name", run.deployment_name))
        
        # Check target name
        if run.target_name and alert.resource_name:
            if run.target_name.lower() in alert.resource_name.lower():
                matches.append(("target_name", run.target_name))
        
        # Check in raw metadata
        if run.deployment_name and alert.raw_metadata:
            metadata_str = str(alert.raw_metadata).lower()
            if run.deployment_name.lower() in metadata_str:
                matches.append(("deployment_in_metadata", run.deployment_name))
        
        if matches:
            return True, {
                "matched": True,
                "matches": matches,
            }
        
        return False, {"matched": False}
    
    def _match_category(
        self, 
        alert: DefenderAlert, 
        run: AttackResult
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if alert category maps to the attack category.
        """
        if not alert.category:
            return False, {"matched": False, "reason": "No alert category"}
        
        # Normalize alert category
        alert_cat_normalized = alert.category.lower().replace(" ", "").replace("-", "").replace("_", "")
        
        # Get mapped attack category
        mapped_attack_cat = ALERT_TO_ATTACK_CATEGORY_MAP.get(alert_cat_normalized)
        
        if mapped_attack_cat and mapped_attack_cat == run.attack_category.value:
            return True, {
                "matched": True,
                "alert_category": alert.category,
                "attack_category": run.attack_category.value,
                "mapped_via": alert_cat_normalized,
            }
        
        # Also check for partial match in attack category
        run_cat_normalized = run.attack_category.value.lower().replace("-", "")
        if alert_cat_normalized in run_cat_normalized or run_cat_normalized in alert_cat_normalized:
            return True, {
                "matched": True,
                "alert_category": alert.category,
                "attack_category": run.attack_category.value,
                "match_type": "partial"
            }
        
        return False, {
            "matched": False,
            "alert_category": alert.category,
            "attack_category": run.attack_category.value,
        }
    
    def _match_resource(
        self, 
        alert: DefenderAlert, 
        run: AttackResult
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if alert and run relate to the same Foundry resource.
        """
        if not run.foundry_resource_name:
            return False, {"matched": False, "reason": "No Foundry resource on run"}
        
        # Check resource name
        if alert.resource_name:
            if run.foundry_resource_name.lower() in alert.resource_name.lower():
                return True, {
                    "matched": True,
                    "foundry_resource": run.foundry_resource_name,
                    "alert_resource": alert.resource_name,
                }
        
        # Check in raw metadata
        if alert.raw_metadata:
            metadata_str = str(alert.raw_metadata).lower()
            if run.foundry_resource_name.lower() in metadata_str:
                return True, {
                    "matched": True,
                    "foundry_resource": run.foundry_resource_name,
                    "match_type": "in_metadata",
                }
        
        return False, {"matched": False}
    
    def _match_metadata(
        self, 
        alert: DefenderAlert, 
        run: AttackResult
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check for any metadata field matches.
        """
        matches = []
        
        # Check run_id in alert metadata
        if alert.raw_metadata:
            metadata_str = str(alert.raw_metadata).lower()
            
            # Check if run_id appears
            if run.run_id.lower() in metadata_str:
                matches.append(("run_id", run.run_id))
            
            # Check if scenario_id appears
            if run.scenario_id and run.scenario_id.lower() in metadata_str:
                matches.append(("scenario_id", run.scenario_id))
            
            # Check if campaign_id appears
            if run.campaign_id and run.campaign_id.lower() in metadata_str:
                matches.append(("campaign_id", run.campaign_id))
        
        # Check run metadata for alert references
        if run.metadata:
            run_metadata_str = str(run.metadata).lower()
            if alert.alert_id.lower() in run_metadata_str:
                matches.append(("alert_id_in_run", alert.alert_id))
        
        if matches:
            return True, {
                "matched": True,
                "matches": matches,
            }
        
        return False, {"matched": False}
    
    # -------------------------------------------------------------------------
    # Correlation Scoring
    # -------------------------------------------------------------------------
    
    def _calculate_correlation_score(
        self,
        alert: DefenderAlert,
        run: AttackResult,
        time_window_seconds: int = 300,
    ) -> Tuple[float, List[CorrelationMethod], Dict[str, Any]]:
        """
        Calculate overall correlation score between an alert and a run.
        
        Returns:
            Tuple of (score, methods_used, match_details)
        """
        total_score = 0.0
        methods_used = []
        match_details = {}
        
        # 1. Correlation ID match (strongest signal)
        matched, details = self._match_correlation_id(alert, run)
        match_details["correlation_id"] = details
        if matched:
            total_score += CORRELATION_WEIGHTS[CorrelationMethod.CORRELATION_ID]
            methods_used.append(CorrelationMethod.CORRELATION_ID)
        
        # 2. Timestamp proximity
        score, details = self._match_timestamp_proximity(alert, run, time_window_seconds)
        match_details["timestamp_proximity"] = details
        if score > 0:
            total_score += score * CORRELATION_WEIGHTS[CorrelationMethod.TIMESTAMP_PROXIMITY]
            methods_used.append(CorrelationMethod.TIMESTAMP_PROXIMITY)
        
        # 3. Agent context
        matched, details = self._match_agent_context(alert, run)
        match_details["agent_context"] = details
        if matched:
            total_score += CORRELATION_WEIGHTS[CorrelationMethod.AGENT_CONTEXT]
            methods_used.append(CorrelationMethod.AGENT_CONTEXT)
        
        # 4. Target context
        matched, details = self._match_target_context(alert, run)
        match_details["target_context"] = details
        if matched:
            total_score += CORRELATION_WEIGHTS[CorrelationMethod.TARGET_CONTEXT]
            methods_used.append(CorrelationMethod.TARGET_CONTEXT)
        
        # 5. Category match
        matched, details = self._match_category(alert, run)
        match_details["category_match"] = details
        if matched:
            total_score += CORRELATION_WEIGHTS[CorrelationMethod.CATEGORY_MATCH]
            methods_used.append(CorrelationMethod.CATEGORY_MATCH)
        
        # 6. Resource match
        matched, details = self._match_resource(alert, run)
        match_details["resource_match"] = details
        if matched:
            total_score += CORRELATION_WEIGHTS[CorrelationMethod.RESOURCE_MATCH]
            methods_used.append(CorrelationMethod.RESOURCE_MATCH)
        
        # 7. Metadata match
        matched, details = self._match_metadata(alert, run)
        match_details["metadata_match"] = details
        if matched:
            total_score += CORRELATION_WEIGHTS[CorrelationMethod.METADATA_MATCH]
            methods_used.append(CorrelationMethod.METADATA_MATCH)
        
        # Cap score at 1.0
        total_score = min(total_score, 1.0)
        
        return total_score, methods_used, match_details
    
    def _score_to_confidence(self, score: float) -> CorrelationConfidence:
        """Convert numeric score to confidence level."""
        if score >= CONFIDENCE_THRESHOLDS[CorrelationConfidence.HIGH]:
            return CorrelationConfidence.HIGH
        elif score >= CONFIDENCE_THRESHOLDS[CorrelationConfidence.MEDIUM]:
            return CorrelationConfidence.MEDIUM
        elif score >= CONFIDENCE_THRESHOLDS[CorrelationConfidence.LOW]:
            return CorrelationConfidence.LOW
        else:
            return CorrelationConfidence.UNLINKED
    
    def _generate_reason(
        self, 
        confidence: CorrelationConfidence,
        methods_used: List[CorrelationMethod],
        match_details: Dict[str, Any],
    ) -> str:
        """Generate human-readable reason for correlation."""
        if confidence == CorrelationConfidence.UNLINKED:
            return "No sufficient correlation signals found"
        
        parts = []
        
        if CorrelationMethod.CORRELATION_ID in methods_used:
            parts.append("exact correlation ID match")
        
        if CorrelationMethod.TIMESTAMP_PROXIMITY in methods_used:
            delta = match_details.get("timestamp_proximity", {}).get("delta_seconds", "?")
            parts.append(f"timestamp within {delta}s")
        
        if CorrelationMethod.AGENT_CONTEXT in methods_used:
            agent_id = match_details.get("agent_context", {}).get("agent_id", "")
            if agent_id:
                parts.append(f"same agent ({agent_id[:8]}...)")
            else:
                parts.append("agent context match")
        
        if CorrelationMethod.TARGET_CONTEXT in methods_used:
            parts.append("same target/deployment")
        
        if CorrelationMethod.CATEGORY_MATCH in methods_used:
            parts.append("category match")
        
        if CorrelationMethod.RESOURCE_MATCH in methods_used:
            parts.append("same Foundry resource")
        
        if CorrelationMethod.METADATA_MATCH in methods_used:
            parts.append("metadata match")
        
        confidence_label = confidence.value.capitalize()
        methods_str = ", ".join(parts) if parts else "weak signals"
        
        return f"{confidence_label} confidence: {methods_str}"
    
    # -------------------------------------------------------------------------
    # Public Correlation API
    # -------------------------------------------------------------------------
    
    def correlate_alert_to_run(
        self,
        alert: DefenderAlert,
        run: AttackResult,
        time_window_seconds: int = 300,
    ) -> AlertCorrelation:
        """
        Calculate correlation between a single alert and run.
        
        Args:
            alert: Defender alert to correlate
            run: Attack run to correlate with
            time_window_seconds: Time window for timestamp proximity
            
        Returns:
            AlertCorrelation with confidence, score, and details
        """
        score, methods_used, match_details = self._calculate_correlation_score(
            alert, run, time_window_seconds
        )
        
        confidence = self._score_to_confidence(score)
        reason = self._generate_reason(confidence, methods_used, match_details)
        
        return AlertCorrelation(
            alert_id=alert.alert_id,
            run_id=run.run_id,
            confidence=confidence,
            methods_used=methods_used,
            score=round(score, 3),
            reason=reason,
            match_details=match_details,
            correlated_at=datetime.utcnow(),
            agent_id=run.agent_id,
            campaign_id=run.campaign_id,
        )
    
    def find_best_run_for_alert(
        self,
        alert: DefenderAlert,
        runs: List[AttackResult],
        time_window_seconds: int = 300,
        min_confidence: CorrelationConfidence = CorrelationConfidence.LOW,
    ) -> Optional[AlertCorrelation]:
        """
        Find the best matching run for an alert from a list of runs.
        
        Args:
            alert: Defender alert to correlate
            runs: List of attack runs to consider
            time_window_seconds: Time window for timestamp proximity
            min_confidence: Minimum confidence to return a match
            
        Returns:
            Best AlertCorrelation if above threshold, None otherwise
        """
        best_correlation: Optional[AlertCorrelation] = None
        best_score = 0.0
        
        for run in runs:
            correlation = self.correlate_alert_to_run(alert, run, time_window_seconds)
            
            if correlation.score > best_score:
                best_score = correlation.score
                best_correlation = correlation
        
        # Check if best match meets minimum confidence
        if best_correlation:
            min_score = CONFIDENCE_THRESHOLDS.get(min_confidence, 0.0)
            if best_correlation.score < min_score:
                return None
        
        return best_correlation
    
    def correlate_alerts(
        self,
        request: CorrelationRequest,
    ) -> CorrelationResult:
        """
        Correlate multiple alerts with runs based on request parameters.
        
        Args:
            request: Correlation request with filters and options
            
        Returns:
            CorrelationResult with all found correlations
        """
        store = get_store()
        
        # Get alerts to process
        if request.alert_ids:
            alerts = [
                store.get_defender_alert(aid) 
                for aid in request.alert_ids
            ]
            alerts = [a for a in alerts if a is not None]
        else:
            # Get all unlinked alerts
            all_alerts = store.get_all_defender_alerts(limit=500)
            alerts = [a for a in all_alerts if not a.linked_run_id]
        
        # Get runs to consider
        if request.run_ids:
            runs = [store.get_result(rid) for rid in request.run_ids]
            runs = [r for r in runs if r is not None]
        else:
            # Get recent runs (within expanded time window)
            runs = store.get_all_results(limit=500)
        
        correlations: List[AlertCorrelation] = []
        unlinked_alert_ids: List[str] = []
        linked_count = 0
        
        for alert in alerts:
            best_match = self.find_best_run_for_alert(
                alert,
                runs,
                time_window_seconds=request.time_window_seconds,
                min_confidence=request.min_confidence,
            )
            
            if best_match and best_match.confidence != CorrelationConfidence.UNLINKED:
                correlations.append(best_match)
                
                # Auto-link if requested
                if request.auto_link:
                    self._apply_correlation_link(alert, best_match, store)
                    linked_count += 1
            else:
                unlinked_alert_ids.append(alert.alert_id)
        
        return CorrelationResult(
            total_alerts_processed=len(alerts),
            total_runs_considered=len(runs),
            correlations_found=len(correlations),
            correlations_linked=linked_count,
            correlations=correlations,
            unlinked_alert_ids=unlinked_alert_ids,
        )
    
    def _apply_correlation_link(
        self,
        alert: DefenderAlert,
        correlation: AlertCorrelation,
        store,
    ) -> None:
        """
        Apply the correlation by updating both alert and run records.
        """
        # Update alert with linked run ID
        alert.linked_run_id = correlation.run_id
        alert.linked_agent_id = correlation.agent_id
        alert.linked_campaign_id = correlation.campaign_id
        alert.updated_at = datetime.utcnow()
        store.save_defender_alert(alert)
        
        # Update run with linked alert
        run = store.get_result(correlation.run_id)
        if run:
            linked_alert = {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "severity": alert.severity.value,
                "category": alert.category,
                "timestamp": alert.timestamp.isoformat(),
                "correlation": {
                    "confidence": correlation.confidence.value,
                    "score": correlation.score,
                    "methods_used": [m.value for m in correlation.methods_used],
                    "reason": correlation.reason,
                },
            }
            
            # Add to linked alerts if not already present
            existing_ids = [la.get("alert_id") for la in run.linked_defender_alerts]
            if alert.alert_id not in existing_ids:
                run.linked_defender_alerts.append(linked_alert)
                store.save_result(run)
        
        logger.info(
            f"Linked alert {alert.alert_id[:8]}... to run {correlation.run_id[:8]}... "
            f"(confidence={correlation.confidence.value}, score={correlation.score})"
        )
    
    def manually_link_alert_to_run(
        self,
        alert_id: str,
        run_id: str,
    ) -> Optional[AlertCorrelation]:
        """
        Manually link an alert to a run, bypassing confidence checks.
        
        Args:
            alert_id: Defender alert ID
            run_id: Attack run ID
            
        Returns:
            AlertCorrelation if successful, None if alert/run not found
        """
        store = get_store()
        
        alert = store.get_defender_alert(alert_id)
        run = store.get_result(run_id)
        
        if not alert or not run:
            return None
        
        # Create manual correlation
        correlation = AlertCorrelation(
            alert_id=alert_id,
            run_id=run_id,
            confidence=CorrelationConfidence.HIGH,
            methods_used=[CorrelationMethod.MANUAL],
            score=1.0,
            reason="Manually linked by user",
            match_details={"manual": True},
            correlated_at=datetime.utcnow(),
            agent_id=run.agent_id,
            campaign_id=run.campaign_id,
        )
        
        # Apply the link
        self._apply_correlation_link(alert, correlation, store)
        
        return correlation
    
    def unlink_alert_from_run(
        self,
        alert_id: str,
    ) -> bool:
        """
        Remove the link between an alert and its associated run.
        
        Args:
            alert_id: Defender alert ID to unlink
            
        Returns:
            True if unlinked successfully, False if alert not found
        """
        store = get_store()
        
        alert = store.get_defender_alert(alert_id)
        if not alert:
            return False
        
        run_id = alert.linked_run_id
        
        # Clear alert links
        alert.linked_run_id = None
        alert.linked_agent_id = None
        alert.linked_campaign_id = None
        alert.updated_at = datetime.utcnow()
        store.save_defender_alert(alert)
        
        # Remove from run's linked alerts if we had a run link
        if run_id:
            run = store.get_result(run_id)
            if run:
                run.linked_defender_alerts = [
                    la for la in run.linked_defender_alerts
                    if la.get("alert_id") != alert_id
                ]
                store.save_result(run)
        
        logger.info(f"Unlinked alert {alert_id[:8]}...")
        return True
    
    def get_alerts_for_run(
        self,
        run_id: str,
    ) -> List[DefenderAlert]:
        """
        Get all Defender alerts linked to a specific run.
        
        Args:
            run_id: Attack run ID
            
        Returns:
            List of DefenderAlert objects linked to the run
        """
        store = get_store()
        return store.get_all_defender_alerts(linked_run_id=run_id)
    
    def get_runs_for_alert(
        self,
        alert_id: str,
    ) -> List[AttackResult]:
        """
        Get all runs linked to a specific alert.
        (Usually just one, but could be multiple if manually linked)
        
        Args:
            alert_id: Defender alert ID
            
        Returns:
            List of AttackResult objects linked to the alert
        """
        store = get_store()
        alert = store.get_defender_alert(alert_id)
        
        if not alert or not alert.linked_run_id:
            return []
        
        run = store.get_result(alert.linked_run_id)
        return [run] if run else []


# Module-level singleton accessor
_service_instance: Optional[DefenderAlertCorrelationService] = None


def get_correlation_service() -> DefenderAlertCorrelationService:
    """Get the singleton DefenderAlertCorrelationService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = DefenderAlertCorrelationService()
    return _service_instance
