"""
Purview Governance Event Correlation Service.

Correlates Purview governance events with attack runs and agents using
multiple methods:
- Correlation ID matching (highest confidence)
- Timestamp proximity
- Agent context matching
- Classification matching
- Policy context matching
- Resource matching
- Run metadata matching

The service implements a weighted scoring system that combines multiple
correlation signals to produce a confidence score and links events to
runs when confidence exceeds configurable thresholds.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

from models.schemas import (
    PurviewGovernanceEvent,
    PurviewEventType,
    PurviewPolicyAction,
    PurviewEventStatus,
    AttackResult,
    CampaignResult,
    CorrelationConfidence,
    PurviewCorrelationMethod,
    PurviewEventCorrelation,
    LinkedPurviewEvent,
    PurviewCorrelationRequest,
    PurviewCorrelationResult,
)
from storage import get_store

logger = logging.getLogger(__name__)


# =============================================================================
# CORRELATION WEIGHTS AND THRESHOLDS
# =============================================================================

# Weights for each correlation method (sum to calculate score)
CORRELATION_WEIGHTS = {
    PurviewCorrelationMethod.CORRELATION_ID: 0.50,      # Exact ID match is strongest
    PurviewCorrelationMethod.AGENT_CONTEXT: 0.20,       # Agent ID match
    PurviewCorrelationMethod.TIMESTAMP_PROXIMITY: 0.15, # Time-based match
    PurviewCorrelationMethod.CLASSIFICATION_MATCH: 0.10, # Classification match
    PurviewCorrelationMethod.POLICY_CONTEXT: 0.10,      # Policy context match  
    PurviewCorrelationMethod.RESOURCE_MATCH: 0.08,      # Resource name match
    PurviewCorrelationMethod.RUN_METADATA: 0.05,        # Metadata match
    PurviewCorrelationMethod.CAMPAIGN_LINK: 0.10,       # Campaign link
    PurviewCorrelationMethod.MANUAL: 1.0,               # Manual always high
}

# Confidence thresholds
CONFIDENCE_THRESHOLDS = {
    CorrelationConfidence.HIGH: 0.70,    # >= 70% = high confidence
    CorrelationConfidence.MEDIUM: 0.40,  # >= 40% = medium confidence
    CorrelationConfidence.LOW: 0.20,     # >= 20% = low confidence
    # < 20% = unlinked
}

# Time window for timestamp proximity (seconds)
DEFAULT_TIME_WINDOW_SECONDS = 300  # 5 minutes


# =============================================================================
# CORRELATION SERVICE
# =============================================================================

class PurviewCorrelationService:
    """
    Service for correlating Purview governance events with attack runs.
    
    Uses a multi-method approach to correlate events and runs:
    1. Check for exact correlation ID matches (highest confidence)
    2. Check agent context (agent_id matches)
    3. Check timestamp proximity
    4. Check classification level matches
    5. Check policy context from agent profiles
    6. Check resource name matches
    7. Check run metadata matches
    
    Produces a weighted score and confidence level for each correlation.
    """
    
    def __init__(self):
        self._correlation_cache: Dict[str, PurviewEventCorrelation] = {}
        
    def clear_cache(self):
        """Clear the correlation cache."""
        self._correlation_cache.clear()
    
    # -------------------------------------------------------------------------
    # MAIN CORRELATION METHOD
    # -------------------------------------------------------------------------
    
    def correlate_events(
        self,
        request: PurviewCorrelationRequest,
    ) -> PurviewCorrelationResult:
        """
        Correlate Purview governance events with attack runs.
        
        Args:
            request: Correlation request with filters and options
            
        Returns:
            Correlation result with all correlations and statistics
        """
        store = get_store()
        
        # Get events to correlate
        if request.event_ids:
            events = [
                store.get_purview_event(eid) 
                for eid in request.event_ids 
                if store.get_purview_event(eid)
            ]
        else:
            # Get all unlinked events
            all_events = store.get_all_purview_events()
            events = [e for e in all_events if not e.linked_run_id]
        
        # Get runs to consider
        if request.run_ids:
            runs = [
                store.get_run(rid) 
                for rid in request.run_ids 
                if store.get_run(rid)
            ]
        else:
            # Get recent runs
            runs = store.get_all_runs(limit=500)
        
        # Filter by agent if specified
        if request.agent_id:
            events = [e for e in events if e.linked_agent_id == request.agent_id or not e.linked_agent_id]
            runs = [r for r in runs if r.agent_id == request.agent_id]
        
        # Perform correlation
        correlations: List[PurviewEventCorrelation] = []
        unlinked_event_ids: List[str] = []
        method_breakdown: Dict[str, int] = {}
        
        for event in events:
            best_correlation = self._find_best_correlation(
                event=event,
                runs=runs,
                request=request,
            )
            
            if best_correlation and best_correlation.confidence != CorrelationConfidence.UNLINKED:
                correlations.append(best_correlation)
                
                # Track methods used
                for method in best_correlation.methods_used:
                    method_breakdown[method.value] = method_breakdown.get(method.value, 0) + 1
                
                # Auto-link if requested and confidence meets threshold
                if request.auto_link:
                    if self._meets_threshold(best_correlation.confidence, request.min_confidence):
                        self._apply_correlation(event, best_correlation, store)
            else:
                unlinked_event_ids.append(event.event_id)
        
        # Calculate confidence breakdown
        high_count = sum(1 for c in correlations if c.confidence == CorrelationConfidence.HIGH)
        medium_count = sum(1 for c in correlations if c.confidence == CorrelationConfidence.MEDIUM)
        low_count = sum(1 for c in correlations if c.confidence == CorrelationConfidence.LOW)
        
        return PurviewCorrelationResult(
            total_events_processed=len(events),
            total_runs_considered=len(runs),
            correlations_found=len(correlations),
            correlations_linked=len(correlations) if request.auto_link else 0,
            high_confidence_count=high_count,
            medium_confidence_count=medium_count,
            low_confidence_count=low_count,
            correlations=correlations,
            unlinked_event_ids=unlinked_event_ids,
            method_breakdown=method_breakdown,
        )
    
    def _find_best_correlation(
        self,
        event: PurviewGovernanceEvent,
        runs: List[AttackResult],
        request: PurviewCorrelationRequest,
    ) -> Optional[PurviewEventCorrelation]:
        """
        Find the best correlation for a single event across all runs.
        """
        best_correlation: Optional[PurviewEventCorrelation] = None
        best_score = 0.0
        
        for run in runs:
            correlation = self._correlate_event_to_run(
                event=event,
                run=run,
                request=request,
            )
            
            if correlation and correlation.score > best_score:
                best_score = correlation.score
                best_correlation = correlation
        
        return best_correlation
    
    def _correlate_event_to_run(
        self,
        event: PurviewGovernanceEvent,
        run: AttackResult,
        request: PurviewCorrelationRequest,
    ) -> Optional[PurviewEventCorrelation]:
        """
        Calculate correlation between a single event and run.
        """
        methods_used: List[PurviewCorrelationMethod] = []
        match_details: Dict[str, Any] = {}
        score = 0.0
        reasons: List[str] = []
        
        # 1. Correlation ID match (highest weight)
        if event.correlation_id and run.correlation_id:
            if event.correlation_id == run.correlation_id:
                methods_used.append(PurviewCorrelationMethod.CORRELATION_ID)
                score += CORRELATION_WEIGHTS[PurviewCorrelationMethod.CORRELATION_ID]
                match_details["correlation_id"] = {
                    "matched": True,
                    "value": event.correlation_id
                }
                reasons.append(f"Exact correlation ID match ({event.correlation_id[:12]}...)")
        
        # 2. Agent context match
        if event.linked_agent_id and run.agent_id:
            if event.linked_agent_id == run.agent_id:
                methods_used.append(PurviewCorrelationMethod.AGENT_CONTEXT)
                score += CORRELATION_WEIGHTS[PurviewCorrelationMethod.AGENT_CONTEXT]
                match_details["agent_context"] = {
                    "matched": True,
                    "agent_id": event.linked_agent_id
                }
                reasons.append(f"Agent ID match ({event.linked_agent_id})")
        
        # 3. Timestamp proximity
        time_delta = self._calculate_time_delta(event.timestamp, run.timestamp)
        if time_delta is not None:
            time_window = request.time_window_seconds
            if time_delta <= time_window:
                # Score decreases as time delta increases
                time_score_factor = 1.0 - (time_delta / time_window)
                adjusted_score = CORRELATION_WEIGHTS[PurviewCorrelationMethod.TIMESTAMP_PROXIMITY] * time_score_factor
                
                methods_used.append(PurviewCorrelationMethod.TIMESTAMP_PROXIMITY)
                score += adjusted_score
                match_details["timestamp_proximity"] = {
                    "matched": True,
                    "delta_seconds": time_delta,
                    "within_window": True,
                    "score_factor": time_score_factor
                }
                reasons.append(f"Timestamp within {int(time_delta)}s")
        
        # 4. Classification match (if enabled)
        if request.use_classification_matching and event.classification:
            agent_classification = self._get_run_classification(run)
            if agent_classification and event.classification.lower() == agent_classification.lower():
                methods_used.append(PurviewCorrelationMethod.CLASSIFICATION_MATCH)
                score += CORRELATION_WEIGHTS[PurviewCorrelationMethod.CLASSIFICATION_MATCH]
                match_details["classification"] = {
                    "matched": True,
                    "classification": event.classification
                }
                reasons.append(f"Classification match ({event.classification})")
        
        # 5. Policy context match (if enabled)
        if request.use_policy_context and event.policy_name:
            policy_match = self._check_policy_context_match(event, run)
            if policy_match:
                methods_used.append(PurviewCorrelationMethod.POLICY_CONTEXT)
                score += CORRELATION_WEIGHTS[PurviewCorrelationMethod.POLICY_CONTEXT]
                match_details["policy_context"] = {
                    "matched": True,
                    "policy_name": event.policy_name,
                    **policy_match
                }
                reasons.append(f"Policy context match ({event.policy_name})")
        
        # 6. Resource match
        if event.resource_name and run.foundry_resource_name:
            if event.resource_name.lower() == run.foundry_resource_name.lower():
                methods_used.append(PurviewCorrelationMethod.RESOURCE_MATCH)
                score += CORRELATION_WEIGHTS[PurviewCorrelationMethod.RESOURCE_MATCH]
                match_details["resource"] = {
                    "matched": True,
                    "resource_name": event.resource_name
                }
                reasons.append(f"Resource match ({event.resource_name})")
        
        # 7. Campaign link
        if event.linked_campaign_id and run.campaign_id:
            if event.linked_campaign_id == run.campaign_id:
                methods_used.append(PurviewCorrelationMethod.CAMPAIGN_LINK)
                score += CORRELATION_WEIGHTS[PurviewCorrelationMethod.CAMPAIGN_LINK]
                match_details["campaign"] = {
                    "matched": True,
                    "campaign_id": event.linked_campaign_id
                }
                reasons.append(f"Campaign link ({event.linked_campaign_id[:12]}...)")
        
        # 8. Run metadata match
        metadata_match = self._check_metadata_match(event, run)
        if metadata_match:
            methods_used.append(PurviewCorrelationMethod.RUN_METADATA)
            score += CORRELATION_WEIGHTS[PurviewCorrelationMethod.RUN_METADATA]
            match_details["metadata"] = {
                "matched": True,
                **metadata_match
            }
            reasons.append("Metadata match")
        
        # No matches found
        if not methods_used:
            return None
        
        # Determine confidence level
        confidence = self._score_to_confidence(score)
        
        # Build reason string
        reason = "; ".join(reasons) if reasons else "No strong correlation found"
        
        return PurviewEventCorrelation(
            event_id=event.event_id,
            run_id=run.run_id,
            confidence=confidence,
            methods_used=methods_used,
            score=min(score, 1.0),  # Cap at 1.0
            reason=reason,
            match_details=match_details,
            agent_id=event.linked_agent_id or run.agent_id,
            campaign_id=run.campaign_id,
            policy_name=event.policy_name,
            classification=event.classification,
        )
    
    # -------------------------------------------------------------------------
    # HELPER METHODS
    # -------------------------------------------------------------------------
    
    def _calculate_time_delta(
        self, 
        event_time: datetime, 
        run_time: datetime
    ) -> Optional[float]:
        """Calculate time difference in seconds between event and run."""
        try:
            delta = abs((event_time - run_time).total_seconds())
            return delta
        except Exception:
            return None
    
    def _get_run_classification(self, run: AttackResult) -> Optional[str]:
        """Extract classification from run's agent context snapshot."""
        if run.agent_context_snapshot:
            # Try direct classification field
            if "data_classification" in run.agent_context_snapshot:
                return run.agent_context_snapshot["data_classification"]
            # Try purview context
            if "purview_context" in run.agent_context_snapshot:
                purview = run.agent_context_snapshot["purview_context"]
                if isinstance(purview, dict) and "classification" in purview:
                    return purview["classification"]
        return None
    
    def _check_policy_context_match(
        self, 
        event: PurviewGovernanceEvent, 
        run: AttackResult
    ) -> Optional[Dict[str, Any]]:
        """
        Check if the event's policy matches the policy context in the run.
        """
        if not run.agent_context_snapshot:
            return None
        
        # Check various locations for policy info
        policy_sources = [
            run.agent_context_snapshot.get("policy_profile", {}),
            run.agent_context_snapshot.get("purview_context", {}),
            run.agent_context_snapshot.get("governance", {}),
        ]
        
        for source in policy_sources:
            if not isinstance(source, dict):
                continue
            
            # Check policy name
            source_policy = source.get("policy_name") or source.get("name") or source.get("policy_set_name")
            if source_policy and event.policy_name:
                if source_policy.lower() == event.policy_name.lower():
                    return {"matched_in": "agent_context_snapshot", "source_policy": source_policy}
                # Partial match
                if event.policy_name.lower() in source_policy.lower() or source_policy.lower() in event.policy_name.lower():
                    return {"matched_in": "agent_context_snapshot", "partial_match": True}
        
        return None
    
    def _check_metadata_match(
        self, 
        event: PurviewGovernanceEvent, 
        run: AttackResult
    ) -> Optional[Dict[str, Any]]:
        """
        Check for matching metadata between event and run.
        """
        matches = {}
        
        # Check if event references the run in its metadata
        if event.raw_metadata:
            if event.raw_metadata.get("run_id") == run.run_id:
                matches["run_id_in_event"] = True
            if event.raw_metadata.get("scenario_id") == run.scenario_id:
                matches["scenario_id_match"] = True
        
        # Check if run references the event
        if run.metadata:
            if run.metadata.get("purview_event_id") == event.event_id:
                matches["event_id_in_run"] = True
        
        # Check additional context matches
        if event.additional_context and run.metadata:
            for key in ["target", "deployment", "model"]:
                if key in event.additional_context and key in run.metadata:
                    if event.additional_context[key] == run.metadata[key]:
                        matches[f"{key}_match"] = True
        
        return matches if matches else None
    
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
    
    def _meets_threshold(
        self, 
        actual: CorrelationConfidence, 
        minimum: CorrelationConfidence
    ) -> bool:
        """Check if correlation meets the minimum confidence threshold."""
        confidence_order = [
            CorrelationConfidence.UNLINKED,
            CorrelationConfidence.LOW,
            CorrelationConfidence.MEDIUM,
            CorrelationConfidence.HIGH,
        ]
        return confidence_order.index(actual) >= confidence_order.index(minimum)
    
    def _apply_correlation(
        self,
        event: PurviewGovernanceEvent,
        correlation: PurviewEventCorrelation,
        store,
    ):
        """
        Apply the correlation by updating the event and run records.
        """
        # Update event with linked run ID
        store.link_purview_event_to_run(
            event_id=event.event_id,
            run_id=correlation.run_id,
            correlation_id=correlation.agent_id or None,
        )
        
        # Build linked event data for the run
        linked_event = LinkedPurviewEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            policy_name=event.policy_name,
            policy_action=event.policy_action,
            classification=event.classification,
            timestamp=event.timestamp,
            compliance_state=event.compliance_state,
            correlation=correlation,
        )
        
        # Add to run's linked events
        run = store.get_run(correlation.run_id)
        if run:
            linked_events = run.linked_purview_events or []
            # Avoid duplicates
            if not any(e.get("event_id") == event.event_id for e in linked_events):
                linked_events.append(linked_event.model_dump())
                store.update_run(correlation.run_id, {"linked_purview_events": linked_events})
        
        # Cache the correlation
        self._correlation_cache[event.event_id] = correlation
        
        logger.info(
            f"Linked Purview event {event.event_id} to run {correlation.run_id} "
            f"with confidence {correlation.confidence.value} (score: {correlation.score:.2f})"
        )
    
    # -------------------------------------------------------------------------
    # PUBLIC METHODS FOR MANUAL CORRELATION
    # -------------------------------------------------------------------------
    
    def link_event_manually(
        self,
        event_id: str,
        run_id: str,
        reason: str = "Manually linked by user",
    ) -> Optional[PurviewEventCorrelation]:
        """
        Manually link a governance event to a run.
        
        This creates a high-confidence correlation with MANUAL method.
        """
        store = get_store()
        
        event = store.get_purview_event(event_id)
        run = store.get_run(run_id)
        
        if not event or not run:
            return None
        
        correlation = PurviewEventCorrelation(
            event_id=event_id,
            run_id=run_id,
            confidence=CorrelationConfidence.HIGH,
            methods_used=[PurviewCorrelationMethod.MANUAL],
            score=1.0,
            reason=reason,
            match_details={"manual": True, "user_reason": reason},
            agent_id=event.linked_agent_id or run.agent_id,
            campaign_id=run.campaign_id,
            policy_name=event.policy_name,
            classification=event.classification,
        )
        
        self._apply_correlation(event, correlation, store)
        
        return correlation
    
    def unlink_event(self, event_id: str) -> bool:
        """
        Remove the correlation for an event.
        """
        store = get_store()
        
        event = store.get_purview_event(event_id)
        if not event or not event.linked_run_id:
            return False
        
        # Get the run and remove the linked event
        run = store.get_run(event.linked_run_id)
        if run and run.linked_purview_events:
            updated_events = [
                e for e in run.linked_purview_events 
                if e.get("event_id") != event_id
            ]
            store.update_run(event.linked_run_id, {"linked_purview_events": updated_events})
        
        # Clear the link from the event
        store.update_purview_event_status(event_id, PurviewEventStatus.PENDING)
        event.linked_run_id = None
        store.save_purview_event(event)
        
        # Remove from cache
        if event_id in self._correlation_cache:
            del self._correlation_cache[event_id]
        
        logger.info(f"Unlinked Purview event {event_id}")
        return True
    
    def get_correlation(self, event_id: str) -> Optional[PurviewEventCorrelation]:
        """Get the correlation for an event if it exists."""
        return self._correlation_cache.get(event_id)
    
    def get_linked_events_for_run(self, run_id: str) -> List[LinkedPurviewEvent]:
        """Get all governance events linked to a specific run."""
        store = get_store()
        run = store.get_run(run_id)
        
        if not run or not run.linked_purview_events:
            return []
        
        # Reconstruct LinkedPurviewEvent objects from stored data
        linked = []
        for data in run.linked_purview_events:
            try:
                linked.append(LinkedPurviewEvent(**data))
            except Exception as e:
                logger.warning(f"Failed to parse linked event: {e}")
        
        return linked


# =============================================================================
# SINGLETON ACCESSOR
# =============================================================================

_purview_correlation_service: Optional[PurviewCorrelationService] = None


def get_purview_correlation_service() -> PurviewCorrelationService:
    """Get the singleton Purview correlation service instance."""
    global _purview_correlation_service
    if _purview_correlation_service is None:
        _purview_correlation_service = PurviewCorrelationService()
    return _purview_correlation_service
