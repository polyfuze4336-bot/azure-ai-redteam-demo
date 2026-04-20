"""
In-memory storage for demo purposes.
Replace with Azure Cosmos DB or other persistence for production.
"""

from typing import List, Optional, Dict
from datetime import datetime
import threading

from models.schemas import (
    AttackResult, 
    CampaignResult, 
    CampaignStatus,
    DefenderAlert,
    DefenderAlertStatus,
    DefenderAlertSeverity,
    DefenderAlertSource,
    PurviewGovernanceEvent,
    PurviewEventType,
    PurviewEventStatus,
    PurviewEventSource,
    PurviewPolicyAction,
)


class MemoryStore:
    """
    Thread-safe in-memory storage for attack results and campaigns.
    Suitable for demo purposes - no persistence across restarts.
    """
    
    _instance = None
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
        if self._initialized:
            return
        
        self._results: Dict[str, AttackResult] = {}
        self._campaigns: Dict[str, CampaignResult] = {}
        self._defender_alerts: Dict[str, DefenderAlert] = {}
        self._purview_events: Dict[str, PurviewGovernanceEvent] = {}
        self._results_lock = threading.Lock()
        self._campaigns_lock = threading.Lock()
        self._alerts_lock = threading.Lock()
        self._purview_lock = threading.Lock()
        self._initialized = True
    
    # -------------------------------------------------------------------------
    # Attack Results
    # -------------------------------------------------------------------------
    
    def save_result(self, result: AttackResult) -> AttackResult:
        """Save an attack result."""
        with self._results_lock:
            self._results[result.run_id] = result
        return result
    
    def get_result(self, run_id: str) -> Optional[AttackResult]:
        """Get a specific attack result by ID."""
        with self._results_lock:
            return self._results.get(run_id)
    
    def get_all_results(
        self, 
        limit: int = 100, 
        offset: int = 0,
        category: Optional[str] = None,
        campaign_id: Optional[str] = None
    ) -> List[AttackResult]:
        """Get all attack results with optional filtering."""
        with self._results_lock:
            results = list(self._results.values())
        
        # Sort by timestamp descending (newest first)
        results.sort(key=lambda r: r.timestamp, reverse=True)
        
        # Apply filters
        if category:
            results = [r for r in results if r.attack_category.value == category]
        if campaign_id:
            results = [r for r in results if r.campaign_id == campaign_id]
        
        # Apply pagination
        return results[offset:offset + limit]
    
    def count_results(self) -> int:
        """Get total count of results."""
        with self._results_lock:
            return len(self._results)
    
    def delete_result(self, run_id: str) -> bool:
        """Delete a specific result."""
        with self._results_lock:
            if run_id in self._results:
                del self._results[run_id]
                return True
            return False
    
    # Aliases for correlation service compatibility
    def get_run(self, run_id: str) -> Optional[AttackResult]:
        """Alias for get_result - used by correlation services."""
        return self.get_result(run_id)
    
    def get_all_runs(self, limit: int = 100, offset: int = 0) -> List[AttackResult]:
        """Alias for get_all_results - used by correlation services."""
        return self.get_all_results(limit=limit, offset=offset)
    
    def update_run(self, run_id: str, updates: Dict) -> Optional[AttackResult]:
        """
        Update specific fields on an attack result.
        
        Args:
            run_id: ID of the run to update
            updates: Dictionary of field names and values to update
            
        Returns:
            Updated AttackResult or None if not found
        """
        with self._results_lock:
            if run_id not in self._results:
                return None
            
            result = self._results[run_id]
            
            # Apply updates to mutable fields
            for key, value in updates.items():
                if hasattr(result, key):
                    setattr(result, key, value)
            
            return result
    
    # -------------------------------------------------------------------------
    # Campaigns
    # -------------------------------------------------------------------------
    
    def save_campaign(self, campaign: CampaignResult) -> CampaignResult:
        """Save or update a campaign."""
        with self._campaigns_lock:
            self._campaigns[campaign.campaign_id] = campaign
        return campaign
    
    def get_campaign(self, campaign_id: str) -> Optional[CampaignResult]:
        """Get a specific campaign by ID."""
        with self._campaigns_lock:
            return self._campaigns.get(campaign_id)
    
    def get_all_campaigns(self, limit: int = 50, offset: int = 0) -> List[CampaignResult]:
        """Get all campaigns."""
        with self._campaigns_lock:
            campaigns = list(self._campaigns.values())
        
        # Sort by created_at descending
        campaigns.sort(key=lambda c: c.created_at, reverse=True)
        
        return campaigns[offset:offset + limit]
    
    def count_campaigns(self) -> int:
        """Get total count of campaigns."""
        with self._campaigns_lock:
            return len(self._campaigns)
    
    def update_campaign_status(
        self, 
        campaign_id: str, 
        status: CampaignStatus,
        completed_at: Optional[datetime] = None
    ) -> Optional[CampaignResult]:
        """Update campaign status."""
        with self._campaigns_lock:
            if campaign_id in self._campaigns:
                campaign = self._campaigns[campaign_id]
                campaign.status = status
                if completed_at:
                    campaign.completed_at = completed_at
                return campaign
            return None
    
    def update_campaign_metrics(
        self,
        campaign_id: str,
        campaign: CampaignResult,
    ) -> Optional[CampaignResult]:
        """Update campaign with final metrics."""
        with self._campaigns_lock:
            if campaign_id in self._campaigns:
                self._campaigns[campaign_id] = campaign
                return campaign
            return None
    
    def add_result_to_campaign(
        self, 
        campaign_id: str, 
        result: AttackResult
    ) -> Optional[CampaignResult]:
        """Add a result to a campaign and update stats."""
        with self._campaigns_lock:
            if campaign_id not in self._campaigns:
                return None
            
            campaign = self._campaigns[campaign_id]
            campaign.results.append(result)
            campaign.total_attacks += 1
            
            # Update counters based on outcome
            if result.outcome.value == "safe":
                campaign.blocked_count += 1
            elif result.outcome.value == "vulnerable":
                campaign.passed_count += 1
            else:
                campaign.flagged_count += 1
            
            return campaign
    
    # -------------------------------------------------------------------------
    # Defender Alerts
    # -------------------------------------------------------------------------
    
    def save_defender_alert(self, alert: DefenderAlert) -> DefenderAlert:
        """Save a Defender alert."""
        with self._alerts_lock:
            self._defender_alerts[alert.alert_id] = alert
        return alert
    
    def save_defender_alerts(self, alerts: List[DefenderAlert]) -> List[DefenderAlert]:
        """Save multiple Defender alerts."""
        with self._alerts_lock:
            for alert in alerts:
                self._defender_alerts[alert.alert_id] = alert
        return alerts
    
    def get_defender_alert(self, alert_id: str) -> Optional[DefenderAlert]:
        """Get a specific Defender alert by ID."""
        with self._alerts_lock:
            return self._defender_alerts.get(alert_id)
    
    def get_all_defender_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[List[DefenderAlertSeverity]] = None,
        status: Optional[List[DefenderAlertStatus]] = None,
        source: Optional[List[DefenderAlertSource]] = None,
        correlation_id: Optional[str] = None,
        linked_run_id: Optional[str] = None,
        linked_agent_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[DefenderAlert]:
        """Get all Defender alerts with optional filtering."""
        with self._alerts_lock:
            alerts = list(self._defender_alerts.values())
        
        # Sort by timestamp descending (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        
        # Apply filters
        if severity:
            alerts = [a for a in alerts if a.severity in severity]
        if status:
            alerts = [a for a in alerts if a.status in status]
        if source:
            alerts = [a for a in alerts if a.source in source]
        if correlation_id:
            alerts = [a for a in alerts if a.correlation_id == correlation_id]
        if linked_run_id:
            alerts = [a for a in alerts if a.linked_run_id == linked_run_id]
        if linked_agent_id:
            alerts = [a for a in alerts if a.linked_agent_id == linked_agent_id]
        if start_time:
            alerts = [a for a in alerts if a.timestamp >= start_time]
        if end_time:
            alerts = [a for a in alerts if a.timestamp <= end_time]
        
        # Apply pagination
        return alerts[offset:offset + limit]
    
    def count_defender_alerts(self) -> int:
        """Get total count of Defender alerts."""
        with self._alerts_lock:
            return len(self._defender_alerts)
    
    def update_defender_alert_status(
        self,
        alert_id: str,
        status: DefenderAlertStatus,
    ) -> Optional[DefenderAlert]:
        """Update a Defender alert's status."""
        with self._alerts_lock:
            if alert_id in self._defender_alerts:
                self._defender_alerts[alert_id].status = status
                self._defender_alerts[alert_id].updated_at = datetime.utcnow()
                return self._defender_alerts[alert_id]
            return None
    
    def link_alert_to_run(
        self,
        alert_id: str,
        run_id: str,
    ) -> Optional[DefenderAlert]:
        """Link a Defender alert to an attack run."""
        with self._alerts_lock:
            if alert_id in self._defender_alerts:
                self._defender_alerts[alert_id].linked_run_id = run_id
                self._defender_alerts[alert_id].updated_at = datetime.utcnow()
                return self._defender_alerts[alert_id]
            return None
    
    def link_alert_to_agent(
        self,
        alert_id: str,
        agent_id: str,
    ) -> Optional[DefenderAlert]:
        """Link a Defender alert to an agent profile."""
        with self._alerts_lock:
            if alert_id in self._defender_alerts:
                self._defender_alerts[alert_id].linked_agent_id = agent_id
                self._defender_alerts[alert_id].updated_at = datetime.utcnow()
                return self._defender_alerts[alert_id]
            return None
    
    def delete_defender_alert(self, alert_id: str) -> bool:
        """Delete a specific Defender alert."""
        with self._alerts_lock:
            if alert_id in self._defender_alerts:
                del self._defender_alerts[alert_id]
                return True
            return False
    
    def clear_defender_alerts(self) -> None:
        """Clear all Defender alerts."""
        with self._alerts_lock:
            self._defender_alerts.clear()
    
    # -------------------------------------------------------------------------
    # Purview Governance Events
    # -------------------------------------------------------------------------
    
    def save_purview_event(self, event: PurviewGovernanceEvent) -> PurviewGovernanceEvent:
        """Save a Purview governance event."""
        with self._purview_lock:
            self._purview_events[event.event_id] = event
        return event
    
    def save_purview_events(self, events: List[PurviewGovernanceEvent]) -> List[PurviewGovernanceEvent]:
        """Save multiple Purview governance events."""
        with self._purview_lock:
            for event in events:
                self._purview_events[event.event_id] = event
        return events
    
    def get_purview_event(self, event_id: str) -> Optional[PurviewGovernanceEvent]:
        """Get a specific Purview governance event by ID."""
        with self._purview_lock:
            return self._purview_events.get(event_id)
    
    def get_all_purview_events(
        self,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[List[PurviewEventType]] = None,
        status: Optional[List[PurviewEventStatus]] = None,
        policy_action: Optional[List[PurviewPolicyAction]] = None,
        source: Optional[List[PurviewEventSource]] = None,
        policy_name: Optional[str] = None,
        classification: Optional[str] = None,
        linked_run_id: Optional[str] = None,
        linked_agent_id: Optional[str] = None,
        linked_campaign_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[PurviewGovernanceEvent]:
        """Get all Purview governance events with optional filtering."""
        with self._purview_lock:
            events = list(self._purview_events.values())
        
        # Sort by timestamp descending (newest first)
        events.sort(key=lambda e: e.timestamp, reverse=True)
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type in event_type]
        if status:
            events = [e for e in events if e.status in status]
        if policy_action:
            events = [e for e in events if e.policy_action in policy_action]
        if source:
            events = [e for e in events if e.source in source]
        if policy_name:
            events = [e for e in events if policy_name.lower() in e.policy_name.lower()]
        if classification:
            events = [e for e in events if e.classification == classification]
        if linked_run_id:
            events = [e for e in events if e.linked_run_id == linked_run_id]
        if linked_agent_id:
            events = [e for e in events if e.linked_agent_id == linked_agent_id]
        if linked_campaign_id:
            events = [e for e in events if e.linked_campaign_id == linked_campaign_id]
        if correlation_id:
            events = [e for e in events if e.correlation_id == correlation_id]
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        
        # Apply pagination
        return events[offset:offset + limit]
    
    def count_purview_events(self) -> int:
        """Get total count of Purview governance events."""
        with self._purview_lock:
            return len(self._purview_events)
    
    def update_purview_event_status(
        self,
        event_id: str,
        status: PurviewEventStatus,
    ) -> Optional[PurviewGovernanceEvent]:
        """Update a Purview governance event's status."""
        with self._purview_lock:
            if event_id in self._purview_events:
                self._purview_events[event_id].status = status
                return self._purview_events[event_id]
            return None
    
    def link_purview_event_to_run(
        self,
        event_id: str,
        run_id: str,
        correlation_id: Optional[str] = None,
    ) -> Optional[PurviewGovernanceEvent]:
        """Link a Purview governance event to an attack run."""
        with self._purview_lock:
            if event_id in self._purview_events:
                self._purview_events[event_id].linked_run_id = run_id
                if correlation_id:
                    self._purview_events[event_id].correlation_id = correlation_id
                return self._purview_events[event_id]
            return None
    
    def link_purview_event_to_agent(
        self,
        event_id: str,
        agent_id: str,
    ) -> Optional[PurviewGovernanceEvent]:
        """Link a Purview governance event to an agent profile."""
        with self._purview_lock:
            if event_id in self._purview_events:
                self._purview_events[event_id].linked_agent_id = agent_id
                return self._purview_events[event_id]
            return None
    
    def get_purview_events_for_run(self, run_id: str) -> List[PurviewGovernanceEvent]:
        """Get all Purview governance events linked to a specific run."""
        with self._purview_lock:
            return [e for e in self._purview_events.values() if e.linked_run_id == run_id]
    
    def get_purview_events_for_agent(self, agent_id: str) -> List[PurviewGovernanceEvent]:
        """Get all Purview governance events linked to a specific agent."""
        with self._purview_lock:
            return [e for e in self._purview_events.values() if e.linked_agent_id == agent_id]
    
    def delete_purview_event(self, event_id: str) -> bool:
        """Delete a specific Purview governance event."""
        with self._purview_lock:
            if event_id in self._purview_events:
                del self._purview_events[event_id]
                return True
            return False
    
    def clear_purview_events(self) -> None:
        """Clear all Purview governance events."""
        with self._purview_lock:
            self._purview_events.clear()
    
    # -------------------------------------------------------------------------
    # Utility
    # -------------------------------------------------------------------------
    
    def clear_all(self) -> None:
        """Clear all stored data (useful for testing)."""
        with self._results_lock:
            self._results.clear()
        with self._campaigns_lock:
            self._campaigns.clear()
        with self._alerts_lock:
            self._defender_alerts.clear()
        with self._purview_lock:
            self._purview_events.clear()
    
    def get_statistics(self) -> Dict:
        """Get overall statistics."""
        with self._results_lock:
            results = list(self._results.values())
        
        total = len(results)
        blocked = sum(1 for r in results if r.outcome.value == "safe")
        passed = sum(1 for r in results if r.outcome.value == "vulnerable")
        flagged = sum(1 for r in results if r.outcome.value == "partial")
        avg_latency = sum(r.latency_ms for r in results) / total if total > 0 else 0
        
        # Get alert statistics
        with self._alerts_lock:
            alerts = list(self._defender_alerts.values())
        total_alerts = len(alerts)
        high_severity_alerts = sum(
            1 for a in alerts 
            if a.severity in [DefenderAlertSeverity.HIGH, DefenderAlertSeverity.CRITICAL]
        )
        new_alerts = sum(1 for a in alerts if a.status == DefenderAlertStatus.NEW)
        
        return {
            "total_attacks": total,
            "blocked_count": blocked,
            "passed_count": passed,
            "flagged_count": flagged,
            "avg_latency_ms": round(avg_latency, 1),
            "block_rate": round((blocked / total) * 100, 1) if total > 0 else 0,
            "total_campaigns": self.count_campaigns(),
            "total_defender_alerts": total_alerts,
            "high_severity_alerts": high_severity_alerts,
            "new_alerts": new_alerts,
            "total_purview_events": self.count_purview_events(),
        }


# Module-level singleton accessor
_store_instance: Optional[MemoryStore] = None


def get_store() -> MemoryStore:
    """Get the singleton store instance."""
    global _store_instance
    if _store_instance is None:
        _store_instance = MemoryStore()
    return _store_instance
