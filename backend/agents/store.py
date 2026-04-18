"""
Agent invocation history store.

Provides in-memory storage for agent invocation records with
querying capabilities for observability and debugging.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

from .models import (
    AgentInvocation,
    InvocationStatus,
    InvocationListResponse,
    InvocationSummary,
)


class AgentInvocationStore:
    """
    In-memory store for agent invocation history.
    
    Provides storage and querying for agent invocation records,
    supporting the observability goals of the demo.
    """
    
    _instance: Optional["AgentInvocationStore"] = None
    
    def __init__(self, max_history: int = 1000):
        """
        Initialize the invocation store.
        
        Args:
            max_history: Maximum number of invocations to retain
        """
        self._invocations: Dict[str, AgentInvocation] = {}
        self._by_agent: Dict[str, List[str]] = defaultdict(list)
        self._by_run: Dict[str, List[str]] = defaultdict(list)
        self._by_campaign: Dict[str, List[str]] = defaultdict(list)
        self._by_correlation: Dict[str, List[str]] = defaultdict(list)
        self._max_history = max_history
    
    def store(self, invocation: AgentInvocation) -> None:
        """
        Store an invocation record.
        
        Args:
            invocation: The invocation to store
        """
        inv_id = invocation.invocation_id
        
        # Store the invocation
        self._invocations[inv_id] = invocation
        
        # Update indices
        self._by_agent[invocation.agent_id].append(inv_id)
        
        if invocation.linked_run_id:
            self._by_run[invocation.linked_run_id].append(inv_id)
        
        if invocation.linked_campaign_id:
            self._by_campaign[invocation.linked_campaign_id].append(inv_id)
        
        if invocation.correlation_id:
            self._by_correlation[invocation.correlation_id].append(inv_id)
        
        # Enforce max history
        self._enforce_limit()
    
    def update(self, invocation: AgentInvocation) -> None:
        """
        Update an existing invocation record.
        
        Args:
            invocation: The updated invocation
        """
        if invocation.invocation_id in self._invocations:
            self._invocations[invocation.invocation_id] = invocation
    
    def get(self, invocation_id: str) -> Optional[AgentInvocation]:
        """Get an invocation by ID."""
        return self._invocations.get(invocation_id)
    
    def get_by_agent(
        self, 
        agent_id: str, 
        limit: int = 50
    ) -> List[AgentInvocation]:
        """Get invocations for a specific agent."""
        inv_ids = self._by_agent.get(agent_id, [])[-limit:]
        return [self._invocations[id] for id in reversed(inv_ids)]
    
    def get_by_run(self, run_id: str) -> List[AgentInvocation]:
        """Get all invocations linked to a run."""
        inv_ids = self._by_run.get(run_id, [])
        return [self._invocations[id] for id in inv_ids]
    
    def get_by_campaign(self, campaign_id: str) -> List[AgentInvocation]:
        """Get all invocations linked to a campaign."""
        inv_ids = self._by_campaign.get(campaign_id, [])
        return [self._invocations[id] for id in inv_ids]
    
    def get_by_correlation(self, correlation_id: str) -> List[AgentInvocation]:
        """Get all invocations with a correlation ID."""
        inv_ids = self._by_correlation.get(correlation_id, [])
        return [self._invocations[id] for id in inv_ids]
    
    def list_recent(
        self, 
        limit: int = 50, 
        offset: int = 0,
        status: Optional[InvocationStatus] = None,
        agent_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> InvocationListResponse:
        """
        List recent invocations with optional filtering.
        
        Args:
            limit: Maximum number to return
            offset: Number to skip
            status: Filter by status
            agent_id: Filter by agent
            since: Only include invocations after this time
            
        Returns:
            Paginated list response
        """
        # Get all invocations sorted by timestamp (newest first)
        invocations = sorted(
            self._invocations.values(),
            key=lambda x: x.timestamp,
            reverse=True
        )
        
        # Apply filters
        if status is not None:
            invocations = [i for i in invocations if i.status == status]
        
        if agent_id is not None:
            invocations = [i for i in invocations if i.agent_id == agent_id]
        
        if since is not None:
            invocations = [i for i in invocations if i.timestamp >= since]
        
        total = len(invocations)
        
        # Apply pagination
        page_invocations = invocations[offset:offset + limit]
        
        return InvocationListResponse(
            invocations=page_invocations,
            total=total,
            page=(offset // limit) + 1 if limit > 0 else 1,
            page_size=limit,
        )
    
    def get_summary(
        self, 
        since: Optional[datetime] = None
    ) -> InvocationSummary:
        """
        Get summary statistics for invocations.
        
        Args:
            since: Only include invocations after this time
            
        Returns:
            Summary statistics
        """
        invocations = list(self._invocations.values())
        
        if since is not None:
            invocations = [i for i in invocations if i.timestamp >= since]
        
        if not invocations:
            return InvocationSummary(
                total_invocations=0,
                completed_count=0,
                failed_count=0,
                pending_count=0,
                average_latency_ms=0.0,
                by_agent={},
                by_status={},
            )
        
        # Count by status
        by_status: Dict[str, int] = defaultdict(int)
        by_agent: Dict[str, int] = defaultdict(int)
        total_latency = 0
        completed_count = 0
        
        for inv in invocations:
            by_status[inv.status.value] += 1
            by_agent[inv.agent_name] += 1
            
            if inv.status == InvocationStatus.COMPLETED:
                total_latency += inv.latency_ms
                completed_count += 1
        
        avg_latency = total_latency / completed_count if completed_count > 0 else 0.0
        
        return InvocationSummary(
            total_invocations=len(invocations),
            completed_count=by_status.get("completed", 0),
            failed_count=by_status.get("failed", 0),
            pending_count=by_status.get("pending", 0) + by_status.get("running", 0),
            average_latency_ms=round(avg_latency, 2),
            by_agent=dict(by_agent),
            by_status=dict(by_status),
        )
    
    def clear(self) -> None:
        """Clear all invocation history."""
        self._invocations.clear()
        self._by_agent.clear()
        self._by_run.clear()
        self._by_campaign.clear()
        self._by_correlation.clear()
    
    def _enforce_limit(self) -> None:
        """Remove oldest invocations if over limit."""
        if len(self._invocations) <= self._max_history:
            return
        
        # Sort by timestamp and remove oldest
        sorted_invocations = sorted(
            self._invocations.items(),
            key=lambda x: x[1].timestamp
        )
        
        to_remove = len(self._invocations) - self._max_history
        for inv_id, inv in sorted_invocations[:to_remove]:
            self._remove_from_indices(inv_id, inv)
            del self._invocations[inv_id]
    
    def _remove_from_indices(self, inv_id: str, inv: AgentInvocation) -> None:
        """Remove an invocation from all indices."""
        if inv_id in self._by_agent.get(inv.agent_id, []):
            self._by_agent[inv.agent_id].remove(inv_id)
        
        if inv.linked_run_id and inv_id in self._by_run.get(inv.linked_run_id, []):
            self._by_run[inv.linked_run_id].remove(inv_id)
        
        if inv.linked_campaign_id and inv_id in self._by_campaign.get(inv.linked_campaign_id, []):
            self._by_campaign[inv.linked_campaign_id].remove(inv_id)
        
        if inv.correlation_id and inv_id in self._by_correlation.get(inv.correlation_id, []):
            self._by_correlation[inv.correlation_id].remove(inv_id)
    
    @property
    def count(self) -> int:
        """Get total number of stored invocations."""
        return len(self._invocations)


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_store_instance: Optional[AgentInvocationStore] = None


def get_agent_store() -> AgentInvocationStore:
    """Get the singleton agent invocation store instance."""
    global _store_instance
    if _store_instance is None:
        _store_instance = AgentInvocationStore()
    return _store_instance
