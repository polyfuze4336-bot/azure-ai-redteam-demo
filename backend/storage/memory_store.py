"""
In-memory storage for demo purposes.
Replace with Azure Cosmos DB or other persistence for production.
"""

from typing import List, Optional, Dict
from datetime import datetime
import threading

from models.schemas import AttackResult, CampaignResult, CampaignStatus


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
        self._results_lock = threading.Lock()
        self._campaigns_lock = threading.Lock()
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
    # Utility
    # -------------------------------------------------------------------------
    
    def clear_all(self) -> None:
        """Clear all stored data (useful for testing)."""
        with self._results_lock:
            self._results.clear()
        with self._campaigns_lock:
            self._campaigns.clear()
    
    def get_statistics(self) -> Dict:
        """Get overall statistics."""
        with self._results_lock:
            results = list(self._results.values())
        
        total = len(results)
        blocked = sum(1 for r in results if r.outcome.value == "safe")
        passed = sum(1 for r in results if r.outcome.value == "vulnerable")
        flagged = sum(1 for r in results if r.outcome.value == "partial")
        avg_latency = sum(r.latency_ms for r in results) / total if total > 0 else 0
        
        return {
            "total_attacks": total,
            "blocked_count": blocked,
            "passed_count": passed,
            "flagged_count": flagged,
            "avg_latency_ms": round(avg_latency, 1),
            "block_rate": round((blocked / total) * 100, 1) if total > 0 else 0,
            "total_campaigns": self.count_campaigns(),
        }


# Module-level singleton accessor
_store_instance: Optional[MemoryStore] = None


def get_store() -> MemoryStore:
    """Get the singleton store instance."""
    global _store_instance
    if _store_instance is None:
        _store_instance = MemoryStore()
    return _store_instance
