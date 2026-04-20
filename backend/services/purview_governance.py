"""
Microsoft Purview Governance Event Ingestion Service.

Retrieves real Purview governance context, policy evaluations, and compliance
events from Microsoft Purview APIs or configured adapters. Normalizes data
into the internal governance event model for the Secure Agent Lifecycle demo.

This service supports multiple ingestion modes:
- Direct Purview API connection via Microsoft Graph
- Azure Activity Log monitoring for governance events
- Adapter/import mode for pre-configured governance records
- Manual event injection for demo scenarios

The design is modular to support real governance when available while
maintaining demo functionality when direct API access is limited.
"""

import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum
import httpx

from models.schemas import (
    PurviewGovernanceEvent,
    PurviewEventType,
    PurviewPolicyAction,
    PurviewEventStatus,
    PurviewEventSource,
    PurviewEventFilter,
    PurviewIngestionStatus,
    PurviewCorrelationStats,
)

logger = logging.getLogger(__name__)


class PurviewConnectionState(str, Enum):
    """Connection state to Purview APIs."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ADAPTER_MODE = "adapter_mode"
    ERROR = "error"


class PurviewGovernanceIngestionService:
    """
    Service for ingesting Microsoft Purview governance events.
    
    Connects to Microsoft Purview APIs to retrieve real governance context,
    policy evaluations, and compliance events. Supports fallback to
    adapter/import mode when direct API access is unavailable.
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
        
        # Configuration from environment
        self._tenant_id = os.getenv("AZURE_TENANT_ID", "")
        self._client_id = os.getenv("PURVIEW_CLIENT_ID", os.getenv("AZURE_CLIENT_ID", ""))
        self._client_secret = os.getenv("PURVIEW_CLIENT_SECRET", os.getenv("AZURE_CLIENT_SECRET", ""))
        self._purview_account = os.getenv("PURVIEW_ACCOUNT_NAME", "")
        self._subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
        
        # Purview API endpoints
        self._graph_base_url = "https://graph.microsoft.com/v1.0"
        self._purview_base_url = f"https://{self._purview_account}.purview.azure.com" if self._purview_account else ""
        
        # State tracking
        self._connection_state = PurviewConnectionState.DISCONNECTED
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._last_sync: Optional[datetime] = None
        self._last_error: Optional[str] = None
        self._events_ingested: int = 0
        self._connection_method: str = "not_configured"
        
        # In-memory event cache
        self._event_cache: Dict[str, PurviewGovernanceEvent] = {}
        
        # Adapter mode flag - used when direct API unavailable but
        # governance records are available through import
        self._adapter_mode = False
        
        self._initialized = True
        logger.info("PurviewGovernanceIngestionService initialized")
    
    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------
    
    async def _get_access_token(self, scope: str = "https://graph.microsoft.com/.default") -> Optional[str]:
        """
        Get access token for Microsoft Graph or Purview API using client credentials flow.
        """
        if not self._tenant_id or not self._client_id or not self._client_secret:
            logger.warning("Purview API credentials not configured")
            return None
        
        # Check if existing token is still valid
        if self._access_token and self._token_expiry:
            if datetime.utcnow() < self._token_expiry - timedelta(minutes=5):
                return self._access_token
        
        token_url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(token_url, data=data)
                response.raise_for_status()
                token_data = response.json()
                
                self._access_token = token_data["access_token"]
                expires_in = token_data.get("expires_in", 3600)
                self._token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
                
                logger.info("Successfully obtained Purview API access token")
                return self._access_token
                
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get Purview access token: {e.response.status_code}")
            self._last_error = f"Authentication failed: {e.response.status_code}"
            return None
        except Exception as e:
            logger.error(f"Error getting Purview access token: {e}")
            self._last_error = f"Authentication error: {str(e)}"
            return None
    
    # -------------------------------------------------------------------------
    # Real Event Ingestion from Purview APIs
    # -------------------------------------------------------------------------
    
    async def _fetch_compliance_events_from_graph(
        self,
        filter_params: Optional[PurviewEventFilter] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch compliance and governance events from Microsoft Graph.
        
        Uses the /security/informationProtection APIs and compliance APIs
        to retrieve policy evaluation events.
        """
        token = await self._get_access_token("https://graph.microsoft.com/.default")
        if not token:
            logger.warning("No access token available, cannot fetch compliance events")
            return []
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        events = []
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # Try fetching from audit logs (compliance events)
                audit_url = f"{self._graph_base_url}/auditLogs/directoryAudits"
                
                params = {
                    "$top": filter_params.limit if filter_params else 50,
                    "$orderby": "activityDateTime desc",
                }
                
                # Filter for policy-related activities
                odata_filters = ["activityDisplayName eq 'Apply protection policy'"]
                
                if filter_params:
                    if filter_params.start_time:
                        odata_filters.append(f"activityDateTime ge {filter_params.start_time.isoformat()}Z")
                    if filter_params.end_time:
                        odata_filters.append(f"activityDateTime le {filter_params.end_time.isoformat()}Z")
                
                if odata_filters:
                    params["$filter"] = " and ".join(odata_filters)
                
                response = await client.get(audit_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    events.extend(data.get("value", []))
                    self._connection_state = PurviewConnectionState.CONNECTED
                    self._connection_method = "graph_api"
                    logger.info(f"Fetched {len(events)} audit events from Graph API")
                else:
                    logger.warning(f"Graph audit API returned {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Error fetching compliance events from Graph: {e}")
            self._last_error = f"Graph API error: {str(e)}"
        
        return events
    
    async def _fetch_policy_events_from_purview(
        self,
        filter_params: Optional[PurviewEventFilter] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch policy evaluation events directly from Purview Data Policy APIs.
        
        This connects to the Purview account's policy engine for real
        governance context.
        """
        if not self._purview_base_url:
            logger.debug("Purview account not configured, skipping direct API")
            return []
        
        # Purview uses a different scope
        token = await self._get_access_token(f"https://purview.azure.net/.default")
        if not token:
            return []
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        events = []
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # Query policy evaluation audit logs from Purview
                policy_url = f"{self._purview_base_url}/policystore/metadataRoleBinding"
                
                params = {
                    "api-version": "2022-11-01-preview",
                }
                
                response = await client.get(policy_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    events.extend(data.get("value", []))
                    self._connection_state = PurviewConnectionState.CONNECTED
                    self._connection_method = "purview_api"
                    logger.info(f"Fetched {len(events)} policy events from Purview")
                else:
                    logger.debug(f"Purview policy API returned {response.status_code}")
                    
        except Exception as e:
            logger.debug(f"Purview direct API not available: {e}")
        
        return events
    
    async def _fetch_activity_log_events(
        self,
        filter_params: Optional[PurviewEventFilter] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch governance-related events from Azure Activity Log.
        
        Monitors for policy-related operations on AI resources.
        """
        if not self._subscription_id:
            return []
        
        token = await self._get_access_token("https://management.azure.com/.default")
        if not token:
            return []
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=7)
        
        if filter_params:
            if filter_params.start_time:
                start_time = filter_params.start_time
            if filter_params.end_time:
                end_time = filter_params.end_time
        
        activity_url = (
            f"https://management.azure.com/subscriptions/{self._subscription_id}"
            f"/providers/microsoft.insights/eventtypes/management/values"
        )
        
        params = {
            "api-version": "2015-04-01",
            "$filter": (
                f"eventTimestamp ge '{start_time.isoformat()}Z' and "
                f"eventTimestamp le '{end_time.isoformat()}Z' and "
                "(resourceProvider eq 'Microsoft.Purview' or "
                "resourceProvider eq 'Microsoft.Authorization')"
            ),
        }
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(activity_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    events = data.get("value", [])
                    logger.info(f"Fetched {len(events)} governance events from Activity Log")
                    return events
                else:
                    logger.debug(f"Activity Log API returned {response.status_code}")
                    
        except Exception as e:
            logger.debug(f"Activity Log API error: {e}")
        
        return []
    
    # -------------------------------------------------------------------------
    # Event Normalization
    # -------------------------------------------------------------------------
    
    def _normalize_graph_audit_event(self, raw_event: Dict[str, Any]) -> PurviewGovernanceEvent:
        """
        Normalize a Graph audit log event into internal governance event model.
        """
        # Extract event details
        activity_name = raw_event.get("activityDisplayName", "Unknown Activity")
        activity_dt = raw_event.get("activityDateTime", "")
        
        # Determine event type from activity
        event_type = PurviewEventType.AUDIT_LOG
        if "protection" in activity_name.lower():
            event_type = PurviewEventType.POLICY_EVALUATION
        elif "classification" in activity_name.lower():
            event_type = PurviewEventType.CLASSIFICATION_APPLIED
        elif "label" in activity_name.lower():
            event_type = PurviewEventType.LABEL_CHANGE
        
        # Determine policy action
        result = raw_event.get("result", "success").lower()
        if result == "success":
            policy_action = PurviewPolicyAction.ALLOW
        elif result == "failure":
            policy_action = PurviewPolicyAction.DENY
        else:
            policy_action = PurviewPolicyAction.AUDIT
        
        # Parse timestamp
        timestamp = datetime.utcnow()
        if activity_dt:
            try:
                timestamp = datetime.fromisoformat(activity_dt.replace("Z", "+00:00")).replace(tzinfo=None)
            except:
                pass
        
        # Extract target resources
        target_resources = raw_event.get("targetResources", [])
        affected_entity = None
        if target_resources:
            affected_entity = target_resources[0].get("displayName", target_resources[0].get("id"))
        
        # Build description
        reason = raw_event.get("resultReason", "")
        description = f"{activity_name}"
        if reason:
            description += f": {reason}"
        
        return PurviewGovernanceEvent(
            event_id=raw_event.get("id", f"pgov-graph-{hash(activity_dt)}"),
            event_type=event_type,
            policy_name=raw_event.get("operationType", activity_name),
            policy_action=policy_action,
            classification=None,  # Extract from target if available
            timestamp=timestamp,
            processed_at=datetime.utcnow(),
            status=PurviewEventStatus.PROCESSED,
            source=PurviewEventSource.GRAPH_SECURITY_API,
            description=description,
            affected_entity=affected_entity,
            compliance_state="compliant" if result == "success" else "non_compliant",
            raw_metadata=raw_event,
        )
    
    def _normalize_activity_log_event(self, raw_event: Dict[str, Any]) -> PurviewGovernanceEvent:
        """
        Normalize an Azure Activity Log event into governance event model.
        """
        # Extract event details
        operation_name = raw_event.get("operationName", {}).get("localizedValue", "Unknown Operation")
        event_timestamp = raw_event.get("eventTimestamp", "")
        
        # Determine event type
        event_type = PurviewEventType.AUDIT_LOG
        if "policy" in operation_name.lower():
            event_type = PurviewEventType.POLICY_EVALUATION
        elif "role" in operation_name.lower():
            event_type = PurviewEventType.ACCESS_GRANTED
        
        # Determine action from status
        status_value = raw_event.get("status", {}).get("value", "")
        if status_value == "Succeeded":
            policy_action = PurviewPolicyAction.ALLOW
        elif status_value == "Failed":
            policy_action = PurviewPolicyAction.DENY
        else:
            policy_action = PurviewPolicyAction.AUDIT
        
        # Parse timestamp
        timestamp = datetime.utcnow()
        if event_timestamp:
            try:
                timestamp = datetime.fromisoformat(event_timestamp.replace("Z", "+00:00")).replace(tzinfo=None)
            except:
                pass
        
        # Extract resource info
        resource_id = raw_event.get("resourceId", "")
        resource_type = raw_event.get("resourceType", {}).get("localizedValue")
        
        return PurviewGovernanceEvent(
            event_id=raw_event.get("eventDataId", f"pgov-activity-{hash(event_timestamp)}"),
            event_type=event_type,
            policy_name=operation_name,
            policy_action=policy_action,
            timestamp=timestamp,
            processed_at=datetime.utcnow(),
            status=PurviewEventStatus.PROCESSED,
            source=PurviewEventSource.AZURE_ACTIVITY_LOG,
            resource_name=resource_id.split("/")[-1] if resource_id else None,
            resource_type=resource_type,
            description=raw_event.get("description", operation_name),
            compliance_state="compliant" if status_value == "Succeeded" else "non_compliant",
            raw_metadata=raw_event,
        )
    
    def _normalize_purview_policy_event(self, raw_event: Dict[str, Any]) -> PurviewGovernanceEvent:
        """
        Normalize a Purview policy event into internal model.
        """
        # Extract from Purview policy format
        binding_name = raw_event.get("properties", {}).get("bindingName", "Unknown Binding")
        status = raw_event.get("properties", {}).get("status", "active")
        
        event_type = PurviewEventType.POLICY_EVALUATION
        policy_action = PurviewPolicyAction.ALLOW if status == "active" else PurviewPolicyAction.DENY
        
        return PurviewGovernanceEvent(
            event_id=raw_event.get("id", f"pgov-purview-{hash(binding_name)}"),
            event_type=event_type,
            policy_name=binding_name,
            policy_action=policy_action,
            timestamp=datetime.utcnow(),
            processed_at=datetime.utcnow(),
            status=PurviewEventStatus.PROCESSED,
            source=PurviewEventSource.PURVIEW_POLICY_ENGINE,
            purview_account_name=self._purview_account,
            description=f"Policy binding: {binding_name}",
            compliance_state="compliant",
            raw_metadata=raw_event,
        )
    
    # -------------------------------------------------------------------------
    # Public API Methods
    # -------------------------------------------------------------------------
    
    async def get_events(
        self,
        filter_params: Optional[PurviewEventFilter] = None,
    ) -> List[PurviewGovernanceEvent]:
        """
        Get governance events with optional filtering.
        
        Attempts to retrieve from Purview APIs first, then falls back
        to cached/adapter events if needed.
        """
        # First try to get fresh events from real sources
        events = await self.sync_events(filter_params)
        
        # If no events from APIs, return from cache
        if not events:
            events = self._get_cached_events(filter_params)
        
        return events
    
    async def sync_events(
        self,
        filter_params: Optional[PurviewEventFilter] = None,
    ) -> List[PurviewGovernanceEvent]:
        """
        Sync governance events from all available sources.
        
        Attempts multiple sources in priority order:
        1. Direct Purview Policy API
        2. Microsoft Graph compliance APIs
        3. Azure Activity Log
        4. Cached/adapter events
        """
        all_events: List[PurviewGovernanceEvent] = []
        
        # Try each source in order
        try:
            # 1. Direct Purview API
            purview_raw = await self._fetch_policy_events_from_purview(filter_params)
            for raw in purview_raw:
                event = self._normalize_purview_policy_event(raw)
                all_events.append(event)
                self._event_cache[event.event_id] = event
            
            # 2. Graph compliance APIs
            graph_raw = await self._fetch_compliance_events_from_graph(filter_params)
            for raw in graph_raw:
                event = self._normalize_graph_audit_event(raw)
                all_events.append(event)
                self._event_cache[event.event_id] = event
            
            # 3. Activity Log
            activity_raw = await self._fetch_activity_log_events(filter_params)
            for raw in activity_raw:
                event = self._normalize_activity_log_event(raw)
                all_events.append(event)
                self._event_cache[event.event_id] = event
            
            if all_events:
                self._last_sync = datetime.utcnow()
                self._events_ingested += len(all_events)
                self._adapter_mode = False
                logger.info(f"Synced {len(all_events)} governance events from APIs")
            else:
                # No events from APIs - check adapter mode
                if self._event_cache:
                    self._adapter_mode = True
                    self._connection_state = PurviewConnectionState.ADAPTER_MODE
                    logger.info("No new API events, using adapter mode")
                    
        except Exception as e:
            logger.error(f"Error syncing governance events: {e}")
            self._last_error = str(e)
            self._connection_state = PurviewConnectionState.ERROR
        
        # Sort by timestamp descending
        all_events.sort(key=lambda e: e.timestamp, reverse=True)
        
        # Apply pagination
        if filter_params:
            all_events = all_events[filter_params.offset:filter_params.offset + filter_params.limit]
        
        return all_events
    
    def _get_cached_events(
        self,
        filter_params: Optional[PurviewEventFilter] = None,
    ) -> List[PurviewGovernanceEvent]:
        """Get events from cache with filtering."""
        events = list(self._event_cache.values())
        
        if filter_params:
            # Apply filters
            if filter_params.event_type:
                events = [e for e in events if e.event_type in filter_params.event_type]
            if filter_params.status:
                events = [e for e in events if e.status in filter_params.status]
            if filter_params.policy_action:
                events = [e for e in events if e.policy_action in filter_params.policy_action]
            if filter_params.policy_name:
                events = [e for e in events if filter_params.policy_name.lower() in e.policy_name.lower()]
            if filter_params.classification:
                events = [e for e in events if e.classification == filter_params.classification]
            if filter_params.linked_run_id:
                events = [e for e in events if e.linked_run_id == filter_params.linked_run_id]
            if filter_params.linked_agent_id:
                events = [e for e in events if e.linked_agent_id == filter_params.linked_agent_id]
            if filter_params.linked_campaign_id:
                events = [e for e in events if e.linked_campaign_id == filter_params.linked_campaign_id]
            if filter_params.correlation_id:
                events = [e for e in events if e.correlation_id == filter_params.correlation_id]
            if filter_params.source:
                events = [e for e in events if e.source in filter_params.source]
            if filter_params.start_time:
                events = [e for e in events if e.timestamp >= filter_params.start_time]
            if filter_params.end_time:
                events = [e for e in events if e.timestamp <= filter_params.end_time]
            
            # Sort and paginate
            events.sort(key=lambda e: e.timestamp, reverse=True)
            events = events[filter_params.offset:filter_params.offset + filter_params.limit]
        
        return events
    
    # -------------------------------------------------------------------------
    # Adapter/Import Methods
    # -------------------------------------------------------------------------
    
    def import_event(self, event: PurviewGovernanceEvent) -> PurviewGovernanceEvent:
        """
        Import a governance event through the adapter interface.
        
        Used when direct API access is limited but governance records
        are available through configured adapters or manual import.
        """
        event.processed_at = datetime.utcnow()
        if event.source == PurviewEventSource.ADAPTER_IMPORT:
            pass  # Already marked as adapter
        elif event.source == PurviewEventSource.MANUAL_ENTRY:
            pass  # Manual entry
        else:
            event.source = PurviewEventSource.ADAPTER_IMPORT
        
        self._event_cache[event.event_id] = event
        self._events_ingested += 1
        self._adapter_mode = True
        self._connection_state = PurviewConnectionState.ADAPTER_MODE
        
        logger.info(f"Imported governance event: {event.event_id}")
        return event
    
    def import_events_batch(
        self, 
        events: List[PurviewGovernanceEvent],
    ) -> int:
        """Import multiple governance events at once."""
        count = 0
        for event in events:
            self.import_event(event)
            count += 1
        return count
    
    def create_policy_evaluation_event(
        self,
        policy_name: str,
        action: PurviewPolicyAction,
        classification: Optional[str] = None,
        linked_agent_id: Optional[str] = None,
        linked_run_id: Optional[str] = None,
        compliance_state: str = "compliant",
        description: Optional[str] = None,
    ) -> PurviewGovernanceEvent:
        """
        Create a policy evaluation event for demo scenarios.
        
        This is used when real Purview API is not available but
        governance context needs to be demonstrated.
        """
        event = PurviewGovernanceEvent(
            event_type=PurviewEventType.POLICY_EVALUATION,
            policy_name=policy_name,
            policy_action=action,
            classification=classification,
            linked_agent_id=linked_agent_id,
            linked_run_id=linked_run_id,
            status=PurviewEventStatus.PROCESSED,
            source=PurviewEventSource.ADAPTER_IMPORT,
            purview_account_name=self._purview_account or "demo-purview",
            description=description or f"Policy evaluation: {policy_name}",
            compliance_state=compliance_state,
        )
        
        return self.import_event(event)
    
    # -------------------------------------------------------------------------
    # Linking Methods
    # -------------------------------------------------------------------------
    
    def link_event_to_run(
        self,
        event_id: str,
        run_id: str,
        correlation_id: Optional[str] = None,
    ) -> Optional[PurviewGovernanceEvent]:
        """Link a governance event to an attack run."""
        if event_id not in self._event_cache:
            return None
        
        event = self._event_cache[event_id]
        event.linked_run_id = run_id
        if correlation_id:
            event.correlation_id = correlation_id
        
        return event
    
    def link_event_to_agent(
        self,
        event_id: str,
        agent_id: str,
    ) -> Optional[PurviewGovernanceEvent]:
        """Link a governance event to an agent profile."""
        if event_id not in self._event_cache:
            return None
        
        event = self._event_cache[event_id]
        event.linked_agent_id = agent_id
        
        return event
    
    def get_events_for_run(self, run_id: str) -> List[PurviewGovernanceEvent]:
        """Get all governance events linked to a specific run."""
        return [e for e in self._event_cache.values() if e.linked_run_id == run_id]
    
    def get_events_for_agent(self, agent_id: str) -> List[PurviewGovernanceEvent]:
        """Get all governance events linked to a specific agent."""
        return [e for e in self._event_cache.values() if e.linked_agent_id == agent_id]
    
    # -------------------------------------------------------------------------
    # Status and Statistics
    # -------------------------------------------------------------------------
    
    def get_ingestion_status(self) -> PurviewIngestionStatus:
        """Get current status of the ingestion service."""
        # Determine if enabled
        enabled = bool(self._tenant_id and self._client_id)
        
        # Determine source availability
        source_available = self._connection_state in [
            PurviewConnectionState.CONNECTED,
            PurviewConnectionState.ADAPTER_MODE,
        ]
        
        # Build message
        if self._connection_state == PurviewConnectionState.CONNECTED:
            message = f"Connected to Purview via {self._connection_method}"
        elif self._connection_state == PurviewConnectionState.ADAPTER_MODE:
            message = "Operating in adapter mode with imported governance records"
        elif self._connection_state == PurviewConnectionState.ERROR:
            message = f"Connection error: {self._last_error or 'Unknown error'}"
        elif not enabled:
            message = "Purview integration not configured (credentials missing)"
        else:
            message = "Not connected to Purview APIs"
        
        return PurviewIngestionStatus(
            enabled=enabled,
            source_available=source_available,
            adapter_mode=self._adapter_mode,
            last_sync_at=self._last_sync,
            last_error=self._last_error,
            events_ingested=self._events_ingested,
            configured_account=self._purview_account or None,
            connection_method=self._connection_method,
            message=message,
        )
    
    def get_correlation_stats(self) -> PurviewCorrelationStats:
        """Get statistics about event correlation."""
        events = list(self._event_cache.values())
        
        linked_to_runs = sum(1 for e in events if e.linked_run_id)
        linked_to_agents = sum(1 for e in events if e.linked_agent_id)
        unlinked = sum(1 for e in events if not e.linked_run_id and not e.linked_agent_id)
        
        # Count by action
        allow_count = sum(1 for e in events if e.policy_action == PurviewPolicyAction.ALLOW)
        deny_count = sum(1 for e in events if e.policy_action == PurviewPolicyAction.DENY)
        audit_count = sum(1 for e in events if e.policy_action == PurviewPolicyAction.AUDIT)
        flag_count = sum(1 for e in events if e.policy_action == PurviewPolicyAction.FLAG_FOR_REVIEW)
        
        # Count by compliance
        compliant_count = sum(1 for e in events if e.compliance_state == "compliant")
        non_compliant_count = sum(1 for e in events if e.compliance_state == "non_compliant")
        
        return PurviewCorrelationStats(
            total_events=len(events),
            linked_to_runs=linked_to_runs,
            linked_to_agents=linked_to_agents,
            unlinked=unlinked,
            allow_count=allow_count,
            deny_count=deny_count,
            audit_count=audit_count,
            flag_count=flag_count,
            compliant_count=compliant_count,
            non_compliant_count=non_compliant_count,
        )
    
    def count_events(self) -> int:
        """Get total count of cached events."""
        return len(self._event_cache)
    
    def clear_cache(self) -> None:
        """Clear the event cache."""
        self._event_cache.clear()
        logger.info("Purview event cache cleared")
    
    def get_event(self, event_id: str) -> Optional[PurviewGovernanceEvent]:
        """Get a specific event by ID."""
        return self._event_cache.get(event_id)


# Singleton accessor
_service_instance: Optional[PurviewGovernanceIngestionService] = None


def get_purview_governance_service() -> PurviewGovernanceIngestionService:
    """Get the singleton Purview governance service instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = PurviewGovernanceIngestionService()
    return _service_instance
