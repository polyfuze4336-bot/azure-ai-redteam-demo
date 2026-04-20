"""
Microsoft Defender Alert Ingestion Service.

Retrieves real Defender alerts from Microsoft Graph Security API and normalizes
them into the internal alert model. Supports fallback mode when real alerts
are unavailable.
"""

import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum
import httpx

from models.schemas import (
    DefenderAlert,
    DefenderAlertSeverity,
    DefenderAlertStatus,
    DefenderAlertSource,
    DefenderAlertFilter,
    DefenderIngestionStatus,
)

logger = logging.getLogger(__name__)


class DefenderConnectionState(str, Enum):
    """Connection state to Defender APIs."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FALLBACK = "fallback"
    ERROR = "error"


class DefenderAlertIngestionService:
    """
    Service for ingesting Microsoft Defender alerts related to AI workloads.
    
    Connects to Microsoft Graph Security API to retrieve real alerts.
    Falls back to a placeholder mode only when real source is unavailable.
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
        self._client_id = os.getenv("DEFENDER_CLIENT_ID", os.getenv("AZURE_CLIENT_ID", ""))
        self._client_secret = os.getenv("DEFENDER_CLIENT_SECRET", os.getenv("AZURE_CLIENT_SECRET", ""))
        self._subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
        self._resource_group = os.getenv("DEFENDER_RESOURCE_GROUP", os.getenv("AZURE_RESOURCE_GROUP", ""))
        
        # Graph Security API endpoints
        self._graph_base_url = "https://graph.microsoft.com/v1.0"
        self._security_api_url = f"{self._graph_base_url}/security"
        
        # State tracking
        self._connection_state = DefenderConnectionState.DISCONNECTED
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._last_sync: Optional[datetime] = None
        self._last_error: Optional[str] = None
        self._alerts_ingested: int = 0
        
        # In-memory alert cache (also stored in MemoryStore)
        self._alert_cache: Dict[str, DefenderAlert] = {}
        
        # Fallback mode flag
        self._fallback_active = False
        
        self._initialized = True
        logger.info("DefenderAlertIngestionService initialized")
    
    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------
    
    async def _get_access_token(self) -> Optional[str]:
        """
        Get access token for Microsoft Graph Security API using client credentials flow.
        """
        if not self._tenant_id or not self._client_id or not self._client_secret:
            logger.warning("Defender API credentials not configured")
            return None
        
        # Check if existing token is still valid
        if self._access_token and self._token_expiry:
            if datetime.utcnow() < self._token_expiry - timedelta(minutes=5):
                return self._access_token
        
        token_url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
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
                
                logger.info("Successfully obtained Defender API access token")
                return self._access_token
                
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to get Defender access token: {e.response.status_code}")
            self._last_error = f"Authentication failed: {e.response.status_code}"
            return None
        except Exception as e:
            logger.error(f"Error getting Defender access token: {e}")
            self._last_error = f"Authentication error: {str(e)}"
            return None
    
    # -------------------------------------------------------------------------
    # Real Alert Ingestion from Microsoft Graph Security API
    # -------------------------------------------------------------------------
    
    async def _fetch_alerts_from_graph(
        self,
        filter_params: Optional[DefenderAlertFilter] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch alerts from Microsoft Graph Security API.
        
        Uses the /security/alerts_v2 endpoint for enhanced alert data.
        """
        token = await self._get_access_token()
        if not token:
            logger.warning("No access token available, cannot fetch real alerts")
            return []
        
        # Build OData filter
        odata_filters = []
        
        if filter_params:
            # Time filter
            if filter_params.start_time:
                odata_filters.append(f"createdDateTime ge {filter_params.start_time.isoformat()}Z")
            if filter_params.end_time:
                odata_filters.append(f"createdDateTime le {filter_params.end_time.isoformat()}Z")
            
            # Severity filter
            if filter_params.severity:
                severities = [f"'{s.value}'" for s in filter_params.severity]
                odata_filters.append(f"severity in ({','.join(severities)})")
            
            # Status filter
            if filter_params.status:
                statuses = [f"'{s.value}'" for s in filter_params.status]
                odata_filters.append(f"status in ({','.join(statuses)})")
        
        # Default: Get alerts from last 7 days if no time filter
        if not filter_params or (not filter_params.start_time and not filter_params.end_time):
            week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
            odata_filters.append(f"createdDateTime ge {week_ago}Z")
        
        # Focus on AI/ML related alerts
        # Filter for alerts related to Azure OpenAI, Content Safety, or AI workloads
        ai_categories = [
            "AIWorkloadAttack",
            "JailbreakAttempt",
            "PromptInjection",
            "ContentSafetyViolation",
            "AIModelAbuse",
            "DataExfiltration",
        ]
        category_filter = " or ".join([f"contains(category, '{c}')" for c in ai_categories])
        odata_filters.append(f"({category_filter})")
        
        params = {
            "$top": filter_params.limit if filter_params else 50,
            "$skip": filter_params.offset if filter_params else 0,
            "$orderby": "createdDateTime desc",
        }
        
        if odata_filters:
            params["$filter"] = " and ".join(odata_filters)
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # Try the v2 alerts endpoint first
                response = await client.get(
                    f"{self._security_api_url}/alerts_v2",
                    headers=headers,
                    params=params,
                )
                
                if response.status_code == 404:
                    # Fall back to v1 alerts endpoint
                    response = await client.get(
                        f"{self._security_api_url}/alerts",
                        headers=headers,
                        params=params,
                    )
                
                response.raise_for_status()
                data = response.json()
                
                self._connection_state = DefenderConnectionState.CONNECTED
                self._fallback_active = False
                logger.info(f"Fetched {len(data.get('value', []))} alerts from Graph Security API")
                
                return data.get("value", [])
                
        except httpx.HTTPStatusError as e:
            logger.error(f"Graph Security API error: {e.response.status_code}")
            self._last_error = f"API error: {e.response.status_code}"
            self._connection_state = DefenderConnectionState.ERROR
            return []
        except Exception as e:
            logger.error(f"Error fetching alerts from Graph: {e}")
            self._last_error = f"Fetch error: {str(e)}"
            self._connection_state = DefenderConnectionState.ERROR
            return []
    
    async def _fetch_alerts_from_defender_for_cloud(
        self,
        filter_params: Optional[DefenderAlertFilter] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch alerts from Microsoft Defender for Cloud REST API.
        
        Alternative source for security alerts with more detailed context.
        """
        token = await self._get_access_token()
        if not token or not self._subscription_id:
            return []
        
        # Defender for Cloud alerts API
        api_url = (
            f"https://management.azure.com/subscriptions/{self._subscription_id}"
            f"/providers/Microsoft.Security/alerts?api-version=2022-01-01"
        )
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(api_url, headers=headers)
                response.raise_for_status()
                data = response.json()
                
                logger.info(f"Fetched {len(data.get('value', []))} alerts from Defender for Cloud")
                return data.get("value", [])
                
        except Exception as e:
            logger.warning(f"Defender for Cloud API not available: {e}")
            return []
    
    # -------------------------------------------------------------------------
    # Alert Normalization
    # -------------------------------------------------------------------------
    
    def _normalize_graph_alert(self, raw_alert: Dict[str, Any]) -> DefenderAlert:
        """
        Normalize a raw Microsoft Graph Security alert into internal model.
        """
        # Map severity
        severity_map = {
            "informational": DefenderAlertSeverity.INFORMATIONAL,
            "low": DefenderAlertSeverity.LOW,
            "medium": DefenderAlertSeverity.MEDIUM,
            "high": DefenderAlertSeverity.HIGH,
            "critical": DefenderAlertSeverity.CRITICAL,
            "unknown": DefenderAlertSeverity.MEDIUM,
        }
        
        # Map status
        status_map = {
            "new": DefenderAlertStatus.NEW,
            "newAlert": DefenderAlertStatus.NEW,
            "inProgress": DefenderAlertStatus.IN_PROGRESS,
            "resolved": DefenderAlertStatus.RESOLVED,
            "dismissed": DefenderAlertStatus.DISMISSED,
            "unknown": DefenderAlertStatus.UNKNOWN,
        }
        
        # Extract alert details
        alert_id = raw_alert.get("id", "")
        title = raw_alert.get("title", raw_alert.get("alertDisplayName", "Unknown Alert"))
        description = raw_alert.get("description", "No description available")
        
        raw_severity = raw_alert.get("severity", "medium").lower()
        severity = severity_map.get(raw_severity, DefenderAlertSeverity.MEDIUM)
        
        raw_status = raw_alert.get("status", "new")
        status = status_map.get(raw_status, DefenderAlertStatus.NEW)
        
        # Parse timestamps
        created_str = raw_alert.get("createdDateTime", raw_alert.get("timeGenerated"))
        detected_str = raw_alert.get("detectionDateTime", created_str)
        
        timestamp = datetime.utcnow()
        detected_at = datetime.utcnow()
        
        if created_str:
            try:
                timestamp = datetime.fromisoformat(created_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except:
                pass
        
        if detected_str:
            try:
                detected_at = datetime.fromisoformat(detected_str.replace("Z", "+00:00")).replace(tzinfo=None)
            except:
                pass
        
        # Extract correlation info
        correlation_id = raw_alert.get("correlationKey", raw_alert.get("correlationId"))
        
        # Determine source
        provider = raw_alert.get("productName", raw_alert.get("vendorName", "")).lower()
        if "defender for ai" in provider or "ai" in raw_alert.get("category", "").lower():
            source = DefenderAlertSource.DEFENDER_FOR_AI
        elif "content safety" in provider:
            source = DefenderAlertSource.CONTENT_SAFETY
        elif "sentinel" in provider:
            source = DefenderAlertSource.SENTINEL
        else:
            source = DefenderAlertSource.DEFENDER_FOR_CLOUD
        
        # Extract tactics and techniques (MITRE ATT&CK)
        tactics = raw_alert.get("tactics", [])
        techniques = raw_alert.get("techniques", [])
        
        # If mitreTactics is available (v2 schema)
        if "mitreTactics" in raw_alert:
            tactics = raw_alert["mitreTactics"]
        if "mitreTechniques" in raw_alert:
            techniques = raw_alert["mitreTechniques"]
        
        # Extract remediation steps
        remediation_steps = []
        if "remediationSteps" in raw_alert:
            steps = raw_alert["remediationSteps"]
            if isinstance(steps, list):
                remediation_steps = steps
            elif isinstance(steps, str):
                remediation_steps = [steps]
        
        # Extract resource info
        resource_name = None
        resource_type = None
        affected_resources = raw_alert.get("affectedResources", raw_alert.get("entities", []))
        if affected_resources and len(affected_resources) > 0:
            resource = affected_resources[0]
            resource_name = resource.get("name", resource.get("address", resource.get("displayName")))
            resource_type = resource.get("type", resource.get("@odata.type", ""))
        
        # Check if part of incident
        is_incident = raw_alert.get("incidentId") is not None
        incident_id = raw_alert.get("incidentId")
        
        return DefenderAlert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity,
            status=status,
            timestamp=timestamp,
            detected_at=detected_at,
            updated_at=None,
            correlation_id=correlation_id,
            linked_run_id=None,  # Will be resolved by linking logic
            linked_agent_id=None,
            linked_campaign_id=None,
            source=source,
            resource_name=resource_name,
            resource_type=resource_type,
            subscription_id=raw_alert.get("subscriptionId", self._subscription_id),
            category=raw_alert.get("category"),
            tactics=tactics if isinstance(tactics, list) else [],
            techniques=techniques if isinstance(techniques, list) else [],
            remediation_steps=remediation_steps,
            is_incident=is_incident,
            incident_id=incident_id,
            raw_metadata=raw_alert,
        )
    
    def _normalize_defender_cloud_alert(self, raw_alert: Dict[str, Any]) -> DefenderAlert:
        """
        Normalize a raw Defender for Cloud alert into internal model.
        """
        properties = raw_alert.get("properties", {})
        
        severity_map = {
            "Informational": DefenderAlertSeverity.INFORMATIONAL,
            "Low": DefenderAlertSeverity.LOW,
            "Medium": DefenderAlertSeverity.MEDIUM,
            "High": DefenderAlertSeverity.HIGH,
        }
        
        status_map = {
            "Active": DefenderAlertStatus.NEW,
            "InProgress": DefenderAlertStatus.IN_PROGRESS,
            "Resolved": DefenderAlertStatus.RESOLVED,
            "Dismissed": DefenderAlertStatus.DISMISSED,
        }
        
        # Extract timestamps
        timestamp = datetime.utcnow()
        if "timeGeneratedUtc" in properties:
            try:
                timestamp = datetime.fromisoformat(
                    properties["timeGeneratedUtc"].replace("Z", "+00:00")
                ).replace(tzinfo=None)
            except:
                pass
        
        return DefenderAlert(
            alert_id=raw_alert.get("id", "").split("/")[-1],
            title=properties.get("alertDisplayName", "Unknown Alert"),
            description=properties.get("description", ""),
            severity=severity_map.get(properties.get("severity", "Medium"), DefenderAlertSeverity.MEDIUM),
            status=status_map.get(properties.get("status", "Active"), DefenderAlertStatus.NEW),
            timestamp=timestamp,
            detected_at=timestamp,
            source=DefenderAlertSource.DEFENDER_FOR_CLOUD,
            resource_name=properties.get("compromisedEntity"),
            category=properties.get("alertType"),
            tactics=properties.get("intent", "").split(",") if properties.get("intent") else [],
            techniques=[],
            remediation_steps=properties.get("remediationSteps", []),
            raw_metadata=raw_alert,
        )
    
    # -------------------------------------------------------------------------
    # Fallback Alert Generation
    # -------------------------------------------------------------------------
    
    def _generate_fallback_alerts(
        self,
        filter_params: Optional[DefenderAlertFilter] = None,
    ) -> List[DefenderAlert]:
        """
        Generate placeholder alerts ONLY when real Defender source is unavailable.
        
        This is NOT simulation - these are clearly marked as fallback alerts
        and should only be used for demo continuity when the real API is down.
        """
        logger.warning("Generating fallback alerts - real Defender source unavailable")
        self._fallback_active = True
        
        # Return empty list by default - only generate minimal fallback if explicitly needed
        # This ensures we don't pollute the UI with fake alerts
        return []
    
    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------
    
    async def sync_alerts(
        self,
        filter_params: Optional[DefenderAlertFilter] = None,
    ) -> List[DefenderAlert]:
        """
        Sync alerts from Microsoft Defender.
        
        Attempts to fetch real alerts first. Only falls back to placeholder
        alerts if the real source is completely unavailable.
        """
        normalized_alerts: List[DefenderAlert] = []
        
        # Try Graph Security API first
        graph_alerts = await self._fetch_alerts_from_graph(filter_params)
        for raw_alert in graph_alerts:
            try:
                alert = self._normalize_graph_alert(raw_alert)
                normalized_alerts.append(alert)
                self._alert_cache[alert.alert_id] = alert
            except Exception as e:
                logger.warning(f"Failed to normalize Graph alert: {e}")
        
        # Try Defender for Cloud API as supplementary source
        if not graph_alerts:
            cloud_alerts = await self._fetch_alerts_from_defender_for_cloud(filter_params)
            for raw_alert in cloud_alerts:
                try:
                    alert = self._normalize_defender_cloud_alert(raw_alert)
                    # Avoid duplicates
                    if alert.alert_id not in self._alert_cache:
                        normalized_alerts.append(alert)
                        self._alert_cache[alert.alert_id] = alert
                except Exception as e:
                    logger.warning(f"Failed to normalize Defender Cloud alert: {e}")
        
        # Fallback mode - only if NO real alerts available
        if not normalized_alerts and self._connection_state == DefenderConnectionState.ERROR:
            normalized_alerts = self._generate_fallback_alerts(filter_params)
        
        self._last_sync = datetime.utcnow()
        self._alerts_ingested += len(normalized_alerts)
        
        logger.info(f"Synced {len(normalized_alerts)} alerts (fallback={self._fallback_active})")
        return normalized_alerts
    
    async def get_alerts(
        self,
        filter_params: Optional[DefenderAlertFilter] = None,
    ) -> List[DefenderAlert]:
        """
        Get alerts from cache, optionally filtering.
        
        If cache is empty, triggers a sync first.
        """
        if not self._alert_cache:
            await self.sync_alerts(filter_params)
        
        alerts = list(self._alert_cache.values())
        
        # Apply filters
        if filter_params:
            if filter_params.severity:
                alerts = [a for a in alerts if a.severity in filter_params.severity]
            if filter_params.status:
                alerts = [a for a in alerts if a.status in filter_params.status]
            if filter_params.source:
                alerts = [a for a in alerts if a.source in filter_params.source]
            if filter_params.start_time:
                alerts = [a for a in alerts if a.timestamp >= filter_params.start_time]
            if filter_params.end_time:
                alerts = [a for a in alerts if a.timestamp <= filter_params.end_time]
            if filter_params.correlation_id:
                alerts = [a for a in alerts if a.correlation_id == filter_params.correlation_id]
            if filter_params.linked_run_id:
                alerts = [a for a in alerts if a.linked_run_id == filter_params.linked_run_id]
            if filter_params.linked_agent_id:
                alerts = [a for a in alerts if a.linked_agent_id == filter_params.linked_agent_id]
            if filter_params.category:
                alerts = [a for a in alerts if a.category and filter_params.category.lower() in a.category.lower()]
        
        # Sort by timestamp descending
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        
        # Apply pagination
        limit = filter_params.limit if filter_params else 50
        offset = filter_params.offset if filter_params else 0
        
        return alerts[offset:offset + limit]
    
    async def get_alert_by_id(self, alert_id: str) -> Optional[DefenderAlert]:
        """Get a specific alert by ID."""
        return self._alert_cache.get(alert_id)
    
    async def link_alert_to_run(
        self,
        alert_id: str,
        run_id: str,
    ) -> Optional[DefenderAlert]:
        """Link an alert to a specific attack run."""
        if alert_id in self._alert_cache:
            self._alert_cache[alert_id].linked_run_id = run_id
            self._alert_cache[alert_id].updated_at = datetime.utcnow()
            return self._alert_cache[alert_id]
        return None
    
    async def link_alert_to_agent(
        self,
        alert_id: str,
        agent_id: str,
    ) -> Optional[DefenderAlert]:
        """Link an alert to a specific agent profile."""
        if alert_id in self._alert_cache:
            self._alert_cache[alert_id].linked_agent_id = agent_id
            self._alert_cache[alert_id].updated_at = datetime.utcnow()
            return self._alert_cache[alert_id]
        return None
    
    async def update_alert_status(
        self,
        alert_id: str,
        status: DefenderAlertStatus,
    ) -> Optional[DefenderAlert]:
        """Update alert status locally."""
        if alert_id in self._alert_cache:
            self._alert_cache[alert_id].status = status
            self._alert_cache[alert_id].updated_at = datetime.utcnow()
            return self._alert_cache[alert_id]
        return None
    
    def get_ingestion_status(self) -> DefenderIngestionStatus:
        """Get current status of the ingestion service."""
        enabled = bool(self._tenant_id and self._client_id)
        source_available = self._connection_state == DefenderConnectionState.CONNECTED
        
        if source_available:
            message = "Connected to Microsoft Defender APIs"
        elif self._fallback_active:
            message = "Fallback mode active - real Defender source unavailable"
        elif not enabled:
            message = "Defender integration not configured (missing credentials)"
        else:
            message = f"Disconnected: {self._last_error or 'Unknown error'}"
        
        return DefenderIngestionStatus(
            enabled=enabled,
            source_available=source_available,
            fallback_active=self._fallback_active,
            last_sync_at=self._last_sync,
            last_error=self._last_error,
            alerts_ingested=self._alerts_ingested,
            configured_resource=self._resource_group if self._resource_group else None,
            message=message,
        )
    
    def clear_cache(self) -> None:
        """Clear the alert cache."""
        self._alert_cache.clear()
        logger.info("Alert cache cleared")
    
    def count_alerts(self) -> int:
        """Get count of cached alerts."""
        return len(self._alert_cache)


# Module-level singleton accessor
_service_instance: Optional[DefenderAlertIngestionService] = None


def get_defender_alert_service() -> DefenderAlertIngestionService:
    """Get the singleton DefenderAlertIngestionService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = DefenderAlertIngestionService()
    return _service_instance
