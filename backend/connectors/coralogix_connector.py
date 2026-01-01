"""
Coralogix SIEM Connector

Handles webhook-based alert ingestion from Coralogix.
Supports multiple log sources (CloudTrail, Windows Events, Linux syslogs, etc.)
"""

import os
import hmac
import hashlib
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from connectors.base import BaseSIEMConnector, ConnectorConfig
from connectors.field_mapper import FieldMapper
from connectors.aws_mitre_mapping import get_mitre_mapping, infer_severity_from_event
from schemas.unified_alert import (
    UnifiedAlert, AlertAssets, IdentityInfo, AttackerInfo,
    NetworkContext, ProcessInfo, FileInfo, GeoLocation,
    SeverityLevel, IdentityType
)


from connectors.registry import ConnectorRegistry

@ConnectorRegistry.register("coralogix")
class CoralogixConnector(BaseSIEMConnector):
    """
    Coralogix webhook connector
    
    Receives alerts via Generic Webhook and normalizes to UnifiedAlert schema.
    Handles multiple log sources with flexible field mapping.
    """
    
    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        self.webhook_secret = config.webhook_secret or os.getenv("CORALOGIX_WEBHOOK_SECRET")
    
    async def test_connection(self) -> bool:
        """
        Test connection (for webhooks, just verify config)
        """
        return self.webhook_secret is not None
    
    async def validate_webhook_signature(
        self, 
        headers: Dict[str, str], 
        body: bytes,
        query_params: Dict[str, str] = None
    ) -> bool:
        """
        Validate Coralogix webhook request
        
        Supports:
        1. API Key in Query Param (?api_key=...)
        2. API Key in Header (X-CyberMaps-API-Key)
        3. HMAC Signature (Legacy/Future proofing)
        
        Args:
            headers: HTTP headers
            body: Raw request body
            query_params: URL query parameters (Optional)
            
        Returns:
            bool: True if valid (or no secret configured)
        """
        if not self.webhook_secret:
            # No secret configured, skip validation (development mode)
            return True
            
        # 1. Check Query Parameter (Easiest for Generic Webhooks)
        if query_params:
            api_key = query_params.get("api_key")
            if api_key and api_key == self.webhook_secret:
                return True
                
        # 2. Check Custom Header
        api_key_header = headers.get("x-cybermaps-api-key") or headers.get("X-CyberMaps-API-Key")
        if api_key_header and api_key_header == self.webhook_secret:
            return True
        
        # 3. Check HMAC Signature (Legacy/Advanced)
        # Coralogix may use different header names if they add signing later
        signature_header = headers.get("X-Coralogix-Signature") or headers.get("X-Hub-Signature-256")
        
        if signature_header:
            # Compute expected signature
            expected_signature = hmac.new(
                self.webhook_secret.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures (constant-time comparison)
            if hmac.compare_digest(signature_header, f"sha256={expected_signature}"):
                return True
                
        return False
    
    def normalize_alert(self, raw_alert: Dict[str, Any]) -> UnifiedAlert:
        """
        Transform Coralogix alert to UnifiedAlert
        
        Handles both:
        1. Direct log events (CloudTrail, Windows Events, etc.)
        2. Coralogix-wrapped alerts (if alert rules are configured)
        
        Args:
            raw_alert: Raw webhook payload from Coralogix
            
        Returns:
            UnifiedAlert: Normalized alert
        """
        # Detect if this is a wrapped alert or direct log
        is_wrapped = "alert" in raw_alert or "alertName" in raw_alert
        
        if is_wrapped:
            return self._normalize_wrapped_alert(raw_alert)
        else:
            return self._normalize_direct_log(raw_alert)
    
    def _normalize_wrapped_alert(self, raw_alert: Dict[str, Any]) -> UnifiedAlert:
        """
        Normalize Coralogix alert (when alert rules are configured)
        
        Expected structure:
        {
            "alert": {
                "id": "...",
                "name": "...",
                "severity": "High",
                "timestamp": "...",
                "tags": [...],
                "metadata": { ... original log ... }
            }
        }
        """
        alert_data = raw_alert.get("alert", raw_alert)
        metadata = alert_data.get("metadata", {})
        
        # Extract MITRE tags if present
        mitre_tactics = []
        mitre_techniques = []
        
        tags = alert_data.get("tags", [])
        # Handle case where tags is a string (comma separated)
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
            
        for tag in tags:
            if tag.startswith("mitre_tactic:"):
                mitre_tactics.append(tag.replace("mitre_tactic:", ""))
            elif tag.startswith("mitre_technique:"):
                mitre_techniques.append(tag.replace("mitre_technique:", ""))
        
        # Check if severity is mapped in fields
        severity = alert_data.get("severity", "Medium")
        
        # Fallback: Infer MITRE from event if not present
        if not mitre_tactics and "eventName" in metadata:
            mitre_mapping = get_mitre_mapping(metadata.get("eventName"))
            if mitre_mapping:
                mitre_tactics = mitre_mapping.tactics
                mitre_techniques = mitre_mapping.techniques
        
        # Build UnifiedAlert
        return UnifiedAlert(
            alert_id=alert_data.get("id", str(uuid.uuid4())),
            source_platform="coralogix",
            name=alert_data.get("name", "Coralogix Alert"),
            description=alert_data.get("description", ""),
            severity=self._normalize_severity(alert_data.get("severity", "Medium")),
            timestamp_utc=self._parse_timestamp(alert_data.get("timestamp")),
            alert_created_utc=self._parse_timestamp(alert_data.get("timestamp")),
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            tags=tags,
            raw_log=raw_alert,
            # Parse metadata for assets/attacker info
            **self._extract_context(metadata)
        )
    
    def _normalize_direct_log(self, raw_log: Dict[str, Any]) -> UnifiedAlert:
        """
        Normalize direct log event (CloudTrail, Windows Event, etc.)
        
        Detects log type and applies appropriate mapping.
        """
        # Detect log type
        log_type = self._detect_log_type(raw_log)
        
        if log_type == "cloudtrail":
            return self._normalize_cloudtrail(raw_log)
        elif log_type == "windows_event":
            return self._normalize_windows_event(raw_log)
        else:
            return self._normalize_generic_log(raw_log)
    
    def _detect_log_type(self, log: Dict[str, Any]) -> str:
        """Detect the type of log"""
        if "eventVersion" in log and "eventSource" in log:
            return "cloudtrail"
        elif "EventID" in log or "eventID" in log:
            return "windows_event"
        else:
            return "generic"
    
    def _normalize_cloudtrail(self, event: Dict[str, Any]) -> UnifiedAlert:
        """
        Normalize AWS CloudTrail event
        
        Uses the field mapping from analysis document.
        """
        event_name = event.get("eventName", "Unknown AWS Event")
        
        # Strip TestIngestion prefix if present for MITRE mapping
        clean_event_name = event_name.replace("TestIngestion-", "")
        
        # Get MITRE mapping using clean event name
        mitre_mapping = get_mitre_mapping(clean_event_name)
        mitre_tactics = mitre_mapping.tactics if mitre_mapping else []
        mitre_techniques = mitre_mapping.techniques if mitre_mapping else []
        
        # Infer severity using clean event name
        severity = infer_severity_from_event({**event, "eventName": clean_event_name})
        
        # Extract user identity
        user_identity = event.get("userIdentity", {})
        identity_type_raw = user_identity.get("type", "")
        identity_type = self._map_aws_identity_type(identity_type_raw)
        
        # Get username
        username = (
            user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName") or
            user_identity.get("userName") or
            user_identity.get("principalId", "")
        )
        
        # Check if privileged
        is_privileged = any(keyword in username.lower() for keyword in ["admin", "root", "poweruser"])
        
        # Build identity
        identity = IdentityInfo(
            username=username,
            user_id=user_identity.get("arn"),
            identity_type=identity_type,
            is_privileged=is_privileged,
            authentication_method="AWS STS" if identity_type_raw == "AssumedRole" else None
        )
        
        # Build assets
        assets = AlertAssets(
            asset_id=user_identity.get("accountId"),
            business_unit=event.get("awsRegion"),
            identities=[identity]
        )
        
        # Build attacker info
        source_ip = event.get("sourceIPAddress", "")
        attacker = AttackerInfo(
            source_ips=[source_ip] if source_ip else [],
            user_agent=event.get("userAgent"),
            attack_vector="cloud_api_abuse"
        )
        
        # Build network context
        network = NetworkContext(
            protocol="HTTPS",
            direction="outbound"
        )
        
        # Build tags
        tags = [
            "aws",
            event.get("eventSource", "").replace(".amazonaws.com", ""),
            event.get("eventCategory", "").lower(),
            event.get("awsRegion", "")
        ]
        tags = [t for t in tags if t]  # Remove empty tags
        
        return UnifiedAlert(
            alert_id=event.get("eventID", str(uuid.uuid4())),
            source_platform="coralogix",
            name=f"AWS {event_name}",
            description=mitre_mapping.description if mitre_mapping else f"AWS API call: {event_name}",
            severity=SeverityLevel(severity),
            timestamp_utc=self._parse_timestamp(event.get("eventTime")),
            alert_created_utc=self._parse_timestamp(event.get("eventTime")),
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            assets=assets,
            attacker=attacker,
            network=network,
            tags=tags,
            raw_log=event,
            rule_name=f"CloudTrail-{event_name}",
            event_count=1
        )
    
    def _normalize_windows_event(self, event: Dict[str, Any]) -> UnifiedAlert:
        """
        Normalize Windows Event Log
        
        TODO: Implement Windows Event mapping
        """
        event_id = event.get("EventID") or event.get("eventID")
        
        return UnifiedAlert(
            alert_id=str(uuid.uuid4()),
            source_platform="coralogix",
            name=f"Windows Event {event_id}",
            description=event.get("Message", ""),
            severity=SeverityLevel.MEDIUM,
            timestamp_utc=self._parse_timestamp(event.get("TimeCreated") or event.get("@timestamp")),
            alert_created_utc=datetime.utcnow(),
            raw_log=event,
            tags=["windows", f"event_id_{event_id}"]
        )
    
    def _normalize_generic_log(self, log: Dict[str, Any]) -> UnifiedAlert:
        """
        Normalize generic log (fallback)
        """
        return UnifiedAlert(
            alert_id=str(uuid.uuid4()),
            source_platform="coralogix",
            name=log.get("message", "Generic Log Event"),
            description=str(log),
            severity=SeverityLevel.INFORMATIONAL,
            timestamp_utc=self._parse_timestamp(log.get("timestamp") or log.get("@timestamp")),
            alert_created_utc=datetime.utcnow(),
            raw_log=log,
            tags=["generic"]
        )
    
    def _extract_context(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract assets, attacker, network context from metadata
        
        Returns dict with keys: assets, attacker, network
        """
        # This is a helper for wrapped alerts
        # For now, return empty context (can be enhanced)
        return {
            "assets": AlertAssets(),
            "attacker": AttackerInfo(),
            "network": NetworkContext()
        }
    
    def _map_aws_identity_type(self, aws_type: str) -> IdentityType:
        """Map AWS identity type to IdentityType enum"""
        mapping = {
            "AssumedRole": IdentityType.SERVICE_ACCOUNT,
            "IAMUser": IdentityType.HUMAN,
            "Root": IdentityType.HUMAN,
            "AWSService": IdentityType.SERVICE_PRINCIPAL,
            "AWSAccount": IdentityType.SERVICE_ACCOUNT,
        }
        return mapping.get(aws_type, IdentityType.HUMAN)
    
    def _normalize_severity(self, severity: str) -> SeverityLevel:
        """Normalize severity string to SeverityLevel enum"""
        severity_lower = severity.lower()
        
        if severity_lower in ["critical", "crit", "5"]:
            return SeverityLevel.CRITICAL
        elif severity_lower in ["high", "4"]:
            return SeverityLevel.HIGH
        elif severity_lower in ["medium", "med", "3"]:
            return SeverityLevel.MEDIUM
        elif severity_lower in ["low", "2"]:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFORMATIONAL
    
    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse timestamp to datetime (UTC)"""
        if isinstance(timestamp, datetime):
            return timestamp
        
        if isinstance(timestamp, str):
            try:
                # Try ISO 8601 format
                from dateutil import parser
                dt = parser.parse(timestamp)
                # Ensure UTC
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=None)  # Assume UTC
                return dt.astimezone(None).replace(tzinfo=None)
            except Exception:
                pass
        
        # Fallback to current time
        return datetime.utcnow()
    
    def get_default_field_mapping(self) -> Dict[str, str]:
        """
        Default field mapping for Coralogix
        
        This is flexible and can be overridden per connector instance.
        """
        return {
            # CloudTrail mappings
            "eventID": "alert_id",
            "eventName": "name",
            "eventTime": "timestamp_utc",
            "userIdentity.sessionContext.sessionIssuer.userName": "assets.identities[0].username",
            "userIdentity.arn": "assets.identities[0].user_id",
            "userIdentity.accountId": "assets.asset_id",
            "sourceIPAddress": "attacker.source_ips[0]",
            "userAgent": "attacker.user_agent",
            "awsRegion": "tags[]",
            "eventSource": "tags[]",
        }
