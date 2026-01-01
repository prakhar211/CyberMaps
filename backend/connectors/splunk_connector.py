from typing import Dict, Any
from connectors.base import BaseSIEMConnector, ConnectorConfig
from connectors.registry import ConnectorRegistry
from schemas.unified_alert import UnifiedAlert, SeverityLevel
import uuid
from datetime import datetime

@ConnectorRegistry.register("splunk")
class SplunkConnector(BaseSIEMConnector):
    """
    Splunk Connector (Stub)
    Receives alerts from Splunk Webhook Actions.
    """
    
    async def test_connection(self) -> bool:
        return True

    async def validate_webhook_signature(self, headers: Dict[str, str], body: bytes, query_params: Dict[str, str] = None) -> bool:
        # Splunk webhooks don't usually sign requests unless configured with a custom secret header
        return True

    def normalize_alert(self, raw_alert: Dict[str, Any]) -> UnifiedAlert:
        """
        Normalize Splunk alert.
        Expected standard Splunk webhook keys: 'search_name', 'result', 'owner', 'app'
        """
        result = raw_alert.get("result", {})
        search_name = raw_alert.get("search_name", "Splunk Alert")
        
        return UnifiedAlert(
            alert_id=raw_alert.get("sid", str(uuid.uuid4())),
            source_platform="splunk",
            name=search_name,
            description=f"Splunk alert from search: {search_name}",
            severity=SeverityLevel.MEDIUM, # default
            timestamp_utc=datetime.utcnow(),
            alert_created_utc=datetime.utcnow(),
            raw_log=raw_alert,
            tags=["splunk"]
        )

    def get_default_field_mapping(self) -> Dict[str, str]:
        return {}
