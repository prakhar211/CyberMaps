"""
Base SIEM Connector Interface

This module defines the abstract base class that all SIEM connectors must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel
from schemas.unified_alert import UnifiedAlert



class ConnectorConfig(BaseModel):
    """Configuration for SIEM connector"""
    platform: str  # "coralogix" | "sentinel" | "splunk" | "elk"
    enabled: bool = True
    
    # Authentication
    api_endpoint: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    webhook_secret: Optional[str] = None
    
    # Polling configuration (for API-based connectors)
    poll_interval_seconds: int = 300  # 5 minutes default
    lookback_minutes: int = 10
    
    # Query configuration
    custom_query: Optional[str] = None
    index_name: Optional[str] = None
    workspace_id: Optional[str] = None
    
    # Field mapping overrides
    field_mapping: Optional[Dict[str, str]] = None
    
    class Config:
        extra = "allow"  # Allow additional platform-specific fields


class BaseSIEMConnector(ABC):
    """
    Abstract base class for all SIEM connectors
    
    Each SIEM platform (Coralogix, Sentinel, Splunk, ELK) implements this interface.
    """
    
    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.platform = config.platform
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """
        Test connectivity and authentication to SIEM
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def validate_webhook_signature(
        self, 
        headers: Dict[str, str], 
        body: bytes
    ) -> bool:
        """
        Validate webhook signature to ensure authenticity
        
        Args:
            headers: HTTP headers from webhook request
            body: Raw request body
            
        Returns:
            bool: True if signature is valid
        """
        pass
    
    @abstractmethod
    def normalize_alert(self, raw_alert: Dict[str, Any]) -> UnifiedAlert:
        """
        Transform raw SIEM alert to UnifiedAlert schema
        
        Args:
            raw_alert: Raw alert data from SIEM
            
        Returns:
            UnifiedAlert: Normalized alert
        """
        pass
    
    @abstractmethod
    def get_default_field_mapping(self) -> Dict[str, str]:
        """
        Get platform-specific default field mappings
        
        Returns:
            Dict mapping source fields to UnifiedAlert fields
        """
        pass
    
    def get_field_mapping(self) -> Dict[str, str]:
        """
        Get field mapping for this connector (with overrides)
        
        Returns:
            Dict: Field mapping (defaults + custom overrides)
        """
        mapping = self.get_default_field_mapping()
        if self.config.field_mapping:
            mapping.update(self.config.field_mapping)
        return mapping
    
    # Optional methods for API-based connectors
    async def fetch_alerts(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Fetch raw alerts from SIEM within time range (for polling-based connectors)
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            List of raw alert dictionaries
        """
        raise NotImplementedError(
            f"{self.platform} connector does not support API polling"
        )
    
    async def push_enrichment(
        self, 
        alert_id: str, 
        enrichment_data: Dict[str, Any]
    ) -> bool:
        """
        Push enriched data back to SIEM (bidirectional sync)
        
        Args:
            alert_id: Original alert ID in SIEM
            enrichment_data: Enrichment to push back
            
        Returns:
            bool: True if successful
        """
        raise NotImplementedError(
            f"{self.platform} connector does not support enrichment push"
        )
