"""
Field Mapper Utility

Maps SIEM-specific fields to UnifiedAlert schema using flexible path expressions.
Supports dot notation, JSONPath queries, and array handling.
"""

from typing import Dict, Any, List, Optional
import jmespath
from datetime import datetime
from dateutil import parser as date_parser


class FieldMapper:
    """
    Maps SIEM-specific fields to UnifiedAlert schema
    
    Supports:
    - Simple field mapping: "src_ip" -> "attacker.source_ips[0]"
    - Dot notation: "user.name" -> "assets.identities[0].username"
    - JSONPath queries: "Entities[?Type=='ip'].Address" -> "assets.ip_addresses"
    - Array aggregation: field[] notation
    """
    
    def __init__(self, field_mapping: Dict[str, str]):
        """
        Initialize field mapper
        
        Args:
            field_mapping: Dict mapping source fields to target fields
        """
        self.field_mapping = field_mapping
    
    def map(self, source_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply field mapping to source data
        
        Args:
            source_data: Raw data from SIEM
            
        Returns:
            Dict with mapped fields
        """
        result = {}
        
        for source_field, target_field in self.field_mapping.items():
            value = self._extract_value(source_data, source_field)
            if value is not None:
                self._set_nested_value(result, target_field, value)
        
        return result
    
    def _extract_value(self, data: Dict, field_path: str) -> Any:
        """
        Extract value using dot notation or JSONPath
        
        Args:
            data: Source data dictionary
            field_path: Path to field (e.g., "user.name" or "Entities[?Type=='ip']")
            
        Returns:
            Extracted value or None
        """
        # Try JSONPath first (for complex queries)
        if '[?' in field_path or '@' in field_path:
            try:
                return jmespath.search(field_path, data)
            except Exception:
                return None
        
        # Simple dot notation
        keys = field_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            elif isinstance(value, list) and key.isdigit():
                try:
                    value = value[int(key)]
                except (IndexError, ValueError):
                    return None
            else:
                return None
                
            if value is None:
                return None
        
        return value
    
    def _set_nested_value(self, data: Dict, field_path: str, value: Any):
        """
        Set value in nested dict using dot notation
        
        Args:
            data: Target dictionary
            field_path: Path where to set value (e.g., "assets.hostname")
            value: Value to set
        """
        # Handle array notation: "field[]" means append to list
        if field_path.endswith('[]'):
            field_path = field_path[:-2]
            keys = field_path.split('.')
            
            # Navigate to parent
            current = data
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            # Ensure target is a list
            final_key = keys[-1]
            if final_key not in current:
                current[final_key] = []
            
            # Append value(s)
            if isinstance(value, list):
                current[final_key].extend(value)
            else:
                current[final_key].append(value)
            return
        
        # Regular nested assignment
        keys = field_path.split('.')
        current = data
        
        for i, key in enumerate(keys[:-1]):
            if key not in current:
                # Determine if next level should be list or dict
                next_key = keys[i + 1]
                current[key] = [] if next_key.isdigit() else {}
            current = current[key]
        
        current[keys[-1]] = value
    
    @staticmethod
    def parse_datetime(value: Any) -> Optional[datetime]:
        """
        Parse various datetime formats to datetime object
        
        Args:
            value: String, int (timestamp), or datetime
            
        Returns:
            datetime object or None
        """
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, (int, float)):
            # Unix timestamp
            try:
                return datetime.fromtimestamp(value)
            except Exception:
                return None
        
        if isinstance(value, str):
            try:
                # Try ISO 8601 and other common formats
                return date_parser.parse(value)
            except Exception:
                return None
        
        return None
    
    @staticmethod
    def normalize_severity(value: str) -> str:
        """
        Normalize severity to standard levels
        
        Args:
            value: Severity string from SIEM
            
        Returns:
            Normalized severity: Critical | High | Medium | Low | Informational
        """
        value_lower = str(value).lower()
        
        if value_lower in ['critical', 'crit', '5', 'emergency']:
            return "Critical"
        elif value_lower in ['high', '4', 'alert', 'error']:
            return "High"
        elif value_lower in ['medium', 'med', '3', 'warning', 'warn']:
            return "Medium"
        elif value_lower in ['low', '2', 'notice']:
            return "Low"
        else:
            return "Informational"
    
    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """
        Extract IP addresses from text using regex
        
        Args:
            text: Text containing IP addresses
            
        Returns:
            List of IP addresses
        """
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, text)
    
    @staticmethod
    def extract_domains(text: str) -> List[str]:
        """
        Extract domain names from text
        
        Args:
            text: Text containing domains
            
        Returns:
            List of domain names
        """
        import re
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        return re.findall(domain_pattern, text)
