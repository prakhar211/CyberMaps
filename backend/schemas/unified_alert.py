"""
Unified Alert Data Models

This module defines the comprehensive data models for normalized security alerts
from multiple SIEM platforms (Coralogix, Azure Sentinel, Splunk, ELK).

All alerts are normalized to a common schema based on industry standards and
SOC/IR team requirements.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum
import uuid


# === Enumerations ===

class SeverityLevel(str, Enum):
    """Alert severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class AlertStatus(str, Enum):
    """Alert investigation status"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IdentityType(str, Enum):
    """Type of identity (human or non-human)"""
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    MACHINE = "machine"


class IOCType(str, Enum):
    """Indicator of Compromise types"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    PROCESS = "process"


# === Nested Models ===

class GeoLocation(BaseModel):
    """Geographical location data"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None  # Autonomous System Number
    isp: Optional[str] = None  # Internet Service Provider


class IOC(BaseModel):
    """Individual Indicator of Compromise"""
    type: IOCType
    value: str
    reputation_score: Optional[float] = None  # 0-100
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sources: List[str] = Field(default_factory=list)  # ["VirusTotal", "AbuseIPDB"]


class IdentityInfo(BaseModel):
    """Human and non-human identity details"""
    username: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    user_id: Optional[str] = None  # SID, UID, AAD Object ID, ARN
    identity_type: IdentityType = IdentityType.HUMAN
    display_name: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    is_privileged: bool = False  # Admin, root, etc.
    authentication_method: Optional[str] = None  # "NTLM", "Kerberos", "OAuth2"


class AlertAssets(BaseModel):
    """Assets involved in the security event"""
    # Host Information
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    mac_addresses: List[str] = Field(default_factory=list)
    asset_id: Optional[str] = None  # Internal asset tracking ID or cloud resource ID
    os: Optional[str] = None
    asset_type: Optional[str] = None  # "workstation" | "server" | "mobile" | "iot"
    business_unit: Optional[str] = None
    criticality: Optional[str] = None  # "critical" | "high" | "medium" | "low"
    
    # Identity Information
    identities: List[IdentityInfo] = Field(default_factory=list)


class AttackerInfo(BaseModel):
    """Attacker-related artifacts and indicators"""
    # Network Indicators
    source_ips: List[str] = Field(default_factory=list)
    source_ports: List[int] = Field(default_factory=list)
    source_geo: Optional[GeoLocation] = None
    
    # User Agent & Browser
    user_agent: Optional[str] = None
    browser: Optional[str] = None
    os: Optional[str] = None
    
    # Attack Vector
    attack_vector: Optional[str] = None  # "phishing" | "exploit" | "brute_force" | "malware"
    attack_technique_details: Optional[str] = None
    
    # Threat Intelligence
    threat_actor: Optional[str] = None  # "APT29", "Lazarus Group"
    campaign: Optional[str] = None
    malware_family: Optional[str] = None
    
    # IOCs
    iocs: List[IOC] = Field(default_factory=list)


class NetworkContext(BaseModel):
    """Network-related context"""
    destination_ips: List[str] = Field(default_factory=list)
    destination_ports: List[int] = Field(default_factory=list)
    destination_domains: List[str] = Field(default_factory=list)
    destination_urls: List[str] = Field(default_factory=list)
    
    protocol: Optional[str] = None  # "HTTP", "SMB", "RDP", "DNS"
    direction: Optional[str] = None  # "inbound" | "outbound" | "lateral"
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    packet_count: Optional[int] = None
    
    # DNS Context
    dns_query: Optional[str] = None
    dns_response: Optional[List[str]] = None
    
    # HTTP Context
    http_method: Optional[str] = None
    http_status_code: Optional[int] = None
    http_referrer: Optional[str] = None


class ProcessInfo(BaseModel):
    """Process execution details"""
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_id: Optional[int] = None
    process_guid: Optional[str] = None
    command_line: Optional[str] = None
    
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_command_line: Optional[str] = None
    
    process_hash: Optional[str] = None  # SHA256, MD5
    process_signature: Optional[str] = None
    process_integrity_level: Optional[str] = None  # "High", "System"
    
    user: Optional[str] = None


class FileInfo(BaseModel):
    """File-related context"""
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size: Optional[int] = None
    file_type: Optional[str] = None
    file_extension: Optional[str] = None
    
    file_created: Optional[datetime] = None
    file_modified: Optional[datetime] = None
    file_accessed: Optional[datetime] = None
    
    file_signature: Optional[str] = None


# === Main Unified Alert Model ===

class UnifiedAlert(BaseModel):
    """
    Normalized alert schema across all SIEM platforms
    
    This is the core data model that all SIEM connectors normalize to.
    """
    
    # === Identification ===
    alert_id: str  # Unique ID from source SIEM
    cybermap_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_platform: str  # "coralogix" | "sentinel" | "splunk" | "elk"
    
    # === MITRE ATT&CK Mapping ===
    mitre_tactics: List[str] = Field(default_factory=list)  # ["Initial Access", "Execution"]
    mitre_techniques: List[str] = Field(default_factory=list)  # ["T1566.001", "T1059.001"]
    mitre_subtechniques: Optional[List[str]] = None
    kill_chain_phase: Optional[str] = None  # "weaponization", "delivery", etc.
    
    # === Alert Metadata ===
    name: str  # Alert title
    description: str = ""  # Detailed description
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: Optional[float] = None  # 0.0 to 1.0
    status: AlertStatus = AlertStatus.OPEN
    
    # === Temporal Data (ALL IN UTC) ===
    timestamp_utc: datetime  # When the malicious activity occurred
    alert_created_utc: datetime  # When the alert was generated
    first_seen_utc: Optional[datetime] = None
    last_seen_utc: Optional[datetime] = None
    ingested_at_utc: datetime = Field(default_factory=datetime.utcnow)
    
    # === Asset Information ===
    assets: AlertAssets = Field(default_factory=AlertAssets)
    
    # === Attacker Artifacts ===
    attacker: AttackerInfo = Field(default_factory=AttackerInfo)
    
    # === Network Context ===
    network: NetworkContext = Field(default_factory=NetworkContext)
    
    # === Process & File Context ===
    process: Optional[ProcessInfo] = None
    file: Optional[FileInfo] = None
    
    # === Additional Context ===
    tags: List[str] = Field(default_factory=list)  # ["ransomware", "apt29", "finance_dept"]
    rule_name: Optional[str] = None  # Detection rule that triggered this
    rule_id: Optional[str] = None
    event_count: int = 1  # Number of events aggregated into this alert
    
    # === Raw Data ===
    raw_log: Optional[Dict[str, Any]] = None  # Original SIEM event (for forensics)
    siem_url: Optional[str] = None  # Deep link back to SIEM
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "evt-123456",
                "source_platform": "coralogix",
                "name": "Suspicious PowerShell Execution",
                "severity": "High",
                "timestamp_utc": "2025-12-08T10:30:00Z",
                "mitre_tactics": ["Execution", "Defense Evasion"],
                "mitre_techniques": ["T1059.001"],
                "assets": {
                    "hostname": "WKS-FINANCE-01",
                    "ip_addresses": ["10.0.1.50"],
                    "identities": [{
                        "username": "jdoe",
                        "email": "john.doe@acme.com",
                        "identity_type": "human"
                    }]
                },
                "attacker": {
                    "source_ips": ["192.168.1.100"],
                    "user_agent": "Mozilla/5.0..."
                }
            }
        }
