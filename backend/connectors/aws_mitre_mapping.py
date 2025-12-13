"""
AWS CloudTrail Event to MITRE ATT&CK Mapping

Maps AWS CloudTrail API events to MITRE ATT&CK tactics and techniques.
Used for inferring MITRE tags when not provided by SIEM.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MITREMapping:
    """MITRE ATT&CK mapping for an event"""
    tactics: List[str]
    techniques: List[str]
    description: str


# Comprehensive AWS CloudTrail -> MITRE ATT&CK mappings
AWS_EVENT_TO_MITRE: Dict[str, MITREMapping] = {
    # === Defense Evasion ===
    "StopLogging": MITREMapping(
        tactics=["Defense Evasion"],
        techniques=["T1562.008"],  # Impair Defenses: Disable Cloud Logs
        description="Stopping CloudTrail logging to evade detection"
    ),
    "DeleteTrail": MITREMapping(
        tactics=["Defense Evasion"],
        techniques=["T1562.008"],
        description="Deleting CloudTrail to remove audit trail"
    ),
    "UpdateTrail": MITREMapping(
        tactics=["Defense Evasion"],
        techniques=["T1562.008"],
        description="Modifying CloudTrail configuration"
    ),
    "PutEventSelectors": MITREMapping(
        tactics=["Defense Evasion"],
        techniques=["T1562.008"],
        description="Changing what events are logged"
    ),
    "DeleteFlowLogs": MITREMapping(
        tactics=["Defense Evasion"],
        techniques=["T1562.008"],
        description="Deleting VPC flow logs"
    ),
    "DeleteLogGroup": MITREMapping(
        tactics=["Defense Evasion"],
        techniques=["T1562.008"],
        description="Deleting CloudWatch log group"
    ),
    "DeleteLogStream": MITREMapping(
        tactics=["Defense Evasion"],
        techniques=["T1562.008"],
        description="Deleting CloudWatch log stream"
    ),
    
    # === Privilege Escalation ===
    "AssumeRole": MITREMapping(
        tactics=["Privilege Escalation", "Defense Evasion"],
        techniques=["T1078.004"],  # Valid Accounts: Cloud Accounts
        description="Assuming IAM role for elevated privileges"
    ),
    "CreateAccessKey": MITREMapping(
        tactics=["Persistence", "Privilege Escalation"],
        techniques=["T1098"],  # Account Manipulation
        description="Creating access key for persistence"
    ),
    "AttachUserPolicy": MITREMapping(
        tactics=["Privilege Escalation", "Persistence"],
        techniques=["T1098.001"],  # Account Manipulation: Additional Cloud Credentials
        description="Attaching policy to user for privilege escalation"
    ),
    "AttachRolePolicy": MITREMapping(
        tactics=["Privilege Escalation"],
        techniques=["T1098.001"],
        description="Attaching policy to role"
    ),
    "PutUserPolicy": MITREMapping(
        tactics=["Privilege Escalation", "Persistence"],
        techniques=["T1098"],
        description="Adding inline policy to user"
    ),
    "PutRolePolicy": MITREMapping(
        tactics=["Privilege Escalation"],
        techniques=["T1098"],
        description="Adding inline policy to role"
    ),
    "UpdateAssumeRolePolicy": MITREMapping(
        tactics=["Privilege Escalation"],
        techniques=["T1098"],
        description="Modifying role trust policy"
    ),
    
    # === Credential Access ===
    "GetSecretValue": MITREMapping(
        tactics=["Credential Access"],
        techniques=["T1555.006"],  # Credentials from Password Stores: Cloud Secrets Management Stores
        description="Retrieving secret from Secrets Manager"
    ),
    "GetParameter": MITREMapping(
        tactics=["Credential Access"],
        techniques=["T1555"],
        description="Retrieving parameter from Systems Manager"
    ),
    "GetPasswordData": MITREMapping(
        tactics=["Credential Access"],
        techniques=["T1552.005"],  # Unsecured Credentials: Cloud Instance Metadata API
        description="Retrieving EC2 instance password"
    ),
    "GetSessionToken": MITREMapping(
        tactics=["Credential Access"],
        techniques=["T1528"],  # Steal Application Access Token
        description="Obtaining temporary security credentials"
    ),
    
    # === Discovery ===
    "DescribeInstances": MITREMapping(
        tactics=["Discovery"],
        techniques=["T1580"],  # Cloud Infrastructure Discovery
        description="Enumerating EC2 instances"
    ),
    "ListBuckets": MITREMapping(
        tactics=["Discovery"],
        techniques=["T1580"],
        description="Enumerating S3 buckets"
    ),
    "DescribeDBInstances": MITREMapping(
        tactics=["Discovery"],
        techniques=["T1580"],
        description="Enumerating RDS databases"
    ),
    "ListUsers": MITREMapping(
        tactics=["Discovery"],
        techniques=["T1087.004"],  # Account Discovery: Cloud Account
        description="Enumerating IAM users"
    ),
    "ListRoles": MITREMapping(
        tactics=["Discovery"],
        techniques=["T1087.004"],
        description="Enumerating IAM roles"
    ),
    "GetAccountAuthorizationDetails": MITREMapping(
        tactics=["Discovery"],
        techniques=["T1087.004"],
        description="Gathering account authorization details"
    ),
    "DescribeRegions": MITREMapping(
        tactics=["Discovery"],
        techniques=["T1580"],
        description="Enumerating AWS regions"
    ),
    
    # === Persistence ===
    "CreateUser": MITREMapping(
        tactics=["Persistence"],
        techniques=["T1136.003"],  # Create Account: Cloud Account
        description="Creating new IAM user for persistence"
    ),
    "CreateRole": MITREMapping(
        tactics=["Persistence"],
        techniques=["T1098"],
        description="Creating new IAM role"
    ),
    "CreateLoginProfile": MITREMapping(
        tactics=["Persistence"],
        techniques=["T1136.003"],
        description="Creating console password for user"
    ),
    "CreateKeyPair": MITREMapping(
        tactics=["Persistence"],
        techniques=["T1098.004"],  # Account Manipulation: SSH Authorized Keys
        description="Creating EC2 key pair for SSH access"
    ),
    "AuthorizeSecurityGroupIngress": MITREMapping(
        tactics=["Persistence", "Defense Evasion"],
        techniques=["T1562.007"],  # Impair Defenses: Disable or Modify Cloud Firewall
        description="Opening firewall rules"
    ),
    
    # === Initial Access ===
    "ConsoleLogin": MITREMapping(
        tactics=["Initial Access"],
        techniques=["T1078.004"],  # Valid Accounts: Cloud Accounts
        description="Console login event"
    ),
    
    # === Exfiltration ===
    "GetObject": MITREMapping(
        tactics=["Collection"],
        techniques=["T1530"],  # Data from Cloud Storage Object
        description="Downloading object from S3"
    ),
    "CopyObject": MITREMapping(
        tactics=["Exfiltration"],
        techniques=["T1537"],  # Transfer Data to Cloud Account
        description="Copying S3 object (potential exfiltration)"
    ),
    "CreateSnapshot": MITREMapping(
        tactics=["Exfiltration"],
        techniques=["T1537"],
        description="Creating EBS snapshot for exfiltration"
    ),
    "ModifySnapshotAttribute": MITREMapping(
        tactics=["Exfiltration"],
        techniques=["T1537"],
        description="Sharing snapshot with external account"
    ),
    
    # === Impact ===
    "DeleteBucket": MITREMapping(
        tactics=["Impact"],
        techniques=["T1485"],  # Data Destruction
        description="Deleting S3 bucket"
    ),
    "DeleteDBInstance": MITREMapping(
        tactics=["Impact"],
        techniques=["T1485"],
        description="Deleting RDS database"
    ),
    "TerminateInstances": MITREMapping(
        tactics=["Impact"],
        techniques=["T1489"],  # Service Stop
        description="Terminating EC2 instances"
    ),
    "DeleteVolume": MITREMapping(
        tactics=["Impact"],
        techniques=["T1485"],
        description="Deleting EBS volume"
    ),
    
    # === Lateral Movement ===
    "AssumeRole": MITREMapping(
        tactics=["Lateral Movement"],
        techniques=["T1550.001"],  # Use Alternate Authentication Material: Application Access Token
        description="Using assumed role for lateral movement"
    ),
}


def get_mitre_mapping(event_name: str) -> Optional[MITREMapping]:
    """
    Get MITRE ATT&CK mapping for AWS CloudTrail event
    
    Args:
        event_name: AWS API event name (e.g., "CreateAccessKey")
        
    Returns:
        MITREMapping or None if not found
    """
    return AWS_EVENT_TO_MITRE.get(event_name)


def infer_severity_from_event(event: Dict) -> str:
    """
    Infer alert severity from CloudTrail event
    
    Args:
        event: CloudTrail event dictionary
        
    Returns:
        Severity level: Critical | High | Medium | Low
    """
    event_name = event.get("eventName", "")
    error_code = event.get("errorCode")
    read_only = event.get("readOnly", True)
    
    # Critical: Security-impacting failures
    if error_code:
        if "AccessDenied" in error_code or "Unauthorized" in error_code:
            return "High"  # Potential unauthorized access attempt
        return "Medium"
    
    # Critical: Destructive actions
    destructive_events = [
        "DeleteBucket", "DeleteTrail", "DeleteLogGroup",
        "TerminateInstances", "DeleteDBInstance", "DeleteVolume"
    ]
    if event_name in destructive_events:
        return "Critical"
    
    # High: Security configuration changes
    security_events = [
        "StopLogging", "DeleteTrail", "PutBucketPolicy",
        "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
        "AuthorizeSecurityGroupIngress", "ModifySnapshotAttribute"
    ]
    if event_name in security_events:
        return "High"
    
    # Medium: Write operations
    if not read_only:
        return "Medium"
    
    # Low: Read-only operations
    return "Low"
