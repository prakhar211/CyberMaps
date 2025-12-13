#!/usr/bin/env python3
"""
Attack Simulation Script for CyberMaps
Simulates realistic cyberattack scenarios by posting sequential alerts to the backend.
"""

import requests
import time
import argparse
import uuid
from datetime import datetime

BASE_URL = "http://localhost:8000"

# Attack Scenario Definitions
SCENARIOS = {
    "ransomware": {
        "name": "Ransomware Campaign",
        "description": "Simulates a typical ransomware attack chain",
        "alerts": [
            {
                "name": "Suspicious Phishing Email Detected",
                "severity": "High",
                "tactic": "Initial Access",
                "technique": "Phishing",
                "description": "Email from unknown sender with malicious attachment detected by email gateway"
            },
            {
                "name": "Malicious Macro Execution",
                "severity": "Critical",
                "tactic": "Execution",
                "technique": "User Execution",
                "description": "VBA macro executed from Office document, spawned cmd.exe"
            },
            {
                "name": "Registry Persistence Modified",
                "severity": "High",
                "tactic": "Persistence",
                "technique": "Registry Run Keys",
                "description": "Modification detected to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            },
            {
                "name": "Token Impersonation Detected",
                "severity": "Critical",
                "tactic": "Privilege Escalation",
                "technique": "Access Token Manipulation",
                "description": "Process attempted to duplicate administrator token"
            },
            {
                "name": "LSASS Memory Dump",
                "severity": "Critical",
                "tactic": "Credential Access",
                "technique": "LSASS Memory",
                "description": "Suspicious process reading from lsass.exe memory space"
            },
            {
                "name": "RDP Session to Domain Controller",
                "severity": "Critical",
                "tactic": "Lateral Movement",
                "technique": "Remote Desktop Protocol",
                "description": "Workstation initiated RDP connection to DC01.corp.local"
            },
            {
                "name": "Mass File Enumeration",
                "severity": "Medium",
                "tactic": "Collection",
                "technique": "Data from Local System",
                "description": "Process accessed 500+ files in Documents and Desktop folders"
            },
            {
                "name": "Large Data Upload to External IP",
                "severity": "High",
                "tactic": "Exfiltration",
                "technique": "Exfiltration Over Web Service",
                "description": "10GB uploaded to unknown cloud storage service"
            },
            {
                "name": "Ransomware Encryption in Progress",
                "severity": "Critical",
                "tactic": "Impact",
                "technique": "Data Encrypted for Impact",
                "description": "Mass file modification (.encrypted extension), ransom note detected"
            }
        ]
    },
    "apt": {
        "name": "APT (Advanced Persistent Threat)",
        "description": "Simulates a sophisticated targeted attack",
        "alerts": [
            {
                "name": "Targeted Spear Phishing",
                "severity": "High",
                "tactic": "Initial Access",
                "technique": "Spear Phishing Link",
                "description": "Email targeting C-level executive with credential harvesting link"
            },
            {
                "name": "Obfuscated PowerShell Execution",
                "severity": "Critical",
                "tactic": "Execution",
                "technique": "PowerShell",
                "description": "Base64-encoded PowerShell command executed via scheduled task"
            },
            {
                "name": "Scheduled Task Created",
                "severity": "Medium",
                "tactic": "Persistence",
                "technique": "Scheduled Task/Job",
                "description": "New scheduled task 'SystemUpdate' created for daily execution"
            },
            {
                "name": "Internal Network Scanning",
                "severity": "Medium",
                "tactic": "Discovery",
                "technique": "Network Service Discovery",
                "description": "Port scan detected targeting internal subnets 10.0.0.0/8"
            },
            {
                "name": "SMB Exploitation Attempt",
                "severity": "Critical",
                "tactic": "Lateral Movement",
                "technique": "Exploitation of Remote Services",
                "description": "EternalBlue exploit attempted against multiple internal hosts"
            },
            {
                "name": "Database Query Anomaly",
                "severity": "High",
                "tactic": "Collection",
                "technique": "Data from Information Repositories",
                "description": "User account executed unusual bulk SELECT queries on customer database"
            },
            {
                "name": "C2 Beacon Communication",
                "severity": "Critical",
                "tactic": "Command and Control",
                "technique": "Web Service",
                "description": "Periodic HTTPS beaconing to known APT infrastructure detected"
            },
            {
                "name": "Slow Data Exfiltration",
                "severity": "High",
                "tactic": "Exfiltration",
                "technique": "Exfiltration Over C2 Channel",
                "description": "Small encrypted data transfers over extended period to C2 server"
            }
        ]
    },
    "aws_breach": {
        "name": "AWS Cloud Breach",
        "description": "Simulates a cloud-focused attack targeting AWS infrastructure",
        "alerts": [
            {
                "name": "Leaked AWS Access Keys Detected",
                "severity": "Critical",
                "tactic": "Initial Access",
                "technique": "Valid Accounts",
                "description": "AWS access keys found in public GitHub repository, credentials actively used"
            },
            {
                "name": "Unauthorized IAM User Creation",
                "severity": "Critical",
                "tactic": "Persistence",
                "technique": "Create Account",
                "description": "New IAM user 'admin-backup' created with AdministratorAccess policy"
            },
            {
                "name": "IAM Policy Privilege Escalation",
                "severity": "Critical",
                "tactic": "Privilege Escalation",
                "technique": "Valid Accounts",
                "description": "IAM policy modified to grant iam:AttachUserPolicy on all resources"
            },
            {
                "name": "CloudTrail Logging Disabled",
                "severity": "Critical",
                "tactic": "Defense Evasion",
                "technique": "Impair Defenses",
                "description": "CloudTrail logging stopped in us-east-1 region, audit trail compromised"
            },
            {
                "name": "AWS Service Enumeration",
                "severity": "Medium",
                "tactic": "Discovery",
                "technique": "Cloud Service Discovery",
                "description": "Automated scanning of EC2, S3, RDS, and Lambda resources across all regions"
            },
            {
                "name": "EC2 Instance Role Assumption",
                "severity": "High",
                "tactic": "Lateral Movement",
                "technique": "Use Alternate Authentication Material",
                "description": "Attacker assumed EC2 instance role with elevated permissions"
            },
            {
                "name": "Mass S3 Bucket Download",
                "severity": "Critical",
                "tactic": "Collection",
                "technique": "Data from Cloud Storage",
                "description": "Bulk download of 50GB from 'customer-data-prod' S3 bucket"
            },
            {
                "name": "Data Exfiltration to External Account",
                "severity": "Critical",
                "tactic": "Exfiltration",
                "technique": "Transfer Data to Cloud Account",
                "description": "S3 objects copied to attacker-controlled AWS account in different region"
            }
        ]
    }
}

def post_alert(alert_data):
    """Post an alert to the backend API."""
    try:
        # Add unique ID and timestamp
        alert_data['id'] = f"sim-{uuid.uuid4().hex[:8]}"
        
        response = requests.post(f"{BASE_URL}/alerts", json=alert_data)
        response.raise_for_status()
        
        print(f"✓ [{datetime.now().strftime('%H:%M:%S')}] Posted: {alert_data['tactic']} - {alert_data['name']}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"✗ Error posting alert: {e}")
        return None

def simulate_attack(scenario_name="ransomware", delay=5):
    """Simulate an attack scenario."""
    if scenario_name not in SCENARIOS:
        print(f"Error: Unknown scenario '{scenario_name}'")
        print(f"Available scenarios: {', '.join(SCENARIOS.keys())}")
        return
    
    scenario = SCENARIOS[scenario_name]
    
    print("=" * 60)
    print(f"CyberMaps Attack Simulation")
    print(f"Scenario: {scenario['name']}")
    print(f"Description: {scenario['description']}")
    print(f"Total Alerts: {len(scenario['alerts'])}")
    print(f"Delay: {delay} seconds between alerts")
    print("=" * 60)
    print()
    
    # Check if backend is reachable
    try:
        response = requests.get(f"{BASE_URL}/health")
        response.raise_for_status()
        print("✓ Backend is reachable")
        print()
    except requests.exceptions.RequestException:
        print("✗ Error: Cannot reach backend at", BASE_URL)
        print("  Make sure the FastAPI server is running (uvicorn main:app --reload --port 8000)")
        return
    
    # Post alerts sequentially
    for i, alert in enumerate(scenario['alerts'], 1):
        print(f"[{i}/{len(scenario['alerts'])}] ", end="")
        post_alert(alert)
        
        # Wait before next alert (except for the last one)
        if i < len(scenario['alerts']):
            time.sleep(delay)
    
    print()
    print("=" * 60)
    print("✓ Simulation Complete!")
    print(f"  {len(scenario['alerts'])} alerts posted to the backend")
    print("  Check the CyberMaps UI to see the attack progression")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simulate cyberattack scenarios for CyberMaps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Scenarios:
  ransomware  - Simulates a ransomware attack chain (9 alerts)
  apt         - Simulates an Advanced Persistent Threat (8 alerts)
  aws_breach  - Simulates an AWS cloud infrastructure breach (8 alerts)

Examples:
  python simulate_attack.py
  python simulate_attack.py --scenario apt --delay 3
  python simulate_attack.py --scenario aws_breach --delay 5
        """
    )
    
    parser.add_argument(
        '--scenario',
        type=str,
        default='ransomware',
        choices=list(SCENARIOS.keys()),
        help='Attack scenario to simulate (default: ransomware)'
    )
    
    parser.add_argument(
        '--delay',
        type=int,
        default=5,
        help='Delay in seconds between alerts (default: 5)'
    )
    
    args = parser.parse_args()
    
    simulate_attack(scenario_name=args.scenario, delay=args.delay)
