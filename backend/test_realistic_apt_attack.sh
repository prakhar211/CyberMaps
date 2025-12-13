#!/bin/bash
# Realistic AWS Attack Scenario - APT Compromise
# Based on real-world cloud security attacks
# Simulates a sophisticated APT attack chain in AWS environment

echo "🎯 Simulating Realistic AWS APT Attack Chain"
echo "=============================================="
echo ""

# Get current timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Attacker Details
ATTACKER_IP="185.220.101.42"  # Known Tor exit node
ATTACKER_USER_AGENT="aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0-kali3-amd64"

# Victim Organization
ORG_ACCOUNT="987654321098"
ORG_REGION="us-east-1"

echo "📧 Alert 1: Phishing - Compromised IAM User Login"
echo "MITRE: Initial Access (T1078.004)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"IAMUser\",
      \"principalId\": \"AIDAI4QEXAMPLEUSER01\",
      \"arn\": \"arn:aws:iam::${ORG_ACCOUNT}:user/sarah.chen\",
      \"accountId\": \"${ORG_ACCOUNT}\",
      \"accessKeyId\": \"AKIAI44QH8DHBEXAMPLE\",
      \"userName\": \"sarah.chen\"
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"signin.amazonaws.com\",
    \"eventName\": \"ConsoleLogin\",
    \"awsRegion\": \"${ORG_REGION}\",
    \"sourceIPAddress\": \"${ATTACKER_IP}\",
    \"userAgent\": \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\",
    \"requestParameters\": null,
    \"responseElements\": {
      \"ConsoleLogin\": \"Success\"
    },
    \"additionalEventData\": {
      \"LoginTo\": \"https://console.aws.amazon.com/console/home\",
      \"MobileVersion\": \"No\",
      \"MFAUsed\": \"No\"
    },
    \"eventID\": \"apt-attack-$(date +%s)-001\",
    \"readOnly\": false,
    \"eventType\": \"AwsConsoleSignIn\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"${ORG_ACCOUNT}\",
    \"eventCategory\": \"Management\"
  }"

echo -e "\n\n"
sleep 2

echo "🔑 Alert 2: Privilege Escalation - Creating Admin Access Key"
echo "MITRE: Persistence + Privilege Escalation (T1098)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"IAMUser\",
      \"principalId\": \"AIDAI4QEXAMPLEUSER01\",
      \"arn\": \"arn:aws:iam::${ORG_ACCOUNT}:user/sarah.chen\",
      \"accountId\": \"${ORG_ACCOUNT}\",
      \"accessKeyId\": \"AKIAI44QH8DHBEXAMPLE\",
      \"userName\": \"sarah.chen\"
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"iam.amazonaws.com\",
    \"eventName\": \"CreateAccessKey\",
    \"awsRegion\": \"${ORG_REGION}\",
    \"sourceIPAddress\": \"${ATTACKER_IP}\",
    \"userAgent\": \"${ATTACKER_USER_AGENT}\",
    \"requestParameters\": {
      \"userName\": \"admin-backup\"
    },
    \"responseElements\": {
      \"accessKey\": {
        \"userName\": \"admin-backup\",
        \"accessKeyId\": \"AKIAI99MALICIOUSKEY\",
        \"status\": \"Active\",
        \"createDate\": \"$TIMESTAMP\"
      }
    },
    \"requestID\": \"apt-attack-$(date +%s)-002\",
    \"eventID\": \"apt-attack-$(date +%s)-002\",
    \"readOnly\": false,
    \"eventType\": \"AwsApiCall\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"${ORG_ACCOUNT}\",
    \"eventCategory\": \"Management\"
  }"

echo -e "\n\n"
sleep 2

echo "🛡️ Alert 3: Defense Evasion - Disabling CloudTrail Logging"
echo "MITRE: Defense Evasion (T1562.008)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"AssumedRole\",
      \"principalId\": \"AROAI99MALICIOUSROLE:attacker-session\",
      \"arn\": \"arn:aws:sts::${ORG_ACCOUNT}:assumed-role/AdminRole/attacker-session\",
      \"accountId\": \"${ORG_ACCOUNT}\",
      \"accessKeyId\": \"ASIAI99TEMPORARYKEY01\",
      \"sessionContext\": {
        \"sessionIssuer\": {
          \"type\": \"Role\",
          \"principalId\": \"AROAI99MALICIOUSROLE\",
          \"arn\": \"arn:aws:iam::${ORG_ACCOUNT}:role/AdminRole\",
          \"accountId\": \"${ORG_ACCOUNT}\",
          \"userName\": \"AdminRole\"
        },
        \"attributes\": {
          \"creationDate\": \"$TIMESTAMP\",
          \"mfaAuthenticated\": false
        }
      }
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"cloudtrail.amazonaws.com\",
    \"eventName\": \"StopLogging\",
    \"awsRegion\": \"${ORG_REGION}\",
    \"sourceIPAddress\": \"${ATTACKER_IP}\",
    \"userAgent\": \"${ATTACKER_USER_AGENT}\",
    \"requestParameters\": {
      \"name\": \"production-audit-trail\"
    },
    \"responseElements\": null,
    \"requestID\": \"apt-attack-$(date +%s)-003\",
    \"eventID\": \"apt-attack-$(date +%s)-003\",
    \"readOnly\": false,
    \"eventType\": \"AwsApiCall\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"${ORG_ACCOUNT}\",
    \"eventCategory\": \"Management\"
  }"

echo -e "\n\n"
sleep 2

echo "🔐 Alert 4: Credential Access - Stealing Secrets from Secrets Manager"
echo "MITRE: Credential Access (T1555.006)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"AssumedRole\",
      \"principalId\": \"AROAI99MALICIOUSROLE:attacker-session\",
      \"arn\": \"arn:aws:sts::${ORG_ACCOUNT}:assumed-role/AdminRole/attacker-session\",
      \"accountId\": \"${ORG_ACCOUNT}\",
      \"accessKeyId\": \"ASIAI99TEMPORARYKEY01\"
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"secretsmanager.amazonaws.com\",
    \"eventName\": \"GetSecretValue\",
    \"awsRegion\": \"${ORG_REGION}\",
    \"sourceIPAddress\": \"${ATTACKER_IP}\",
    \"userAgent\": \"${ATTACKER_USER_AGENT}\",
    \"requestParameters\": {
      \"secretId\": \"prod/database/master-credentials\"
    },
    \"responseElements\": null,
    \"requestID\": \"apt-attack-$(date +%s)-004\",
    \"eventID\": \"apt-attack-$(date +%s)-004\",
    \"readOnly\": true,
    \"eventType\": \"AwsApiCall\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"${ORG_ACCOUNT}\",
    \"eventCategory\": \"Management\",
    \"tlsDetails\": {
      \"tlsVersion\": \"TLSv1.3\",
      \"cipherSuite\": \"TLS_AES_128_GCM_SHA256\"
    }
  }"

echo -e "\n\n"
sleep 2

echo "📤 Alert 5: Exfiltration - Creating EBS Snapshot for Data Theft"
echo "MITRE: Exfiltration (T1537)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"AssumedRole\",
      \"principalId\": \"AROAI99MALICIOUSROLE:attacker-session\",
      \"arn\": \"arn:aws:sts::${ORG_ACCOUNT}:assumed-role/AdminRole/attacker-session\",
      \"accountId\": \"${ORG_ACCOUNT}\",
      \"accessKeyId\": \"ASIAI99TEMPORARYKEY01\"
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"ec2.amazonaws.com\",
    \"eventName\": \"CreateSnapshot\",
    \"awsRegion\": \"${ORG_REGION}\",
    \"sourceIPAddress\": \"${ATTACKER_IP}\",
    \"userAgent\": \"${ATTACKER_USER_AGENT}\",
    \"requestParameters\": {
      \"volumeId\": \"vol-0a1b2c3d4e5f6g7h8\",
      \"description\": \"Backup for data exfiltration\",
      \"tagSpecificationSet\": {}
    },
    \"responseElements\": {
      \"requestId\": \"apt-attack-$(date +%s)-005\",
      \"snapshotId\": \"snap-0x9y8z7w6v5u4t3s2\",
      \"volumeId\": \"vol-0a1b2c3d4e5f6g7h8\",
      \"state\": \"pending\",
      \"startTime\": \"$TIMESTAMP\",
      \"progress\": \"0%\",
      \"ownerId\": \"${ORG_ACCOUNT}\",
      \"volumeSize\": 500,
      \"encrypted\": false
    },
    \"requestID\": \"apt-attack-$(date +%s)-005\",
    \"eventID\": \"apt-attack-$(date +%s)-005\",
    \"readOnly\": false,
    \"eventType\": \"AwsApiCall\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"${ORG_ACCOUNT}\",
    \"eventCategory\": \"Management\"
  }"

echo -e "\n\n"
sleep 2

echo "💥 Alert 6: Impact - Deleting Critical S3 Bucket (Ransomware)"
echo "MITRE: Impact (T1485)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"AssumedRole\",
      \"principalId\": \"AROAI99MALICIOUSROLE:attacker-session\",
      \"arn\": \"arn:aws:sts::${ORG_ACCOUNT}:assumed-role/AdminRole/attacker-session\",
      \"accountId\": \"${ORG_ACCOUNT}\",
      \"accessKeyId\": \"ASIAI99TEMPORARYKEY01\"
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"s3.amazonaws.com\",
    \"eventName\": \"DeleteBucket\",
    \"awsRegion\": \"${ORG_REGION}\",
    \"sourceIPAddress\": \"${ATTACKER_IP}\",
    \"userAgent\": \"${ATTACKER_USER_AGENT}\",
    \"requestParameters\": {
      \"bucketName\": \"acme-corp-customer-data-prod\",
      \"Host\": \"acme-corp-customer-data-prod.s3.amazonaws.com\"
    },
    \"responseElements\": null,
    \"requestID\": \"apt-attack-$(date +%s)-006\",
    \"eventID\": \"apt-attack-$(date +%s)-006\",
    \"readOnly\": false,
    \"resources\": [
      {
        \"type\": \"AWS::S3::Bucket\",
        \"ARN\": \"arn:aws:s3:::acme-corp-customer-data-prod\"
      }
    ],
    \"eventType\": \"AwsApiCall\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"${ORG_ACCOUNT}\",
    \"eventCategory\": \"Management\"
  }"

echo -e "\n\n=============================================="
echo "✅ APT Attack Chain Simulation Complete!"
echo ""
echo "📊 Attack Summary:"
echo "  1. Initial Access: Compromised IAM user login from Tor"
echo "  2. Persistence: Created backdoor access key"
echo "  3. Defense Evasion: Disabled CloudTrail logging"
echo "  4. Credential Access: Stole database credentials"
echo "  5. Exfiltration: Created EBS snapshot"
echo "  6. Impact: Deleted critical S3 bucket"
echo ""
echo "🎯 MITRE ATT&CK Tactics Covered: 6/14"
echo "⚠️  Severity: CRITICAL - Full compromise scenario"
echo "=============================================="
