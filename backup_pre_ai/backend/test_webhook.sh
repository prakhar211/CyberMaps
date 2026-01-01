#!/bin/bash
# Test Coralogix Webhook with Real Log Structure
# Based on the screenshot provided

echo "Testing Coralogix Webhook Endpoint..."
echo "======================================"

# Get current timestamp for test identification
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Test 1: AWS CloudTrail CreateLogStream event (from screenshot)
echo -e "\n📝 Test 1: CloudTrail CreateLogStream Event"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"AssumedRole\",
      \"principalId\": \"AROATZAO3D3B7QC5HRCKQ:CloudTrail-cx-1751260802651-LambdaFunction-6EumBxDNCTGG\",
      \"arn\": \"arn:aws:sts::259876658883:assumed-role/CloudTrail-cx-1751260802651-LambdaExecutionRole-drfR9Kc808w5/CloudTrail-cx-1751260802651-LambdaFunction-6EumBxDNCTGG\",
      \"accountId\": \"259876658883\",
      \"accessKeyId\": \"ASIATZAO3D3BW4NZ6GK5\",
      \"sessionContext\": {
        \"sessionIssuer\": {
          \"type\": \"Role\",
          \"principalId\": \"AROATZAO3D3B7QC5HRCKQ\",
          \"arn\": \"arn:aws:iam::259876658883:role/CloudTrail-cx-1751260802651-LambdaExecutionRole-drfR9Kc808w5\",
          \"accountId\": \"259876658883\",
          \"userName\": \"CloudTrail-cx-1751260802651-LambdaExecutionRole-drfR9Kc808w5\"
        },
        \"attributes\": {
          \"creationDate\": \"$TIMESTAMP\",
          \"mfaAuthenticated\": false
        }
      }
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"logs.amazonaws.com\",
    \"eventName\": \"TestIngestion-CreateLogStream\",
    \"awsRegion\": \"ap-south-1\",
    \"sourceIPAddress\": \"13.235.54.4\",
    \"userAgent\": \"awslambda-worker/1.0.0 rusoto/0.48.0 rust/1.87.0 linux\",
    \"requestParameters\": {
      \"logGroupName\": \"/aws/lambda/CloudTrail-cx-1751260802651-LambdaFunction-6EumBxDNCTGG\",
      \"logStreamName\": \"2025/07/29/[\$LATEST]f27eff66c8c614faba7213f0fc2e8ec4c\"
    },
    \"responseElements\": null,
    \"requestID\": \"7e85b216-1043-47b4-9191-0a58f4e69ed1\",
    \"eventID\": \"test-evt-$(date +%s)-001\",
    \"readOnly\": false,
    \"eventType\": \"AwsApiCall\",
    \"apiVersion\": \"20140328\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"259876658883\",
    \"eventCategory\": \"Management\",
    \"tlsDetails\": {
      \"tlsVersion\": \"TLSv1.3\"
    },
    \"inScopeOf\": {
      \"issuerType\": \"AWS::Lambda::Function\",
      \"credentialsIssuedTo\": \"arn:aws:lambda:ap-south-1:259876658883:function:CloudTrail-cx-1751260802651-LambdaFunction-6EumBxDNCTGG\"
    }
  }"

echo -e "\n\n"

# Test 2: High-severity event - StopLogging (Defense Evasion)
echo "🚨 Test 2: High Severity - StopLogging (Defense Evasion)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d "{
    \"eventVersion\": \"1.11\",
    \"userIdentity\": {
      \"type\": \"IAMUser\",
      \"principalId\": \"AIDAI23HXS4EXAMPLE\",
      \"arn\": \"arn:aws:iam::259876658883:user/suspicious-admin\",
      \"accountId\": \"259876658883\",
      \"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\",
      \"userName\": \"suspicious-admin\"
    },
    \"eventTime\": \"$TIMESTAMP\",
    \"eventSource\": \"cloudtrail.amazonaws.com\",
    \"eventName\": \"TestIngestion-StopLogging\",
    \"awsRegion\": \"us-east-1\",
    \"sourceIPAddress\": \"203.0.113.42\",
    \"userAgent\": \"aws-cli/2.0.0 Python/3.9.0 Linux/5.10.0\",
    \"requestParameters\": {
      \"name\": \"production-trail\"
    },
    \"responseElements\": null,
    \"requestID\": \"abc-123-def-456\",
    \"eventID\": \"test-evt-$(date +%s)-002\",
    \"readOnly\": false,
    \"eventType\": \"AwsApiCall\",
    \"managementEvent\": true,
    \"recipientAccountId\": \"259876658883\",
    \"eventCategory\": \"Management\"
  }"

echo -e "\n\n"

# Test 3: Critical event - CreateAccessKey (Persistence)
echo "⚠️  Test 3: Critical - CreateAccessKey (Persistence)"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d '{
    "eventVersion": "1.11",
    "userIdentity": {
      "type": "AssumedRole",
      "principalId": "AROAI23HXS4EXAMPLE:attacker-session",
      "arn": "arn:aws:sts::259876658883:assumed-role/CompromisedRole/attacker-session",
      "accountId": "259876658883",
      "accessKeyId": "ASIATZAO3D3BW4NZ6GK5",
      "sessionContext": {
        "sessionIssuer": {
          "type": "Role",
          "principalId": "AROAI23HXS4EXAMPLE",
          "arn": "arn:aws:iam::259876658883:role/CompromisedRole",
          "accountId": "259876658883",
          "userName": "CompromisedRole"
        },
        "attributes": {
          "creationDate": "2025-12-08T08:15:00Z",
          "mfaAuthenticated": false
        }
      }
    },
    "eventTime": "2025-12-08T08:20:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "198.51.100.42",
    "userAgent": "aws-cli/2.0.0 Python/3.9.0 Windows/10",
    "requestParameters": {
      "userName": "backdoor-user"
    },
    "responseElements": {
      "accessKey": {
        "userName": "backdoor-user",
        "accessKeyId": "AKIAI44QH8DHBEXAMPLE",
        "status": "Active",
        "createDate": "2025-12-08T08:20:00Z"
      }
    },
    "requestID": "create-key-123",
    "eventID": "evt-create-key-001",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "259876658883",
    "eventCategory": "Management"
  }'

echo -e "\n\n"

# Test 4: Credential Access - GetSecretValue
echo "🔑 Test 4: Credential Access - GetSecretValue"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d '{
    "eventVersion": "1.11",
    "userIdentity": {
      "type": "AssumedRole",
      "principalId": "AROAI23HXS4EXAMPLE:malicious-session",
      "arn": "arn:aws:sts::259876658883:assumed-role/AppRole/malicious-session",
      "accountId": "259876658883",
      "accessKeyId": "ASIATZAO3D3BW4NZ6GK5"
    },
    "eventTime": "2025-12-08T08:30:00Z",
    "eventSource": "secretsmanager.amazonaws.com",
    "eventName": "GetSecretValue",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.100",
    "userAgent": "aws-sdk-python/1.20.0 Python/3.9.0",
    "requestParameters": {
      "secretId": "prod/database/master-password"
    },
    "responseElements": null,
    "requestID": "get-secret-123",
    "eventID": "evt-get-secret-001",
    "readOnly": true,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "259876658883",
    "eventCategory": "Management"
  }'

echo -e "\n\n"

# Test 5: Exfiltration - CreateSnapshot
echo "📤 Test 5: Exfiltration - CreateSnapshot"
curl -X POST http://localhost:8000/api/webhooks/coralogix \
  -H "Content-Type: application/json" \
  -d '{
    "eventVersion": "1.11",
    "userIdentity": {
      "type": "IAMUser",
      "principalId": "AIDAI23HXS4EXAMPLE",
      "arn": "arn:aws:iam::259876658883:user/attacker",
      "accountId": "259876658883",
      "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "userName": "attacker"
    },
    "eventTime": "2025-12-08T08:45:00Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "CreateSnapshot",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.100",
    "userAgent": "aws-cli/2.0.0",
    "requestParameters": {
      "volumeId": "vol-0123456789abcdef0",
      "description": "Backup for exfiltration"
    },
    "responseElements": {
      "snapshotId": "snap-0123456789abcdef0"
    },
    "requestID": "create-snap-123",
    "eventID": "evt-create-snap-001",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "259876658883",
    "eventCategory": "Management"
  }'

echo -e "\n\n======================================"
echo "✅ All tests completed!"
echo "Check the responses above for alert IDs and status"
