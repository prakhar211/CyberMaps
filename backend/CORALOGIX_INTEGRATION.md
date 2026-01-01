# Coralogix Integration Guide

> **Developing Locally?** See [LOCAL_WEBHOOK_TESTING.md](../LOCAL_WEBHOOK_TESTING.md) for instructions on how to use ngrok to receive webhooks on localhost.

Since Coralogix Generic Webhooks do not support automatic signing (HMAC) by default, CyberMaps uses an **API Key** mechanism to secure the webhook endpoint.

## 1. Get your API Key
You can use any random string as your API Key. Ensure it matches the `CORALOGIX_WEBHOOK_SECRET` set in your CyberMaps backend environment variables.

Example:
```bash
CORALOGIX_WEBHOOK_SECRET=my_secure_random_string_123
```

## 2. Configure Coralogix Webhook

1. Go to **Data Flow** > **Webhooks** in Coralogix.
2. Click **+ Add New** > **Generic Webhook**.
3. **Name**: `CyberMaps Integration`
4. **URL**: 
   ```
   https://your-cybermaps-domain.com/api/webhooks/coralogix?api_key=my_secure_random_string_123
   ```
   *Replace `my_secure_random_string_123` with your secret.*
   *Alternatively, you can add a Custom Header: `X-CyberMaps-API-Key: my_secure_random_string_123` if your webhook provider supports it.*

5. **Method**: `POST`
6. **Body**: Select **Custom** (or specific JSON option).
7. **Payload**: Copy and paste the following JSON template. This maps Coralogix variables to the format CyberMaps expects.

```json
{
  "alert": {
    "name": "$ALERT_NAME",
    "id": "$ALERT_ID",
    "severity": "$ALERT_SEVERITY",
    "timestamp": "$EVENT_TIMESTAMP",
    "description": "Coralogix Alert: $ALERT_NAME triggered by $MATCH_COUNT events.",
    "tags": ["source:coralogix", "mitre_tactic:Initial Access"], 
    "metadata": {
        "log_url": "$LOG_URL",
        "description": "$ALERT_DESCRIPTION"
    }
  }
}
```

> **Note on Tags**: Coralogix placeholders might not automatically extract MITRE tactics. You can:
> - Hardcode tags if you are creating specific webhooks for specific alerts (e.g. "mitre_tactic:Persistence").
> - Or pass them in the description or metadata if you have a way to inject them.

## 3. Test Configuration
Click **Test Configuration**. You should see a success message. CyberMaps will log: `Received Coralogix Test Payload`.
