"""
Webhook Receiver Endpoints

Receives security alerts from SIEM platforms via webhooks.
Uses ConnectorRegistry to dynamically load the appropriate connector.
"""

from fastapi import APIRouter, Request, HTTPException, Depends
from typing import Dict, Any, List
import logging
import json
from datetime import datetime

# Connectors
from connectors.registry import ConnectorRegistry
from connectors.base import ConnectorConfig
# Ensure connectors are registered
import connectors.coralogix_connector
import connectors.splunk_connector

# Core
from core.deps import get_repository
from core.repository import AlertRepository
from schemas.unified_alert import UnifiedAlert
from core.prediction import TACTICS

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])
logger = logging.getLogger(__name__)

@router.get("/health")
async def webhook_health():
    """Health check endpoint for webhooks"""
    return {"status": "healthy", "service": "webhook_receiver", "supported_platforms": ConnectorRegistry.list_platforms()}

@router.post("/{platform}")
async def receive_webhook(
    platform: str, 
    request: Request,
    repo: AlertRepository = Depends(get_repository)
):
    """
    Generic Webhook Receiver
    
    Dynamically loads the connector for {platform} and processes the alert.
    """
    platform = platform.lower()
    connector_cls = ConnectorRegistry.get_connector_class(platform)
    
    if not connector_cls:
        raise HTTPException(status_code=404, detail=f"Platform '{platform}' not supported. Available: {ConnectorRegistry.list_platforms()}")

    try:
        # Get raw body for signature validation
        body = await request.body()
        headers = dict(request.headers)
        query_params = dict(request.query_params)

        # Initialize Connector
        # In a real app, we would load config from DB or Env based on platform/tenant
        # For now, we use default/env config
        config = ConnectorConfig(
            platform=platform,
            enabled=True
        )
        connector = connector_cls(config)
        
        # Validate Signature/Auth
        is_valid = await connector.validate_webhook_signature(headers, body, query_params)
        if not is_valid:
            logger.warning(f"Invalid signature for {platform}")
            raise HTTPException(status_code=401, detail="Invalid signature or API key")

        # Parse JSON
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        # Handle Test Payload (Standardize this? Coralogix has a specific one)
        # TODO: Move test check to BaseConnector or individual connectors
        if platform == "coralogix" and ("test" in payload or payload.get("alert", {}).get("name") == "Test Alert"):
             return {"status": "success", "message": "Test connection successful"}

        # Normalize
        try:
            unified_alert: UnifiedAlert = connector.normalize_alert(payload)
        except Exception as e:
            logger.error(f"Normalization failed for {platform}: {e}", exc_info=True)
            raise HTTPException(status_code=422, detail=f"Normalization failed: {str(e)}")

        # Store using Repository
        _store_alert(repo, unified_alert, payload)
        
        logger.info(f"Ingested {platform} alert: {unified_alert.name} ({unified_alert.cybermap_id})")
        
        return {
            "status": "success",
            "alert_id": unified_alert.cybermap_id,
            "message": "Alert processed successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing webhook for {platform}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

def _store_alert(repo: AlertRepository, alert: UnifiedAlert, raw_payload: Dict[str, Any]):
    """Helper to convert UnifiedAlert to Repo/DB format and save"""
    
    # Clean up tactics
    tactic_list = []
    if alert.mitre_tactics:
        tactic_list = [t for t in alert.mitre_tactics if t in TACTICS]
    
    tactic_str = ", ".join(tactic_list) if tactic_list else "Unknown"

    # Convert to Dict for Repository
    # The SqliteRepository currently expects a Dict slightly different from UnifiedAlert
    # We should align them, but for now we map manually.
    
    alert_data = {
        "id": alert.cybermap_id,
        "name": alert.name,
        "severity": alert.severity.value,
        "tactic": tactic_str,
        "technique": ", ".join(alert.mitre_techniques) if alert.mitre_techniques else None,
        "description": alert.description,
        "raw_data": raw_payload, # Store original raw payload
        "created_at": alert.timestamp_utc
    }
    
    repo.create_alert(alert_data)
