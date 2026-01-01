"""
Webhook Receiver Endpoints

Receives security alerts from SIEM platforms via webhooks.
"""

from fastapi import APIRouter, Request, HTTPException, Depends
from typing import Dict, Any
import logging
from connectors.coralogix_connector import CoralogixConnector
from connectors.base import ConnectorConfig
from schemas.unified_alert import UnifiedAlert
from database import SessionLocal
from markov import TACTICS  # Import TACTICS list for validation
import json


router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])
logger = logging.getLogger(__name__)


# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/coralogix")
async def receive_coralogix_webhook(request: Request):
    """
    Receive alerts from Coralogix via Generic Webhook
    
    Coralogix sends alerts to this endpoint. We normalize and store them.
    
    Returns:
        Dict with status and alert ID
    """
    try:
        # Get raw body for signature validation
        body = await request.body()
        headers = dict(request.headers)
        
        # Parse JSON payload
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Initialize Coralogix connector
        connector = CoralogixConnector(ConnectorConfig(
            platform="coralogix",
            enabled=True
        ))
        
        # Validate webhook signature
        is_valid = await connector.validate_webhook_signature(headers, body)
        if not is_valid:
            logger.warning("Invalid webhook signature from Coralogix")
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
        
        # Normalize alert
        try:
            unified_alert = connector.normalize_alert(payload)
        except Exception as e:
            logger.error(f"Failed to normalize Coralogix alert: {e}", exc_info=True)
            raise HTTPException(status_code=422, detail=f"Failed to normalize alert: {str(e)}")
        
        # Store alert in database
        try:
            from models import AlertModel
            from datetime import datetime
            
            # Prepare tactic string
            tactic_str = ", ".join(unified_alert.mitre_tactics) if unified_alert.mitre_tactics else "Unknown"
            
            # Validate each tactic in the list
            if unified_alert.mitre_tactics:
                valid_tactics = []
                invalid_tactics = []
                
                for tactic in unified_alert.mitre_tactics:
                    if tactic in TACTICS:
                        valid_tactics.append(tactic)
                    else:
                        invalid_tactics.append(tactic)
                
                if invalid_tactics:
                    logger.warning(f"Alert contains invalid tactics: {', '.join(invalid_tactics)}. Valid tactics: {', '.join(valid_tactics)}")
                
                # Use only valid tactics, or "Unknown" if none are valid
                tactic_str = ", ".join(valid_tactics) if valid_tactics else "Unknown"
            
            db_alert = AlertModel(
                id=unified_alert.cybermap_id,
                name=unified_alert.name,
                severity=unified_alert.severity.value,
                tactic=tactic_str,
                technique=", ".join(unified_alert.mitre_techniques) if unified_alert.mitre_techniques else None,
                description=unified_alert.description,
                created_at=unified_alert.timestamp_utc,
                raw_data=payload  # Store the complete CloudTrail event
            )
            
            # Get database session
            db = next(get_db())
            db.add(db_alert)
            db.commit()
            db.refresh(db_alert)
            
            logger.info(f"Stored alert in database: {unified_alert.name} (ID: {unified_alert.cybermap_id})")
            
        except Exception as e:
            logger.error(f"Failed to store alert in database: {e}", exc_info=True)
            # Don't fail the request if storage fails
        
        logger.info(f"Received Coralogix alert: {unified_alert.name} (ID: {unified_alert.cybermap_id})")
        
        # TODO: Trigger attack graph analysis
        # TODO: Trigger enrichment pipeline
        
        return {
            "status": "success",
            "alert_id": unified_alert.cybermap_id,
            "message": "Alert ingested successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing Coralogix webhook: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/sentinel")
async def receive_sentinel_webhook(request: Request):
    """
    Receive alerts from Azure Sentinel via Logic Apps
    
    TODO: Implement Sentinel connector
    """
    return {"status": "not_implemented", "message": "Sentinel connector coming soon"}


@router.get("/health")
async def webhook_health():
    """Health check endpoint for webhooks"""
    return {"status": "healthy", "service": "webhook_receiver"}
