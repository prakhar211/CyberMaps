from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Optional, Any
import networkx as nx
from core.prediction import predictor, TACTICS
from core.repository import AlertRepository
from core.engine import GraphBuilder

from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
import uuid
from datetime import datetime

from core.deps import get_db, get_repository

from ai_engine import ai_engine
# Import webhook router
from routers.webhooks import router as webhooks_router
from routers.simulation import router as simulation_router

# Create Tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI Attack Path Predictor", version="1.0.0")

# CORS setup
origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "*"  # Allow all for Vercel/Playground access
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(webhooks_router)
app.include_router(simulation_router)


# --- Pydantic Models ---

class AlertBase(BaseModel):
    name: str
    severity: str
    tactic: str # MITRE Tactic
    technique: Optional[str] = None
    description: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None # Support for raw logs

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: Optional[str] = None
    
    class Config:
        from_attributes = True

class PredictionRequest(BaseModel):
    current_tactic: str
    n_steps: int = 1
    investigation_id: Optional[str] = None # Added for Context

class PredictionItem(BaseModel):
    tactic: str
    probability: float
    target_layer: Optional[str] = None
    # AI Enriched Fields
    huntingQueries: Optional[List[Dict[str, str]]] = None
    detectionRules: Optional[List[Dict[str, str]]] = None
    description: Optional[str] = None
    contextIOCs: Optional[List[Dict[str, str]]] = None

class PredictionResponse(BaseModel):
    next_tactics: List[PredictionItem]

class InvestigationRequest(BaseModel):
    name: str
    alert_ids: List[str]

class Investigation(BaseModel):
    id: str
    name: str
    created_at: datetime
    alert_ids: List[str]
    graph: Dict[str, Any] # Store the correlated graph
    
    model_config = ConfigDict(from_attributes=True)

class AppendAlertsRequest(BaseModel):
    alert_ids: List[str]

# --- Initial Data Seeding ---
def seed_initial_data(db: Session):
    if db.query(models.AlertModel).count() == 0:
        initial_alerts = [
            models.AlertModel(id="a1", name="Phishing Email", severity="High", tactic="Initial Access", technique="Phishing", description="Suspicious email with link"),
            models.AlertModel(id="a2", name="Malicious Process", severity="Medium", tactic="Execution", technique="Command and Scripting Interpreter", description="Powershell execution"),
            models.AlertModel(id="a3", name="C2 Beacon", severity="Critical", tactic="Command and Control", technique="Web Service", description="Periodic HTTP requests"),
        ]
        db.add_all(initial_alerts)
        db.commit()
        print("DEBUG: Seeded initial alerts.")

# Seed on startup (hacky but works for simple app)
with SessionLocal() as db:
    seed_initial_data(db)


# --- Endpoints ---

@app.get("/alerts", response_model=List[Alert])
def get_alerts(
    time_filter: Optional[str] = None,  # "30m", "1h", "24h", "7d", "all"
    repo: AlertRepository = Depends(get_repository)
):
    """
    Get alerts with optional time-based filtering
    
    Args:
        time_filter: Time range filter - "30m", "1h", "24h", "7d", or "all" (default)
    """
    return repo.get_alerts(time_filter)

def validate_tactic(tactic_string: str) -> tuple:
    """
    Validate that tactic string contains only valid MITRE tactics.
    Returns (is_valid, error_message)
    """
    if not tactic_string or tactic_string.strip() == "":
        return False, "Tactic cannot be empty"
    
    # Split by comma for multi-tactic support
    tactics = [t.strip() for t in tactic_string.split(',')]
    
    invalid_tactics = []
    for tactic in tactics:
        # Allow "Unknown" for operational events
        if tactic not in TACTICS and tactic != "Unknown":
            invalid_tactics.append(tactic)
    
    if invalid_tactics:
        return False, f"Invalid tactics: {', '.join(invalid_tactics)}. Must be one of: {', '.join(TACTICS)} or 'Unknown'"
    
    return True, ""

@app.post("/alerts", response_model=Alert)
def create_alert(alert: Alert, repo: AlertRepository = Depends(get_repository)):
    # Validate tactic before creating alert
    is_valid, error_msg = validate_tactic(alert.tactic)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    
    # Check if ID provided, else generate
    alert_id = alert.id if alert.id else str(uuid.uuid4())
    
    # Normalize raw_data if present (Manual Entry support)
    raw_data_final = alert.raw_data
    if raw_data_final:
        import json
        # Hard limit size check (10KB)
        try:
            serialized_size = len(json.dumps(raw_data_final))
            if serialized_size > 10000:
                raise HTTPException(status_code=400, detail="Raw data too large. Limit is 10KB.")
        except Exception as e:
            # If serialization fails (shouldn't for valid dict), or other error
            if isinstance(e, HTTPException): raise e
            # Fallback
            pass

        # 1. Normalize Source IP
        if "sourceIPAddress" not in raw_data_final:
            for key in ["Source IP", "src_ip", "ip", "source_ip"]:
                if key in raw_data_final:
                    raw_data_final["sourceIPAddress"] = raw_data_final[key]
                    break
        
        # 2. Normalize User Identity
        if "userIdentity" not in raw_data_final:
            user_name = None
            for key in ["UserName", "User", "username", "user"]:
                if key in raw_data_final:
                    user_name = raw_data_final[key]
                    break
            
            if user_name:
                # Structure it like CloudTrail for compatibility with Summary
                raw_data_final["userIdentity"] = {
                    "userName": user_name,
                    "type": "ManualUser"
                }

        # 3. Normalize Timestamp
        if "eventTime" not in raw_data_final:
            for key in ["Timestamps", "Timestamp", "time", "date"]:
                if key in raw_data_final:
                    raw_data_final["eventTime"] = raw_data_final[key]
                    break
        
        # 4. Normalize Host/Resource (Where)
        if "requestParameters" not in raw_data_final:
             # Try to map Hostname/Resource to a generic parameter for 'Where' logic
             resource = None
             for key in ["Hostname", "host", "ComputerName", "Resource", "target"]:
                 if key in raw_data_final:
                     resource = raw_data_final[key]
                     break
             
             if resource:
                 # Hack: Put it in requestParameters.instanceId or similar to be picked up
                 # Or just generic key that our Summary logic might use if we expand it.
                 # Current Summary logic checks for specific param keys.
                 # Let's map to 'destionation' or 'target' if we update summary, 
                 # but for now, let's just leave it in raw_data. 
                 # The Summary logic falls back to simple parsing if needed, but it's stricter.
                 # Let's pretend it's an instance for better visualization if it looks like a host.
                 raw_data_final["requestParameters"] = {"instanceId": resource}

    # Use Repository to create alert
    alert_dict = alert.model_dump()
    alert_dict['id'] = alert_id
    alert_dict['raw_data'] = raw_data_final
    
    return repo.create_alert(alert_dict)

@app.post("/predict", response_model=PredictionResponse)
async def predict_next_step(request: PredictionRequest, repo: AlertRepository = Depends(get_repository)):
    # Handle multi-tactic strings - extract first tactic for validation
    current_tactic = request.current_tactic
    if ',' in current_tactic:
        tactics = [t.strip() for t in current_tactic.split(',')]
        current_tactic = tactics[0]
    
    # Validate the tactic
    if current_tactic not in TACTICS:
        raise HTTPException(status_code=400, detail=f"Invalid tactic: {current_tactic}")
    
    # Pass original tactic string to predictor (it handles multi-tactics internally)
    predictions = predictor.predict_next(request.current_tactic)
    # Logic to map tactic to target layer
    def get_target_layer(tactic):
        if tactic in ["Discovery", "Lateral Movement"]: return "Database"
        if tactic in ["Exfiltration"]: return "Internet"
        if tactic in ["Command and Control"]: return "Firewall"
        return None

    # Format for response
    formatted_items = []
    
    # If investigation_id is present, we try to enrich the TOP result with AI
    ai_context = None
    if request.investigation_id:
        inv = repo.get_investigation_by_id(request.investigation_id)
        if inv and inv.alert_ids:
             # Fetch alerts
             alerts = repo.get_alerts_by_ids(inv.alert_ids)
             
             # helper to safely get attr or key
             def get_attr(obj, attr, default=None):
                 if isinstance(obj, dict): return obj.get(attr, default)
                 return getattr(obj, attr, default)

             # Convert to dicts
             ai_context = []
             for a in alerts:
                 if hasattr(a, "model_dump"):
                    ai_context.append(a.model_dump())
                 elif hasattr(a, "__dict__"):
                    d = {k:v for k,v in a.__dict__.items() if not k.startswith('_')}
                    ai_context.append(d)
                 else:
                    ai_context.append(a)
    
    for i, p in enumerate(predictions):
        tactic_name = p[0]
        prob = p[1]
        
        item = PredictionItem(
            tactic=tactic_name,
            probability=prob,
            target_layer=get_target_layer(tactic_name)
        )
        
        # Only enrich the top-most prediction (index 0) to save time/cost
        if i == 0 and ai_context:
            intel = await ai_engine.generate_hunting_intel(
                current_tactic=request.current_tactic,
                predicted_tactic=tactic_name,
                alerts_context=ai_context
            )
            
            # Map valid fields
            if intel:
                item.huntingQueries = intel.get("huntingQueries")
                item.detectionRules = intel.get("detectionRules")
                item.description = intel.get("description")
                item.contextIOCs = intel.get("contextIOCs")

        formatted_items.append(item)

    return PredictionResponse(next_tactics=formatted_items)

# Mock Threat Intel Data (Static)
TACTIC_INFO = {
    "Reconnaissance": {
        "description": "The adversary is trying to gather information they can use to plan future operations.",
        "impact": "Information gathered can be used to identify vulnerabilities and target critical systems.",
        "mitigation": "Limit information exposed in public facing systems. Monitor logs for scanning activity.",
        "logs": ["Web Server Access Logs", "Firewall Allow/Deny Logs", "DNS Query Logs"]
    },
    "Resource Development": {
        "description": "The adversary is trying to establish resources they can use to support operations.",
        "impact": "Adversaries may use these resources to launch attacks, store stolen data, or command compromised systems.",
        "mitigation": "Monitor for newly registered domains and compromised accounts.",
        "logs": ["Domain Registration Records", "SSL Certificate Logs", "Threat Intel Feeds"]
    },
    "Initial Access": {
        "description": "The adversary is trying to get into your network.",
        "impact": "Successful access allows the adversary to execute code and potentially move laterally within the network.",
        "mitigation": "Enforce MFA, patch vulnerability facing internet, and train users against phishing.",
        "logs": ["Email Gateway Logs", "VPN Login Logs", "Web Server Error Logs", "Failed Auth Events"]
    },
    "Execution": {
        "description": "The adversary is trying to run malicious code.",
        "impact": "Malicious code execution is often a precursor to further malicious activities such as persistence or data theft.",
        "mitigation": "Use application allowlisting (AppLocker) and Endpoint Detection & Response (EDR).",
        "logs": ["Sysmon Event ID 1 (Process Create)", "PowerShell Script Block Logging", "Windows Event ID 4688"]
    },
    "Persistence": {
        "description": "The adversary is trying to maintain their foothold.",
        "impact": "Allows the adversary to retain access even if credentials are changed or systems are restarted.",
        "mitigation": "Monitor for changes to scheduled tasks, startup folders, and registry keys.",
        "logs": ["Registry Event Logs", "Scheduled Task Logs (Event ID 4698)", "Startup Folder Monitoring"]
    },
    "Privilege Escalation": {
        "description": "The adversary is trying to gain higher-level permissions.",
        "impact": "Higher privileges enable the adversary to access restricted data and control critical system functions.",
        "mitigation": "Audit user permissions and enforce principle of least privilege.",
        "logs": ["Windows Event ID 4672 (Admin Logon)", "Sudo Usage Logs", "User Group Modification Logs"]
    },
    "Defense Evasion": {
        "description": "The adversary is trying to avoid being detected.",
        "impact": "Hides malicious activity, making detection and response more difficult and delaying remediation.",
        "mitigation": "Monitor for disabling of security tools and clearing of event logs.",
        "logs": ["Windows Event ID 1102 (Log Clear)", "Antivirus Alert Logs", "Sysmon Event ID 7 (Image Load)"]
    },
    "Credential Access": {
        "description": "The adversary is trying to steal account names and passwords.",
        "impact": "Stolen credentials provided legitimate-looking access to systems, data, and resources.",
        "mitigation": "Monitor for LSASS dumping and unusual login patterns.",
        "logs": ["Windows Event ID 4624 (Logon)", "LSASS Access Logs (Sysmon ID 10)", "Kerberos Ticket Logs"]
    },
    "Discovery": {
        "description": "The adversary is trying to figure out your environment.",
        "impact": "Provides the adversary with knowledge of the network topology, systems, and sensitive data locations.",
        "mitigation": "Monitor for network scanning and enumeration commands.",
        "logs": ["Process Execution Logs (net.exe, whoami)", "Network Flow Logs", "DNS Reverse Lookups"]
    },
    "Lateral Movement": {
        "description": "The adversary is trying to move through your environment.",
        "impact": "Expands the scope of the compromise to additional systems, increasing the potential for damage.",
        "mitigation": "Segment networks and monitor for RDP/SMB usage between workstations.",
        "logs": ["RDP Login Logs (Event ID 4624 Type 10)", "SMB Session Logs", "PsExec Execution Logs"]
    },
    "Collection": {
        "description": "The adversary is trying to gather data of interest to their goal.",
        "impact": "Sensitive data is gathered and staged for potential exfiltration, leading to data loss/breach.",
        "mitigation": "Encrypt sensitive data at rest and monitor for mass file access.",
        "logs": ["File Access Logs (Audit Object Access)", "Database Query Logs", "SharePoint Access Logs"]
    },
    "Command and Control": {
        "description": "The adversary is trying to communicate with compromised systems to control them.",
        "impact": "Allows the adversary to remotely control compromised systems and exfiltrate data.",
        "mitigation": "Block known C2 domains and monitor for beaconing traffic.",
        "logs": ["Proxy Logs", "Firewall Traffic Logs", "DNS Request Logs"]
    },
    "Exfiltration": {
        "description": "The adversary is trying to steal data.",
        "impact": "Results in the unauthorized transfer of sensitive data out of the network, causing financial and reputational damage.",
        "mitigation": "Monitor for large data transfers out of the network.",
        "logs": ["DLP Alerts", "FTP/SCP Transfer Logs", "Cloud Storage Upload Logs"]
    },
    "Impact": {
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        "impact": "Destruction or manipulation of data and systems can cause significant operational disruption.",
        "mitigation": "Maintain offline backups and disaster recovery plans.",
        "logs": ["System Availability Logs", "Backup Integrity Logs", "Disk Wiping Alerts"]
    }
}

@app.post("/tactic/{name}")
async def get_tactic_info_post(name: str):
    return get_tactic_info(name)

@app.get("/tactic/{name}")
def get_tactic_info(name: str):
    name_clean = name.split(":")[0].strip() 
    info = TACTIC_INFO.get(name_clean)
    if not info:
        for key in TACTIC_INFO:
            if key.lower() in name_clean.lower() or name_clean.lower() in key.lower():
                return TACTIC_INFO[key]
        return {"description": "No specific intelligence available for this tactic.", "mitigation": "General security best practices apply."}
    return info

@app.get("/tactics")
def get_tactics():
    return TACTICS

@app.get("/")
def read_root():
    return {"status": "active", "message": "CyberMaps AI Backend is running with SQLite Persistence"}

@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/correlate", response_model=Investigation)
def correlate_investigation(request: InvestigationRequest, repo: AlertRepository = Depends(get_repository)):
    # Find alerts from Repo
    # Repo returns objects (AlertModel or MockAlert). We need to support property access.
    selected_alerts = repo.get_alerts_by_ids(request.alert_ids)
    
    # helper to safely get attr or key
    def get_attr(obj, attr, default=None):
        if isinstance(obj, dict): return obj.get(attr, default)
        return getattr(obj, attr, default)
    
    # Convert objects to dicts for GraphBuilder
    alerts_dicts = []
    for a in selected_alerts:
        # Check if it has .model_dump() (Pydantic/SQLAlchemy mixed) or need manual conversion
        if hasattr(a, "model_dump"):
             alerts_dicts.append(a.model_dump())
        elif hasattr(a, "__dict__"):
             # For MockAlert or simple objects
             # Filter out private/internal attrs
             d = {k:v for k,v in a.__dict__.items() if not k.startswith('_')}
             alerts_dicts.append(d)
        else:
             # Fallback
             alerts_dicts.append(a)

    # Count operational events before correlation
    operational_events = [a for a in alerts_dicts if a.get("tactic") == "Unknown"]
    
    # Correlate (this will filter out Unknown tactics)
    graph_data = GraphBuilder.build_graph(alerts_dicts)
    
    # Add metadata about filtered events
    if operational_events:
        graph_data["metadata"] = {
            "total_alerts": len(alerts_dicts),
            "security_alerts": len(alerts_dicts) - len(operational_events),
            "operational_events_filtered": len(operational_events),
            "operational_event_names": [e.get("name") for e in operational_events]
        }
    
    # Create and Save Investigation via Repo
    inv_data = {
        "name": request.name,
        "alert_ids": request.alert_ids,
        "graph": graph_data
    }
    new_investigation = repo.create_investigation(inv_data)
    
    return new_investigation

@app.get("/investigations", response_model=List[Investigation])
def get_investigations(repo: AlertRepository = Depends(get_repository)):
    return repo.get_investigations()

@app.get("/investigations/{investigation_id}", response_model=Investigation)
def get_investigation(investigation_id: str, repo: AlertRepository = Depends(get_repository)):
    inv = repo.get_investigation_by_id(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv

@app.delete("/investigations/{investigation_id}")
def delete_investigation(investigation_id: str, repo: AlertRepository = Depends(get_repository)):
    repo.delete_investigation(investigation_id)
    return {"status": "success", "message": "Investigation deleted"}

@app.put("/investigations/{investigation_id}/alerts")
def append_alerts_to_investigation(investigation_id: str, request: AppendAlertsRequest, repo: AlertRepository = Depends(get_repository)):
    # Find investigation
    investigation = repo.get_investigation_by_id(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    # Update alert list (deduplicate)
    current_ids = set(investigation.alert_ids or [])
    new_ids = set(request.alert_ids)
    new_alert_ids = list(set(investigation.alert_ids + request.alert_ids))
    
    # Fetch all alerts to rebuild graph
    all_alerts = repo.get_alerts_by_ids(new_alert_ids)
    
     # helper to safely get attr or key
    def get_attr(obj, attr, default=None):
        if isinstance(obj, dict): return obj.get(attr, default)
        return getattr(obj, attr, default)
    
    # Convert objects to dicts for GraphBuilder
    alerts_dicts = []
    for a in all_alerts:
        if hasattr(a, "model_dump"):
             alerts_dicts.append(a.model_dump())
        elif hasattr(a, "__dict__"):
             d = {k:v for k,v in a.__dict__.items() if not k.startswith('_')}
             alerts_dicts.append(d)
        else:
             alerts_dicts.append(a)

    alerts_dicts = [a for a in alerts_dicts if isinstance(a, dict)] # Ensure only dicts

    # Rebuild Graph
    graph_data = GraphBuilder.build_graph(alerts_dicts)
    
    # Update Repo with new IDs AND new Graph
    repo.update_investigation(investigation_id, alert_ids=new_alert_ids, graph=graph_data)
    
    # Refresh object in local var (though usually repo returns it)
    investigation.alert_ids = new_alert_ids
    investigation.graph = graph_data
    
    return investigation

@app.get("/investigations/{investigation_id}/summary")
def get_investigation_summary(investigation_id: str, repo: AlertRepository = Depends(get_repository)):
    """
    Enhanced investigation summary with timeline and context-aware remediation
    """
    investigation = repo.get_investigation_by_id(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Get all alerts involved
    alert_ids = investigation.alert_ids or []
    alerts = repo.get_alerts_by_ids(alert_ids)
    
    # Convert to dicts for easier manipulation
    alert_dicts = []
    for alert in alerts:
        # helper to safely get attr or key
        def get_attr(obj, attr, default=None):
            if isinstance(obj, dict): return obj.get(attr, default)
            return getattr(obj, attr, default)
        
        # Get raw data properly
        raw_data = get_attr(alert, "raw_data") or {}

        alert_dict = {
            "id": get_attr(alert, "id"),
            "name": get_attr(alert, "name"),
            "severity": get_attr(alert, "severity"),
            "tactic": get_attr(alert, "tactic"),
            "technique": get_attr(alert, "technique"),
            "description": get_attr(alert, "description"),
            "created_at": get_attr(alert, "created_at"),
            "raw_data": raw_data
        }
        alert_dicts.append(alert_dict)
    
    # Sort by timestamp
    sorted_alerts = sorted(alert_dicts, key=lambda x: x.get("created_at") or datetime.min)
    
    # Filter out Unknown tactics for analysis
    security_alerts = [a for a in sorted_alerts if a.get("tactic") and a.get("tactic") != "Unknown"]
    
    # Build timeline data
    timeline = []
    for idx, alert in enumerate(sorted_alerts, 1):  # Start from 1 for step numbering
        raw_data = alert.get("raw_data", {})
        
        # Extract Who (actor/identity) + source IP
        who = "Unknown Actor"
        source_ip = None
        
        if raw_data.get("userIdentity"):
            user_id = raw_data["userIdentity"]
            who = user_id.get("userName") or user_id.get("principalId", "Unknown Actor")
            if user_id.get("type") == "AssumedRole":
                who = f"{who} (Role)"
        
        # Add source IP to WHO
        if raw_data.get("sourceIPAddress"):
            source_ip = raw_data["sourceIPAddress"]
            who = f"{who} from {source_ip}"
        
        # Extract What (action)
        what = alert.get("name", "Unknown Action")
        if raw_data.get("eventName"):
            what = raw_data["eventName"]
        
        # Extract When (timestamp)
        when = alert.get("created_at")
        if raw_data.get("eventTime"):
            when = raw_data["eventTime"]
        
        # Extract Where (target resource/system being attacked)
        where = "AWS Account"
        
        # Special handling for ConsoleLogin - show the AWS account being accessed
        if what == "ConsoleLogin" and raw_data.get("userIdentity"):
            account_id = raw_data["userIdentity"].get("accountId")
            if account_id:
                where = f"AWS Account: {account_id}"
        # Try to extract the target resource from the event
        elif raw_data.get("requestParameters"):
            params = raw_data["requestParameters"]
            
            # S3 bucket
            if params.get("bucketName"):
                where = f"S3: {params['bucketName']}"
            # Secrets Manager
            elif params.get("secretId"):
                where = f"Secrets: {params['secretId']}"
            # IAM user/role
            elif params.get("userName"):
                where = f"IAM User: {params['userName']}"
            elif params.get("roleName"):
                where = f"IAM Role: {params['roleName']}"
            # Access key
            elif params.get("accessKeyId"):
                where = f"Access Key: {params['accessKeyId'][:20]}..."
            # EBS snapshot
            elif params.get("snapshotId"):
                where = f"EBS: {params['snapshotId']}"
            # VPC
            elif params.get("vpcId"):
                where = f"VPC: {params['vpcId']}"
        
        # Also check responseElements for some events
        if where == "AWS Account" and raw_data.get("responseElements"):
            resp = raw_data["responseElements"]
            
            # Created IAM user
            if resp.get("user", {}).get("userName"):
                where = f"IAM User: {resp['user']['userName']}"
            # Created access key
            elif resp.get("accessKey", {}).get("userName"):
                where = f"IAM User: {resp['accessKey']['userName']}"
        
        # Fallback to service/region if no specific resource
        if where == "AWS Account" and raw_data.get("awsRegion"):
            where = f"{raw_data['awsRegion']} region"
        
        timeline.append({
            "step": idx,  # Add step number for chronological order
            "who": who,
            "what": what,
            "when": when.isoformat() if hasattr(when, 'isoformat') else str(when),
            "where": where,
            "tactic": alert.get("tactic", "Unknown"),
            "severity": alert.get("severity", "Unknown")
        })
    
    # Generate intelligent narrative
    summary_text = ""
    impact_text = ""
    mitigation_text = ""
    mitre_info = []

    if len(security_alerts) > 0:
        tactics = [a.get("tactic") for a in security_alerts if a.get("tactic")]
        
        # Get unique tactics preserving chronological order (adjacent deduplication)
        narrative_tactics = []
        last_tactic = None
        
        for alert in security_alerts:
            tactic = alert.get("tactic")
            technique = alert.get("technique")
            if not tactic: continue
            
            # Populate MITRE Info
            if tactic and tactic != "Unknown":
                mitre_info.append({
                    "tactic": tactic,
                    "technique": technique or "Unknown Technique"
                })

            current_tactics_in_alert = [t.strip() for t in tactic.split(',')]
            
            for t in current_tactics_in_alert:
                if t != last_tactic:
                    narrative_tactics.append(t)
                    last_tactic = t

        # Build Summary
        summary_text = f"This alert triggers when correlated activity indicates a potential {len(security_alerts)}-stage attack sequence. "
        
        # Add chain description
        chain_str = ' -> '.join(narrative_tactics)
        summary_text += f"The observed attack chain covers: {chain_str}. "
        
        if len(narrative_tactics) > 0:
            first_tactic = narrative_tactics[0]
            summary_text += f"The sequence begins with {first_tactic}, suggesting an initial foothold or reconnaissance effort. "
            
            # Add specific behaviors based on tactics
            behaviors = []
            if "Discovery" in narrative_tactics:
                behaviors.append("internal reconnaissance (Discovery)")
            if "Lateral Movement" in narrative_tactics:
                behaviors.append("movement between systems (Lateral Movement)")
            if "Collection" in narrative_tactics:
                behaviors.append("data gathering (Collection)")
            if "Exfiltration" in narrative_tactics:
                behaviors.append("data theft (Exfiltration)")
            
            if behaviors:
                summary_text += f"Correlated events indicate behavior consistent with {', '.join(behaviors)}. "

        # Build Impact
        impact_paragraphs = []
        unique_tactics_set = set(narrative_tactics)
        for tactic in unique_tactics_set:
            tactic_info = TACTIC_INFO.get(tactic)
            if tactic_info and tactic_info.get("impact"):
                impact_paragraphs.append(tactic_info["impact"])
        
        if impact_paragraphs:
            impact_text = " ".join(impact_paragraphs)
        else:
            impact_text = "The impact of this activity depends on the sensitivity of the affected systems and data."

        # Build Mitigation (Contextual Paragraph)
        mitigation_paragraphs = []
        for tactic in unique_tactics_set:
            tactic_info = TACTIC_INFO.get(tactic)
            if tactic_info and tactic_info.get("mitigation"):
                mitigation_paragraphs.append(tactic_info["mitigation"])
        
        if mitigation_paragraphs:
            mitigation_text = " ".join(mitigation_paragraphs)
        else:
            mitigation_text = "Investigate the source of the activity and applying standard incident response procedures."

    else:
        summary_text = "Investigation contains operational events only. No security-critical attack progression detected."
        impact_text = "Low security impact. Operational checks recommended."
        mitigation_text = "Review operational procedures."
    
    # Generate context-aware remediation steps (List format for checklist)
    remediation_steps = []
    
    if len(security_alerts) > 0:
        tactics_involved = set([a.get("tactic") for a in security_alerts if a.get("tactic")])
        
        # Initial Access remediation
        if "Initial Access" in tactics_involved:
            remediation_steps.append("Isolate compromised account - Force password reset and revoke active sessions")
            remediation_steps.append("Enable MFA if not already enforced across all user accounts")
        
        # Persistence remediation
        if "Persistence" in tactics_involved or "Privilege Escalation" in tactics_involved:
            remediation_steps.append("Audit and remove unauthorized IAM access keys, roles, and policies")
            remediation_steps.append("Review CloudTrail logs for all actions taken by compromised credentials")
        
        # Defense Evasion remediation
        if "Defense Evasion" in tactics_involved:
            remediation_steps.append("Re-enable CloudTrail logging and enable log file validation")
            remediation_steps.append("Configure AWS Config for continuous compliance monitoring")
        
        # Credential Access remediation
        if "Credential Access" in tactics_involved:
            remediation_steps.append("Rotate all exposed secrets in AWS Secrets Manager and Parameter Store")
            remediation_steps.append("Enable secret rotation policies for automatic credential rotation")
        
        # Exfiltration remediation
        if "Exfiltration" in tactics_involved:
            remediation_steps.append("Delete unauthorized EBS snapshots and review sharing permissions")
            remediation_steps.append("Enable VPC Flow Logs and analyze for data exfiltration patterns")
        
        # Impact remediation
        if "Impact" in tactics_involved:
            remediation_steps.append("Attempt data recovery from backups and enable versioning on S3 buckets")
            remediation_steps.append("Enable MFA Delete on critical data stores to prevent future loss")
            remediation_steps.append("Investigate for ransomware indicators and IOCs across environment")
        
        # General cloud security hardening
        remediation_steps.append("Implement least-privilege IAM policies using AWS IAM Access Analyzer")
        remediation_steps.append("Enable AWS GuardDuty for continuous threat detection")
        remediation_steps.append("Configure CloudWatch alarms for suspicious API activity")
    
    # Metrics
    severity_breakdown = {}
    for alert in sorted_alerts:
        sev = alert.get("severity", "Unknown")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
    
    tactics_involved_list = list(set([a.get("tactic") for a in security_alerts if a.get("tactic")]))
    
    return {
        "correlation_analysis": {
            "summary": summary_text,
            "impact": impact_text,
            "mitigation": mitigation_text,
            "mitre_technique": mitre_info
        },
        "narrative": summary_text, # Backward compatibility if needed, though we will use correlation_analysis in frontend
        "timeline": timeline,
        "remediation_steps": remediation_steps,
        "metrics": {
            "total_alerts": len(sorted_alerts),
            "security_alerts": len(security_alerts),
            "operational_alerts": len(sorted_alerts) - len(security_alerts),
            "severity_breakdown": severity_breakdown,
            "tactics_involved": tactics_involved_list
        }
    }
