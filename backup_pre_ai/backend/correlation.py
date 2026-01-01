from typing import List, Dict, Any
from markov import TACTIC_TO_INDEX

# Heuristic for layers based on keywords in Alert Name or Description
LAYER_KEYWORDS = {
    "Firewall": ["scan", "flood", "firewall", "connection", "port"],
    "Web Server": ["http", "web", "inject", "app", "iis", "apache", "url", "xss", "sql"],
    "Database": ["dump", "database", "table", "row", "select", "db", "customer", "record"],
    "Auth Server": ["login", "brute", "password", "kerberos", "ticket", "auth", "ad ", "active directory"],
    "Workstation": ["phishing", "attachment", "exe", "powershell", "user", "client", "office", "macro"]
}

def guess_layer(alert: Dict[str, Any]) -> str:
    """Guess the asset layer based on alert content."""
    text = (alert.get("name", "") + " " + alert.get("description", "")).lower()
    for layer, keywords in LAYER_KEYWORDS.items():
        if any(k in text for k in keywords):
            return layer
            
    # Fallback based on Tactic if no specific asset keyword found
    tactic = alert.get("tactic", "")
    if tactic in ["Reconnaissance", "Initial Access"]:
        return "Firewall"
    elif tactic in ["Execution", "Persistence"]:
        return "Workstation"
    elif tactic in ["Discovery", "Lateral Movement"]:
        return "Web Server"
    elif tactic in ["Collection", "Exfiltration"]:
        return "Database"
        
    return "Unknown Layer"

def correlate_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sort alerts by kill chain and generate graph nodes/edges.
    
    Filters out operational events (Unknown tactics) to focus on security-critical alerts.
    """
    # Filter out operational events with "Unknown" tactic
    security_alerts = [
        alert for alert in alerts 
        if alert.get("tactic") and alert.get("tactic") != "Unknown"
    ]
    
    # Log filtered operational events
    operational_count = len(alerts) - len(security_alerts)
    if operational_count > 0:
        print(f"INFO: Filtered out {operational_count} operational event(s) with Unknown tactic")
    
    # If no security alerts, return empty graph
    if not security_alerts:
        return {"nodes": [], "edges": []}
    
    # Helper function to get the earliest tactic index from a tactic string
    def get_tactic_index(tactic_str: str) -> int:
        """
        Parse tactic string (which may contain multiple tactics separated by commas)
        and return the lowest index (earliest in kill chain).
        
        Example: "Persistence, Privilege Escalation" -> returns index of "Persistence"
        """
        if not tactic_str:
            return 999  # Put at end if no tactic
        
        # Split by comma and strip whitespace
        tactics = [t.strip() for t in tactic_str.split(',')]
        
        # Get index for each tactic, return the minimum (earliest in kill chain)
        indices = []
        for tactic in tactics:
            idx = TACTIC_TO_INDEX.get(tactic, 999)
            indices.append(idx)
        
        return min(indices) if indices else 999
    
    # 1. Sort by MITRE Tactic Index (earliest tactic in kill chain)
    sorted_alerts = sorted(
        security_alerts, 
        key=lambda a: get_tactic_index(a.get("tactic", ""))
    )
    
    nodes = []
    edges = []
    
    # 2. Build Nodes with Layer info
    for i, alert in enumerate(sorted_alerts):
        layer = guess_layer(alert)
        
        # Map Layer to Icon
        icon_map = {
            "Firewall": "Firewall", 
            "Web Server": "Server",
            "Database": "Database",
            "Auth Server": "Auth", 
            "Workstation": "Workstation"
        }
        icon = icon_map.get(layer, "Activity")

        # Build original_alert object with raw_data
        original_alert_data = {
            **alert,  # Include all alert fields
            "raw_log": alert.get("raw_data", {})  # Map raw_data to raw_log for frontend
        }

        nodes.append({
            "id": f"alert-{alert['id']}",
            "type": "deviceNode", 
            "data": { 
                "label": f"{alert['tactic']}: {alert['name']}",
                "original_label": alert['name'],
                "tactic": alert['tactic'],
                "layer": layer,
                "icon": icon,
                "status": "compromised",
                "original_alert": original_alert_data  # Include raw_data here
            },
            "position": {"x": 0, "y": 0} 
        })
        
        # 3. Create Edges (Linear path for "Investigation View")
        if i > 0:
            prev = nodes[i-1]
            edges.append({
                "id": f"e-{prev['id']}-{nodes[-1]['id']}",
                "source": prev['id'],
                "target": nodes[-1]['id'],
                "animated": True,
                "label": "Next Step",
                "style": { "stroke": "#00f3ff" }
            })
            
    return {"nodes": nodes, "edges": edges}

