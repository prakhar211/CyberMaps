import requests
import json

BASE_URL = "http://localhost:8000"

def test_api():
    print("Testing API...")
    
    # 1. Test Health
    try:
        resp = requests.get(f"{BASE_URL}/health")
        print(f"Health Check: {resp.json()}")
    except Exception as e:
        print(f"Failed to connect to backend: {e}")
        return

    # 2. Test Get Alerts
    resp = requests.get(f"{BASE_URL}/alerts")
    print(f"Alerts Status: {resp.status_code}")
    alerts = resp.json()
    print(f"Alerts Count: {len(alerts)}")

    # 3. Test Create Alert
    new_alert = {
        "id": f"a{len(alerts)+1}",
        "name": "Manual Test Alert",
        "severity": "High",
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files",
        "description": "Created via API Test"
    }
    resp = requests.post(f"{BASE_URL}/alerts", json=new_alert)
    print(f"Create Alert Status: {resp.status_code}")
    if resp.status_code == 200:
         print(f"Created: {resp.json()}")

    # 4. Test Prediction
    payload = {"current_tactic": "Initial Access", "n_steps": 1}
    resp = requests.post(f"{BASE_URL}/predict", json=payload)
    if resp.status_code == 200:
        print("Prediction Success:")
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f"Prediction Failed: {resp.text}")

if __name__ == "__main__":
    test_api()
