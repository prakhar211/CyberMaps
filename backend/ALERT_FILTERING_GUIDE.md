# Alert Filtering & Database Persistence - Quick Guide

## ✅ What's Been Implemented

### 1. **Database Persistence**
- Alerts from webhooks are now **saved to the database**
- Each alert gets a `created_at` timestamp (UTC)
- Alerts are visible in the `/alerts` endpoint

### 2. **Time-Based Filtering**
Added query parameter `time_filter` to `/alerts` endpoint:

```bash
# Get alerts from last 30 minutes
curl "http://localhost:8000/alerts?time_filter=30m"

# Get alerts from last 1 hour
curl "http://localhost:8000/alerts?time_filter=1h"

# Get alerts from last 24 hours
curl "http://localhost:8000/alerts?time_filter=24h"

# Get alerts from last 7 days
curl "http://localhost:8000/alerts?time_filter=7d"

# Get all alerts (default)
curl "http://localhost:8000/alerts?time_filter=all"
# or simply
curl "http://localhost:8000/alerts"
```

### 3. **TestIngestion Prefix**
Test alerts now have **"TestIngestion-"** prefix in their event names:
- `AWS TestIngestion-CreateLogStream`
- `AWS TestIngestion-StopLogging`
- etc.

This makes them easy to identify and filter!

---

## 📊 Current Test Results

After running `./test_webhook.sh`, you now have **5 new alerts** in the database:

| Alert Name | Severity | MITRE Tactic | Alert ID |
|-----------|----------|--------------|----------|
| AWS TestIngestion-CreateLogStream | Medium | (Low priority) | `e98e3a33...` |
| AWS TestIngestion-StopLogging | High | Defense Evasion | `e3d27f4d...` |
| AWS CreateAccessKey | High | Persistence, Privilege Escalation | `4d974eb5...` |
| AWS GetSecretValue | Low | Credential Access | `cba8585d...` |
| AWS CreateSnapshot | Medium | Exfiltration | `093840a3...` |

---

## 🎯 How to Use in Frontend

Update your frontend to add time filter buttons:

```javascript
// In your alerts component
const [timeFilter, setTimeFilter] = useState('30m');

// Fetch alerts with filter
useEffect(() => {
  fetch(`http://localhost:8000/alerts?time_filter=${timeFilter}`)
    .then(res => res.json())
    .then(data => setAlerts(data));
}, [timeFilter]);

// UI buttons
<div>
  <button onClick={() => setTimeFilter('30m')}>Last 30 mins</button>
  <button onClick={() => setTimeFilter('1h')}>Last 1 hour</button>
  <button onClick={() => setTimeFilter('24h')}>Last 24 hours</button>
  <button onClick={() => setTimeFilter('7d')}>Last 7 days</button>
  <button onClick={() => setTimeFilter('all')}>All</button>
</div>
```

---

## 🔍 Finding TestIngestion Alerts

### Option 1: Filter by Time
```bash
# Get recent alerts (includes TestIngestion alerts)
curl "http://localhost:8000/alerts?time_filter=30m"
```

### Option 2: Search by Name (in frontend)
Filter alerts client-side:
```javascript
const testAlerts = alerts.filter(alert => 
  alert.name.includes('TestIngestion')
);
```

### Option 3: Database Query (backend)
```sql
SELECT * FROM alerts 
WHERE name LIKE '%TestIngestion%' 
ORDER BY created_at DESC;
```

---

## 📝 Database Schema

The `alerts` table now has:
```sql
CREATE TABLE alerts (
    id VARCHAR PRIMARY KEY,
    name VARCHAR,
    severity VARCHAR,
    tactic VARCHAR,
    technique VARCHAR,
    description VARCHAR,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP  -- NEW!
);
```

---

## 🚀 Next Steps

1. **Frontend Integration**: Add time filter dropdown to alerts page
2. **Search Functionality**: Add search box to filter by alert name
3. **Sorting**: Add ability to sort by severity, time, tactic
4. **Pagination**: If you have many alerts, add pagination

---

## 🧪 Testing Commands

```bash
# Run test script (creates 5 new alerts with TestIngestion prefix)
./test_webhook.sh

# View recent alerts
curl "http://localhost:8000/alerts?time_filter=30m" | jq

# View all alerts
curl "http://localhost:8000/alerts" | jq

# Count alerts
curl "http://localhost:8000/alerts" | jq 'length'

# Find TestIngestion alerts
curl "http://localhost:8000/alerts" | jq '.[] | select(.name | contains("TestIngestion"))'
```

---

## ✅ Summary

- ✅ Alerts are now **persisted to database**
- ✅ **Time filtering** works (30m, 1h, 24h, 7d, all)
- ✅ **TestIngestion prefix** added to test alerts
- ✅ Alerts **ordered by most recent first**
- ✅ Ready for frontend integration!
