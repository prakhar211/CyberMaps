# CyberMaps Deployment Guide

CyberMaps can be deployed in two modes: **Web Playground** (Public) and **Local Enterprise** (Private).

## 1. Local Enterprise Version (Docker)
This is the recommended deployment for SOC/IR teams. It runs entirely within your network, ensuring logs never leave your infrastructure.

### Prerequisites
- Docker & Docker Compose
- API Key for Google Gemini (Optional, for AI features)

### Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/CyberMaps.git
   cd CyberMaps
   ```

2. Create a `.env` file in `backend/`:
   ```bash
   echo "GOOGLE_API_KEY=your_key_here" > backend/.env
   ```

3. Run with Docker Compose:
   ```bash
   docker-compose up --build
   ```

4. Access the application:
   - **Frontend**: http://localhost:5173
   - **Backend API**: http://localhost:8000/docs

---

## 2. Web Playground (Vercel/Netlify)
This is a stateless version for demonstrations and community trial.

### Backend (Railway/Render)
Since the backend requires Python, it must be hosted on a service like Railway, Render, or equivalent.
1. Connect your repo to Render.
2. Set Root Directory to `backend/`.
3. Set Build Command: `pip install -r requirements.txt`
4. Set Start Command: `uvicorn main:app --host 0.0.0.0 --port 10000`

### Frontend (Vercel)
1. Connect your repo to Vercel.
2. Set Root Directory to `frontend/`.
3. Set Environment Variable `VITE_API_URL` to your backend URL (e.g., `https://cybermaps-api.onrender.com`).

---

## 3. Webhook Integration
To send alerts to CyberMaps Local:

### Generic Webhook
POST to `http://localhost:8000/api/webhooks/{platform}`
Supported platforms: `coralogix`, `splunk`

**Example (Splunk):**
```bash
curl -X POST http://localhost:8000/api/webhooks/splunk \
  -d '{"search_name": "Malware Detected", "result": {"src_ip": "1.2.3.4"}}'
```

### Coralogix
Configure a "Generic Webhook" in Coralogix integrations pointing to your local instance (exposed via Ngrok/Tunnel) or internal server IP.
