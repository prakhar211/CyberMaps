# CyberMaps

A Next-Gen Cyber Warfare HUD for visualizing and analyzing security threats using MITRE ATT&CK framework.

## Overview

CyberMaps is an advanced cybersecurity investigation platform that helps security analysts visualize attack paths, predict adversary tactics, and streamline incident response. Built with a modern tech stack (React + Vite frontend, Python FastAPI backend), it provides an immersive HUD-style interface for mapping and analyzing cyber threats.

## Features

- **Attack Path Visualization**: Interactive graph-based visualization of security alerts and attack chains
- **Tactic Prediction**: ML-powered Markov chain model to predict next probable adversary tactics based on MITRE ATT&CK framework
- **Investigation Management**: Create and manage multiple security investigations with timeline analysis
- **Alert Correlation**: Analyze relationships between security events and identify attack patterns
- **Severity Gradient System**: Visual highlighting of critical tactics with probability-based coloring and animations
- **OLED Deep HUD Theme**: Premium, retractable sidebar interface with cyber warfare aesthetics

## Tech Stack

### Frontend
- React 18+ with Vite
- React Flow for graph visualization
- Modern CSS with glassmorphism and animations
- Responsive design with dark mode optimization

### Backend
- Python 3.10+
- FastAPI for API endpoints
- SQLite database
- Markov chain-based prediction engine
- MITRE ATT&CK framework integration

## Getting Started

### Prerequisites
- Node.js 16+ and npm
- Python 3.10+
- pip

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd CyberMaps
```

2. **Set up the backend**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Set up the frontend**
```bash
cd frontend
npm install
```

### Running the Application

1. **Start the backend server**
```bash
cd backend
source venv/bin/activate  # On Windows: venv\Scripts\activate
uvicorn main:app --reload
```

2. **Start the frontend development server**
```bash
cd frontend
npm run dev
```

The application will be available at `http://localhost:5173` (frontend) with the API running on `http://localhost:8000`.

## Usage

1. **Create an Investigation**: Start by creating a new security investigation
2. **Add Alerts**: Import or manually add security alerts to the investigation
3. **Analyze Attack Path**: Visualize the attack chain and relationships between alerts
4. **Review Predictions**: Examine predicted next tactics based on observed attacker behavior
5. **Timeline Analysis**: Review the attack timeline with WHO, WHAT, WHEN, WHERE, WHY details

## Future Objectives

### 1. DFIR Report Generation for Complete Attack Chains

When a complete end-to-end tactics chain is observed indicating a successful breach in the environment, the system will automatically detect this and provide capabilities to generate comprehensive Digital Forensics and Incident Response (DFIR) reports.

**Features to be implemented:**
- **Attack Chain Detection**: Automatic identification of complete attack sequences from initial access through impact/exfiltration
- **DFIR Report Button**: One-click report generation for completed attack chains
- **Comprehensive Timelining**: Detailed chronological reconstruction of the complete attack lifecycle
- **Mitigation Recommendations**: AI-generated future steps and best practices to prevent similar attacks
- **IOC Cataloging**: Automated extraction and listing of all Indicators of Compromise (IOCs) involved in the breach, including:
  - IP addresses and domains
  - File hashes
  - User accounts
  - Command patterns
  - Network artifacts
- **Export Formats**: Multiple report formats (PDF, JSON, STIX/TAXII) for integration with other security tools

### 2. Gamification for Cybersecurity Community Learning

Transform CyberMaps into an educational platform that helps the cybersecurity community learn through interactive, game-like experiences.

**Features to be implemented:**
- **Challenge Modes**: Pre-built attack scenarios for analysts to investigate and solve
- **Scoring System**: Points and badges for accurate threat identification and prediction
- **Leaderboards**: Community rankings based on investigation accuracy and speed
- **Learning Paths**: Guided tutorials for different skill levels (beginner, intermediate, advanced)
- **Attack Pattern Library**: Curated collection of real-world attack patterns for training
- **Collaborative Mode**: Team-based investigation challenges
- **Achievement System**: Unlock achievements for mastering different MITRE ATT&CK tactics and techniques
- **Time Trials**: Speed-based investigation challenges with performance metrics
- **Community Contributions**: Allow users to submit and share their own attack scenarios

### 3. Threat Hunting Assistance

Empower security analysts to perform proactive threat hunting by providing actionable intelligence based on predicted tactics.

**Features to be implemented:**
- **IOC Collection and Sharing**: 
  - Automatic extraction of IOCs from current investigation
  - Export IOCs in standard formats (STIX, OpenIOC, CSV)
  - Integration with threat intelligence platforms
  - Community IOC sharing and crowdsourcing
  
- **SIEM Query Generation**:
  - Automatically generate SIEM queries based on predicted tactics
  - Support for multiple SIEM platforms:
    - Splunk SPL queries
    - Elastic Query DSL
    - QRadar AQL
    - Azure Sentinel KQL
    - Chronicle YARA-L
  - Query templates for each MITRE ATT&CK technique
  - Copy-to-clipboard functionality for quick deployment
  
- **Detection Rule Creation**:
  - Generate detection rules in multiple formats:
    - Sigma rules
    - YARA rules
    - Snort/Suricata rules
    - Custom detection logic
  - Rule validation and testing
  - Version control for detection rules
  - Integration with SOAR platforms
  
- **Threat Hunting Playbooks**:
  - Automated playbook suggestions based on predicted tactics
  - Step-by-step hunting procedures
  - Expected artifacts and evidence locations
  - Links to relevant ATT&CK techniques and sub-techniques

## Project Structure

```
CyberMaps/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── database.py          # Database configuration
│   ├── models.py            # Data models
│   ├── markov_predictor.py  # Tactic prediction engine
│   └── venv/                # Python virtual environment
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Main React component
│   │   ├── index.css        # Global styles and theme
│   │   └── main.jsx         # Entry point
│   ├── public/              # Static assets
│   └── package.json         # Dependencies
└── README.md                # This file
```

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

[Add your license information here]

## Contact

[Add contact information here]
