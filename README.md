# 🛡️ Incident Response Automation Tool

A comprehensive, AI-powered incident response automation system that parses security logs, detects threats, and provides intelligent analysis using the Foundation-Sec-8B security language model.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)
![AI](https://img.shields.io/badge/AI-Foundation--Sec--8B-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🌟 Features

### Log Parsing
- **Linux Authentication Logs** (`auth.log`): SSH authentication, sudo commands, session management
- **Windows Security Events**: Event IDs 4624, 4625, 4688, 4672, 4720, 4732, and 30+ more
- **IDS/IPS Alerts**: Snort and Suricata alert formats (JSON/EVE)
- **Automatic Format Detection**: Unified parser auto-detects log types

### Threat Detection
- **Brute Force Attacks**: Configurable thresholds, distributed attack detection
- **Suspicious Login Behavior**: Unusual hours, privileged account usage, geographic anomalies
- **Unknown/Malicious Processes**: Pattern matching for known attack tools (mimikatz, cobalt strike, etc.)
- **IOC Matching**: IP addresses, domains, file hashes, process names, command patterns

### AI-Powered Analysis
- **Foundation-Sec-8B Integration**: Security-specialized language model from Hugging Face
- **Automated Incident Analysis**: Severity assessment, attack classification, remediation suggestions
- **Mock Mode**: Testing without GPU requirements

### Dashboard & Reporting
- **Streamlit Web Interface**: Real-time incident monitoring and management
- **Incident Management**: View, filter, search, and update incident status
- **Export Capabilities**: JSON and PDF report generation
- **Statistics & Metrics**: Overview of security posture

## 📁 Project Structure

```
Incident Response Automation/
├── src/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── log_parser.py      # Log parsing for multiple formats
│   │   ├── detection.py       # Threat detection engine
│   │   └── export.py          # JSON/PDF export functionality
│   ├── ai/
│   │   ├── __init__.py
│   │   └── analyzer.py        # AI analysis with Foundation-Sec-8B
│   ├── db/
│   │   ├── __init__.py
│   │   └── database.py        # SQLite database operations
│   └── dashboard/
│       ├── __init__.py
│       └── app.py             # Streamlit dashboard
├── tests/
│   ├── __init__.py
│   ├── test_log_parser.py     # Log parser tests
│   ├── test_detection.py      # Detection engine tests
│   ├── test_ai_analyzer.py    # AI analyzer tests
│   └── test_database.py       # Database tests
├── logs/
│   ├── sample_auth.log        # Sample Linux auth logs
│   ├── sample_windows_security.json  # Sample Windows events
│   ├── sample_ids.json        # Sample IDS alerts
│   └── iocs.json              # Indicators of Compromise
├── reports/                   # Generated reports directory
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- pip (Python package manager)
- 16GB+ RAM recommended for AI model (or use mock mode)
- CUDA-compatible GPU recommended (optional, for faster AI inference)

### Installation

1. **Clone or download the project**
   ```bash
   cd "Incident Response Automation"
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # Windows
   .\venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download the AI Model (Optional)**
   
   The Foundation-Sec-8B model will be downloaded automatically on first use. However, you can pre-download it:
   
   ```python
   from transformers import AutoModelForCausalLM, AutoTokenizer
   
   model_name = "fdtn-ai/Foundation-Sec-8B"
   tokenizer = AutoTokenizer.from_pretrained(model_name)
   model = AutoModelForCausalLM.from_pretrained(model_name)
   ```
   
   **Note**: The model requires approximately 16GB of disk space and 16GB+ RAM. For systems without these resources, use the Mock AI mode.

### Running the Dashboard

```bash
python -m streamlit run src/dashboard/app.py
```

The dashboard will open in your default browser at `http://localhost:8501`.

**Windows note (Python 3.13):** if `streamlit run ...` prints `Failed to find real location of ...python.exe`, always use `python -m streamlit ...`.

### Populate Sample Incidents (for Demo)

The dashboard reads incidents from `data/incidents.db`. To generate demo incidents from the sample logs in `logs/`, run:

```bash
python test_populate.py
```

Then refresh the dashboard.

## 🧭 Architecture Overview

### High-level Data Flow

1. **Ingest logs**: `UnifiedLogParser.parse_file()` yields normalized `ParsedLogEntry` records from Linux auth logs, Windows Security events, or IDS JSON.
2. **Detect incidents**: `DetectionEngine.detect_all()` runs several detectors and returns `Detection` objects (type, severity, alert, IOCs, related log entries).
3. **Persist**: `detection_to_incident()` converts a `Detection` into an `Incident` and stores it in SQLite via `IncidentDatabase.add_incident()`.
4. **Analyze (optional)**: The Streamlit dashboard triggers AI analysis using `src/ai/analyzer.py` and stores the resulting summary back into the incident.
5. **Report**: incidents can be exported to JSON/PDF using `src/core/export.py`.

### Main Entry Points

- **Web UI**: `src/dashboard/app.py`
- **Populate demo DB**: `test_populate.py`
- **Core pipeline (programmatic)**: `src/core/log_parser.py` + `src/core/detection.py` + `src/db/database.py`

## 💻 Usage

### Command Line Usage

#### Parse Logs
```python
from src.core.log_parser import UnifiedLogParser

parser = UnifiedLogParser()
events = parser.parse_file("logs/sample_auth.log")

for event in events:
    print(f"[{event.timestamp}] {event.event_type}: {event.message}")
```

#### Detect Threats
```python
from src.core.log_parser import UnifiedLogParser
from src.core.detection import DetectionEngine

# Parse logs
parser = UnifiedLogParser()
events = list(parser.parse_file("logs/sample_auth.log"))

# Initialize detection engine with IOCs
engine = DetectionEngine(ioc_file="logs/iocs.json")

# Detect threats
detections = engine.detect_all(events)

for detection in detections:
    print(f"[{detection.severity.value}] {detection.detection_type.value}: {detection.alert}")
```

#### AI Analysis
```python
from src.ai.analyzer import analyze_incident

# Analyze an incident
result = analyze_incident(
    alert="Multiple failed SSH login attempts from 203.0.113.50",
    log_snippet="Dec 27 08:15:23 server sshd[1234]: Failed password for root from 203.0.113.50",
    iocs=["203.0.113.50"],
    use_mock=False  # Set to True for testing without GPU
)

print(f"Severity: {result.severity}")
print(f"Summary: {result.summary}")
print(f"Recommendations: {result.recommendations}")
```

#### Database Operations
```python
from src.db.database import IncidentDatabase, Incident

# Initialize database
db = IncidentDatabase("incidents.db")

# Create an incident
incident = Incident(
    alert="Brute Force Attack Detected",
    ioc="203.0.113.50",
    log_snippet="Multiple failed SSH attempts...",
    severity="high",
    status="new"
)

# Save to database
incident_id = db.add_incident(incident)

# Query incidents
high_severity = db.get_incidents_by_severity("high")
recent = db.get_recent_incidents(hours=24)
```

#### Export Reports
```python
from src.core.export import export_incidents_json, export_incidents_pdf
from src.db.database import IncidentDatabase

db = IncidentDatabase("incidents.db")
incidents = db.get_all_incidents()

# Export to JSON
export_incidents_json(incidents, "reports/incidents.json")

# Export to PDF
export_incidents_pdf(incidents, "reports/incidents.pdf")
```

### Dashboard Features

#### Overview Page
- Total incident count
- Severity distribution (Critical, High, Medium, Low)
- Status breakdown (New, Investigating, Resolved, False Positive)
- Recent activity timeline

#### Incidents Page
- Filterable incident list
- Search by alert, IOC, or description
- Sort by date, severity, or status
- Bulk actions (mark resolved, delete)

#### Incident Details
- Full incident information
- Associated IOCs and log snippets
- AI analysis trigger
- Status update controls
- Export individual incident

#### Settings
- AI model configuration (Mock vs Full)
- Detection thresholds
- IOC file management
- Database maintenance

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=src --cov-report=html

# Run specific test file
pytest tests/test_detection.py -v

# Run specific test
pytest tests/test_log_parser.py::TestLinuxAuthLogParser::test_parse_failed_password -v
```

## 📚 Module-by-Module Documentation

### 1) Log Parsing: `src/core/log_parser.py`

**Goal:** convert raw logs into a single normalized format (`ParsedLogEntry`) so detection rules can be log-source-agnostic.

**Key types**
- `LogType`: `LINUX_AUTH`, `WINDOWS_SECURITY`, `WINDOWS_SYSTEM`, `IDS_LOG`, `UNKNOWN`
- `ParsedLogEntry`: normalized fields: `timestamp`, `source`, `event_type`, `user`, `source_ip`, `message`, `raw_log`, `metadata`, `log_type`

**Key classes**
- `LinuxAuthLogParser`: parses `auth.log`-style files (SSH failed/success, sudo command, sessions)
- `WindowsEventLogParser`: parses Windows Security event logs (JSON arrays / JSON lines / XML-like sources)
- `IDSLogParser`: parses IDS alert JSON (Snort/Suricata EVE-like)
- `UnifiedLogParser`: detects file type and routes to the correct parser

**How to use**
```python
from src.core.log_parser import UnifiedLogParser

parser = UnifiedLogParser()
entries = list(parser.parse_file("logs/sample_auth.log"))
```

### 2) Detection: `src/core/detection.py`

**Goal:** transform parsed entries into actionable detections.

**Key types**
- `DetectionType`: `BRUTE_FORCE`, `SUSPICIOUS_LOGIN`, `UNKNOWN_PROCESS`, `IOC_MATCH`, etc.
- `Severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `Detection`: includes `alert`, `severity`, `iocs`, `timestamp`, `log_entries`, and helper `get_log_snippet()`

**Detectors**
- `BruteForceDetector`: identifies repeated failed logins and distributed attempts
- `SuspiciousLoginDetector`: flags unusual hours, privileged users, rapid successive logins, etc.
- `UnknownProcessDetector`: identifies suspicious or known-bad process patterns (Windows `4688`, Linux command patterns)
- `IOCMatcher`: matches parsed content against the IOC database

**Orchestrator**
- `DetectionEngine.detect_all(log_entries)`: runs all detectors and returns sorted detections

**Config knobs**
- `DetectionEngine(brute_force_threshold=5, brute_force_window=10, ioc_file=...)`

### 3) IOC Store: `logs/iocs.json` (loaded by `IOCDatabase`)

The tool expects a JSON object with an `indicators` section containing lists like `ip_addresses`, `domains`, `file_hashes`, `process_names`, etc. The loader extracts the `value` fields and compiles any custom regex patterns.

### 4) Database: `src/db/database.py`

**Goal:** store incidents in SQLite and provide query/stats helpers for the dashboard.

**Key type**
- `Incident`: dataclass representation of stored records.

**Key API**
- `IncidentDatabase.add_incident(incident) -> int`
- `IncidentDatabase.get_incident(id) -> Incident | None`
- `IncidentDatabase.get_all_incidents() -> list[Incident]`
- `IncidentDatabase.get_statistics() -> dict`

**Important helper**
- `detection_to_incident(detection) -> Incident`: converts detections into database-ready incidents.

### 5) AI Analysis: `src/ai/analyzer.py`

**Goal:** produce a structured incident-analysis response (summary, classification, severity, response steps).

**Two modes**
- `MockAIAnalyzer`: fast, deterministic testing without downloading/loading the model
- `AIAnalyzer`: loads `fdtn-ai/Foundation-Sec-8B` via Transformers and generates analysis text, then parses it into `AIAnalysisResult`

**Main function used by the dashboard**
- `analyze_incident(...)` (wrapper that can run mock or real model)

### 6) Simplified AI Interface (Optional): `src/ai/ai_engine.py`

This file was added per request. It loads the model at import time and returns a raw generated string. It is **not** used by the dashboard (the dashboard uses `src/ai/analyzer.py`).

### 7) Dashboard: `src/dashboard/app.py`

**Goal:** provide an interactive UI to inspect incidents, trigger AI analysis, update statuses, and export reports.

**Pages**
- Overview: metrics, severity distribution, recent incidents
- All Incidents: list, filtering/search, selection
- Incident Details: full record view, AI trigger, status changes, export single
- Settings: toggle Mock AI, model config

### 8) Export: `src/core/export.py`

**JSON export**
- `export_incidents_json(incidents, output_path, include_metadata=True)`

**PDF export**
- `export_incidents_pdf(incidents, output_path, title=...)`
- Uses `reportlab` if available.

## 📊 Database Schema

The SQLite database stores incidents with the following schema:

```sql
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert TEXT NOT NULL,
    ioc TEXT,
    log_snippet TEXT,
    ai_summary TEXT,
    severity TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'new',
    timestamp TEXT NOT NULL,
    detection_type TEXT,
    source_ips TEXT,
    users TEXT,
    metadata TEXT DEFAULT '{}'
);
```

**Where it lives**
- Default path: `data/incidents.db` (created automatically)

## 🧰 Operations Runbook

### Fresh start (reset demo data)

1. Stop Streamlit.
2. Delete `data/incidents.db`.
3. Recreate incidents from samples:

```bash
python test_populate.py
python -m streamlit run src/dashboard/app.py
```

### Running without the real AI model

Use **Mock AI** in the dashboard settings (default). This avoids large downloads and GPU/CPU memory pressure.

### Running with the real AI model

- Ensure `transformers` + `torch` are installed and you have enough RAM/disk.
- In Settings, disable Mock AI and trigger analysis on an incident.

## 🔒 Safety Notes

- Only analyze logs you are authorized to access.
- Treat exported incident reports as sensitive data.
- If you enable real-model inference on production logs, consider redacting secrets (tokens, passwords) from log snippets.

## 🤖 AI Model Details

### Foundation-Sec-8B

This tool uses the **fdtn-ai/Foundation-Sec-8B** model from Hugging Face, specifically designed for cybersecurity tasks.

**Model Capabilities:**
- Security incident classification
- Threat severity assessment
- Attack technique identification (MITRE ATT&CK mapping)
- Remediation recommendations
- Log analysis and summarization

**Requirements:**
- ~16GB disk space for model files
- ~16GB RAM for inference
- CUDA GPU recommended (but not required)

**Using Mock Mode:**
For testing or systems without sufficient resources:

```python
from src.ai.analyzer import analyze_incident

result = analyze_incident(
    alert="Test alert",
    log_snippet="Test log",
    use_mock=True  # Uses mock analyzer
)
```

## 📈 Example Output

### Detection Result
```json
{
    "detection_type": "brute_force",
    "severity": "high",
    "confidence": 0.95,
    "description": "Detected 47 failed login attempts from 203.0.113.50 within 5 minutes",
    "source_ip": "203.0.113.50",
    "target_user": "root",
    "recommendation": "Block source IP, investigate for compromise"
}
```

### AI Analysis Result
```json
{
    "severity": "high",
    "summary": "SSH brute force attack targeting root account from known malicious IP",
    "attack_type": "Credential Access - Brute Force (T1110)",
    "indicators": ["203.0.113.50", "Multiple failed authentications", "Root account targeting"],
    "recommendations": [
        "Immediately block 203.0.113.50 at firewall",
        "Review successful logins from this IP",
        "Enable account lockout policies",
        "Consider implementing fail2ban",
        "Audit root account for unauthorized access"
    ],
    "mitre_techniques": ["T1110.001", "T1078"],
    "confidence": 0.92
}
```

## 🔧 Configuration

### Detection Thresholds

Edit detection parameters in `src/core/detection.py`:

```python
# Brute force detection
BRUTE_FORCE_THRESHOLD = 5  # Failed attempts
BRUTE_FORCE_WINDOW = 300   # Seconds (5 minutes)

# Suspicious login hours
SUSPICIOUS_HOURS_START = 22  # 10 PM
SUSPICIOUS_HOURS_END = 6     # 6 AM
```

### IOC Configuration

Add custom IOCs to `logs/iocs.json`:

```json
{
    "indicators": {
        "ip_addresses": [
            {
                "value": "1.2.3.4",
                "type": "ipv4",
                "threat_type": "c2",
                "description": "Custom threat",
                "confidence": "high"
            }
        ]
    }
}
```

## 🛠️ Troubleshooting

### Common Issues

1. **Model download fails**
   ```bash
   # Clear Hugging Face cache and retry
   rm -rf ~/.cache/huggingface
   ```

2. **Out of memory during AI analysis**
   - Use mock mode: `use_mock=True`
   - Reduce batch size in analyzer settings
   - Use CPU instead of GPU (slower but less memory)

3. **Streamlit port conflict**
   ```bash
   streamlit run src/dashboard/app.py --server.port 8502
   ```

4. **Database locked error**
   - Ensure only one instance accesses the database
   - Check for zombie processes

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) by fdtn-ai
- [Streamlit](https://streamlit.io/) for the dashboard framework
- [MITRE ATT&CK](https://attack.mitre.org/) for threat classification
- The cybersecurity community for IOC feeds and threat intelligence

## 📞 Support

For issues and feature requests, please open an issue on the project repository.

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before analyzing logs from systems you do not own.
