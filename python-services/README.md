# AI Analyzer Microservice

Optional Python microservice for AI-powered incident analysis.

## Features

- Automated incident classification
- MITRE ATT&CK framework mapping
- Recommended actions based on incident type
- Threat scoring
- IOC extraction

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python ai_analyzer.py
```

The service will run on `http://localhost:5001`

## API Endpoints

### POST /analyze
Analyze an incident and return AI insights.

Request body:
```json
{
  "incident": {
    "id": 1,
    "detection_type": "brute_force",
    "severity": "high",
    "source_ips": "192.168.1.100",
    "users": "admin"
  }
}
```

### GET /health
Health check endpoint.

## Mock Mode

This is a mock implementation. For production, replace with actual ML models and threat intelligence feeds.
