# SecureOps Platform

A comprehensive Security Operations Center (SOC) web application that combines **Risk Management** and **Incident Response** capabilities into a unified platform.

## Overview

SecureOps Platform integrates two powerful security frameworks:
- **Risk Management** - Proactively identify and manage organizational risks
- **Incident Response** - Reactively detect and respond to security incidents

## Features

### Risk Management Module
- ✅ **Asset Management** - Track hardware, software, data, personnel, and facilities
- ✅ **Threat Catalog** - Maintain database of security threats
- ✅ **Vulnerability Tracking** - Monitor system vulnerabilities
- ✅ **Risk Assessment** - Automatic risk scoring (Likelihood × Impact)
- ✅ **Risk Matrix** - Interactive 5×5 heat map visualization
- ✅ **Treatment Plans** - Track risk mitigation strategies

### Incident Response Module
- ✅ **Log Upload & Parsing** - Support for Linux auth.log, Windows Security events, IDS logs
- ✅ **Automated Threat Detection** - Detect brute force, suspicious logins, privilege escalation
- ✅ **Incident Management** - Track and manage security incidents
- ✅ **AI Analysis** - Mock AI-powered incident classification (extensible)
- ✅ **Risk-Incident Correlation** - Link incidents to assets and risks

### Unified Dashboard
- ✅ Real-time statistics and metrics
- ✅ Risk distribution charts
- ✅ Incident severity tracking
- ✅ Treatment progress overview
- ✅ Top 10 highest risks
- ✅ Recent incident timeline

### Reporting
- ✅ PDF report generation
- ✅ Excel export for data analysis
- ✅ JSON export for programmatic access

## Technology Stack

### Backend
- **Node.js** with Express.js
- **SQLite** database
- **Multer** for file uploads
- **PDFKit** and **ExcelJS** for report generation

### Frontend
- **React.js** with React Router
- **Axios** for API calls
- **Chart.js** for data visualization
- Modern, responsive UI design

### Optional Microservice
- **Python/Flask** for AI analysis (mock mode included)

## Installation

### Prerequisites
- Node.js (v16 or higher)
- npm or yarn
- Python 3.8+ (optional, for AI microservice)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd new_project
   ```

2. **Install all dependencies**
   ```bash
   npm run install-all
   ```

3. **Seed the database with sample data**
   ```bash
   npm run seed
   ```

4. **Start the development servers**
   ```bash
   npm run dev
   ```

   This will start:
   - Backend API on `http://localhost:5000`
   - Frontend on `http://localhost:3000`

### Manual Installation

#### Backend
```bash
cd backend
npm install
npm start
```

#### Frontend
```bash
cd frontend
npm install
npm start
```

#### Python AI Service (Optional)
```bash
cd python-services
pip install -r requirements.txt
python ai_analyzer.py
```

## API Endpoints

### Assets
- `GET /api/assets` - Get all assets
- `POST /api/assets` - Create new asset
- `GET /api/assets/:id` - Get asset by ID
- `PUT /api/assets/:id` - Update asset
- `DELETE /api/assets/:id` - Delete asset

### Risks
- `GET /api/risks` - Get all risks
- `GET /api/risks/stats` - Get risk statistics
- `GET /api/risks/matrix` - Get risk matrix data
- `POST /api/risks` - Create new risk
- `PUT /api/risks/:id` - Update risk
- `DELETE /api/risks/:id` - Delete risk

### Incidents
- `GET /api/incidents` - Get all incidents
- `GET /api/incidents/stats` - Get incident statistics
- `POST /api/incidents` - Create new incident
- `POST /api/incidents/:id/analyze` - Trigger AI analysis
- `PUT /api/incidents/:id/link-asset` - Link incident to asset
- `PUT /api/incidents/:id/link-risk` - Link incident to risk

### Logs
- `POST /api/logs/upload` - Upload and parse log file
- `POST /api/logs/detect` - Detect threats from log data

### Dashboard
- `GET /api/dashboard/stats` - Get unified dashboard statistics

### Reports
- `GET /api/reports/pdf` - Generate PDF report
- `GET /api/reports/excel` - Generate Excel report
- `GET /api/reports/json` - Get JSON report data

## Usage Guide

### 1. Dashboard
Navigate to the dashboard to see:
- Overall security posture
- Risk and incident distributions
- Top risks requiring attention
- Recent security incidents

### 2. Asset Management
1. Go to **Assets** menu
2. Click **Add Asset** to create new assets
3. Specify category, criticality (1-5), and owner
4. Track asset value for risk calculations

### 3. Risk Assessment
1. Define **Threats** and **Vulnerabilities**
2. Create **Risks** by linking assets, threats, and vulnerabilities
3. Set **Likelihood** (1-5) and **Impact** (1-5)
4. System automatically calculates risk score and level
5. View **Risk Matrix** for heat map visualization

### 4. Risk Treatment
1. For each risk, create a **Treatment** plan
2. Choose treatment type: Mitigate, Accept, Transfer, or Avoid
3. Assign owner and set due date
4. Track progress: Planned → In Progress → Completed

### 5. Incident Response
1. Upload security logs via **Log Upload**
2. System automatically parses and detects threats
3. View detected incidents in **Incidents** menu
4. Link incidents to related assets and risks
5. Trigger AI analysis for recommendations

### 6. Reporting
1. Go to **Reports** menu
2. Generate PDF or Excel reports
3. Reports include comprehensive data on all security aspects

## Risk Calculation

Risk scores are calculated using the formula:
```
Risk Score = Likelihood × Impact
```

Where both Likelihood and Impact range from 1-5, resulting in scores from 1-25.

Risk levels are determined as:
- **Critical**: 20-25 (Red)
- **High**: 12-19 (Orange)
- **Medium**: 6-11 (Yellow)
- **Low**: 1-5 (Green)

## License

MIT License

## Support

For issues, questions, or contributions, please open an issue on GitHub.

Built with ❤️ for security professionals.