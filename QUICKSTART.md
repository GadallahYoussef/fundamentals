# SecureOps Platform - Quick Start Guide

## Installation & Setup

### 1. Install Dependencies

From the project root:
```bash
# Install all dependencies (root, backend, frontend)
npm run install-all
```

Or manually:
```bash
# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install

# Root
cd ..
npm install
```

### 2. Initialize Database

```bash
# Seed the database with sample data
npm run seed
```

This will create:
- 12 sample assets
- 12 threats
- 12 vulnerabilities
- 15 risk scenarios
- 10 incidents
- 10 treatment plans
- 5 IOCs

### 3. Start the Application

**Option A: Start both servers together (Recommended)**
```bash
npm run dev
```

**Option B: Start servers separately**

Terminal 1 - Backend:
```bash
npm run backend
# Or: cd backend && npm start
```

Terminal 2 - Frontend:
```bash
npm run frontend
# Or: cd frontend && npm start
```

### 4. Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000
- **API Health Check**: http://localhost:5000/api/health

## Optional: Python AI Service

```bash
cd python-services
pip install -r requirements.txt
python ai_analyzer.py
```

The AI service will be available at http://localhost:5001

## Quick Feature Tour

### Dashboard
- View overall security posture
- See risk and incident distributions
- Track treatment progress

### Assets
- Manage organizational assets
- Set criticality levels (1-5)
- Track asset values

### Risk Management
1. Define threats and vulnerabilities
2. Create risks by linking assets, threats, and vulnerabilities
3. Set likelihood and impact (1-5 each)
4. System calculates risk score automatically
5. View risk matrix visualization

### Incident Response
1. Upload security logs (Linux, Windows, IDS formats)
2. System automatically detects threats
3. Review incidents
4. Link to related assets and risks
5. Trigger AI analysis for recommendations

### Reports
- Generate PDF reports
- Export to Excel
- JSON data export

## Testing the API

Run the included test script:
```bash
./test-api.sh
```

Or test manually:
```bash
# Health check
curl http://localhost:5000/api/health

# Get dashboard stats
curl http://localhost:5000/api/dashboard/stats

# Get all assets
curl http://localhost:5000/api/assets

# Get all risks
curl http://localhost:5000/api/risks

# Get risk matrix
curl http://localhost:5000/api/risks/matrix
```

## Troubleshooting

### Port Already in Use
If port 5000 or 3000 is in use:
```bash
# Backend - set PORT in backend/.env
PORT=5001

# Frontend - set PORT in terminal
PORT=3001 npm start
```

### Database Issues
Reset the database:
```bash
cd backend
rm secureops.db
node utils/seed.js
```

### Module Not Found
Reinstall dependencies:
```bash
npm run install-all
```

## Project Structure
```
SecureOps/
├── backend/          # Express.js API server
├── frontend/         # React.js web application
├── python-services/  # Optional AI microservice
└── package.json      # Root package with scripts
```

## Next Steps

1. Explore the dashboard
2. Create new assets
3. Define risks
4. Upload sample log files
5. Generate reports
6. Customize for your organization

For detailed documentation, see the main README.md file.
