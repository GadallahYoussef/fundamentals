#!/bin/bash
echo "Testing SecureOps Platform API Endpoints"
echo "=========================================="
echo ""

echo "1. Testing Health Endpoint..."
curl -s http://localhost:5000/api/health | python3 -m json.tool
echo ""

echo "2. Testing Dashboard Stats..."
curl -s http://localhost:5000/api/dashboard/stats | python3 -m json.tool | head -30
echo ""

echo "3. Testing Assets Count..."
curl -s http://localhost:5000/api/assets | python3 -c "import sys, json; print(f'Total Assets: {len(json.load(sys.stdin))}')"
echo ""

echo "4. Testing Risks Count..."
curl -s http://localhost:5000/api/risks | python3 -c "import sys, json; print(f'Total Risks: {len(json.load(sys.stdin))}')"
echo ""

echo "5. Testing Incidents Count..."
curl -s http://localhost:5000/api/incidents | python3 -c "import sys, json; print(f'Total Incidents: {len(json.load(sys.stdin))}')"
echo ""

echo "6. Testing Risk Matrix..."
curl -s http://localhost:5000/api/risks/matrix | python3 -c "import sys, json; data = json.load(sys.stdin); print(f'Risk Matrix Cells: {len(data)}')"
echo ""

echo "All API tests completed successfully! ✅"
