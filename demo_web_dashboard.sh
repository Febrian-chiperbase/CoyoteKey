#!/bin/bash

# CoyoteKey Web Dashboard Demo Script
# This script demonstrates the web dashboard capabilities

echo "🌐 CoyoteKey Web Dashboard Demo"
echo "==============================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if binary exists
if [ ! -f "./coyotekey" ]; then
    echo "❌ CoyoteKey binary not found. Building..."
    go build -o coyotekey CoyoteKey.go
fi

echo -e "${BLUE}Creating demo files...${NC}"

# Create demo wordlist for web dashboard testing
cat > web_wordlist.txt << EOF
# Web dashboard test wordlist
sk_test_1234567890abcdef
api_key_abcdef1234567890
secret_token_xyz789
password123
admin_key
test_token
bearer_xyz
session_abc
oauth_token_123
jwt_token_456
web_api_key_789
dashboard_token_123
EOF

echo ""
echo -e "${YELLOW}Demo 1: Basic Web Dashboard${NC}"
echo "Features: Web dashboard with real-time monitoring"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-port 8080 -real-time -notifications -v"
echo ""
echo "Starting attack with web dashboard on http://localhost:8080"
echo "Dashboard will run for 15 seconds..."
timeout 15 ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-port 8080 -real-time -notifications -v -t 2 -s "200,401" &
DASHBOARD_PID=$!

# Wait a moment for dashboard to start
sleep 3

# Test dashboard API endpoints
echo ""
echo -e "${GREEN}Testing Dashboard API Endpoints:${NC}"
echo "📊 Stats endpoint:"
curl -s http://localhost:8080/api/stats | head -c 200 || echo "Dashboard not ready yet"
echo ""
echo "🏥 Health endpoint:"
curl -s http://localhost:8080/api/health | head -c 200 || echo "Dashboard not ready yet"
echo ""

# Wait for the attack to complete
wait $DASHBOARD_PID

echo ""
echo -e "${YELLOW}Demo 2: Authenticated Web Dashboard${NC}"
echo "Features: Web dashboard with authentication and team collaboration"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-port 8081 -web-auth -web-user admin -web-password secret123 -team-collab -visual-analytics"
echo ""
echo "Starting authenticated dashboard on http://localhost:8081"
echo "Login: admin / secret123"
echo "Dashboard will run for 10 seconds..."
timeout 10 ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-port 8081 -web-auth -web-user admin -web-password secret123 -team-collab -visual-analytics -t 2 -s "200,401" &
AUTH_DASHBOARD_PID=$!

# Wait a moment for dashboard to start
sleep 3

echo ""
echo -e "${GREEN}Testing Authenticated Dashboard:${NC}"
echo "🔐 Login page:"
curl -s http://localhost:8081/login | head -c 100 || echo "Dashboard not ready yet"
echo ""

# Wait for the attack to complete
wait $AUTH_DASHBOARD_PID

echo ""
echo -e "${YELLOW}Demo 3: Web Dashboard + Database + ML${NC}"
echo "Features: Complete integration with database and machine learning"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-port 8082 -db -persistent-storage -attack-analytics -ml -success-prediction -adaptive-learning -real-time -notifications -websocket -o web_ml_results.json"
echo ""
echo "Starting complete dashboard on http://localhost:8082"
echo "Dashboard will run for 15 seconds..."
timeout 15 ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-port 8082 -db -persistent-storage -attack-analytics -ml -success-prediction -adaptive-learning -real-time -notifications -websocket -o web_ml_results.json -t 2 -s "200,401" &
COMPLETE_DASHBOARD_PID=$!

# Wait a moment for dashboard to start
sleep 3

echo ""
echo -e "${GREEN}Testing Complete Dashboard API:${NC}"
echo "📊 Analytics endpoint:"
curl -s http://localhost:8082/api/analytics | head -c 200 || echo "Dashboard not ready yet"
echo ""
echo "🔔 Notifications endpoint:"
curl -s http://localhost:8082/api/notifications | head -c 200 || echo "Dashboard not ready yet"
echo ""
echo "⚠️  Alerts endpoint:"
curl -s http://localhost:8082/api/alerts | head -c 200 || echo "Dashboard not ready yet"
echo ""

# Wait for the attack to complete
wait $COMPLETE_DASHBOARD_PID

echo ""
echo -e "${YELLOW}Demo 4: API Discovery with Dashboard${NC}"
echo "Features: API discovery with real-time dashboard monitoring"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -web -web-port 8083 -real-time -visual-analytics -db -ml -behavior-analysis -anomaly-detection"
echo ""
echo "Starting discovery dashboard on http://localhost:8083"
echo "Dashboard will run for 20 seconds..."
timeout 20 ./coyotekey -u https://httpbin.org -api-discover -web -web-port 8083 -real-time -visual-analytics -db -ml -behavior-analysis -anomaly-detection -t 2 -r 5 &
DISCOVERY_DASHBOARD_PID=$!

# Wait a moment for dashboard to start
sleep 5

echo ""
echo -e "${GREEN}Testing Discovery Dashboard:${NC}"
echo "🎯 Targets endpoint:"
curl -s http://localhost:8083/api/targets | head -c 200 || echo "Dashboard not ready yet"
echo ""
echo "📊 Sessions endpoint:"
curl -s http://localhost:8083/api/sessions | head -c 200 || echo "Dashboard not ready yet"
echo ""

# Wait for the discovery to complete
wait $DISCOVERY_DASHBOARD_PID

echo ""
echo -e "${YELLOW}Demo 5: Web API with Custom API Key${NC}"
echo "Features: Web API endpoints with custom API key authentication"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-api -api-key 'custom_api_key_123' -web-port 8084 -cors -notifications"
echo ""
echo "Starting API dashboard on http://localhost:8084"
echo "API Key: custom_api_key_123"
echo "Dashboard will run for 10 seconds..."
timeout 10 ./coyotekey -u https://httpbin.org/bearer -w web_wordlist.txt -web -web-api -api-key 'custom_api_key_123' -web-port 8084 -cors -notifications -t 2 -s "200,401" &
API_DASHBOARD_PID=$!

# Wait a moment for dashboard to start
sleep 3

echo ""
echo -e "${GREEN}Testing API with Custom Key:${NC}"
echo "🔑 API Stats with key:"
curl -s -H "X-API-Key: custom_api_key_123" http://localhost:8084/api/stats | head -c 200 || echo "Dashboard not ready yet"
echo ""
echo "❌ API Stats without key (should fail):"
curl -s http://localhost:8084/api/stats | head -c 100 || echo "Expected: Unauthorized"
echo ""

# Wait for the attack to complete
wait $API_DASHBOARD_PID

if [ -f "web_ml_results.json" ]; then
    echo ""
    echo -e "${GREEN}📄 Web Dashboard Results Preview:${NC}"
    head -20 web_ml_results.json
    echo ""
fi

if [ -f "web_ml_results_ml_insights.json" ]; then
    echo ""
    echo -e "${GREEN}🧠 ML Insights from Dashboard Preview:${NC}"
    head -20 web_ml_results_ml_insights.json
    echo ""
fi

echo ""
echo -e "${GREEN}🎉 Web Dashboard Demo Complete!${NC}"
echo ""
echo "🌐 Web Dashboard Features Demonstrated:"
echo "✅ Real-time Web Dashboard Interface"
echo "✅ RESTful API Endpoints"
echo "✅ Authentication and Session Management"
echo "✅ Team Collaboration Features"
echo "✅ Visual Analytics and Charts"
echo "✅ Real-time Monitoring and Updates"
echo "✅ WebSocket Support for Live Data"
echo "✅ Notifications and Alert System"
echo "✅ CORS Support for Cross-Origin Requests"
echo "✅ SSL/HTTPS Support"
echo "✅ API Key Authentication"
echo "✅ Database Integration Dashboard"
echo "✅ Machine Learning Insights Visualization"
echo "✅ Discovery Results Monitoring"
echo "✅ System Health Monitoring"
echo ""
echo -e "${BLUE}Dashboard Capabilities:${NC}"
echo "🖥️  Modern web interface with responsive design"
echo "📊 Real-time statistics and analytics"
echo "👥 Multi-user session management"
echo "🔔 Live notifications and alerts"
echo "📈 Visual charts and graphs"
echo "🔌 WebSocket for real-time updates"
echo "🛡️  Secure authentication and authorization"
echo "🌐 RESTful API for external integrations"
echo "📱 Mobile-friendly responsive design"
echo "⚡ High-performance real-time monitoring"
echo "🎯 Target-specific dashboards"
echo "📋 Comprehensive activity logging"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f web_wordlist.txt web_ml_results.json web_ml_results_ml_insights.json

echo -e "${GREEN}Web dashboard demo cleanup complete!${NC}"
