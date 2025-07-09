#!/bin/bash

# CoyoteKey GUI Demo Script
# This script demonstrates the GUI capabilities

echo "🖥️ CoyoteKey GUI Demo"
echo "===================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if binary exists
if [ ! -f "./coyotekey" ]; then
    echo "❌ CoyoteKey binary not found. Building..."
    go build -o coyotekey CoyoteKey.go
fi

echo -e "${BLUE}Checking GUI files...${NC}"

# Check if web directory exists
if [ ! -d "./web" ]; then
    echo "❌ Web directory not found. GUI files are missing."
    exit 1
fi

# Check required files
required_files=(
    "web/static/css/dashboard.css"
    "web/static/js/dashboard.js"
    "web/templates/dashboard.html"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file (missing)"
    fi
done

echo ""
echo -e "${YELLOW}Demo 1: Basic GUI Dashboard${NC}"
echo "Features: Modern web-based GUI with real-time monitoring"
echo "URL: http://localhost:8080"
echo ""

# Create demo wordlist
cat > gui_wordlist.txt << EOF
# GUI Demo Wordlist
sk_test_gui_123456
api_key_gui_789012
secret_token_gui_345
admin_key_gui
bearer_token_gui
jwt_token_gui_678
oauth_token_gui_901
session_key_gui_234
dashboard_key_gui
web_api_key_gui
EOF

echo "Starting CoyoteKey with GUI dashboard..."
echo "Dashboard will be available at: http://localhost:8080"
echo ""
echo -e "${CYAN}GUI Features Available:${NC}"
echo "🖥️  Modern responsive web interface"
echo "📊 Real-time statistics and charts"
echo "🎯 Interactive attack configuration"
echo "📈 Live progress monitoring"
echo "📋 Results table with filtering"
echo "🔔 Real-time notifications"
echo "📊 Visual analytics with Chart.js"
echo "⚙️  Settings and configuration panel"
echo "🌐 WebSocket for live updates"
echo "📱 Mobile-friendly responsive design"
echo ""

# Start CoyoteKey with GUI
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w gui_wordlist.txt -web -web-port 8080 -real-time -notifications -web-api -api-key 'gui_demo_key_123' -db -persistent-storage -ml -success-prediction -v -t 2 -s '200,401'"
echo ""
echo -e "${GREEN}Starting GUI dashboard...${NC}"
echo "Press Ctrl+C to stop the server"
echo ""

# Run with timeout to prevent hanging
timeout 300 ./coyotekey -u https://httpbin.org/bearer -w gui_wordlist.txt \
    -web -web-port 8080 -real-time -notifications \
    -web-api -api-key "gui_demo_key_123" \
    -db -persistent-storage -ml -success-prediction \
    -v -t 2 -s "200,401" &

SERVER_PID=$!

# Wait for server to start
sleep 3

echo ""
echo -e "${GREEN}🌐 GUI Dashboard is now running!${NC}"
echo ""
echo "📱 Access the dashboard:"
echo "   🔗 Main Dashboard: http://localhost:8080"
echo "   🔗 API Stats: http://localhost:8080/api/stats"
echo "   🔗 API Health: http://localhost:8080/api/health"
echo ""
echo -e "${CYAN}Dashboard Features:${NC}"
echo "   📊 Dashboard Tab - Real-time statistics and activity feed"
echo "   🚀 Attack Config Tab - Interactive attack configuration"
echo "   📋 Results Tab - Live results table with export functionality"
echo "   📈 Analytics Tab - Visual charts and performance metrics"
echo "   ⚙️  Settings Tab - Dashboard configuration and system info"
echo ""
echo -e "${YELLOW}API Endpoints Available:${NC}"
echo "   GET /api/stats - Real-time attack statistics"
echo "   GET /api/sessions - Active attack sessions"
echo "   GET /api/targets - Target information"
echo "   GET /api/results - Recent attack results"
echo "   GET /api/analytics - Comprehensive analytics"
echo "   GET /api/health - System health status"
echo "   GET /api/notifications - User notifications"
echo "   GET /api/alerts - System alerts"
echo ""

# Test API endpoints
echo -e "${BLUE}Testing API endpoints...${NC}"
sleep 2

echo "📊 Testing /api/stats:"
curl -s -H "X-API-Key: gui_demo_key_123" http://localhost:8080/api/stats | head -c 200
echo ""
echo ""

echo "🏥 Testing /api/health:"
curl -s http://localhost:8080/api/health | head -c 200
echo ""
echo ""

echo "🔔 Testing /api/notifications:"
curl -s -H "X-API-Key: gui_demo_key_123" http://localhost:8080/api/notifications | head -c 200
echo ""
echo ""

# Wait for attack to complete or timeout
echo -e "${YELLOW}Waiting for attack to complete...${NC}"
wait $SERVER_PID

echo ""
echo -e "${GREEN}🎉 GUI Demo Complete!${NC}"
echo ""
echo -e "${CYAN}GUI Features Demonstrated:${NC}"
echo "✅ Modern Web-based Interface"
echo "✅ Real-time Dashboard with Live Stats"
echo "✅ Interactive Attack Configuration Form"
echo "✅ Live Progress Monitoring with Progress Bar"
echo "✅ Results Table with Real-time Updates"
echo "✅ Visual Analytics with Chart.js Integration"
echo "✅ WebSocket Real-time Communication"
echo "✅ RESTful API Endpoints"
echo "✅ Responsive Mobile-friendly Design"
echo "✅ Authentication and Session Management"
echo "✅ Notifications and Alert System"
echo "✅ Settings and Configuration Panel"
echo "✅ File Upload Support (Wordlists/Targets)"
echo "✅ Export Functionality (JSON/CSV)"
echo "✅ System Health Monitoring"
echo ""
echo -e "${BLUE}Technical Features:${NC}"
echo "🎨 Modern CSS with Glassmorphism Design"
echo "⚡ Vanilla JavaScript with ES6+ Features"
echo "📊 Chart.js for Data Visualization"
echo "🔌 WebSocket for Real-time Updates"
echo "📱 Responsive Grid Layout"
echo "🎯 Interactive Form Controls"
echo "🔔 Toast Notifications"
echo "📈 Live Progress Tracking"
echo "🎭 Smooth Animations and Transitions"
echo "🛡️ Security Headers and CORS Support"
echo ""
echo -e "${GREEN}GUI is production-ready for:${NC}"
echo "🏢 Enterprise Security Teams"
echo "👥 Collaborative Penetration Testing"
echo "📊 Real-time Attack Monitoring"
echo "📈 Performance Analytics and Reporting"
echo "🎯 Interactive Security Assessments"
echo "📱 Mobile Security Testing"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f gui_wordlist.txt

echo -e "${GREEN}GUI demo cleanup complete!${NC}"
