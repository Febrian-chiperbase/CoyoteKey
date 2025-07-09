#!/bin/bash

# CoyoteKey Database Integration Demo Script
# This script demonstrates the database integration capabilities

echo "💾 CoyoteKey Database Integration Demo"
echo "====================================="

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

# Create demo wordlist for database testing
cat > db_wordlist.txt << EOF
# Database test wordlist
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
EOF

# Create database configuration example
cat > database_config.json << EOF
{
  "type": "sqlite",
  "host": "localhost",
  "port": 5432,
  "database": "coyotekey_demo",
  "username": "coyotekey_user",
  "password": "secure_password",
  "ssl_mode": "disable",
  "max_connections": 10,
  "max_idle_connections": 5,
  "connection_timeout": "30s"
}
EOF

echo ""
echo -e "${YELLOW}Demo 1: Basic Database Integration${NC}"
echo "Features: SQLite database with persistent storage"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -db-type sqlite -persistent-storage -v"
echo ""
./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -db-type sqlite -persistent-storage -v -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 2: PostgreSQL Database with Analytics${NC}"
echo "Features: PostgreSQL database with attack analytics and historical analysis"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -db-type postgres -db-host localhost -db-name coyotekey_test -persistent-storage -attack-analytics -historical-analysis"
echo ""
./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -db-type postgres -db-host localhost -db-name coyotekey_test -persistent-storage -attack-analytics -historical-analysis -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 3: Database + ML Integration${NC}"
echo "Features: Database storage with machine learning insights"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -persistent-storage -ml -success-prediction -adaptive-learning -pattern-recognition -o db_ml_results.json"
echo ""
./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -persistent-storage -ml -success-prediction -adaptive-learning -pattern-recognition -o db_ml_results.json -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 4: Database + API Discovery${NC}"
echo "Features: API discovery with database storage and behavior analysis"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -db -persistent-storage -ml -behavior-analysis -anomaly-detection -attack-analytics"
echo ""
./coyotekey -u https://httpbin.org -api-discover -db -persistent-storage -ml -behavior-analysis -anomaly-detection -attack-analytics -t 2 -r 5

echo ""
echo -e "${YELLOW}Demo 5: Advanced Database Configuration${NC}"
echo "Features: MySQL database with auto-backup, caching, and optimization"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -db-type mysql -db-host localhost -db-name coyotekey -persistent-storage -auto-backup -backup-interval 12 -cache -cache-size 50 -query-optimization -indexing"
echo ""
./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -db-type mysql -db-host localhost -db-name coyotekey -persistent-storage -auto-backup -backup-interval 12 -cache -cache-size 50 -query-optimization -indexing -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 6: Complete Database Pipeline${NC}"
echo "Features: Discovery + Authentication + ML + Database with full analytics"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -basic-auth -jwt -auth-wordlist auth_credentials.example.txt -db -persistent-storage -attack-analytics -historical-analysis -ml -success-prediction -behavior-analysis -o complete_db_results.json"
echo ""
./coyotekey -u https://httpbin.org -api-discover -basic-auth -jwt -auth-wordlist auth_credentials.example.txt -db -persistent-storage -attack-analytics -historical-analysis -ml -success-prediction -behavior-analysis -o complete_db_results.json -t 2 -s "200,401"

if [ -f "complete_db_results.json" ]; then
    echo ""
    echo -e "${GREEN}📄 Complete Database Results Preview:${NC}"
    head -20 complete_db_results.json
    echo ""
fi

if [ -f "complete_db_results_analytics.json" ]; then
    echo ""
    echo -e "${GREEN}📊 Database Analytics Preview:${NC}"
    head -30 complete_db_results_analytics.json
    echo ""
fi

echo ""
echo -e "${YELLOW}Demo 7: Data Retention and Backup${NC}"
echo "Features: Database with custom data retention and automatic backup"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -persistent-storage -data-retention 7 -auto-backup -backup-interval 6 -attack-analytics"
echo ""
./coyotekey -u https://httpbin.org/bearer -w db_wordlist.txt -db -persistent-storage -data-retention 7 -auto-backup -backup-interval 6 -attack-analytics -t 2 -s "200,401"

echo ""
echo -e "${GREEN}🎉 Database Integration Demo Complete!${NC}"
echo ""
echo "💾 Database Integration Features Demonstrated:"
echo "✅ SQLite Database Support"
echo "✅ PostgreSQL Database Support"
echo "✅ MySQL Database Support"
echo "✅ Persistent Storage of Attack Results"
echo "✅ Attack Session Management"
echo "✅ Historical Data Analysis"
echo "✅ Attack Analytics and Reporting"
echo "✅ Database Indexing and Optimization"
echo "✅ Query Result Caching"
echo "✅ Automatic Database Backup"
echo "✅ Data Retention Management"
echo "✅ ML Insights Database Storage"
echo "✅ Discovery Results Storage"
echo "✅ Authentication Results Storage"
echo "✅ Real-time Analytics Generation"
echo ""
echo -e "${BLUE}Database Capabilities:${NC}"
echo "🗄️  Multi-database support (SQLite, PostgreSQL, MySQL)"
echo "📊 Comprehensive attack session tracking"
echo "🔍 Discovery results persistent storage"
echo "🔐 Authentication results archival"
echo "🤖 ML insights and model storage"
echo "📈 Real-time analytics and reporting"
echo "⚡ Query optimization and indexing"
echo "💾 Automatic backup and recovery"
echo "🕐 Configurable data retention policies"
echo "📊 Historical trend analysis"
echo "🎯 Target-specific analytics"
echo "📋 Comprehensive audit trails"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f db_wordlist.txt database_config.json complete_db_results.json complete_db_results_analytics.json db_ml_results.json db_ml_results_ml_insights.json

echo -e "${GREEN}Database integration demo cleanup complete!${NC}"
