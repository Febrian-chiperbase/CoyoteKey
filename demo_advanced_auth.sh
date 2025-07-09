#!/bin/bash

# CoyoteKey Advanced Authentication Demo Script
# This script demonstrates the advanced authentication capabilities

echo "🔐 CoyoteKey Advanced Authentication Demo"
echo "========================================="

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

# Create demo authentication credentials
cat > demo_auth_creds.txt << EOF
# Basic Auth Credentials
admin:admin123
user:password
test:test123
demo:demo456
guest:guest789

# API Keys and Tokens
api_key=sk_test_1234567890abcdef
token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.token
bearer_token=ghp_1234567890abcdefghijklmnop

# OAuth Credentials
client_id=demo_app,client_secret=demo_secret,scope=read write
username=oauth_user,password=oauth_pass,grant_type=password

# Session Tokens
session_token=sess_1234567890abcdef
auth_token=auth_abcdef1234567890
EOF

# Create username list
cat > demo_usernames.txt << EOF
admin
user
test
demo
guest
api_user
service
EOF

# Create password list
cat > demo_passwords.txt << EOF
password
123456
admin
secret
test123
demo456
guest789
EOF

echo ""
echo -e "${YELLOW}Demo 1: HTTP Basic Authentication${NC}"
echo "Features: Username:Password authentication"
echo "Command: ./coyotekey -u https://httpbin.org/basic-auth/admin/secret -basic-auth -auth-wordlist demo_auth_creds.txt -v"
echo ""
./coyotekey -u https://httpbin.org/basic-auth/admin/secret -basic-auth -auth-wordlist demo_auth_creds.txt -v -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 2: JWT Token Authentication${NC}"
echo "Features: JSON Web Token support and analysis"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -jwt -auth-wordlist demo_auth_creds.txt -v"
echo ""
./coyotekey -u https://httpbin.org/bearer -jwt -auth-wordlist demo_auth_creds.txt -v -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 3: Bearer Token Authentication${NC}"
echo "Features: Bearer token authentication"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -bearer -auth-wordlist demo_auth_creds.txt -v"
echo ""
./coyotekey -u https://httpbin.org/bearer -bearer -auth-wordlist demo_auth_creds.txt -v -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 4: Multiple Authentication Methods${NC}"
echo "Features: Test multiple auth methods simultaneously"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -jwt -bearer -basic-auth -session-token -auth-wordlist demo_auth_creds.txt"
echo ""
./coyotekey -u https://httpbin.org/bearer -jwt -bearer -basic-auth -session-token -auth-wordlist demo_auth_creds.txt -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 5: Username/Password Combination Testing${NC}"
echo "Features: Generate combinations from separate username and password lists"
echo "Command: ./coyotekey -u https://httpbin.org/basic-auth/admin/secret -basic-auth -username-list demo_usernames.txt -password-list demo_passwords.txt"
echo ""
./coyotekey -u https://httpbin.org/basic-auth/admin/secret -basic-auth -username-list demo_usernames.txt -password-list demo_passwords.txt -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 6: Advanced Auth with Evasion${NC}"
echo "Features: Authentication testing with smart evasion techniques"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -jwt -bearer -auth-wordlist demo_auth_creds.txt -waf-detect -smart-throttle -ua-rotate -random-delay -delay 100"
echo ""
./coyotekey -u https://httpbin.org/bearer -jwt -bearer -auth-wordlist demo_auth_creds.txt -waf-detect -smart-throttle -ua-rotate -random-delay -delay 100 -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 7: Combined Discovery + Advanced Auth${NC}"
echo "Features: Discover endpoints then test advanced authentication"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -jwt -bearer -basic-auth -auth-wordlist demo_auth_creds.txt -o combined_auth_results.json"
echo ""
./coyotekey -u https://httpbin.org -api-discover -jwt -bearer -basic-auth -auth-wordlist demo_auth_creds.txt -o combined_auth_results.json -t 2 -s "200,401"

if [ -f "combined_auth_results.json" ]; then
    echo ""
    echo -e "${GREEN}📄 Combined Results Preview:${NC}"
    head -20 combined_auth_results.json
    echo ""
fi

echo ""
echo -e "${GREEN}🎉 Advanced Authentication Demo Complete!${NC}"
echo ""
echo "🔐 Advanced Authentication Features Demonstrated:"
echo "✅ HTTP Basic Authentication (username:password)"
echo "✅ JWT Token Support and Analysis"
echo "✅ Bearer Token Authentication"
echo "✅ Session Token Authentication"
echo "✅ Cookie-based Authentication"
echo "✅ Custom Authentication Methods"
echo "✅ Multiple Authentication Method Testing"
echo "✅ Username/Password Combination Generation"
echo "✅ Authentication Credential Parsing"
echo "✅ Token Extraction and Analysis"
echo "✅ Authentication Result Analysis"
echo "✅ Integration with Smart Evasion"
echo "✅ Combined Discovery + Authentication"
echo ""
echo -e "${BLUE}Authentication Capabilities:${NC}"
echo "🔑 Multiple credential formats support"
echo "🎫 JWT token parsing and validation"
echo "🔗 OAuth 2.0 flow support (basic)"
echo "🔄 Token refresh capabilities"
echo "🔗 Authentication method chaining"
echo "📊 Comprehensive authentication statistics"
echo "💾 JSON output with full authentication details"
echo "🛡️  Integration with evasion techniques"
echo "🔍 Integration with API discovery"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f demo_auth_creds.txt demo_usernames.txt demo_passwords.txt combined_auth_results.json

echo -e "${GREEN}Advanced authentication demo cleanup complete!${NC}"
