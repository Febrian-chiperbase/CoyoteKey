#!/bin/bash

# CoyoteKey API Discovery Demo Script
# This script demonstrates the API discovery and enumeration capabilities

echo "🔍 CoyoteKey API Discovery Demo"
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

# Create demo API keys for combined testing
cat > api_discovery_keys.txt << EOF
admin_key_123
test_api_key
demo_token_456
secret_key_789
bearer_token_abc
EOF

echo ""
echo -e "${YELLOW}Demo 1: Basic API Discovery${NC}"
echo "Features: Endpoint discovery with built-in paths"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -t 3 -r 5 -v"
echo ""
./coyotekey -u https://httpbin.org -api-discover -t 3 -r 5 -v

echo ""
echo -e "${YELLOW}Demo 2: Advanced API Discovery${NC}"
echo "Features: Schema analysis + Version detection + Documentation discovery"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -schema-analysis -version-detect -endpoint-enum -t 2 -r 3"
echo ""
./coyotekey -u https://httpbin.org -api-discover -schema-analysis -version-detect -endpoint-enum -t 2 -r 3

echo ""
echo -e "${YELLOW}Demo 3: Custom Path Discovery${NC}"
echo "Features: Custom path wordlist for comprehensive discovery"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -path-wordlist paths.example.txt -t 3 -r 4 -s '200,201,301,302,401,403,500'"
echo ""
./coyotekey -u https://httpbin.org -api-discover -path-wordlist paths.example.txt -t 3 -r 4 -s "200,201,301,302,401,403,500"

echo ""
echo -e "${YELLOW}Demo 4: Discovery + Brute Force Combination${NC}"
echo "Features: Discover endpoints then brute force authentication"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -w api_discovery_keys.txt -H 'Authorization: Bearer %KEY%' -t 2 -r 3 -o discovery_bruteforce.json"
echo ""
./coyotekey -u https://httpbin.org -api-discover -w api_discovery_keys.txt -H "Authorization: Bearer %KEY%" -t 2 -r 3 -o discovery_bruteforce.json

if [ -f "discovery_bruteforce.json" ]; then
    echo ""
    echo -e "${GREEN}📄 Discovery Results Preview:${NC}"
    head -20 discovery_bruteforce.json
    echo ""
fi

echo ""
echo -e "${YELLOW}Demo 5: Stealth API Discovery${NC}"
echo "Features: Discovery with evasion techniques"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -waf-detect -smart-throttle -ua-rotate -header-rotate -random-delay -delay 100 -t 2"
echo ""
./coyotekey -u https://httpbin.org -api-discover -waf-detect -smart-throttle -ua-rotate -header-rotate -random-delay -delay 100 -t 2

echo ""
echo -e "${YELLOW}Demo 6: Multi-Target API Discovery${NC}"
echo "Features: Discover APIs across multiple targets"
echo ""

# Create multi-target file for discovery
cat > discovery_targets.txt << EOF
# Multi-target API discovery
https://httpbin.org
https://jsonplaceholder.typicode.com
https://reqres.in
EOF

echo "Command: ./coyotekey -targets discovery_targets.txt -api-discover -schema-analysis -t 3 -r 2 -o multi_discovery.json"
echo ""
./coyotekey -targets discovery_targets.txt -api-discover -schema-analysis -t 3 -r 2 -o multi_discovery.json

if [ -f "multi_discovery.json" ]; then
    echo ""
    echo -e "${GREEN}📄 Multi-Target Discovery Results:${NC}"
    echo "Number of targets discovered:"
    grep -c '"target":' multi_discovery.json
    echo ""
fi

echo ""
echo -e "${GREEN}🎉 API Discovery Demo Complete!${NC}"
echo ""
echo "🔍 API Discovery Features Demonstrated:"
echo "✅ Automatic endpoint discovery"
echo "✅ Common path enumeration"
echo "✅ Custom wordlist support"
echo "✅ HTTP method enumeration"
echo "✅ API schema analysis"
echo "✅ Version detection"
echo "✅ Documentation discovery"
echo "✅ Framework detection"
echo "✅ Authentication requirement detection"
echo "✅ Multi-target discovery"
echo "✅ Combined discovery + brute force"
echo "✅ Stealth discovery with evasion"
echo ""
echo -e "${BLUE}Discovery Capabilities:${NC}"
echo "🎯 70+ built-in common paths"
echo "📂 214+ paths in example wordlist"
echo "🔍 Multiple HTTP methods testing"
echo "📋 OpenAPI/Swagger detection"
echo "🔢 API version identification"
echo "🔧 Framework fingerprinting"
echo "🔐 Authentication analysis"
echo "📊 Comprehensive statistics"
echo "💾 JSON output with full details"
echo "🛡️  Integration with evasion techniques"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f api_discovery_keys.txt discovery_targets.txt discovery_bruteforce.json multi_discovery.json

echo -e "${GREEN}API discovery demo cleanup complete!${NC}"
