#!/bin/bash

# CoyoteKey Smart Evasion Demo Script
# This script demonstrates the smart evasion capabilities

echo "🛡️  CoyoteKey Smart Evasion Demo"
echo "================================="

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

# Create demo wordlist
cat > evasion_wordlist.txt << EOF
stealth_key_001
ninja_token_123
ghost_api_key
shadow_bearer
phantom_access
EOF

# Create demo targets
cat > evasion_targets.txt << EOF
# Targets for evasion testing
https://httpbin.org/headers GET X-API-Key: %KEY%
https://httpbin.org/status/200 GET Authorization: Bearer %KEY%
https://httpbin.org/get GET Custom-Token: %KEY%
EOF

echo ""
echo -e "${YELLOW}Demo 1: Basic Smart Evasion${NC}"
echo "Features: WAF Detection + Smart Throttling + Random Delays"
echo "Command: ./coyotekey -u https://httpbin.org/headers -w evasion_wordlist.txt -waf-detect -smart-throttle -random-delay -delay 100 -v"
echo ""
./coyotekey -u https://httpbin.org/headers -w evasion_wordlist.txt -waf-detect -smart-throttle -random-delay -delay 100 -v -t 1

echo ""
echo -e "${YELLOW}Demo 2: User-Agent Rotation${NC}"
echo "Features: UA Rotation + Header Rotation + Session Rotation"
echo "Command: ./coyotekey -u https://httpbin.org/headers -w evasion_wordlist.txt -ua-rotate -header-rotate -session-rotate -v"
echo ""
./coyotekey -u https://httpbin.org/headers -w evasion_wordlist.txt -ua-rotate -header-rotate -session-rotate -v -t 1

echo ""
echo -e "${YELLOW}Demo 3: Advanced Multi-Target Evasion${NC}"
echo "Features: All evasion techniques combined"
echo "Command: ./coyotekey -targets evasion_targets.txt -w evasion_wordlist.txt -waf-detect -smart-throttle -ua-rotate -header-rotate -session-rotate -random-delay -delay 50 -t 2"
echo ""
./coyotekey -targets evasion_targets.txt -w evasion_wordlist.txt -waf-detect -smart-throttle -ua-rotate -header-rotate -session-rotate -random-delay -delay 50 -t 2

echo ""
echo -e "${YELLOW}Demo 4: User-Agent List Rotation${NC}"
echo "Features: Custom UA list + WAF detection"
echo "Command: ./coyotekey -u https://httpbin.org/headers -w evasion_wordlist.txt -ua-list user_agents.example.txt -ua-rotate -waf-detect -v"
echo ""
./coyotekey -u https://httpbin.org/headers -w evasion_wordlist.txt -ua-list user_agents.example.txt -ua-rotate -waf-detect -v -t 1

echo ""
echo -e "${YELLOW}Demo 5: Stealth Mode (All Features)${NC}"
echo "Features: Maximum stealth with all evasion techniques"
echo "Command: ./coyotekey -targets evasion_targets.txt -w evasion_wordlist.txt -waf-detect -smart-throttle -ua-list user_agents.example.txt -ua-rotate -header-rotate -session-rotate -random-delay -delay 200 -retries 5 -o stealth_results.json"
echo ""
./coyotekey -targets evasion_targets.txt -w evasion_wordlist.txt -waf-detect -smart-throttle -ua-list user_agents.example.txt -ua-rotate -header-rotate -session-rotate -random-delay -delay 200 -retries 5 -o stealth_results.json -t 2

if [ -f "stealth_results.json" ]; then
    echo ""
    echo -e "${GREEN}📄 Stealth Results Preview:${NC}"
    head -15 stealth_results.json
    echo ""
fi

echo ""
echo -e "${GREEN}🎉 Smart Evasion Demo Complete!${NC}"
echo ""
echo "🛡️  Smart Evasion Features Demonstrated:"
echo "✅ WAF Detection and Adaptive Response"
echo "✅ Smart Throttling based on Response Patterns"
echo "✅ User-Agent Rotation (Built-in + Custom Lists)"
echo "✅ HTTP Header Rotation"
echo "✅ Session Rotation (Random Session IDs)"
echo "✅ Random Delay Variations"
echo "✅ Exponential Backoff with Jitter"
echo "✅ Intelligent Retry Logic"
echo "✅ Response Pattern Analysis"
echo "✅ Rate Limit Detection and Respect"
echo ""
echo -e "${BLUE}Advanced Evasion Techniques:${NC}"
echo "🔍 Automatic WAF signature detection"
echo "⏱️  Adaptive delay adjustment based on responses"
echo "🎭 Realistic browser behavior simulation"
echo "🔄 Intelligent rotation of request characteristics"
echo "🧠 Machine learning-like response analysis"
echo "🛡️  Proactive blocking detection and avoidance"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f evasion_wordlist.txt evasion_targets.txt stealth_results.json

echo -e "${GREEN}Smart evasion demo cleanup complete!${NC}"
