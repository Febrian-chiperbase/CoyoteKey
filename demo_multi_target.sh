#!/bin/bash

# CoyoteKey Multi-Target Demo Script
# This script demonstrates the multi-target capabilities

echo "🎯 CoyoteKey Multi-Target Demo"
echo "=============================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if binary exists
if [ ! -f "./coyotekey" ]; then
    echo "❌ CoyoteKey binary not found. Building..."
    go build -o coyotekey CoyoteKey.go
fi

echo -e "${BLUE}Creating demo files...${NC}"

# Create demo wordlist
cat > demo_wordlist.txt << EOF
demo_key_001
test_api_key
sample_token
admin_key
EOF

# Create demo targets file
cat > demo_targets.txt << EOF
# Demo targets for multi-target testing
https://httpbin.org/headers GET X-API-Key: %KEY%
https://httpbin.org/status/200 GET Authorization: Bearer %KEY%
https://httpbin.org/bearer POST Authorization: Bearer %KEY%
https://httpbin.org/get GET Custom-Token: %KEY%
EOF

echo -e "${YELLOW}Demo 1: Basic Multi-Target${NC}"
echo "Command: ./coyotekey -targets demo_targets.txt -w demo_wordlist.txt -s '200,405' -t 2 -r 2"
echo ""
./coyotekey -targets demo_targets.txt -w demo_wordlist.txt -s "200,405" -t 2 -r 2

echo ""
echo -e "${YELLOW}Demo 2: Multi-Target with JSON Output${NC}"
echo "Command: ./coyotekey -targets demo_targets.txt -w demo_wordlist.txt -s '200' -t 3 -r 3 -o demo_results.json"
echo ""
./coyotekey -targets demo_targets.txt -w demo_wordlist.txt -s "200" -t 3 -r 3 -o demo_results.json

if [ -f "demo_results.json" ]; then
    echo ""
    echo -e "${GREEN}📄 JSON Results Preview:${NC}"
    head -20 demo_results.json
    echo ""
fi

echo ""
echo -e "${YELLOW}Demo 3: Multi-Target with Retry Logic${NC}"
echo "Command: ./coyotekey -targets demo_targets.txt -w demo_wordlist.txt -s '200' -retries 2 -delay 50 -v -t 2"
echo ""
./coyotekey -targets demo_targets.txt -w demo_wordlist.txt -s "200" -retries 2 -delay 50 -v -t 2

echo ""
echo -e "${GREEN}🎉 Multi-Target Demo Complete!${NC}"
echo ""
echo "Key Features Demonstrated:"
echo "✅ Multiple target URLs in single run"
echo "✅ Different HTTP methods per target"
echo "✅ Custom headers per target"
echo "✅ Retry logic with exponential backoff"
echo "✅ Request delays for rate limiting"
echo "✅ JSON output with target information"
echo "✅ Detailed statistics and success rates"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f demo_wordlist.txt demo_targets.txt demo_results.json

echo -e "${GREEN}Demo cleanup complete!${NC}"
