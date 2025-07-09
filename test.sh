#!/bin/bash

# CoyoteKey Test Script
# This script tests the basic functionality of CoyoteKey

set -e

echo "🧪 CoyoteKey Test Suite"
echo "======================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit_code="${3:-0}"
    
    echo -e "\n${YELLOW}Testing: $test_name${NC}"
    echo "Command: $command"
    
    if eval "$command" >/dev/null 2>&1; then
        actual_exit_code=$?
    else
        actual_exit_code=$?
    fi
    
    if [ $actual_exit_code -eq $expected_exit_code ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAILED (exit code: $actual_exit_code, expected: $expected_exit_code)${NC}"
        ((TESTS_FAILED++))
    fi
}

# Check if binary exists
if [ ! -f "./coyotekey" ]; then
    echo -e "${RED}❌ CoyoteKey binary not found. Please build it first with: make build${NC}"
    exit 1
fi

# Test 1: Help flag
run_test "Help flag" "./coyotekey -h" 0

# Test 2: Missing required parameters
run_test "Missing required parameters" "./coyotekey" 1

# Test 3: Invalid URL
run_test "Invalid URL" "./coyotekey -u invalid-url -w sample_wordlist.txt" 1

# Test 4: Non-existent wordlist
run_test "Non-existent wordlist" "./coyotekey -u https://httpbin.org/headers -w non_existent_file.txt" 1

# Create a small test wordlist
echo "test_key_1" > test_small.txt
echo "test_key_2" >> test_small.txt

# Test 5: Basic functionality with httpbin
run_test "Basic functionality" "./coyotekey -u https://httpbin.org/headers -w test_small.txt -t 1 -timeout 5" 0

# Test 6: JSON output
run_test "JSON output" "./coyotekey -u https://httpbin.org/headers -w test_small.txt -t 1 -timeout 5 -o test_output.json" 0

# Check if JSON file was created
if [ -f "test_output.json" ]; then
    echo -e "${GREEN}✅ JSON output file created successfully${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ JSON output file not created${NC}"
    ((TESTS_FAILED++))
fi

# Test 7: Verbose mode
run_test "Verbose mode" "./coyotekey -u https://httpbin.org/headers -w test_small.txt -t 1 -timeout 5 -v" 0

# Test 8: Rate limiting
run_test "Rate limiting" "./coyotekey -u https://httpbin.org/headers -w test_small.txt -t 1 -timeout 5 -r 1" 0

# Test 9: Custom header format
run_test "Custom header format" "./coyotekey -u https://httpbin.org/headers -w test_small.txt -t 1 -timeout 5 -H 'Authorization: Bearer %KEY%'" 0

# Test 10: Multi-target functionality
echo -e "https://httpbin.org/headers\nhttps://httpbin.org/status/200" > test_targets.txt
run_test "Multi-target functionality" "./coyotekey -targets test_targets.txt -w test_small.txt -t 1 -timeout 5" 0

# Test 11: Multi-target with JSON output
run_test "Multi-target JSON output" "./coyotekey -targets test_targets.txt -w test_small.txt -t 1 -timeout 5 -o test_multi_output.json" 0

# Check if multi-target JSON file was created
if [ -f "test_multi_output.json" ]; then
    echo -e "${GREEN}✅ Multi-target JSON output file created successfully${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ Multi-target JSON output file not created${NC}"
    ((TESTS_FAILED++))
fi

# Test 12: Multi-target with retry logic
run_test "Multi-target with retries" "./coyotekey -targets test_targets.txt -w test_small.txt -t 1 -timeout 5 -retries 2" 0

# Cleanup
rm -f test_small.txt test_output.json test_targets.txt test_multi_output.json

# Summary
echo -e "\n${YELLOW}Test Summary${NC}"
echo "============"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed! CoyoteKey is working correctly.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed. Please check the output above.${NC}"
    exit 1
fi
