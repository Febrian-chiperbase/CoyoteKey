#!/bin/bash

# CoyoteKey Machine Learning Demo Script
# This script demonstrates the machine learning capabilities

echo "🤖 CoyoteKey Machine Learning Demo"
echo "=================================="

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

# Create demo wordlist with various patterns
cat > ml_wordlist.txt << EOF
# High entropy keys
sk_test_1234567890abcdef
api_key_abcdef1234567890
secret_token_xyz789

# Low entropy keys
password123
admin
test

# Mixed patterns
User123Token
API_KEY_2024
jwt_token_abc

# Special patterns
Bearer_Token_XYZ
oauth2_access_token
session_id_12345
EOF

# Create training data example
cat > training_data.json << EOF
{
  "features": [
    [16, 4.2, 1, 1, 0, 1, 250, 1024, 200, 14, 2],
    [8, 2.1, 1, 0, 0, 1, 180, 512, 401, 14, 2],
    [12, 3.5, 1, 1, 1, 1, 300, 2048, 200, 15, 3]
  ],
  "labels": [1, 0, 1],
  "metadata": [
    {"url": "https://api.example.com", "success": true, "key_pattern": "ULNS"},
    {"url": "https://api.example.com", "success": false, "key_pattern": "LN"},
    {"url": "https://api.example.com", "success": true, "key_pattern": "ULNS"}
  ]
}
EOF

echo ""
echo -e "${YELLOW}Demo 1: Basic Machine Learning Features${NC}"
echo "Features: Success prediction + Pattern recognition + Adaptive learning"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -success-prediction -pattern-recognition -adaptive-learning -v"
echo ""
./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -success-prediction -pattern-recognition -adaptive-learning -v -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 2: Intelligent Sorting${NC}"
echo "Features: ML-based intelligent wordlist sorting"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -intelligent-sorting -success-prediction -v"
echo ""
./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -intelligent-sorting -success-prediction -v -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 3: Behavior Analysis + Anomaly Detection${NC}"
echo "Features: Target behavior analysis and anomaly detection"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -ml -behavior-analysis -anomaly-detection -pattern-recognition -t 2"
echo ""
./coyotekey -u https://httpbin.org -api-discover -ml -behavior-analysis -anomaly-detection -pattern-recognition -t 2 -r 5

echo ""
echo -e "${YELLOW}Demo 4: ML with Training Data${NC}"
echo "Features: Load existing training data for better predictions"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -training-data training_data.json -success-prediction -confidence-threshold 0.6"
echo ""
./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -training-data training_data.json -success-prediction -confidence-threshold 0.6 -v -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 5: Advanced ML Configuration${NC}"
echo "Features: Custom confidence threshold and learning parameters"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -success-prediction -intelligent-sorting -adaptive-learning -confidence-threshold 0.8 -learning-rate 0.05"
echo ""
./coyotekey -u https://httpbin.org/bearer -w ml_wordlist.txt -ml -success-prediction -intelligent-sorting -adaptive-learning -confidence-threshold 0.8 -learning-rate 0.05 -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 6: ML + Authentication Testing${NC}"
echo "Features: ML-enhanced authentication with multiple methods"
echo "Command: ./coyotekey -u https://httpbin.org/bearer -basic-auth -jwt -bearer -auth-wordlist auth_credentials.example.txt -ml -success-prediction -adaptive-learning"
echo ""
./coyotekey -u https://httpbin.org/bearer -basic-auth -jwt -bearer -auth-wordlist auth_credentials.example.txt -ml -success-prediction -adaptive-learning -t 2 -s "200,401"

echo ""
echo -e "${YELLOW}Demo 7: Complete ML Pipeline${NC}"
echo "Features: Discovery + Authentication + ML analysis with full output"
echo "Command: ./coyotekey -u https://httpbin.org -api-discover -basic-auth -jwt -auth-wordlist auth_credentials.example.txt -ml -success-prediction -behavior-analysis -anomaly-detection -o complete_ml_results.json"
echo ""
./coyotekey -u https://httpbin.org -api-discover -basic-auth -jwt -auth-wordlist auth_credentials.example.txt -ml -success-prediction -behavior-analysis -anomaly-detection -o complete_ml_results.json -t 2 -s "200,401"

if [ -f "complete_ml_results.json" ]; then
    echo ""
    echo -e "${GREEN}📄 Complete ML Results Preview:${NC}"
    head -20 complete_ml_results.json
    echo ""
fi

if [ -f "complete_ml_results_ml_insights.json" ]; then
    echo ""
    echo -e "${GREEN}🧠 ML Insights Preview:${NC}"
    head -30 complete_ml_results_ml_insights.json
    echo ""
fi

echo ""
echo -e "${GREEN}🎉 Machine Learning Demo Complete!${NC}"
echo ""
echo "🤖 Machine Learning Features Demonstrated:"
echo "✅ Success Probability Prediction"
echo "✅ Intelligent Wordlist Sorting"
echo "✅ Pattern Recognition and Analysis"
echo "✅ Adaptive Learning from Results"
echo "✅ Target Behavior Analysis"
echo "✅ Anomaly Detection"
echo "✅ Feature Extraction and Engineering"
echo "✅ Logistic Regression Model"
echo "✅ Confidence-based Decision Making"
echo "✅ Training Data Integration"
echo "✅ ML Insights Export"
echo "✅ Integration with All Existing Features"
echo ""
echo -e "${BLUE}ML Capabilities:${NC}"
echo "🧠 11 engineered features for prediction"
echo "📊 Logistic regression classification"
echo "🎯 Configurable confidence thresholds"
echo "📈 Adaptive learning from attack results"
echo "🔍 Pattern recognition for key analysis"
echo "⚠️  Anomaly detection for unusual responses"
echo "🎲 Intelligent sorting based on success probability"
echo "📋 Comprehensive ML insights and analytics"
echo "🔄 Real-time learning and model updates"
echo "💾 Persistent model and training data storage"

# Cleanup
echo ""
echo "🧹 Cleaning up demo files..."
rm -f ml_wordlist.txt training_data.json complete_ml_results.json complete_ml_results_ml_insights.json

echo -e "${GREEN}Machine learning demo cleanup complete!${NC}"
