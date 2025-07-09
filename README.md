# CoyoteKey - API Key Brute Force Tool

🔑 A powerful and efficient API key brute force tool written in Go with advanced features like rate limiting, proxy support, and detailed reporting.

## Features

- ✅ **Multi-threaded**: Concurrent requests for faster execution
- 🎯 **Multi-Target Support**: Test multiple URLs in a single run
- 🔍 **API Discovery & Enumeration**: Automatic endpoint discovery and analysis
- 🔐 **Advanced Authentication**: JWT, OAuth, Basic Auth, Bearer tokens, and more
- 🤖 **Machine Learning Integration**: AI-powered attack optimization and prediction
- 💾 **Database Integration**: Persistent storage, analytics, and historical analysis
- 🌐 **Web Dashboard**: Real-time monitoring, team collaboration, and visual analytics
- 🛡️ **Smart Evasion**: WAF detection, adaptive throttling, and stealth techniques
- 🔄 **Advanced Rotation**: User-Agent, proxy, and header rotation
- ⏱️ **Rate Limiting**: Control request rate to avoid detection
- 🔄 **Smart Retry Logic**: Automatic retry with exponential backoff
- 🌐 **Proxy Support**: Route traffic through proxy servers with rotation
- 📊 **Detailed Reporting**: Response times, content length, timestamps
- 💾 **JSON Output**: Save results in structured format
- 🔧 **Flexible Headers**: Customizable API key header formats
- 🎯 **Multiple Success Codes**: Define custom success criteria
- 🛡️ **Stealth Mode**: Realistic browser headers and user agents

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd tools_bruteforce_API

# Build the tool
go build -o coyotekey CoyoteKey.go

# Or run directly
go run CoyoteKey.go [options]
```

## Usage

### Basic Usage

```bash
# Single target brute force
./coyotekey -u https://api.example.com/endpoint -w wordlist.txt

# Multiple targets brute force
./coyotekey -targets targets.txt -w wordlist.txt

# API Discovery (no wordlist needed)
./coyotekey -u https://api.example.com -api-discover

# Advanced Authentication Testing
./coyotekey -u https://api.example.com -basic-auth -auth-wordlist credentials.txt

# Machine Learning Enhanced Attack
./coyotekey -u https://api.example.com -w wordlist.txt -ml -success-prediction -intelligent-sorting

# Database-Enhanced Attack with Analytics
./coyotekey -u https://api.example.com -w wordlist.txt -db -persistent-storage -attack-analytics

# Web Dashboard with Real-time Monitoring
./coyotekey -u https://api.example.com -w wordlist.txt -web -real-time -notifications

# Complete Pipeline: Discovery + Auth + ML + Database + Dashboard
./coyotekey -u https://api.example.com -api-discover -jwt -bearer -ml -db -web -attack-analytics -o results.json
```

### Advanced Usage

```bash
# Single target with advanced options
./coyotekey \
  -u https://api.example.com/v1/users \
  -w api_keys.txt \
  -H "Authorization: Bearer %KEY%" \
  -m GET \
  -s "200,201,202" \
  -t 20 \
  -r 10 \
  -timeout 15 \
  -retries 3 \
  -delay 100 \
  -o results.json \
  -v \
  --proxy http://127.0.0.1:8080

# Multi-target with configuration
./coyotekey \
  -targets targets.txt \
  -w wordlist.txt \
  -t 15 \
  -r 5 \
  -retries 2 \
  -o multi_results.json \
  -v

# API Discovery with Analysis
./coyotekey \
  -u https://api.example.com \
  -api-discover \
  -endpoint-enum \
  -schema-analysis \
  -version-detect \
  -path-wordlist paths.txt \
  -t 10 \
  -r 5 \
  -o discovery.json

# Smart Evasion Mode
./coyotekey \
  -u https://protected-api.com/endpoint \
  -w wordlist.txt \
  -waf-detect \
  -smart-throttle \
  -ua-rotate \
  -header-rotate \
  -session-rotate \
  -random-delay \
  -delay 200 \
  -retries 5 \
  -v

# Maximum Stealth Configuration
./coyotekey \
  -targets targets.txt \
  -w wordlist.txt \
  -waf-detect \
  -smart-throttle \
  -ua-list user_agents.txt \
  -ua-rotate \
  -proxy-list proxies.txt \
  -proxy-rotate \
  -header-rotate \
  -session-rotate \
  -random-delay \
  -delay 500 \
  -t 5 \
  -r 2 \
  -retries 10 \
  -o stealth_results.json

# Combined Discovery + Stealth Brute Force
./coyotekey \
  -u https://api.example.com \
  -api-discover \
  -w wordlist.txt \
  -waf-detect \
  -smart-throttle \
  -ua-rotate \
  -header-rotate \
  -o combined_results.json
```

## Command Line Options

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `-u` | Single target API endpoint URL | - | `https://api.example.com/endpoint` |
| `-targets` | File containing multiple target URLs | - | `targets.txt` |
| `-w` | Path to wordlist file (required for brute force) | - | `wordlist.txt` |
| `-H` | HTTP Header format for API Key | `X-API-Key: %KEY%` | `Authorization: Bearer %KEY%` |
| `-m` | HTTP method | `GET` | `POST`, `PUT`, `DELETE` |
| `-s` | Success HTTP status codes (comma-separated) | `200` | `200,201,202` |
| `-t` | Number of concurrent threads | `10` | `20` |
| `-r` | Rate limit (requests per second, 0 = no limit) | `0` | `10` |
| `-timeout` | HTTP request timeout in seconds | `10` | `15` |
| `-retries` | Maximum number of retries for failed requests | `3` | `5` |
| `-delay` | Base delay between requests in milliseconds | `0` | `100` |
| `-random-delay` | Add random delay variation (50-150% of base) | `false` | - |
| `-o` | Output file for results (JSON format) | - | `results.json` |
| `-v` | Verbose output | `false` | - |
| **Web Dashboard Options** |
| `-web` | Enable web dashboard | `false` | - |
| `-web-port` | Web dashboard port | `8080` | `443` |
| `-web-host` | Web dashboard host | `localhost` | `0.0.0.0` |
| `-web-auth` | Enable web dashboard authentication | `false` | - |
| `-web-user` | Web dashboard username | `admin` | `security_team` |
| `-web-password` | Web dashboard password | - | `secure_password_123` |
| `-web-ssl` | Enable SSL for web dashboard | `false` | - |
| `-web-cert` | SSL certificate file for web dashboard | - | `cert.pem` |
| `-web-key` | SSL private key file for web dashboard | - | `key.pem` |
| `-real-time` | Enable real-time monitoring | `false` | - |
| `-team-collab` | Enable team collaboration features | `false` | - |
| `-visual-analytics` | Enable visual analytics | `false` | - |
| `-web-api` | Enable web API endpoints | `false` | - |
| `-api-key` | API key for web API access | - | `secure_api_key_123` |
| `-cors` | Enable CORS for web dashboard | `false` | - |
| `-websocket` | Enable WebSocket for real-time updates | `false` | - |
| `-notifications` | Enable notifications system | `false` | - |
| **Database Integration Options** |
| `-db` | Enable database integration | `false` | - |
| `-db-type` | Database type (sqlite, postgres, mysql) | `sqlite` | `postgres` |
| `-db-url` | Database connection URL | - | `postgres://user:pass@host:5432/db` |
| `-db-host` | Database host | `localhost` | `db.example.com` |
| `-db-port` | Database port | `5432` | `3306` |
| `-db-name` | Database name | `coyotekey` | `coyotekey_prod` |
| `-db-user` | Database username | - | `coyotekey_user` |
| `-db-password` | Database password | - | `secure_password` |
| `-db-ssl` | Enable SSL for database connection | `false` | - |
| `-persistent-storage` | Enable persistent storage of results | `false` | - |
| `-historical-analysis` | Enable historical data analysis | `false` | - |
| `-attack-analytics` | Enable attack analytics and reporting | `false` | - |
| `-data-retention` | Data retention period in days | `30` | `90` |
| `-auto-backup` | Enable automatic database backup | `false` | - |
| `-backup-interval` | Backup interval in hours | `24` | `12` |
| `-query-optimization` | Enable query optimization | `true` | - |
| `-indexing` | Enable database indexing | `true` | - |
| `-cache` | Enable query result caching | `false` | - |
| `-cache-size` | Cache size in MB | `100` | `256` |
| **Machine Learning Options** |
| `-ml` | Enable machine learning features | `false` | - |
| `-success-prediction` | Enable success probability prediction | `false` | - |
| `-intelligent-sorting` | Enable intelligent wordlist sorting | `false` | - |
| `-pattern-recognition` | Enable pattern recognition and analysis | `false` | - |
| `-adaptive-learning` | Enable adaptive learning from results | `false` | - |
| `-behavior-analysis` | Enable target behavior analysis | `false` | - |
| `-anomaly-detection` | Enable anomaly detection | `false` | - |
| `-model-training` | Enable model training mode | `false` | - |
| `-predictive-analysis` | Enable predictive analysis | `false` | - |
| `-ml-model` | Path to ML model file | - | `model.json` |
| `-training-data` | Path to training data file | - | `training.json` |
| `-confidence-threshold` | Confidence threshold for predictions | `0.7` | `0.8` |
| `-learning-rate` | Learning rate for model training | `0.01` | `0.05` |
| `-max-iterations` | Maximum iterations for training | `1000` | `2000` |
| **Advanced Authentication Options** |
| `-basic-auth` | Enable HTTP Basic Authentication | `false` | - |
| `-jwt` | Enable JWT token support and analysis | `false` | - |
| `-oauth` | Enable OAuth 2.0 flow support | `false` | - |
| `-bearer` | Enable Bearer token authentication | `false` | - |
| `-session-token` | Enable session token authentication | `false` | - |
| `-cookie-auth` | Enable cookie-based authentication | `false` | - |
| `-custom-auth` | Enable custom authentication methods | `false` | - |
| `-mfa` | Enable multi-factor authentication support | `false` | - |
| `-auth-chain` | Enable authentication method chaining | `false` | - |
| `-token-refresh` | Enable automatic token refresh | `false` | - |
| `-auth-wordlist` | Wordlist for authentication credentials | - | `credentials.txt` |
| `-username-list` | Username wordlist for basic auth | - | `usernames.txt` |
| `-password-list` | Password wordlist for basic auth | - | `passwords.txt` |
| `-auth-endpoint` | Authentication endpoint URL | - | `https://api.com/auth` |
| `-token-endpoint` | Token endpoint URL for OAuth | - | `https://api.com/token` |
| `-refresh-endpoint` | Token refresh endpoint URL | - | `https://api.com/refresh` |
| **API Discovery Options** |
| `-api-discover` | Enable API endpoint discovery | `false` | - |
| `-endpoint-enum` | Enable endpoint enumeration | `false` | - |
| `-schema-analysis` | Enable API schema analysis | `false` | - |
| `-version-detect` | Enable API version detection | `false` | - |
| `-param-fuzz` | Enable parameter fuzzing | `false` | - |
| `-path-wordlist` | Wordlist file for path discovery | - | `paths.txt` |
| `-discovery-depth` | Maximum depth for recursive discovery | `3` | `5` |
| `-follow-redirects` | Follow HTTP redirects during discovery | `true` | - |
| **Smart Evasion Options** |
| `-proxy` | Single proxy URL | - | `http://127.0.0.1:8080` |
| `-proxy-list` | File containing proxy list | - | `proxies.txt` |
| `-proxy-rotate` | Enable proxy rotation | `false` | - |
| `-ua` | User-Agent string | Mozilla/5.0... | Custom user agent |
| `-ua-list` | File containing User-Agent list | - | `user_agents.txt` |
| `-ua-rotate` | Enable User-Agent rotation | `false` | - |
| `-waf-detect` | Enable WAF detection and adaptive response | `false` | - |
| `-smart-throttle` | Enable smart throttling based on responses | `false` | - |
| `-header-rotate` | Enable additional header rotation | `false` | - |
| `-session-rotate` | Enable session rotation (cookies, etc.) | `false` | - |

## Examples

### 1. Basic API Key Testing
```bash
./coyotekey -u https://api.github.com/user -w github_tokens.txt -H "Authorization: token %KEY%"
```

### 2. Bearer Token Testing
```bash
./coyotekey -u https://api.example.com/profile -w tokens.txt -H "Authorization: Bearer %KEY%" -s "200,201"
```

### 3. Custom Header with Rate Limiting
```bash
./coyotekey -u https://api.service.com/data -w keys.txt -H "X-API-Key: %KEY%" -r 5 -t 15
```

### 4. Multi-Target Testing
```bash
./coyotekey -targets targets.txt -w keys.txt -t 10 -r 5 -o multi_results.json
```

### 5. Advanced Multi-Target with Retry Logic
```bash
./coyotekey -targets api_endpoints.txt -w tokens.txt -retries 5 -delay 200 -v
```

## Web Dashboard

CoyoteKey provides a comprehensive web dashboard for real-time monitoring, team collaboration, and visual analytics:

### 🌐 Core Dashboard Features (`-web`)
- **Real-time Monitoring**: Live attack progress and statistics
- **Team Collaboration**: Multi-user support with session management
- **Visual Analytics**: Interactive charts and graphs
- **RESTful API**: Complete API endpoints for external integrations
- **WebSocket Support**: Real-time updates and notifications
- **Authentication**: Secure login and session management
- **Responsive Design**: Mobile-friendly interface

### 🖥️ Dashboard Interface
The web dashboard provides a modern, intuitive interface accessible via web browser:

```bash
# Basic dashboard
./coyotekey -u https://api.com -w wordlist.txt -web -web-port 8080

# Access dashboard at: http://localhost:8080
```

### 🔐 Authentication & Security
- **Session Management**: Secure user sessions with configurable timeout
- **API Key Authentication**: Secure API access with custom keys
- **SSL/HTTPS Support**: Encrypted connections for production use
- **CORS Support**: Cross-origin resource sharing for web integrations
- **Security Headers**: Production-grade security headers

```bash
# Authenticated dashboard with SSL
./coyotekey -u https://api.com -w wordlist.txt -web -web-port 443 \
  -web-auth -web-user admin -web-password secure123 \
  -web-ssl -web-cert cert.pem -web-key key.pem
```

### 📊 Real-time Monitoring (`-real-time`)
- **Live Statistics**: Real-time attack progress and success rates
- **Target Status**: Individual target monitoring and health
- **Worker Activity**: Live worker status and performance
- **System Health**: CPU, memory, and database monitoring
- **Performance Metrics**: Response times and throughput analysis

### 👥 Team Collaboration (`-team-collab`)
- **Multi-user Support**: Multiple simultaneous users
- **Session Sharing**: Shared attack sessions and results
- **Activity Logging**: Comprehensive user activity tracking
- **Permission Management**: Role-based access control
- **Collaborative Monitoring**: Team-wide visibility

### 📈 Visual Analytics (`-visual-analytics`)
- **Interactive Charts**: Real-time graphs and visualizations
- **Success Rate Trends**: Historical success rate analysis
- **Response Time Charts**: Performance visualization
- **Target Comparison**: Side-by-side target analysis
- **Status Distribution**: HTTP status code breakdown
- **Time-based Analysis**: Hourly and daily patterns

### 🔔 Notifications System (`-notifications`)
- **Real-time Alerts**: Instant notifications for key events
- **Success Notifications**: Immediate alerts for found keys
- **System Alerts**: Performance and error notifications
- **Custom Thresholds**: Configurable alert conditions
- **Multi-channel Support**: Web, API, and WebSocket notifications

### 🌐 RESTful API (`-web-api`)
Complete API endpoints for external integrations:

```bash
# Enable API with custom key
./coyotekey -u https://api.com -w wordlist.txt -web -web-api \
  -api-key "your_secure_api_key_123"
```

#### API Endpoints:
- `GET /api/stats` - Real-time attack statistics
- `GET /api/sessions` - Active attack sessions
- `GET /api/targets` - Target information and statistics
- `GET /api/results` - Recent attack results
- `GET /api/analytics` - Comprehensive analytics data
- `GET /api/health` - System health status
- `GET /api/notifications` - User notifications
- `GET /api/alerts` - System alerts

#### API Authentication:
```bash
# Using API key
curl -H "X-API-Key: your_api_key" http://localhost:8080/api/stats

# Response format
{
  "success": true,
  "data": {
    "total_sessions": 150,
    "active_sessions": 5,
    "total_requests": 50000,
    "successful_requests": 1250,
    "success_rate": 0.025
  },
  "timestamp": "2025-07-09T10:00:00Z"
}
```

### 🔌 WebSocket Support (`-websocket`)
Real-time bidirectional communication:

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8080/ws');

// Subscribe to channels
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'stats'
}));

// Receive real-time updates
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Real-time update:', data);
};
```

#### WebSocket Channels:
- `stats` - Real-time statistics updates
- `notifications` - Live notifications
- `alerts` - System alerts
- `results` - Live attack results

### 🎛️ Dashboard Configuration
```bash
# Complete dashboard setup
./coyotekey -u https://api.com -w wordlist.txt \
  -web -web-port 8080 -web-host 0.0.0.0 \
  -web-auth -web-user admin -web-password secure123 \
  -real-time -team-collab -visual-analytics \
  -notifications -websocket -cors \
  -web-api -api-key "secure_api_key_123" \
  -db -persistent-storage -attack-analytics \
  -ml -success-prediction -adaptive-learning
```

## Dashboard Usage Examples

### Development Dashboard
```bash
# Simple development dashboard
./coyotekey -u https://api.com -w wordlist.txt -web -real-time -notifications
```

### Production Dashboard
```bash
# Secure production dashboard
./coyotekey -u https://api.com -w wordlist.txt \
  -web -web-port 443 -web-ssl -web-cert cert.pem -web-key key.pem \
  -web-auth -web-user admin -web-password production_pass \
  -real-time -team-collab -visual-analytics -notifications \
  -web-api -api-key "prod_api_key_secure" \
  -db -db-type postgres -db-host db.company.com \
  -persistent-storage -attack-analytics -historical-analysis
```

### Team Collaboration Dashboard
```bash
# Multi-user collaborative dashboard
./coyotekey -u https://api.com -w wordlist.txt \
  -web -web-auth -team-collab -visual-analytics \
  -real-time -notifications -websocket -cors \
  -db -persistent-storage -ml -adaptive-learning
```

### API Integration Dashboard
```bash
# Dashboard with external API integration
./coyotekey -u https://api.com -w wordlist.txt \
  -web -web-api -api-key "integration_key_123" \
  -cors -websocket -notifications \
  -db -attack-analytics -ml -behavior-analysis
```

## Database Integration

CoyoteKey provides comprehensive database integration for persistent storage, analytics, and historical analysis:

### 💾 Core Database Features (`-db`)
- **Multi-Database Support**: SQLite, PostgreSQL, and MySQL compatibility
- **Persistent Storage**: Store all attack results, sessions, and analytics
- **Attack Analytics**: Real-time analytics and comprehensive reporting
- **Historical Analysis**: Track trends and patterns over time
- **Session Management**: Complete attack session lifecycle tracking
- **Data Retention**: Configurable data retention policies

### 🗄️ Supported Database Types
- **SQLite** (`-db-type sqlite`): File-based database for development and single-user scenarios
- **PostgreSQL** (`-db-type postgres`): Enterprise-grade database for production environments
- **MySQL** (`-db-type mysql`): Popular database for web applications and analytics

### 📊 Database Schema
CoyoteKey automatically creates and manages the following tables:

```sql
-- Core Tables
attack_sessions     -- Attack session metadata and configuration
attack_targets      -- Target URLs and their statistics
attack_results      -- Individual request/response results
discovery_sessions  -- API discovery session data
discovered_endpoints -- Discovered API endpoints
authentication_results -- Authentication attempt results
ml_insights         -- Machine learning model insights and patterns
```

### 🔧 Database Configuration
```bash
# SQLite (Default - No server required)
./coyotekey -u https://api.com -w wordlist.txt -db -db-type sqlite

# PostgreSQL
./coyotekey -u https://api.com -w wordlist.txt -db -db-type postgres \
  -db-host localhost -db-port 5432 -db-name coyotekey \
  -db-user username -db-password password -db-ssl

# MySQL
./coyotekey -u https://api.com -w wordlist.txt -db -db-type mysql \
  -db-host localhost -db-port 3306 -db-name coyotekey \
  -db-user username -db-password password

# Database URL (Alternative configuration)
./coyotekey -u https://api.com -w wordlist.txt -db \
  -db-url "postgres://user:pass@localhost:5432/coyotekey?sslmode=require"
```

### 📈 Persistent Storage (`-persistent-storage`)
- **Attack Results**: Store every request/response with full metadata
- **Discovery Data**: Persist discovered endpoints and API structure
- **Authentication Results**: Archive authentication attempts and tokens
- **ML Insights**: Store machine learning patterns and predictions
- **Session Tracking**: Complete attack session lifecycle management

### 📊 Attack Analytics (`-attack-analytics`)
Real-time analytics and comprehensive reporting:

```json
{
  "total_sessions": 150,
  "total_targets": 500,
  "total_requests": 50000,
  "successful_attacks": 1250,
  "success_rate": 0.025,
  "avg_response_time": 450.5,
  "top_targets": [
    {
      "url": "https://api.example.com",
      "request_count": 1000,
      "success_count": 25,
      "success_rate": 0.025,
      "avg_response_time": 420.3
    }
  ],
  "status_distribution": [
    {"status_code": 200, "count": 1250, "percentage": 2.5},
    {"status_code": 401, "count": 35000, "percentage": 70.0},
    {"status_code": 403, "count": 10000, "percentage": 20.0}
  ],
  "time_distribution": [
    {"hour": 14, "request_count": 5000, "success_count": 125}
  ]
}
```

### 📈 Historical Analysis (`-historical-analysis`)
- **Trend Analysis**: Track success rates and patterns over time
- **Target Evolution**: Monitor how targets change and respond
- **Performance Metrics**: Historical response time and success rate trends
- **Pattern Recognition**: Identify recurring patterns and behaviors
- **Comparative Analysis**: Compare different attack sessions and strategies

### 🔄 Data Management
- **Data Retention** (`-data-retention N`): Automatic cleanup of old data (default: 30 days)
- **Auto Backup** (`-auto-backup`): Scheduled database backups
- **Backup Interval** (`-backup-interval N`): Backup frequency in hours (default: 24)
- **Query Optimization** (`-query-optimization`): Automatic query performance optimization
- **Database Indexing** (`-indexing`): Automatic index creation for performance
- **Query Caching** (`-cache`): Result caching for improved performance

### 🚀 Performance Optimization
- **Connection Pooling**: Efficient database connection management
- **Batch Operations**: Bulk insert operations for better performance
- **Indexing Strategy**: Optimized indexes for common query patterns
- **Query Optimization**: Automatic query performance tuning
- **Caching Layer**: Intelligent caching for frequently accessed data

## Database Usage Examples

### Basic Database Integration
```bash
# SQLite with persistent storage
./coyotekey -u https://api.com -w wordlist.txt -db -persistent-storage

# PostgreSQL with analytics
./coyotekey -u https://api.com -w wordlist.txt -db -db-type postgres \
  -db-host localhost -db-name coyotekey -persistent-storage -attack-analytics
```

### Advanced Database Configuration
```bash
# Complete database setup with optimization
./coyotekey -u https://api.com -w wordlist.txt -db -db-type postgres \
  -db-host db.example.com -db-port 5432 -db-name coyotekey_prod \
  -db-user coyotekey -db-password secure_pass -db-ssl \
  -persistent-storage -attack-analytics -historical-analysis \
  -auto-backup -backup-interval 12 -data-retention 90 \
  -cache -cache-size 256 -query-optimization -indexing
```

### Database + ML Integration
```bash
# Database with machine learning insights
./coyotekey -u https://api.com -w wordlist.txt -db -persistent-storage \
  -ml -success-prediction -adaptive-learning -pattern-recognition \
  -attack-analytics -o comprehensive_results.json
```

### Discovery + Database
```bash
# API discovery with database storage
./coyotekey -u https://api.com -api-discover -db -persistent-storage \
  -ml -behavior-analysis -anomaly-detection -attack-analytics
```

## Machine Learning Integration

CoyoteKey incorporates advanced machine learning capabilities for intelligent attack optimization:

### 🤖 Core ML Features (`-ml`)
- **Success Prediction**: Predict probability of key success before testing
- **Intelligent Sorting**: Reorder wordlists based on success probability
- **Pattern Recognition**: Analyze successful key patterns and characteristics
- **Adaptive Learning**: Learn from attack results to improve future predictions
- **Behavior Analysis**: Analyze target behavior and response patterns
- **Anomaly Detection**: Detect unusual responses and potential security measures

### 🧠 Machine Learning Models
- **Logistic Regression**: Primary classification model for success prediction
- **Feature Engineering**: 11 engineered features for comprehensive analysis
- **Real-time Learning**: Continuous model updates during attacks
- **Confidence Scoring**: Probability-based decision making with configurable thresholds

### 📊 Feature Engineering
CoyoteKey extracts and analyzes multiple features for ML predictions:

```
Key Characteristics:
- key_length: Length of the API key
- key_entropy: Shannon entropy of the key
- has_numbers: Presence of numeric characters
- has_special_chars: Presence of special characters
- has_uppercase: Presence of uppercase letters
- has_lowercase: Presence of lowercase letters

Response Characteristics:
- response_time: HTTP response time in milliseconds
- content_length: Response content length
- status_code: HTTP status code

Temporal Features:
- hour_of_day: Hour when request was made
- day_of_week: Day of week when request was made
```

### 🎯 Success Prediction (`-success-prediction`)
- Predicts success probability for each API key before testing
- Uses logistic regression with engineered features
- Configurable confidence thresholds
- Real-time prediction during attacks

### 🎲 Intelligent Sorting (`-intelligent-sorting`)
- Reorders wordlists based on ML predictions
- Prioritizes keys with higher success probability
- Reduces time to first successful key
- Optimizes attack efficiency

### 📈 Adaptive Learning (`-adaptive-learning`)
- Learns from successful and failed attempts
- Updates model weights in real-time
- Improves predictions as attack progresses
- Builds knowledge base for future attacks

### 🔍 Pattern Recognition (`-pattern-recognition`)
- Analyzes successful key patterns
- Identifies common characteristics of valid keys
- Tracks pattern frequency and success rates
- Generates pattern-based recommendations

### 🎭 Behavior Analysis (`-behavior-analysis`)
- Analyzes target API behavior patterns
- Tracks response time patterns
- Identifies rate limiting behaviors
- Detects authentication method preferences

### ⚠️ Anomaly Detection (`-anomaly-detection`)
- Detects unusual response times
- Identifies server errors and anomalies
- Flags potential security measures
- Provides anomaly severity scoring

## ML Configuration

### Model Configuration
```bash
# Basic ML features
./coyotekey -u https://api.com -w wordlist.txt -ml -success-prediction

# Advanced ML with custom parameters
./coyotekey -u https://api.com -w wordlist.txt -ml \
  -success-prediction -intelligent-sorting -adaptive-learning \
  -confidence-threshold 0.8 -learning-rate 0.05

# Load existing model and training data
./coyotekey -u https://api.com -w wordlist.txt -ml \
  -ml-model model.json -training-data training.json \
  -success-prediction -pattern-recognition
```

### Training Data Format (`training_data.json`)
```json
{
  "features": [
    [20, 4.5, 1, 1, 1, 1, 250, 1024, 200, 14, 2],
    [8, 2.1, 1, 0, 0, 1, 180, 512, 401, 14, 2]
  ],
  "labels": [1, 0],
  "metadata": [
    {
      "url": "https://api.example.com",
      "success": true,
      "key_pattern": "ULNS",
      "auth_method": "bearer"
    }
  ]
}
```

### ML Model Format (`ml_model.json`)
```json
{
  "type": "LogisticRegression",
  "version": "1.0",
  "accuracy": 0.85,
  "features": ["key_length", "key_entropy", "has_numbers", ...],
  "weights": [0.15, 0.25, 0.10, ...],
  "bias": -0.5,
  "feature_scaling": {
    "key_length": {"mean": 16.5, "std_dev": 8.2}
  }
}
```

### ML Insights Output
```json
{
  "model": {
    "type": "LogisticRegression",
    "accuracy": 0.85,
    "features": 11
  },
  "pattern_analysis": {
    "success_patterns": [
      {"pattern": "ULNS", "success_rate": 0.85, "frequency": 45}
    ],
    "key_patterns": [
      {"pattern": "ULNS", "length": 20, "success_rate": 0.90}
    ],
    "anomalies": [
      {"type": "slow_response", "severity": "medium", "confidence": 0.8}
    ]
  },
  "predictions": [
    {"probability": 0.85, "confidence": 0.7, "class": "success"}
  ]
}
```

## Advanced Authentication Methods

CoyoteKey supports multiple modern authentication methods for comprehensive API security testing:

### 🔐 HTTP Basic Authentication (`-basic-auth`)
- Traditional username:password authentication
- Base64 encoded credentials
- Support for username/password wordlists
- Automatic credential combination generation

### 🎫 JWT Token Support (`-jwt`)
- JSON Web Token parsing and analysis
- Token validation and expiry checking
- Header and payload extraction
- Support for various JWT algorithms

### 🔗 OAuth 2.0 Support (`-oauth`)
- OAuth 2.0 flow implementation
- Client credentials grant type
- Authorization code flow support
- Token refresh capabilities

### 🎯 Bearer Token Authentication (`-bearer`)
- Bearer token authentication
- API key and access token support
- Custom bearer token formats
- Token-based API access testing

### 🍪 Session-based Authentication
- **Session Tokens** (`-session-token`): X-Session-Token headers
- **Cookie Authentication** (`-cookie-auth`): Cookie-based sessions
- Session management and rotation
- Persistent session testing

### 🔧 Custom Authentication (`-custom-auth`)
- Custom header formats and authentication schemes
- Flexible authentication method definition
- Support for proprietary authentication systems
- Custom token and credential formats

### 🔄 Advanced Features
- **Token Refresh** (`-token-refresh`): Automatic token renewal
- **Authentication Chaining** (`-auth-chain`): Multiple auth method testing
- **Multi-Factor Support** (`-mfa`): MFA-aware authentication testing

## Authentication Configuration

### Credential File Format (`credentials.txt`)
```
# Username:Password format
admin:admin123
user:password
test:test123

# Key=Value format for complex credentials
username=admin,password=secret123,scope=read
client_id=app123,client_secret=secret456,grant_type=client_credentials

# Token formats
api_key=sk_test_1234567890abcdef
jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.token
bearer_token=ghp_1234567890abcdefghijklmnop

# OAuth credentials
client_id=oauth_app,client_secret=oauth_secret,scope=read write
access_token=access_123,refresh_token=refresh_456,expires_in=3600
```

### Username/Password Lists
```bash
# Separate username and password files
./coyotekey -u https://api.com -basic-auth \
  -username-list usernames.txt \
  -password-list passwords.txt
```

### Authentication Output Format
```json
{
  "method": {
    "type": "Basic",
    "name": "HTTP Basic Authentication"
  },
  "credential": {
    "username": "admin",
    "password": "secret123"
  },
  "success": true,
  "token": "access_token_here",
  "refresh_token": "refresh_token_here",
  "expires_in": 3600,
  "token_type": "Bearer",
  "response": {
    "status_code": 200,
    "response_time_ms": 245,
    "headers": {
      "Authorization": "Bearer access_token_here"
    }
  }
}
```

## API Discovery & Enumeration

CoyoteKey includes powerful API discovery capabilities to automatically find and analyze API endpoints:

### 🔍 API Discovery (`-api-discover`)
- Automatically discovers API endpoints using common paths
- Tests 70+ built-in common API paths
- Supports custom path wordlists
- Identifies accessible endpoints and their characteristics

### 📂 Endpoint Enumeration (`-endpoint-enum`)
- Tests multiple HTTP methods on discovered endpoints
- Enumerates GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
- Identifies method-specific behaviors and responses
- Maps complete endpoint functionality

### 📋 Schema Analysis (`-schema-analysis`)
- Detects OpenAPI/Swagger documentation
- Analyzes API structure and patterns
- Identifies authentication methods
- Extracts API metadata and specifications

### 🔢 Version Detection (`-version-detect`)
- Automatically detects API versions
- Tests common version endpoints (/version, /v1, /v2, etc.)
- Extracts version information from responses
- Maps version-specific endpoints

### 🎯 Parameter Fuzzing (`-param-fuzz`)
- Identifies common parameters in responses
- Extracts parameter names from JSON responses
- Maps parameter usage across endpoints
- Supports parameter-based discovery

### 📂 Custom Path Discovery (`-path-wordlist`)
- Load custom wordlists for path discovery
- Support for large wordlists (1000+ paths)
- Intelligent path construction and testing
- Recursive discovery capabilities

## API Discovery Configuration

### Path Wordlist Format (`paths.txt`)
```
# API endpoints
api
api/v1
api/v2
rest
graphql

# Authentication
auth
login
oauth
token

# Resources
users
admin
config
docs
```

### Discovery Output Format
```json
{
  "target": "https://api.example.com",
  "endpoints": [
    {
      "url": "https://api.example.com/api/v1/users",
      "method": "GET",
      "status_code": 200,
      "content_type": "application/json",
      "response_time_ms": 245,
      "auth_required": false,
      "framework": "Express.js",
      "api_version": "v1",
      "parameters": ["id", "name", "email"]
    }
  ],
  "schema": {
    "base_url": "https://api.example.com",
    "version": "v1",
    "authentication_methods": ["API Key", "OAuth"],
    "documentation": "https://api.example.com/docs"
  },
  "statistics": {
    "endpoints_found": 25,
    "auth_endpoints": 15,
    "public_endpoints": 10,
    "discovery_time": "45.2s"
  }
}
```

### Combined Discovery + Brute Force
When both `-api-discover` and `-w wordlist.txt` are specified:
1. **Discovery Phase**: Finds all available endpoints
2. **Analysis Phase**: Identifies endpoints requiring authentication
3. **Brute Force Phase**: Tests API keys on auth-required endpoints
4. **Reporting**: Combined results with discovery and brute force data

## Smart Evasion Features

CoyoteKey includes advanced evasion techniques to bypass WAFs, rate limiting, and detection systems:

### 🛡️ WAF Detection (`-waf-detect`)
- Automatically detects Web Application Firewalls
- Recognizes common blocking patterns and status codes
- Adapts behavior based on WAF responses
- Supports CloudFlare, Nginx, and other common WAFs

### 🧠 Smart Throttling (`-smart-throttle`)
- Dynamically adjusts request rate based on responses
- Learns from rate limiting responses
- Implements exponential backoff with jitter
- Respects `Retry-After` headers automatically

### 🔄 User-Agent Rotation (`-ua-rotate`)
- Rotates through realistic browser User-Agents
- Supports custom User-Agent lists (`-ua-list`)
- Includes mobile and API client User-Agents
- Simulates different browsers and platforms

### 🌐 Proxy Rotation (`-proxy-rotate`)
- Rotates through multiple proxy servers
- Supports HTTP, HTTPS, and SOCKS proxies
- Load balances requests across proxies
- Automatic failover on proxy errors

### 📋 Header Rotation (`-header-rotate`)
- Randomizes HTTP headers for each request
- Varies Accept, Accept-Language, Accept-Encoding
- Simulates different client configurations
- Reduces request fingerprinting

### 🎭 Session Rotation (`-session-rotate`)
- Generates random session identifiers
- Adds realistic session headers
- Simulates different user sessions
- Reduces correlation between requests

### 🎲 Random Delays (`-random-delay`)
- Adds human-like timing variations
- Randomizes delays between 50-150% of base delay
- Prevents predictable request patterns
- Simulates natural user behavior

## Smart Evasion Configuration Files

### User-Agent List Format (`user_agents.txt`)
```
# Desktop browsers
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/91.0.4472.124

# Mobile browsers  
Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1

# API clients
curl/7.68.0
Postman/7.36.1
```

### Proxy List Format (`proxies.txt`)
```
# HTTP proxies
http://proxy1.example.com:8080
http://127.0.0.1:3128

# SOCKS proxies
socks5://127.0.0.1:1080
socks5://proxy.example.com:1080
```

## Multi-Target Configuration

Create a targets file with one URL per line. You can specify different methods and headers for each target:

### Basic Format
```
https://api.github.com/user
https://api.example.com/profile
https://httpbin.org/headers
```

### Advanced Format with Methods and Headers
```
# GitHub API
https://api.github.com/user GET Authorization: token %KEY%
https://api.github.com/user/repos GET Authorization: token %KEY%

# Custom API with different methods
https://api.example.com/users GET Authorization: Bearer %KEY%
https://api.example.com/profile POST X-API-Key: %KEY%

# Different header formats
https://custom-api.com/data GET Custom-Auth: %KEY%
```

### Format Specification
```
URL [METHOD] [HEADER_FORMAT]
```
- `URL`: Required - The target endpoint
- `METHOD`: Optional - HTTP method (defaults to global `-m` setting)
- `HEADER_FORMAT`: Optional - Custom header format (defaults to global `-H` setting)

## Wordlist Format

Create a text file with one API key per line:

```
sk-1234567890abcdef
api_key_example_123
bearer_token_xyz789
# Comments are ignored
another_api_key_456
```

## Output Format

### Console Output
```
🎯 Target: https://api.example.com/endpoint
📝 Wordlist: keys.txt (100 keys)
🔑 Header: Authorization: Bearer %KEY%
📡 Method: GET
✅ Success Codes: [200 201]
🧵 Threads: 10
🚀 Starting brute-force attack...

🎉 [FOUND] Worker 3: Key: sk-abc123 -> Status: 200 (245ms)
🎉 [FOUND] Worker 7: Key: api_xyz789 -> Status: 201 (189ms)

==================================================
📊 RESULTS SUMMARY
==================================================
✅ Found 2 valid API key(s):

1. 🔑 Key: sk-abc123
   📊 Status: 200
   🌐 URL: https://api.example.com/endpoint
   ⏱️  Response Time: 245ms
   📏 Content Length: 1024 bytes
   🕐 Timestamp: 2024-01-15 14:30:25
```

### JSON Output (with -o flag)
```json
[
  {
    "key": "sk-abc123",
    "status_code": 200,
    "url": "https://api.example.com/endpoint",
    "response_time_ms": 245,
    "content_length": 1024,
    "timestamp": "2024-01-15T14:30:25Z"
  }
]
```

## Performance Tips

1. **Adjust Thread Count**: Start with 10-20 threads, increase based on target capacity
2. **Use Rate Limiting**: Prevent getting blocked by rate limiting (-r flag)
3. **Monitor Response Times**: High response times may indicate rate limiting
4. **Use Proxy Rotation**: Rotate proxies to avoid IP-based blocking
5. **Realistic Headers**: Use realistic User-Agent strings

## Security Considerations

⚠️ **Important**: This tool is for authorized security testing only. Always ensure you have proper authorization before testing any API endpoints.

- Only test APIs you own or have explicit permission to test
- Respect rate limits and terms of service
- Use responsibly and ethically
- Consider the impact on target systems

## Troubleshooting

### Common Issues

1. **Connection Timeouts**: Increase timeout value with `-timeout`
2. **Rate Limiting**: Reduce thread count or add rate limiting
3. **Proxy Issues**: Verify proxy URL format and connectivity
4. **SSL Errors**: Tool automatically skips SSL verification for testing

### Debug Mode

Use `-v` flag for verbose output to see detailed request/response information.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this tool.
