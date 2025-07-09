# Changelog

All notable changes to CoyoteKey will be documented in this file.

## [2.7.0] - 2025-07-09

### 🌐 Web Dashboard - Real-time Monitoring & Team Collaboration

#### ✨ New Web Dashboard Features
- **Real-time Web Interface** (`-web`): Modern web dashboard for monitoring and control
- **Team Collaboration** (`-team-collab`): Multi-user support with session management
- **Visual Analytics** (`-visual-analytics`): Interactive charts and real-time visualizations
- **RESTful API** (`-web-api`): Complete API endpoints for external integrations
- **WebSocket Support** (`-websocket`): Real-time bidirectional communication
- **Authentication System** (`-web-auth`): Secure login and session management
- **Notifications** (`-notifications`): Real-time alerts and event notifications
- **SSL/HTTPS Support** (`-web-ssl`): Encrypted connections for production use
- **CORS Support** (`-cors`): Cross-origin resource sharing for web integrations

#### 🖥️ Dashboard Architecture
```go
type WebDashboard struct {
    Server          *http.Server          `json:"-"`
    Config          *DashboardConfig      `json:"config"`
    IsRunning       bool                  `json:"is_running"`
    StartTime       time.Time             `json:"start_time"`
    Connections     int                   `json:"connections"`
    ActiveSessions  map[string]*Session   `json:"active_sessions"`
    WebSocketConns  map[string]*WebSocket `json:"-"`
    Notifications   []Notification        `json:"notifications"`
    Alerts          []Alert               `json:"alerts"`
}

type DashboardManager struct {
    Dashboard    *WebDashboard     `json:"dashboard"`
    Database     *DatabaseManager  `json:"-"`
    MLEngine     *MLEngine         `json:"-"`
    Config       *Config           `json:"-"`
    IsRunning    bool              `json:"is_running"`
    StartTime    time.Time         `json:"start_time"`
    Stats        *DashboardStats   `json:"stats"`
}
```

#### 🚀 New Command Line Options
```bash
# Core Dashboard Features
-web                     # Enable web dashboard
-web-port int            # Web dashboard port (default: 8080)
-web-host string         # Web dashboard host (default: localhost)
-web-auth                # Enable web dashboard authentication
-web-user string         # Web dashboard username (default: admin)
-web-password string     # Web dashboard password
-web-ssl                 # Enable SSL for web dashboard
-web-cert string         # SSL certificate file for web dashboard
-web-key string          # SSL private key file for web dashboard

# Advanced Features
-real-time               # Enable real-time monitoring
-team-collab             # Enable team collaboration features
-visual-analytics        # Enable visual analytics
-web-api                 # Enable web API endpoints
-api-key string          # API key for web API access
-cors                    # Enable CORS for web dashboard
-websocket               # Enable WebSocket for real-time updates
-notifications           # Enable notifications system
```

#### 🎯 Usage Examples
```bash
# Basic web dashboard
./coyotekey -u https://api.com -w wordlist.txt -web -real-time -notifications

# Authenticated dashboard with SSL
./coyotekey -u https://api.com -w wordlist.txt -web -web-port 443 \
  -web-auth -web-user admin -web-password secure123 \
  -web-ssl -web-cert cert.pem -web-key key.pem

# Team collaboration dashboard
./coyotekey -u https://api.com -w wordlist.txt -web -web-auth \
  -team-collab -visual-analytics -real-time -notifications \
  -websocket -cors -db -persistent-storage

# Complete dashboard with all features
./coyotekey -u https://api.com -w wordlist.txt \
  -web -web-auth -web-user admin -web-password secure123 \
  -real-time -team-collab -visual-analytics -notifications \
  -websocket -cors -web-api -api-key "secure_api_key_123" \
  -db -persistent-storage -attack-analytics \
  -ml -success-prediction -adaptive-learning
```

#### 🌐 RESTful API Endpoints
Complete API for external integrations:

```bash
# API Endpoints
GET /api/stats          # Real-time attack statistics
GET /api/sessions       # Active attack sessions
GET /api/targets        # Target information and statistics
GET /api/results        # Recent attack results
GET /api/analytics      # Comprehensive analytics data
GET /api/health         # System health status
GET /api/notifications  # User notifications
GET /api/alerts         # System alerts

# Authentication
curl -H "X-API-Key: your_api_key" http://localhost:8080/api/stats
```

#### 📊 Dashboard Interface Features
- **Modern Responsive Design**: Mobile-friendly interface with Bootstrap-style components
- **Real-time Statistics**: Live attack progress, success rates, and performance metrics
- **Interactive Charts**: Dynamic graphs for success rates, response times, and target analysis
- **Live Activity Feed**: Real-time stream of attack events and discoveries
- **Target Management**: Individual target monitoring and health status
- **Worker Status**: Live worker activity and performance monitoring
- **System Health**: CPU, memory, database, and network monitoring

#### 👥 Team Collaboration Features
```go
type Session struct {
    ID              string                 `json:"id"`
    UserID          string                 `json:"user_id"`
    StartTime       time.Time              `json:"start_time"`
    LastActivity    time.Time              `json:"last_activity"`
    IPAddress       string                 `json:"ip_address"`
    UserAgent       string                 `json:"user_agent"`
    AttackSessions  []string               `json:"attack_sessions"`
    Permissions     []string               `json:"permissions"`
    IsActive        bool                   `json:"is_active"`
}
```

- **Multi-user Support**: Simultaneous users with individual sessions
- **Session Management**: Secure session handling with configurable timeout
- **Activity Logging**: Comprehensive user activity tracking
- **Permission Management**: Role-based access control
- **Collaborative Monitoring**: Shared attack sessions and results

#### 🔔 Notifications & Alerts System
```go
type Notification struct {
    ID        string                 `json:"id"`
    Type      string                 `json:"type"`
    Title     string                 `json:"title"`
    Message   string                 `json:"message"`
    Level     string                 `json:"level"` // info, warning, error, success
    Data      map[string]interface{} `json:"data"`
    Read      bool                   `json:"read"`
    UserID    string                 `json:"user_id"`
    Timestamp time.Time              `json:"timestamp"`
}

type Alert struct {
    ID          string                 `json:"id"`
    Type        string                 `json:"type"`
    Condition   string                 `json:"condition"`
    Threshold   float64                `json:"threshold"`
    CurrentValue float64               `json:"current_value"`
    Triggered   bool                   `json:"triggered"`
    Message     string                 `json:"message"`
    Severity    string                 `json:"severity"`
}
```

#### 🔌 WebSocket Real-time Communication
```javascript
// WebSocket connection
const ws = new WebSocket('ws://localhost:8080/ws');

// Subscribe to channels
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'stats'
}));

// Receive real-time updates
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  updateDashboard(data);
};
```

#### WebSocket Channels:
- `stats` - Real-time statistics updates (every 5 seconds)
- `notifications` - Live notifications (immediate)
- `alerts` - System alerts (immediate)
- `results` - Live attack results (immediate)

#### 📁 New Configuration Files
- `dashboard_config.example.json` - Dashboard configuration examples and best practices
- `demo_web_dashboard.sh` - Comprehensive web dashboard demonstration script

#### 🔐 Security Features
- **Authentication**: Secure login with username/password
- **Session Management**: Secure session handling with CSRF protection
- **API Key Authentication**: Secure API access with custom keys
- **SSL/HTTPS Support**: Full SSL encryption for production use
- **Security Headers**: Production-grade security headers
- **CORS Configuration**: Configurable cross-origin resource sharing

#### 📊 Enhanced Dashboard HTML Interface
```html
<!DOCTYPE html>
<html>
<head>
    <title>CoyoteKey Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <div class="header">
        <h1>🔐 CoyoteKey Dashboard</h1>
        <p>Real-time API Security Testing Monitor</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value" id="total-sessions">0</div>
            <div class="stat-label">Total Sessions</div>
        </div>
        <!-- More stat cards -->
    </div>
    
    <div class="section">
        <h2>System Status</h2>
        <p>Dashboard Status: <span class="status-running">🟢 Running</span></p>
        <!-- System status information -->
    </div>
    
    <script>
        // Auto-refresh every 5 seconds
        setInterval(refreshStats, 5000);
        
        // WebSocket connection for real-time updates
        const ws = new WebSocket('ws://localhost:8080/ws');
    </script>
</body>
</html>
```

#### 🛡️ Integration with Existing Features
- **Database Integration**: Dashboard displays database statistics and health
- **ML Integration**: Visual ML insights, predictions, and model performance
- **API Discovery**: Real-time discovery progress and results visualization
- **Authentication**: Live authentication attempt monitoring
- **Smart Evasion**: WAF detection and evasion technique effectiveness
- **Multi-Target Support**: Target-specific dashboards and comparison

#### 📈 Performance & Scalability
- **Efficient WebSocket Management**: Optimized real-time communication
- **Concurrent User Support**: Handle multiple simultaneous users
- **Resource Optimization**: Minimal resource overhead for dashboard
- **Caching Strategy**: Intelligent caching for improved performance
- **Responsive Design**: Optimized for various screen sizes and devices

#### 🎯 Dashboard-Enhanced Workers
```go
func dashboardEnhancedWorker(id int, config *Config, jobs <-chan Job, 
    results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, 
    limiter *rate.Limiter, wafDetector *WAFDetector, 
    throttleController *ThrottleController, rotationManager *RotationManager, 
    mlEngine *MLEngine, dbManager *DatabaseManager, 
    dashboardManager *DashboardManager, sessionID string) {
    // Enhanced worker with dashboard notifications
    // Real-time progress updates to dashboard
    // Live notifications for key discoveries
    // Integration with all existing features
}
```

## [2.6.0] - 2025-07-09

### 💾 Database Integration - Persistent Storage & Analytics

#### ✨ New Database Features
- **Multi-Database Support**: SQLite, PostgreSQL, and MySQL compatibility
- **Persistent Storage** (`-persistent-storage`): Store all attack results, sessions, and analytics
- **Attack Analytics** (`-attack-analytics`): Real-time analytics and comprehensive reporting
- **Historical Analysis** (`-historical-analysis`): Track trends and patterns over time
- **Session Management**: Complete attack session lifecycle tracking
- **Data Retention** (`-data-retention`): Configurable data retention policies with automatic cleanup
- **Auto Backup** (`-auto-backup`): Scheduled database backups with configurable intervals
- **Query Optimization** (`-query-optimization`): Automatic query performance optimization
- **Database Indexing** (`-indexing`): Automatic index creation for optimal performance
- **Query Caching** (`-cache`): Intelligent result caching for improved performance

#### 🗄️ Database Architecture
```go
type DatabaseManager struct {
    Config      *DatabaseConfig `json:"config"`
    Connection  interface{}     `json:"-"`
    IsConnected bool           `json:"is_connected"`
    LastBackup  *time.Time     `json:"last_backup,omitempty"`
    Stats       DatabaseStats  `json:"stats"`
}

type AttackSession struct {
    ID            string                 `json:"id"`
    StartTime     time.Time              `json:"start_time"`
    EndTime       *time.Time             `json:"end_time,omitempty"`
    Status        string                 `json:"status"`
    TargetCount   int                    `json:"target_count"`
    KeyCount      int                    `json:"key_count"`
    SuccessCount  int                    `json:"success_count"`
    TotalRequests int                    `json:"total_requests"`
    Duration      *time.Duration         `json:"duration,omitempty"`
    Config        map[string]interface{} `json:"config"`
}
```

#### 📊 Comprehensive Database Schema
- **attack_sessions**: Attack session metadata and configuration
- **attack_targets**: Target URLs and their statistics
- **attack_results**: Individual request/response results with ML predictions
- **discovery_sessions**: API discovery session data
- **discovered_endpoints**: Discovered API endpoints with full metadata
- **authentication_results**: Authentication attempt results and tokens
- **ml_insights**: Machine learning model insights and patterns

#### 🚀 New Command Line Options
```bash
# Core Database Features
-db                      # Enable database integration
-db-type string          # Database type (sqlite, postgres, mysql)
-db-url string           # Database connection URL
-db-host string          # Database host (default: localhost)
-db-port int             # Database port (default: 5432)
-db-name string          # Database name (default: coyotekey)
-db-user string          # Database username
-db-password string      # Database password
-db-ssl                  # Enable SSL for database connection

# Storage & Analytics
-persistent-storage      # Enable persistent storage of results
-historical-analysis     # Enable historical data analysis
-attack-analytics        # Enable attack analytics and reporting
-data-retention int      # Data retention period in days (default: 30)

# Backup & Optimization
-auto-backup             # Enable automatic database backup
-backup-interval int     # Backup interval in hours (default: 24)
-query-optimization      # Enable query optimization (default: true)
-indexing               # Enable database indexing (default: true)
-cache                  # Enable query result caching
-cache-size int         # Cache size in MB (default: 100)
```

#### 🎯 Usage Examples
```bash
# Basic SQLite database
./coyotekey -u https://api.com -w wordlist.txt -db -persistent-storage

# PostgreSQL with analytics
./coyotekey -u https://api.com -w wordlist.txt -db -db-type postgres \
  -db-host localhost -db-name coyotekey -persistent-storage -attack-analytics

# Complete database setup
./coyotekey -u https://api.com -w wordlist.txt -db -db-type postgres \
  -db-host db.example.com -db-name coyotekey_prod -db-ssl \
  -persistent-storage -attack-analytics -historical-analysis \
  -auto-backup -backup-interval 12 -data-retention 90 \
  -cache -cache-size 256 -query-optimization

# Database + ML + Authentication
./coyotekey -u https://api.com -api-discover -basic-auth -jwt \
  -auth-wordlist credentials.txt -db -persistent-storage \
  -ml -success-prediction -attack-analytics -o complete_results.json
```

#### 📊 Enhanced Analytics Output
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
    {"status_code": 401, "count": 35000, "percentage": 70.0}
  ],
  "time_distribution": [
    {"hour": 14, "request_count": 5000, "success_count": 125}
  ],
  "recent_activity": [
    {"date": "2025-07-09", "session_count": 5, "request_count": 2500}
  ]
}
```

#### 📁 New Configuration Files
- `database_schema.sql` - Complete database schema for all supported databases
- `database_config.example.json` - Database configuration examples and best practices
- `demo_database_integration.sh` - Comprehensive database demonstration script

#### 🔧 Database Performance Features
- **Connection Pooling**: Efficient database connection management
- **Batch Operations**: Bulk insert operations for better performance
- **Indexing Strategy**: Optimized indexes for common query patterns
- **Query Optimization**: Automatic query performance tuning
- **Caching Layer**: Intelligent caching for frequently accessed data
- **Backup Management**: Automated backup with configurable retention

#### 🛡️ Integration with Existing Features
- **ML Integration**: Store ML insights, predictions, and model performance
- **API Discovery**: Persist discovered endpoints and API structure
- **Authentication**: Archive authentication results and token management
- **Smart Evasion**: Track evasion effectiveness and WAF responses
- **Multi-Target Support**: Session management across multiple targets

#### 📈 Advanced Analytics Capabilities
- **Success Rate Trends**: Track success rates over time
- **Target Performance**: Analyze individual target characteristics
- **Method Effectiveness**: Compare different attack methods
- **Time-based Analysis**: Identify optimal attack timing
- **Pattern Recognition**: Historical pattern analysis
- **Anomaly Detection**: Identify unusual behaviors and responses

#### 🔄 Data Management Features
- **Automatic Cleanup**: Configurable data retention with automatic purging
- **Backup Scheduling**: Automated backups with customizable intervals
- **Data Export**: Export analytics and results in multiple formats
- **Historical Queries**: Advanced querying capabilities for historical data
- **Performance Monitoring**: Database performance metrics and optimization

#### 💾 Database-Enhanced Workers
```go
func databaseEnhancedWorker(id int, config *Config, jobs <-chan Job, 
    results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, 
    limiter *rate.Limiter, wafDetector *WAFDetector, 
    throttleController *ThrottleController, rotationManager *RotationManager, 
    mlEngine *MLEngine, dbManager *DatabaseManager, sessionID string) {
    // Enhanced worker with database integration
    // Stores every request/response with full metadata
    // Integrates ML predictions with database storage
    // Provides real-time analytics updates
}
```

#### 🎯 Session Management
- **Attack Sessions**: Complete lifecycle tracking from start to finish
- **Target Management**: Individual target tracking and statistics
- **Result Correlation**: Link results to sessions and targets
- **Configuration Storage**: Store attack configuration for reproducibility
- **Status Tracking**: Real-time session status updates

## [2.5.0] - 2025-07-09

### 🤖 Machine Learning Integration - AI-Powered Attack Optimization

#### ✨ New Machine Learning Features
- **Success Prediction** (`-success-prediction`): AI-powered probability prediction for API key success
- **Intelligent Sorting** (`-intelligent-sorting`): ML-based wordlist optimization and reordering
- **Pattern Recognition** (`-pattern-recognition`): Advanced pattern analysis and key characteristic recognition
- **Adaptive Learning** (`-adaptive-learning`): Real-time learning from attack results and continuous improvement
- **Behavior Analysis** (`-behavior-analysis`): Target API behavior analysis and response pattern recognition
- **Anomaly Detection** (`-anomaly-detection`): Intelligent detection of unusual responses and security measures
- **Predictive Analysis** (`-predictive-analysis`): Advanced predictive modeling for attack optimization
- **Model Training** (`-model-training`): Custom model training capabilities

#### 🧠 Advanced ML Engine
```go
type MLEngine struct {
    Model           *MLModel        `json:"model"`
    TrainingData    *TrainingData   `json:"training_data"`
    PatternAnalysis *PatternAnalysis `json:"pattern_analysis"`
    Predictions     []Prediction    `json:"predictions"`
    IsTraining      bool            `json:"is_training"`
    LastUpdate      time.Time       `json:"last_update"`
}

type MLModel struct {
    Type           string                 `json:"type"`
    Version        string                 `json:"version"`
    Accuracy       float64                `json:"accuracy"`
    Features       []string               `json:"features"`
    Weights        []float64              `json:"weights"`
    Bias           float64                `json:"bias"`
    FeatureScaling map[string]ScalingInfo `json:"feature_scaling"`
}
```

#### 📊 Feature Engineering (11 Features)
- **Key Characteristics**: length, entropy, character types (numbers, special, upper, lower)
- **Response Characteristics**: response time, content length, status code
- **Temporal Features**: hour of day, day of week
- **Advanced Analysis**: pattern recognition, success probability calculation

#### 🎯 Success Prediction System
- **Logistic Regression Model**: Primary classification algorithm for success prediction
- **Real-time Predictions**: Live probability calculation during attacks
- **Confidence Scoring**: Configurable confidence thresholds for decision making
- **Feature Scaling**: Normalized feature values for optimal model performance
- **Probability-based Sorting**: Intelligent wordlist reordering based on success probability

#### 🎲 Intelligent Sorting Algorithm
```go
func (engine *MLEngine) intelligentSort(keys []string, targets []Target) []string {
    // Calculate success probability for each key
    // Sort by probability (highest first)
    // Return optimized wordlist
}
```

#### 📈 Adaptive Learning System
- **Real-time Model Updates**: Continuous learning from attack results
- **Pattern Recognition**: Identification of successful key patterns
- **Behavioral Analysis**: Target-specific behavior learning
- **Knowledge Accumulation**: Building attack knowledge base over time
- **Performance Optimization**: Improving predictions with each attack

#### 🔍 Pattern Analysis Engine
```go
type PatternAnalysis struct {
    SuccessPatterns  []Pattern         `json:"success_patterns"`
    FailurePatterns  []Pattern         `json:"failure_patterns"`
    KeyPatterns      []KeyPattern      `json:"key_patterns"`
    TimePatterns     []TimePattern     `json:"time_patterns"`
    ResponsePatterns []ResponsePattern `json:"response_patterns"`
    Anomalies        []Anomaly         `json:"anomalies"`
}
```

#### ⚠️ Anomaly Detection System
- **Response Time Anomalies**: Detection of unusually slow responses
- **Status Code Anomalies**: Identification of unusual HTTP status codes
- **Content Length Anomalies**: Detection of unexpected response sizes
- **Behavioral Anomalies**: Identification of unusual API behavior patterns
- **Security Measure Detection**: Recognition of potential security countermeasures

#### 🚀 New Command Line Options
```bash
# Core ML Features
-ml                      # Enable machine learning features
-success-prediction      # Enable success probability prediction
-intelligent-sorting     # Enable intelligent wordlist sorting
-pattern-recognition     # Enable pattern recognition and analysis
-adaptive-learning       # Enable adaptive learning from results
-behavior-analysis       # Enable target behavior analysis
-anomaly-detection       # Enable anomaly detection

# Model Configuration
-ml-model file           # Path to ML model file
-training-data file      # Path to training data file
-confidence-threshold N  # Confidence threshold for predictions (default: 0.7)
-learning-rate N         # Learning rate for model training (default: 0.01)
-max-iterations N        # Maximum iterations for training (default: 1000)

# Advanced Features
-model-training          # Enable model training mode
-predictive-analysis     # Enable predictive analysis
```

#### 🎯 Usage Examples
```bash
# Basic ML-enhanced attack
./coyotekey -u https://api.com -w wordlist.txt -ml -success-prediction

# Advanced ML with intelligent sorting
./coyotekey -u https://api.com -w wordlist.txt -ml \
  -success-prediction -intelligent-sorting -adaptive-learning

# ML with custom model and training data
./coyotekey -u https://api.com -w wordlist.txt -ml \
  -ml-model model.json -training-data training.json \
  -success-prediction -confidence-threshold 0.8

# Complete ML pipeline with discovery
./coyotekey -u https://api.com -api-discover -ml \
  -behavior-analysis -anomaly-detection -pattern-recognition \
  -o ml_results.json

# ML-enhanced authentication testing
./coyotekey -u https://api.com -basic-auth -jwt -bearer \
  -auth-wordlist credentials.txt -ml -adaptive-learning \
  -success-prediction -intelligent-sorting
```

#### 📁 New Configuration Files
- `ml_model.example.json` - Example ML model with trained weights and parameters
- `training_data.example.json` - Example training data with features and labels
- `demo_machine_learning.sh` - Comprehensive ML demonstration script

#### 📊 Enhanced ML Output Format
```json
{
  "model": {
    "type": "LogisticRegression",
    "version": "1.0",
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
    "time_patterns": [
      {"hour": 14, "day_of_week": 2, "success_rate": 0.75}
    ],
    "anomalies": [
      {"type": "slow_response", "severity": "medium", "confidence": 0.8}
    ]
  },
  "predictions": [
    {
      "probability": 0.85,
      "confidence": 0.7,
      "class": "success",
      "explanation": "High probability based on key characteristics",
      "recommendations": ["Key characteristics look good for testing"]
    }
  ]
}
```

#### 🔧 Technical Implementation
- **Logistic Regression**: Primary ML algorithm for binary classification
- **Feature Extraction**: Automated feature engineering from request/response data
- **Real-time Learning**: Online learning capabilities with incremental updates
- **Pattern Matching**: Advanced pattern recognition algorithms
- **Statistical Analysis**: Comprehensive statistical analysis of attack results
- **Performance Optimization**: Efficient ML algorithms optimized for real-time use

#### 🛡️ Integration with Existing Features
- **Smart Evasion**: ML-enhanced evasion technique selection
- **API Discovery**: Behavior analysis during endpoint discovery
- **Authentication Testing**: ML-optimized credential testing
- **Multi-Target Support**: ML analysis across multiple targets
- **Rate Limiting**: ML-aware rate limiting and throttling

#### 📈 Performance Benefits
- **Reduced Time to Success**: Intelligent sorting reduces time to first valid key
- **Improved Success Rates**: Pattern recognition improves overall attack success
- **Adaptive Optimization**: Continuous learning improves performance over time
- **Anomaly Awareness**: Early detection of security measures and countermeasures
- **Resource Efficiency**: Optimized resource usage through intelligent prioritization

#### 🧪 ML Model Training
- **Training Data Format**: Structured JSON format for features and labels
- **Feature Engineering**: Automated feature extraction and scaling
- **Model Persistence**: Save and load trained models
- **Cross-validation**: Model validation and accuracy assessment
- **Hyperparameter Tuning**: Configurable learning parameters

## [2.4.0] - 2025-07-09

### 🔐 Advanced Authentication Methods - Modern Auth Support

#### ✨ New Authentication Features
- **HTTP Basic Authentication** (`-basic-auth`): Traditional username:password authentication
- **JWT Token Support** (`-jwt`): JSON Web Token parsing, validation, and analysis
- **OAuth 2.0 Support** (`-oauth`): OAuth 2.0 flow implementation with token management
- **Bearer Token Authentication** (`-bearer`): Bearer token and API key authentication
- **Session Token Support** (`-session-token`): Session-based authentication
- **Cookie Authentication** (`-cookie-auth`): Cookie-based session management
- **Custom Authentication** (`-custom-auth`): Flexible custom authentication methods
- **Multi-Factor Support** (`-mfa`): MFA-aware authentication testing

#### 🔑 Advanced Credential Management
- **Flexible Credential Formats**: Support for multiple credential file formats
- **Username/Password Lists**: Separate wordlists with automatic combination generation
- **Token Extraction**: Automatic token extraction from authentication responses
- **Credential Parsing**: Smart parsing of complex credential formats
- **Authentication Chaining** (`-auth-chain`): Sequential authentication method testing
- **Token Refresh** (`-token-refresh`): Automatic token renewal capabilities

#### 🎫 JWT Token Analysis
```go
type JWTToken struct {
    Header    map[string]interface{} `json:"header"`
    Payload   map[string]interface{} `json:"payload"`
    Signature string                 `json:"signature"`
    Valid     bool                   `json:"valid"`
    ExpiresAt time.Time              `json:"expires_at"`
    IssuedAt  time.Time              `json:"issued_at"`
    Issuer    string                 `json:"issuer"`
    Subject   string                 `json:"subject"`
    Audience  []string               `json:"audience"`
}
```

#### 🔗 OAuth 2.0 Flow Support
```go
type OAuthFlow struct {
    AuthURL      string   `json:"auth_url"`
    TokenURL     string   `json:"token_url"`
    RefreshURL   string   `json:"refresh_url"`
    ClientID     string   `json:"client_id"`
    ClientSecret string   `json:"client_secret"`
    Scope        []string `json:"scope"`
    GrantType    string   `json:"grant_type"`
}
```

#### 📊 Enhanced Authentication Data Structures
```go
type AuthResult struct {
    Method       AuthMethod      `json:"method"`
    Credential   AuthCredential  `json:"credential"`
    Success      bool            `json:"success"`
    Token        string          `json:"token"`
    RefreshToken string          `json:"refresh_token"`
    ExpiresIn    int             `json:"expires_in"`
    TokenType    string          `json:"token_type"`
    Response     AuthResponse    `json:"response"`
}

type AuthCredential struct {
    Username     string            `json:"username"`
    Password     string            `json:"password"`
    APIKey       string            `json:"api_key"`
    Token        string            `json:"token"`
    RefreshToken string            `json:"refresh_token"`
    ClientID     string            `json:"client_id"`
    ClientSecret string            `json:"client_secret"`
    Scope        string            `json:"scope"`
    Metadata     map[string]string `json:"metadata"`
}
```

#### 🚀 New Command Line Options
```bash
# Authentication Method Flags
-basic-auth          # Enable HTTP Basic Authentication
-jwt                 # Enable JWT token support and analysis
-oauth               # Enable OAuth 2.0 flow support
-bearer              # Enable Bearer token authentication
-session-token       # Enable session token authentication
-cookie-auth         # Enable cookie-based authentication
-custom-auth         # Enable custom authentication methods
-mfa                 # Enable multi-factor authentication support

# Authentication Configuration
-auth-wordlist file  # Wordlist for authentication credentials
-username-list file  # Username wordlist for basic auth
-password-list file  # Password wordlist for basic auth
-auth-endpoint url   # Authentication endpoint URL
-token-endpoint url  # Token endpoint URL for OAuth
-refresh-endpoint url # Token refresh endpoint URL

# Advanced Features
-auth-chain          # Enable authentication method chaining
-token-refresh       # Enable automatic token refresh
```

#### 🎯 Usage Examples
```bash
# Basic Authentication
./coyotekey -u https://api.com -basic-auth -auth-wordlist credentials.txt

# JWT Token Testing
./coyotekey -u https://api.com -jwt -auth-wordlist tokens.txt

# OAuth 2.0 Testing
./coyotekey -u https://api.com -oauth -token-endpoint https://api.com/token \
  -auth-wordlist oauth_creds.txt

# Multiple Authentication Methods
./coyotekey -u https://api.com -basic-auth -jwt -bearer -oauth \
  -auth-wordlist all_credentials.txt

# Username/Password Combinations
./coyotekey -u https://api.com -basic-auth \
  -username-list usernames.txt -password-list passwords.txt

# Combined Discovery + Authentication
./coyotekey -u https://api.com -api-discover -jwt -bearer \
  -auth-wordlist tokens.txt -o combined_results.json
```

#### 📁 New Configuration Files
- `auth_credentials.example.txt` - Comprehensive authentication credentials (50+ examples)
- `usernames.example.txt` - Common usernames for authentication testing
- `passwords.example.txt` - Common passwords for authentication testing
- `demo_advanced_auth.sh` - Complete authentication demonstration script

#### 📊 Enhanced Authentication Output
```json
{
  "method": {
    "type": "JWT",
    "name": "JSON Web Token"
  },
  "credential": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "username": "admin"
  },
  "success": true,
  "token": "access_token_here",
  "refresh_token": "refresh_token_here",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "read write",
  "response": {
    "status_code": 200,
    "response_time_ms": 245,
    "headers": {
      "Authorization": "Bearer access_token_here"
    }
  }
}
```

#### 🔧 Technical Improvements
- **Smart Credential Parsing**: Multiple credential format support
- **Token Management**: Automatic token extraction and caching
- **Authentication Flow**: Complete authentication workflow implementation
- **Response Analysis**: Advanced authentication response analysis
- **Security Masking**: Sensitive data masking in output and logs

#### 🛡️ Integration with Existing Features
- **Smart Evasion**: Full integration with WAF detection and evasion techniques
- **API Discovery**: Combined discovery and authentication testing
- **Multi-Target Support**: Authentication testing across multiple targets
- **Rate Limiting**: Respect rate limits during authentication testing
- **Proxy Rotation**: Use proxy rotation for authentication requests

#### 📈 Authentication Statistics
- **Success Rate Analysis**: Authentication success rate tracking
- **Method Effectiveness**: Compare effectiveness of different auth methods
- **Response Time Analysis**: Authentication performance metrics
- **Credential Analysis**: Track successful credential patterns

## [2.3.0] - 2025-07-09

### 🔍 API Discovery & Enumeration - Advanced Reconnaissance Features

#### ✨ New API Discovery Features
- **API Discovery** (`-api-discover`): Automatic endpoint discovery using common paths
- **Endpoint Enumeration** (`-endpoint-enum`): Test multiple HTTP methods on discovered endpoints
- **Schema Analysis** (`-schema-analysis`): Detect and analyze OpenAPI/Swagger documentation
- **Version Detection** (`-version-detect`): Automatically identify API versions
- **Parameter Fuzzing** (`-param-fuzz`): Extract and analyze API parameters
- **Custom Path Discovery** (`-path-wordlist`): Support for custom path wordlists
- **Recursive Discovery** (`-discovery-depth`): Multi-level endpoint discovery

#### 🔍 Intelligent Discovery Engine
- **70+ Built-in Paths**: Comprehensive list of common API endpoints
- **214+ Example Paths**: Extended wordlist for thorough discovery
- **Framework Detection**: Identify Express.js, Django, Flask, Laravel, Spring Boot
- **Authentication Analysis**: Detect endpoints requiring authentication
- **Response Pattern Recognition**: Analyze response characteristics
- **Content Type Detection**: Identify API response formats

#### 📊 Advanced Analysis Capabilities
- **OpenAPI/Swagger Detection**: Automatic documentation discovery
- **API Version Mapping**: Identify and map different API versions
- **Parameter Extraction**: Extract parameters from JSON responses
- **Authentication Method Detection**: Identify OAuth, JWT, API Key authentication
- **Framework Fingerprinting**: Detect underlying technology stack
- **Response Time Analysis**: Performance metrics for each endpoint

#### 🎯 Combined Discovery + Brute Force
- **Two-Phase Operation**: Discovery followed by targeted brute force
- **Smart Target Selection**: Focus on authentication-required endpoints
- **Comprehensive Coverage**: Test all discovered endpoints with API keys
- **Integrated Reporting**: Combined discovery and brute force results
- **Efficient Resource Usage**: Avoid testing public endpoints unnecessarily

#### 📋 Enhanced Data Structures
```go
type APIEndpoint struct {
    URL            string            `json:"url"`
    Method         string            `json:"method"`
    StatusCode     int               `json:"status_code"`
    ContentLength  int64             `json:"content_length"`
    ContentType    string            `json:"content_type"`
    ResponseTime   int64             `json:"response_time_ms"`
    Headers        map[string]string `json:"headers"`
    Parameters     []string          `json:"parameters"`
    AuthRequired   bool              `json:"auth_required"`
    APIVersion     string            `json:"api_version"`
    Framework      string            `json:"framework"`
    Documentation  string            `json:"documentation"`
}

type APISchema struct {
    BaseURL        string                 `json:"base_url"`
    Version        string                 `json:"version"`
    Title          string                 `json:"title"`
    Description    string                 `json:"description"`
    Endpoints      []APIEndpoint          `json:"endpoints"`
    Authentication []string               `json:"authentication_methods"`
    Documentation  string                 `json:"documentation"`
}
```

#### 🚀 New Command Line Options
```bash
# API Discovery Flags
-api-discover        # Enable API endpoint discovery
-endpoint-enum       # Enable endpoint enumeration
-schema-analysis     # Enable API schema analysis
-version-detect      # Enable API version detection
-param-fuzz          # Enable parameter fuzzing
-path-wordlist file  # Custom path wordlist
-discovery-depth N   # Maximum discovery depth
-follow-redirects    # Follow HTTP redirects
```

#### 🎯 Usage Examples
```bash
# Basic API discovery
./coyotekey -u https://api.com -api-discover

# Advanced discovery with analysis
./coyotekey -u https://api.com -api-discover -schema-analysis -version-detect -endpoint-enum

# Custom wordlist discovery
./coyotekey -u https://api.com -api-discover -path-wordlist paths.txt

# Combined discovery + brute force
./coyotekey -u https://api.com -api-discover -w keys.txt -H "Authorization: Bearer %KEY%"

# Multi-target discovery
./coyotekey -targets urls.txt -api-discover -schema-analysis -o discovery.json
```

#### 📁 New Configuration Files
- `paths.example.txt` - Comprehensive path wordlist (214 paths)
- `demo_api_discovery.sh` - Complete discovery demonstration script

#### 📊 Enhanced Output Format
```json
{
  "target": "https://api.example.com",
  "endpoints": [
    {
      "url": "https://api.example.com/api/v1/users",
      "method": "GET",
      "status_code": 200,
      "auth_required": false,
      "framework": "Express.js",
      "api_version": "v1",
      "parameters": ["id", "name", "email"]
    }
  ],
  "schema": {
    "authentication_methods": ["API Key", "OAuth"],
    "documentation": "https://api.example.com/docs"
  },
  "statistics": {
    "endpoints_found": 25,
    "auth_endpoints": 15,
    "discovery_time": "45.2s"
  }
}
```

#### 🔧 Technical Improvements
- **Intelligent Path Construction**: Smart URL building and validation
- **Response Analysis Engine**: Advanced response pattern recognition
- **Framework Detection Logic**: Comprehensive technology identification
- **Authentication Detection**: Smart auth requirement analysis
- **Performance Optimization**: Efficient discovery algorithms

#### 🛡️ Integration with Existing Features
- **Smart Evasion**: Full integration with WAF detection and evasion
- **Multi-Target Support**: Discovery across multiple targets
- **Rate Limiting**: Respect rate limits during discovery
- **Proxy Rotation**: Use proxy rotation for discovery requests
- **User-Agent Rotation**: Apply evasion techniques to discovery

## [2.2.0] - 2025-07-09

### 🛡️ Smart Detection & Evasion - Advanced Security Features

#### ✨ New Smart Evasion Features
- **WAF Detection** (`-waf-detect`): Automatic Web Application Firewall detection and adaptive response
- **Smart Throttling** (`-smart-throttle`): Dynamic request rate adjustment based on response patterns
- **User-Agent Rotation** (`-ua-rotate`): Rotate through realistic browser User-Agents
- **Proxy Rotation** (`-proxy-rotate`): Distribute requests across multiple proxy servers
- **Header Rotation** (`-header-rotate`): Randomize HTTP headers to reduce fingerprinting
- **Session Rotation** (`-session-rotate`): Generate random session identifiers and headers
- **Random Delays** (`-random-delay`): Add human-like timing variations to requests

#### 🧠 Intelligent Response Analysis
- **WAF Signature Detection**: Recognizes CloudFlare, Nginx, and other common WAFs
- **Rate Limit Detection**: Automatically detects and respects rate limiting headers
- **Blocking Pattern Recognition**: Identifies common blocking responses and keywords
- **Adaptive Behavior**: Adjusts strategy based on target responses
- **Response Pattern Learning**: Builds understanding of target behavior over time

#### 🔄 Advanced Rotation Systems
- **Custom Lists Support**: Load User-Agents and proxies from external files
- **Intelligent Distribution**: Smart rotation algorithms for optimal coverage
- **Failover Mechanisms**: Automatic handling of failed proxies/User-Agents
- **Load Balancing**: Distribute requests evenly across available resources

#### ⏱️ Enhanced Timing Controls
- **Exponential Backoff**: Smart retry delays with jitter
- **Adaptive Delays**: Dynamic delay adjustment based on responses
- **Human-like Patterns**: Realistic timing variations to avoid detection
- **Respect Server Hints**: Honor `Retry-After` and similar headers

#### 🛡️ Stealth Techniques
- **Request Fingerprint Randomization**: Vary request characteristics
- **Session Simulation**: Realistic session management
- **Browser Behavior Mimicking**: Simulate real browser requests
- **Anti-Detection Measures**: Multiple layers of evasion

#### 📊 Enhanced Monitoring
- **Evasion Status Reporting**: Track evasion technique effectiveness
- **Block Detection Alerts**: Real-time blocking notifications
- **Performance Metrics**: Monitor evasion impact on performance
- **Success Rate Analysis**: Measure evasion technique success

#### 🚀 New Command Line Options
```bash
# Smart Evasion Flags
-waf-detect          # Enable WAF detection
-smart-throttle      # Enable smart throttling
-ua-rotate           # Enable User-Agent rotation
-ua-list file        # Custom User-Agent list
-proxy-rotate        # Enable proxy rotation  
-proxy-list file     # Custom proxy list
-header-rotate       # Enable header rotation
-session-rotate      # Enable session rotation
-random-delay        # Enable random delay variations
```

#### 🎯 Usage Examples
```bash
# Basic smart evasion
./coyotekey -u https://api.com/endpoint -w keys.txt -waf-detect -smart-throttle

# Maximum stealth mode
./coyotekey -targets urls.txt -w keys.txt -waf-detect -smart-throttle \
  -ua-list user_agents.txt -ua-rotate -proxy-list proxies.txt -proxy-rotate \
  -header-rotate -session-rotate -random-delay -delay 500 -retries 10

# Multi-target with evasion
./coyotekey -targets endpoints.txt -w wordlist.txt -waf-detect \
  -smart-throttle -ua-rotate -header-rotate -random-delay
```

#### 📁 New Configuration Files
- `user_agents.example.txt` - Example User-Agent rotation list
- `proxies.example.txt` - Example proxy rotation list
- `demo_smart_evasion.sh` - Comprehensive evasion demo script

#### 🔧 Technical Improvements
- **Response Analysis Engine**: Advanced response pattern recognition
- **Throttle Controller**: Intelligent request rate management
- **Rotation Manager**: Centralized rotation system management
- **Evasion Metrics**: Detailed evasion technique tracking

#### 🛡️ Security Enhancements
- **Anti-Fingerprinting**: Reduce request signature consistency
- **Detection Avoidance**: Proactive blocking prevention
- **Stealth Optimization**: Minimize detection probability
- **Adaptive Learning**: Improve evasion based on responses

## [2.1.0] - 2025-07-09

### 🎯 Multi-Target Support - Major Feature Addition

#### ✨ New Features
- **Multi-Target Mode**: Test multiple URLs in a single execution with `-targets` flag
- **Smart Retry Logic**: Configurable retry attempts with exponential backoff (`-retries`)
- **Request Delay Control**: Add delays between requests to avoid rate limiting (`-delay`)
- **Per-Target Configuration**: Different HTTP methods and headers per target
- **Enhanced Statistics**: Success rate and average response time across targets
- **Improved Error Handling**: Better error reporting and recovery

#### 🔧 Technical Improvements
- **Job-based Architecture**: Restructured to handle target-key combinations as jobs
- **Worker Pool Enhancement**: Multi-target aware worker goroutines
- **Configuration Flexibility**: Support for mixed target configurations
- **Memory Optimization**: Efficient job distribution and result collection

#### 📊 Enhanced Reporting
- **Multi-Target Summary**: Grouped results by target URL
- **Success Rate Metrics**: Percentage of targets with valid keys found
- **Average Response Time**: Performance metrics across all targets
- **Detailed JSON Output**: Structured results with target information

#### 🚀 Usage Examples
```bash
# Multi-target with file
./coyotekey -targets urls.txt -w wordlist.txt

# Mixed configuration per target
./coyotekey -targets config.txt -w keys.txt -retries 5 -delay 100

# Advanced multi-target with rate limiting
./coyotekey -targets endpoints.txt -w tokens.txt -t 15 -r 10 -o results.json
```

#### 📝 New Command Line Options
- `-targets`: File containing multiple target URLs
- `-retries`: Maximum retry attempts for failed requests (default: 3)
- `-delay`: Delay between requests in milliseconds (default: 0)
- `-multi`: Enable multi-target mode (auto-enabled with `-targets`)

#### 🔄 Backward Compatibility
- All existing single-target functionality preserved
- Existing command line flags work unchanged
- Output format enhanced but compatible

## [2.0.0] - 2025-07-09

### 🎉 Major Upgrade - Complete Rewrite

#### ✨ New Features
- **Rate Limiting**: Added `-r` flag to control requests per second
- **Enhanced Output**: Beautiful emoji-based console output with detailed information
- **JSON Export**: Save results to JSON file with `-o` flag
- **Verbose Mode**: Detailed logging with `-v` flag
- **Response Metrics**: Track response time and content length
- **Improved Headers**: Realistic browser headers for better stealth
- **Better Error Handling**: Comprehensive error handling and reporting
- **Configuration Structure**: Organized code with proper configuration management

#### 🔧 Improvements
- **Performance**: Optimized HTTP client with connection pooling
- **Memory Usage**: Better memory management for large wordlists
- **Code Organization**: Restructured code with proper functions and types
- **User Experience**: Enhanced CLI interface with better help text
- **Documentation**: Comprehensive README with examples and usage guide

#### 🛠️ Technical Changes
- **Go Module**: Updated to proper module structure
- **Dependencies**: Added `golang.org/x/time` for rate limiting
- **HTTP Client**: Enhanced HTTP client configuration
- **Concurrency**: Improved worker goroutine management
- **Data Structures**: Better structured data types with JSON tags

#### 📦 Build System
- **Makefile**: Added comprehensive Makefile for building and management
- **Multi-platform**: Support for building on multiple platforms
- **Installation**: Easy system-wide installation support

#### 📚 Documentation
- **README**: Comprehensive documentation with examples
- **Sample Files**: Added sample wordlist and configuration files
- **Usage Examples**: Multiple usage scenarios and examples

### 🔄 Migration from v1.x

#### Breaking Changes
- Command line interface has been enhanced (all flags remain compatible)
- Output format has been improved (more detailed and structured)
- JSON output structure has been standardized

#### Upgrade Steps
1. Backup your existing wordlists and configurations
2. Build the new version: `make build`
3. Test with your existing wordlists
4. Update any scripts to use new output format if needed

## [1.0.0] - 2024-06-05

### Initial Release
- Basic API key brute forcing functionality
- Multi-threaded execution
- Proxy support
- Custom header formats
- Success code configuration
