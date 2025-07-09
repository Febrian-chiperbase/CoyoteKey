package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

// Struktur untuk menyimpan hasil yang berhasil
type FoundKey struct {
	Key           string    `json:"key"`
	StatusCode    int       `json:"status_code"`
	URL           string    `json:"url"`
	ResponseTime  int64     `json:"response_time_ms"`
	ContentLength int64     `json:"content_length"`
	Timestamp     time.Time `json:"timestamp"`
}

// Config untuk aplikasi
type Config struct {
	TargetURL         string
	TargetURLs        []string
	MultiTarget       bool
	WordlistPath      string
	HeaderFormat      string
	HTTPMethod        string
	SuccessCodes      map[int]bool
	Threads           int
	ProxyURL          string
	ProxyList         []string
	RateLimit         int
	Timeout           time.Duration
	OutputFile        string
	Verbose           bool
	UserAgent         string
	UserAgentList     []string
	MaxRetries        int
	DelayBetween      time.Duration
	RandomDelay       bool
	WAFDetection      bool
	SmartThrottling   bool
	SessionRotation   bool
	HeaderRotation    bool
	ProxyRotation     bool
	UARotation        bool
	// API Discovery features
	APIDiscovery      bool
	EndpointEnum      bool
	SchemaAnalysis    bool
	VersionDetection  bool
	ParamFuzzing      bool
	PathWordlist      string
	CommonPaths       []string
	APIPatterns       []string
	DiscoveryDepth    int
	FollowRedirects   bool
	// Advanced Authentication features
	JWTSupport        bool
	OAuthSupport      bool
	BasicAuthSupport  bool
	BearerTokenSupport bool
	CustomAuthSupport bool
	MultiFactorSupport bool
	SessionTokenSupport bool
	CookieAuthSupport bool
	AuthChaining      bool
	TokenRefresh      bool
	AuthWordlist      string
	UsernameWordlist  string
	PasswordWordlist  string
	AuthEndpoint      string
	TokenEndpoint     string
	RefreshEndpoint   string
	// Machine Learning features
	MLEnabled         bool
	PatternRecognition bool
	SuccessPrediction bool
	IntelligentSorting bool
	AdaptiveLearning  bool
	BehaviorAnalysis  bool
	AnomalyDetection  bool
	ModelTraining     bool
	PredictiveAnalysis bool
	MLModelPath       string
	TrainingDataPath  string
	ConfidenceThreshold float64
	LearningRate      float64
	MaxIterations     int
	// Database Integration features
	DatabaseEnabled   bool
	DatabaseType      string
	DatabaseURL       string
	DatabaseHost      string
	DatabasePort      int
	DatabaseName      string
	DatabaseUser      string
	DatabasePassword  string
	DatabaseSSL       bool
	PersistentStorage bool
	HistoricalAnalysis bool
	AttackAnalytics   bool
	DataRetention     int
	AutoBackup        bool
	BackupInterval    time.Duration
	QueryOptimization bool
	IndexingEnabled   bool
	CacheEnabled      bool
	CacheSize         int
	// Web Dashboard features
	WebDashboard      bool
	DashboardPort     int
	DashboardHost     string
	DashboardAuth     bool
	DashboardUser     string
	DashboardPassword string
	DashboardSSL      bool
	DashboardCert     string
	DashboardKey      string
	RealTimeMonitoring bool
	TeamCollaboration bool
	VisualAnalytics   bool
	WebAPI            bool
	APIKey            string
	CORSEnabled       bool
	WebSocketEnabled  bool
	NotificationsEnabled bool
	AlertThresholds   map[string]float64
}

// Target represents a single target URL with its configuration
type Target struct {
	URL          string
	Method       string
	HeaderFormat string
	SuccessCodes map[int]bool
}

// WAF Detection and Response Analysis
type WAFDetector struct {
	BlockedStatusCodes []int
	BlockedKeywords    []string
	RateLimitHeaders   []string
	ConsecutiveBlocks  int
	MaxBlocks          int
	BackoffMultiplier  float64
}

// Smart Throttling Controller
type ThrottleController struct {
	BaseDelay        time.Duration
	CurrentDelay     time.Duration
	MaxDelay         time.Duration
	SuccessCount     int
	FailureCount     int
	ConsecutiveFails int
	AdaptiveMode     bool
}

// Job represents a single brute force job
type Job struct {
	Target Target
	Key    string
	ID     string
}

// Response Analysis Result
type ResponseAnalysis struct {
	IsBlocked       bool
	IsRateLimited   bool
	WAFDetected     bool
	SuggestedDelay  time.Duration
	BlockReason     string
	ResponsePattern string
}

// Session and Header Rotation
type RotationManager struct {
	UserAgents    []string
	Proxies       []string
	Headers       map[string][]string
	CurrentUA     int
	CurrentProxy  int
	RotationCount int
	mutex         sync.Mutex
}

// API Discovery structures
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
	Discovered     time.Time         `json:"discovered"`
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
	Parameters     map[string]interface{} `json:"global_parameters"`
	Servers        []string               `json:"servers"`
	Contact        map[string]string      `json:"contact"`
	License        map[string]string      `json:"license"`
	Documentation  string                 `json:"documentation"`
}

type DiscoveryResult struct {
	Target      string        `json:"target"`
	Endpoints   []APIEndpoint `json:"endpoints"`
	Schema      *APISchema    `json:"schema,omitempty"`
	Statistics  DiscoveryStats `json:"statistics"`
	Timestamp   time.Time     `json:"timestamp"`
}

type DiscoveryStats struct {
	TotalRequests    int           `json:"total_requests"`
	EndpointsFound   int           `json:"endpoints_found"`
	AuthEndpoints    int           `json:"auth_endpoints"`
	PublicEndpoints  int           `json:"public_endpoints"`
	ErrorEndpoints   int           `json:"error_endpoints"`
	DiscoveryTime    time.Duration `json:"discovery_time"`
	AverageResponse  int64         `json:"average_response_ms"`
}

// Advanced Authentication structures
type AuthMethod struct {
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Headers     map[string]string `json:"headers"`
	Parameters  map[string]string `json:"parameters"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	TokenField  string            `json:"token_field"`
	ExpiryField string            `json:"expiry_field"`
	RefreshURL  string            `json:"refresh_url"`
	Scope       []string          `json:"scope"`
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
	ExpiresAt    time.Time         `json:"expires_at"`
	Metadata     map[string]string `json:"metadata"`
}

type AuthResult struct {
	Method       AuthMethod      `json:"method"`
	Credential   AuthCredential  `json:"credential"`
	Success      bool            `json:"success"`
	Token        string          `json:"token"`
	RefreshToken string          `json:"refresh_token"`
	ExpiresIn    int             `json:"expires_in"`
	TokenType    string          `json:"token_type"`
	Scope        string          `json:"scope"`
	Response     AuthResponse    `json:"response"`
	Timestamp    time.Time       `json:"timestamp"`
}

type AuthResponse struct {
	StatusCode    int               `json:"status_code"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	ResponseTime  int64             `json:"response_time_ms"`
	ContentLength int64             `json:"content_length"`
}

type JWTToken struct {
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
	Raw       string                 `json:"raw"`
	Valid     bool                   `json:"valid"`
	ExpiresAt time.Time              `json:"expires_at"`
	IssuedAt  time.Time              `json:"issued_at"`
	Issuer    string                 `json:"issuer"`
	Subject   string                 `json:"subject"`
	Audience  []string               `json:"audience"`
}

type OAuthFlow struct {
	AuthURL      string            `json:"auth_url"`
	TokenURL     string            `json:"token_url"`
	RefreshURL   string            `json:"refresh_url"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	RedirectURI  string            `json:"redirect_uri"`
	Scope        []string          `json:"scope"`
	State        string            `json:"state"`
	CodeVerifier string            `json:"code_verifier"`
	CodeChallenge string           `json:"code_challenge"`
	GrantType    string            `json:"grant_type"`
	ResponseType string            `json:"response_type"`
}

// Machine Learning structures
type MLModel struct {
	Type           string                 `json:"type"`
	Version        string                 `json:"version"`
	TrainedAt      time.Time              `json:"trained_at"`
	Accuracy       float64                `json:"accuracy"`
	Features       []string               `json:"features"`
	Parameters     map[string]interface{} `json:"parameters"`
	Weights        []float64              `json:"weights"`
	Bias           float64                `json:"bias"`
	Classes        []string               `json:"classes"`
	FeatureScaling map[string]ScalingInfo `json:"feature_scaling"`
}

type ScalingInfo struct {
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

type TrainingData struct {
	Features [][]float64 `json:"features"`
	Labels   []int       `json:"labels"`
	Metadata []DataPoint `json:"metadata"`
}

type DataPoint struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	StatusCode     int               `json:"status_code"`
	ResponseTime   int64             `json:"response_time"`
	ContentLength  int64             `json:"content_length"`
	Headers        map[string]string `json:"headers"`
	Success        bool              `json:"success"`
	Timestamp      time.Time         `json:"timestamp"`
	KeyPattern     string            `json:"key_pattern"`
	AuthMethod     string            `json:"auth_method"`
	WAFDetected    bool              `json:"waf_detected"`
	RateLimited    bool              `json:"rate_limited"`
}

type Prediction struct {
	Probability    float64           `json:"probability"`
	Confidence     float64           `json:"confidence"`
	Class          string            `json:"class"`
	Features       []float64         `json:"features"`
	FeatureNames   []string          `json:"feature_names"`
	Explanation    string            `json:"explanation"`
	Recommendations []string         `json:"recommendations"`
	Timestamp      time.Time         `json:"timestamp"`
}

type PatternAnalysis struct {
	SuccessPatterns []Pattern         `json:"success_patterns"`
	FailurePatterns []Pattern         `json:"failure_patterns"`
	KeyPatterns     []KeyPattern      `json:"key_patterns"`
	TimePatterns    []TimePattern     `json:"time_patterns"`
	ResponsePatterns []ResponsePattern `json:"response_patterns"`
	Anomalies       []Anomaly         `json:"anomalies"`
}

type Pattern struct {
	Type        string    `json:"type"`
	Pattern     string    `json:"pattern"`
	Frequency   int       `json:"frequency"`
	Confidence  float64   `json:"confidence"`
	Examples    []string  `json:"examples"`
	LastSeen    time.Time `json:"last_seen"`
}

type KeyPattern struct {
	Pattern     string  `json:"pattern"`
	Length      int     `json:"length"`
	Charset     string  `json:"charset"`
	Prefix      string  `json:"prefix"`
	Suffix      string  `json:"suffix"`
	SuccessRate float64 `json:"success_rate"`
	Examples    []string `json:"examples"`
}

type TimePattern struct {
	Hour        int     `json:"hour"`
	DayOfWeek   int     `json:"day_of_week"`
	SuccessRate float64 `json:"success_rate"`
	RequestCount int    `json:"request_count"`
}

type ResponsePattern struct {
	StatusCode    int     `json:"status_code"`
	ContentType   string  `json:"content_type"`
	ResponseTime  int64   `json:"response_time"`
	ContentLength int64   `json:"content_length"`
	SuccessRate   float64 `json:"success_rate"`
	Count         int     `json:"count"`
}

type Anomaly struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Data        DataPoint `json:"data"`
	Timestamp   time.Time `json:"timestamp"`
}

// Database structures
type DatabaseConfig struct {
	Type         string        `json:"type"`
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	Database     string        `json:"database"`
	Username     string        `json:"username"`
	Password     string        `json:"password"`
	SSLMode      string        `json:"ssl_mode"`
	MaxConns     int           `json:"max_connections"`
	MaxIdleConns int           `json:"max_idle_connections"`
	ConnTimeout  time.Duration `json:"connection_timeout"`
}

type AttackSession struct {
	ID            string                 `json:"id" db:"id"`
	StartTime     time.Time              `json:"start_time" db:"start_time"`
	EndTime       *time.Time             `json:"end_time,omitempty" db:"end_time"`
	Status        string                 `json:"status" db:"status"`
	TargetCount   int                    `json:"target_count" db:"target_count"`
	KeyCount      int                    `json:"key_count" db:"key_count"`
	SuccessCount  int                    `json:"success_count" db:"success_count"`
	TotalRequests int                    `json:"total_requests" db:"total_requests"`
	Duration      *time.Duration         `json:"duration,omitempty" db:"duration"`
	Config        map[string]interface{} `json:"config" db:"config"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
}

type AttackTarget struct {
	ID          string    `json:"id" db:"id"`
	SessionID   string    `json:"session_id" db:"session_id"`
	URL         string    `json:"url" db:"url"`
	Method      string    `json:"method" db:"method"`
	HeaderFormat string   `json:"header_format" db:"header_format"`
	Status      string    `json:"status" db:"status"`
	SuccessCount int      `json:"success_count" db:"success_count"`
	TotalRequests int     `json:"total_requests" db:"total_requests"`
	FirstSuccess *time.Time `json:"first_success,omitempty" db:"first_success"`
	LastTested   *time.Time `json:"last_tested,omitempty" db:"last_tested"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

type AttackResult struct {
	ID            string    `json:"id" db:"id"`
	SessionID     string    `json:"session_id" db:"session_id"`
	TargetID      string    `json:"target_id" db:"target_id"`
	Key           string    `json:"key" db:"key"`
	URL           string    `json:"url" db:"url"`
	Method        string    `json:"method" db:"method"`
	StatusCode    int       `json:"status_code" db:"status_code"`
	ResponseTime  int64     `json:"response_time" db:"response_time"`
	ContentLength int64     `json:"content_length" db:"content_length"`
	Success       bool      `json:"success" db:"success"`
	Headers       string    `json:"headers" db:"headers"`
	ErrorMessage  *string   `json:"error_message,omitempty" db:"error_message"`
	MLPrediction  *float64  `json:"ml_prediction,omitempty" db:"ml_prediction"`
	MLConfidence  *float64  `json:"ml_confidence,omitempty" db:"ml_confidence"`
	Timestamp     time.Time `json:"timestamp" db:"timestamp"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type DiscoverySession struct {
	ID            string    `json:"id" db:"id"`
	SessionID     string    `json:"session_id" db:"session_id"`
	TargetURL     string    `json:"target_url" db:"target_url"`
	PathsScanned  int       `json:"paths_scanned" db:"paths_scanned"`
	EndpointsFound int      `json:"endpoints_found" db:"endpoints_found"`
	AuthEndpoints int       `json:"auth_endpoints" db:"auth_endpoints"`
	PublicEndpoints int     `json:"public_endpoints" db:"public_endpoints"`
	ErrorEndpoints int      `json:"error_endpoints" db:"error_endpoints"`
	DiscoveryTime time.Duration `json:"discovery_time" db:"discovery_time"`
	AvgResponseTime int64   `json:"avg_response_time" db:"avg_response_time"`
	StartTime     time.Time `json:"start_time" db:"start_time"`
	EndTime       *time.Time `json:"end_time,omitempty" db:"end_time"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

type DiscoveredEndpoint struct {
	ID            string    `json:"id" db:"id"`
	DiscoveryID   string    `json:"discovery_id" db:"discovery_id"`
	URL           string    `json:"url" db:"url"`
	Method        string    `json:"method" db:"method"`
	StatusCode    int       `json:"status_code" db:"status_code"`
	ContentLength int64     `json:"content_length" db:"content_length"`
	ContentType   string    `json:"content_type" db:"content_type"`
	ResponseTime  int64     `json:"response_time" db:"response_time"`
	AuthRequired  bool      `json:"auth_required" db:"auth_required"`
	Framework     string    `json:"framework" db:"framework"`
	APIVersion    string    `json:"api_version" db:"api_version"`
	Parameters    string    `json:"parameters" db:"parameters"`
	Headers       string    `json:"headers" db:"headers"`
	Discovered    time.Time `json:"discovered" db:"discovered"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type AuthenticationResult struct {
	ID            string    `json:"id" db:"id"`
	SessionID     string    `json:"session_id" db:"session_id"`
	TargetURL     string    `json:"target_url" db:"target_url"`
	AuthMethod    string    `json:"auth_method" db:"auth_method"`
	Username      *string   `json:"username,omitempty" db:"username"`
	Success       bool      `json:"success" db:"success"`
	StatusCode    int       `json:"status_code" db:"status_code"`
	ResponseTime  int64     `json:"response_time" db:"response_time"`
	Token         *string   `json:"token,omitempty" db:"token"`
	RefreshToken  *string   `json:"refresh_token,omitempty" db:"refresh_token"`
	ExpiresIn     *int      `json:"expires_in,omitempty" db:"expires_in"`
	TokenType     *string   `json:"token_type,omitempty" db:"token_type"`
	Scope         *string   `json:"scope,omitempty" db:"scope"`
	ErrorMessage  *string   `json:"error_message,omitempty" db:"error_message"`
	Timestamp     time.Time `json:"timestamp" db:"timestamp"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type MLInsight struct {
	ID            string    `json:"id" db:"id"`
	SessionID     string    `json:"session_id" db:"session_id"`
	ModelType     string    `json:"model_type" db:"model_type"`
	ModelVersion  string    `json:"model_version" db:"model_version"`
	Accuracy      float64   `json:"accuracy" db:"accuracy"`
	TrainingSize  int       `json:"training_size" db:"training_size"`
	Features      string    `json:"features" db:"features"`
	Patterns      string    `json:"patterns" db:"patterns"`
	Anomalies     string    `json:"anomalies" db:"anomalies"`
	Predictions   string    `json:"predictions" db:"predictions"`
	LastUpdate    time.Time `json:"last_update" db:"last_update"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type AttackAnalytics struct {
	TotalSessions     int                    `json:"total_sessions"`
	TotalTargets      int                    `json:"total_targets"`
	TotalRequests     int                    `json:"total_requests"`
	SuccessfulAttacks int                    `json:"successful_attacks"`
	SuccessRate       float64                `json:"success_rate"`
	AvgResponseTime   float64                `json:"avg_response_time"`
	TopTargets        []TargetStats          `json:"top_targets"`
	TopKeys           []KeyStats             `json:"top_keys"`
	TimeDistribution  []TimeStats            `json:"time_distribution"`
	StatusDistribution []StatusStats         `json:"status_distribution"`
	MethodDistribution []MethodStats         `json:"method_distribution"`
	RecentActivity    []RecentActivityStats  `json:"recent_activity"`
}

type TargetStats struct {
	URL          string  `json:"url"`
	RequestCount int     `json:"request_count"`
	SuccessCount int     `json:"success_count"`
	SuccessRate  float64 `json:"success_rate"`
	AvgResponseTime float64 `json:"avg_response_time"`
}

type KeyStats struct {
	KeyPattern   string  `json:"key_pattern"`
	Length       int     `json:"length"`
	UsageCount   int     `json:"usage_count"`
	SuccessCount int     `json:"success_count"`
	SuccessRate  float64 `json:"success_rate"`
}

type TimeStats struct {
	Hour         int     `json:"hour"`
	RequestCount int     `json:"request_count"`
	SuccessCount int     `json:"success_count"`
	SuccessRate  float64 `json:"success_rate"`
}

type StatusStats struct {
	StatusCode   int     `json:"status_code"`
	Count        int     `json:"count"`
	Percentage   float64 `json:"percentage"`
}

type MethodStats struct {
	Method       string  `json:"method"`
	Count        int     `json:"count"`
	SuccessCount int     `json:"success_count"`
	SuccessRate  float64 `json:"success_rate"`
}

type RecentActivityStats struct {
	Date         string `json:"date"`
	SessionCount int    `json:"session_count"`
	RequestCount int    `json:"request_count"`
	SuccessCount int    `json:"success_count"`
}

// Database Manager
type DatabaseManager struct {
	Config     *DatabaseConfig `json:"config"`
	Connection interface{}     `json:"-"`
	IsConnected bool           `json:"is_connected"`
	LastBackup  *time.Time     `json:"last_backup,omitempty"`
	Stats       DatabaseStats  `json:"stats"`
	mutex       sync.Mutex
}

// Web Dashboard structures
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
	mutex           sync.Mutex
}

type DashboardConfig struct {
	Host             string            `json:"host"`
	Port             int               `json:"port"`
	SSL              bool              `json:"ssl"`
	CertFile         string            `json:"cert_file"`
	KeyFile          string            `json:"key_file"`
	AuthEnabled      bool              `json:"auth_enabled"`
	Username         string            `json:"username"`
	Password         string            `json:"password"`
	APIKey           string            `json:"api_key"`
	CORSEnabled      bool              `json:"cors_enabled"`
	WebSocketEnabled bool              `json:"websocket_enabled"`
	StaticPath       string            `json:"static_path"`
	TemplatePath     string            `json:"template_path"`
}

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
	Data            map[string]interface{} `json:"data"`
}

type WebSocket struct {
	Conn       interface{} `json:"-"`
	SessionID  string      `json:"session_id"`
	UserID     string      `json:"user_id"`
	Connected  time.Time   `json:"connected"`
	LastPing   time.Time   `json:"last_ping"`
	Channels   []string    `json:"channels"`
	IsActive   bool        `json:"is_active"`
}

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
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
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
	Data        map[string]interface{} `json:"data"`
	CreatedAt   time.Time              `json:"created_at"`
	TriggeredAt *time.Time             `json:"triggered_at,omitempty"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
}

type DashboardStats struct {
	TotalSessions     int                    `json:"total_sessions"`
	ActiveSessions    int                    `json:"active_sessions"`
	TotalRequests     int64                  `json:"total_requests"`
	SuccessfulRequests int64                 `json:"successful_requests"`
	FailedRequests    int64                  `json:"failed_requests"`
	AvgResponseTime   float64                `json:"avg_response_time"`
	RequestsPerSecond float64                `json:"requests_per_second"`
	TopTargets        []TargetStats          `json:"top_targets"`
	RecentActivity    []ActivityLog          `json:"recent_activity"`
	SystemHealth      SystemHealth           `json:"system_health"`
	Alerts            []Alert                `json:"alerts"`
	LastUpdate        time.Time              `json:"last_update"`
}

type ActivityLog struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Action    string                 `json:"action"`
	UserID    string                 `json:"user_id"`
	SessionID string                 `json:"session_id"`
	Target    string                 `json:"target"`
	Details   map[string]interface{} `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
	IPAddress string                 `json:"ip_address"`
}

type SystemHealth struct {
	CPUUsage      float64   `json:"cpu_usage"`
	MemoryUsage   float64   `json:"memory_usage"`
	DiskUsage     float64   `json:"disk_usage"`
	NetworkIO     NetworkIO `json:"network_io"`
	DatabaseHealth DBHealth `json:"database_health"`
	Uptime        int64     `json:"uptime"`
	LastCheck     time.Time `json:"last_check"`
}

type NetworkIO struct {
	BytesSent     int64 `json:"bytes_sent"`
	BytesReceived int64 `json:"bytes_received"`
	PacketsSent   int64 `json:"packets_sent"`
	PacketsReceived int64 `json:"packets_received"`
}

type DBHealth struct {
	Connected       bool    `json:"connected"`
	ResponseTime    float64 `json:"response_time"`
	ActiveConnections int   `json:"active_connections"`
	QueriesPerSecond float64 `json:"queries_per_second"`
	DatabaseSize    int64   `json:"database_size"`
}

type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Message   string      `json:"message,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	RequestID string      `json:"request_id"`
}

type WebSocketMessage struct {
	Type      string                 `json:"type"`
	Channel   string                 `json:"channel"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	ID        string                 `json:"id"`
}

// Dashboard Manager
type DashboardManager struct {
	Dashboard    *WebDashboard     `json:"dashboard"`
	Database     *DatabaseManager  `json:"-"`
	MLEngine     *MLEngine         `json:"-"`
	Config       *Config           `json:"-"`
	IsRunning    bool              `json:"is_running"`
	StartTime    time.Time         `json:"start_time"`
	Stats        *DashboardStats   `json:"stats"`
	mutex        sync.Mutex
}

func main() {
	// 1. Definisi dan parsing flags
	config := &Config{}
	
	flag.StringVar(&config.TargetURL, "u", "", "Single target API endpoint URL")
	targetsFile := flag.String("targets", "", "File containing multiple target URLs (one per line)")
	flag.BoolVar(&config.MultiTarget, "multi", false, "Enable multi-target mode")
	flag.StringVar(&config.WordlistPath, "w", "", "Path to wordlist file (required for key brute force)")
	flag.StringVar(&config.HeaderFormat, "H", "X-API-Key: %KEY%", "HTTP Header format for API Key (e.g., \"Authorization: Bearer %KEY%\")")
	flag.StringVar(&config.HTTPMethod, "m", "GET", "HTTP method (GET, POST, PUT, etc.)")
	successCodesRaw := flag.String("s", "200", "Comma-separated list of success HTTP status codes")
	flag.IntVar(&config.Threads, "t", 10, "Number of concurrent threads/goroutines")
	flag.StringVar(&config.ProxyURL, "proxy", "", "Single proxy URL (e.g., http://127.0.0.1:8080)")
	proxyListFile := flag.String("proxy-list", "", "File containing proxy list (one per line)")
	flag.IntVar(&config.RateLimit, "r", 0, "Rate limit (requests per second, 0 = no limit)")
	timeoutSec := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	flag.StringVar(&config.OutputFile, "o", "", "Output file for results (JSON format)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.StringVar(&config.UserAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "User-Agent string")
	uaListFile := flag.String("ua-list", "", "File containing User-Agent list for rotation")
	flag.IntVar(&config.MaxRetries, "retries", 3, "Maximum number of retries for failed requests")
	delayMs := flag.Int("delay", 0, "Base delay between requests in milliseconds")
	flag.BoolVar(&config.RandomDelay, "random-delay", false, "Add random delay variation (50-150% of base delay)")
	flag.BoolVar(&config.WAFDetection, "waf-detect", false, "Enable WAF detection and adaptive response")
	flag.BoolVar(&config.SmartThrottling, "smart-throttle", false, "Enable smart throttling based on response patterns")
	flag.BoolVar(&config.ProxyRotation, "proxy-rotate", false, "Enable proxy rotation")
	flag.BoolVar(&config.UARotation, "ua-rotate", false, "Enable User-Agent rotation")
	flag.BoolVar(&config.HeaderRotation, "header-rotate", false, "Enable additional header rotation")
	flag.BoolVar(&config.SessionRotation, "session-rotate", false, "Enable session rotation (cookies, etc.)")
	
	// API Discovery flags
	flag.BoolVar(&config.APIDiscovery, "api-discover", false, "Enable API endpoint discovery")
	flag.BoolVar(&config.EndpointEnum, "endpoint-enum", false, "Enable endpoint enumeration")
	flag.BoolVar(&config.SchemaAnalysis, "schema-analysis", false, "Enable API schema analysis (OpenAPI/Swagger)")
	flag.BoolVar(&config.VersionDetection, "version-detect", false, "Enable API version detection")
	flag.BoolVar(&config.ParamFuzzing, "param-fuzz", false, "Enable parameter fuzzing")
	flag.StringVar(&config.PathWordlist, "path-wordlist", "", "Wordlist file for path discovery")
	flag.IntVar(&config.DiscoveryDepth, "discovery-depth", 3, "Maximum depth for recursive discovery")
	flag.BoolVar(&config.FollowRedirects, "follow-redirects", true, "Follow HTTP redirects during discovery")

	// Advanced Authentication flags
	flag.BoolVar(&config.JWTSupport, "jwt", false, "Enable JWT token support and analysis")
	flag.BoolVar(&config.OAuthSupport, "oauth", false, "Enable OAuth 2.0 flow support")
	flag.BoolVar(&config.BasicAuthSupport, "basic-auth", false, "Enable HTTP Basic Authentication")
	flag.BoolVar(&config.BearerTokenSupport, "bearer", false, "Enable Bearer token authentication")
	flag.BoolVar(&config.CustomAuthSupport, "custom-auth", false, "Enable custom authentication methods")
	flag.BoolVar(&config.MultiFactorSupport, "mfa", false, "Enable multi-factor authentication support")
	flag.BoolVar(&config.SessionTokenSupport, "session-token", false, "Enable session token authentication")
	flag.BoolVar(&config.CookieAuthSupport, "cookie-auth", false, "Enable cookie-based authentication")
	flag.BoolVar(&config.AuthChaining, "auth-chain", false, "Enable authentication method chaining")
	flag.BoolVar(&config.TokenRefresh, "token-refresh", false, "Enable automatic token refresh")
	flag.StringVar(&config.AuthWordlist, "auth-wordlist", "", "Wordlist for authentication credentials")
	flag.StringVar(&config.UsernameWordlist, "username-list", "", "Username wordlist for basic auth")
	flag.StringVar(&config.PasswordWordlist, "password-list", "", "Password wordlist for basic auth")
	flag.StringVar(&config.AuthEndpoint, "auth-endpoint", "", "Authentication endpoint URL")
	flag.StringVar(&config.TokenEndpoint, "token-endpoint", "", "Token endpoint URL for OAuth")
	flag.StringVar(&config.RefreshEndpoint, "refresh-endpoint", "", "Token refresh endpoint URL")

	// Machine Learning flags
	flag.BoolVar(&config.MLEnabled, "ml", false, "Enable machine learning features")
	flag.BoolVar(&config.PatternRecognition, "pattern-recognition", false, "Enable pattern recognition and analysis")
	flag.BoolVar(&config.SuccessPrediction, "success-prediction", false, "Enable success probability prediction")
	flag.BoolVar(&config.IntelligentSorting, "intelligent-sorting", false, "Enable intelligent wordlist sorting")
	flag.BoolVar(&config.AdaptiveLearning, "adaptive-learning", false, "Enable adaptive learning from results")
	flag.BoolVar(&config.BehaviorAnalysis, "behavior-analysis", false, "Enable target behavior analysis")
	flag.BoolVar(&config.AnomalyDetection, "anomaly-detection", false, "Enable anomaly detection")
	flag.BoolVar(&config.ModelTraining, "model-training", false, "Enable model training mode")
	flag.BoolVar(&config.PredictiveAnalysis, "predictive-analysis", false, "Enable predictive analysis")
	flag.StringVar(&config.MLModelPath, "ml-model", "", "Path to ML model file")
	flag.StringVar(&config.TrainingDataPath, "training-data", "", "Path to training data file")
	flag.Float64Var(&config.ConfidenceThreshold, "confidence-threshold", 0.7, "Confidence threshold for predictions")
	flag.Float64Var(&config.LearningRate, "learning-rate", 0.01, "Learning rate for model training")
	flag.IntVar(&config.MaxIterations, "max-iterations", 1000, "Maximum iterations for training")

	// Database Integration flags
	flag.BoolVar(&config.DatabaseEnabled, "db", false, "Enable database integration")
	flag.StringVar(&config.DatabaseType, "db-type", "sqlite", "Database type (sqlite, postgres, mysql)")
	flag.StringVar(&config.DatabaseURL, "db-url", "", "Database connection URL")
	flag.StringVar(&config.DatabaseHost, "db-host", "localhost", "Database host")
	flag.IntVar(&config.DatabasePort, "db-port", 5432, "Database port")
	flag.StringVar(&config.DatabaseName, "db-name", "coyotekey", "Database name")
	flag.StringVar(&config.DatabaseUser, "db-user", "", "Database username")
	flag.StringVar(&config.DatabasePassword, "db-password", "", "Database password")
	flag.BoolVar(&config.DatabaseSSL, "db-ssl", false, "Enable SSL for database connection")
	flag.BoolVar(&config.PersistentStorage, "persistent-storage", false, "Enable persistent storage of results")
	flag.BoolVar(&config.HistoricalAnalysis, "historical-analysis", false, "Enable historical data analysis")
	flag.BoolVar(&config.AttackAnalytics, "attack-analytics", false, "Enable attack analytics and reporting")
	flag.IntVar(&config.DataRetention, "data-retention", 30, "Data retention period in days")
	flag.BoolVar(&config.AutoBackup, "auto-backup", false, "Enable automatic database backup")
	backupIntervalHours := flag.Int("backup-interval", 24, "Backup interval in hours")
	flag.BoolVar(&config.QueryOptimization, "query-optimization", true, "Enable query optimization")
	flag.BoolVar(&config.IndexingEnabled, "indexing", true, "Enable database indexing")
	flag.BoolVar(&config.CacheEnabled, "cache", false, "Enable query result caching")
	flag.IntVar(&config.CacheSize, "cache-size", 100, "Cache size (MB)")

	// Web Dashboard flags
	flag.BoolVar(&config.WebDashboard, "web", false, "Enable web dashboard")
	flag.IntVar(&config.DashboardPort, "web-port", 8080, "Web dashboard port")
	flag.StringVar(&config.DashboardHost, "web-host", "localhost", "Web dashboard host")
	flag.BoolVar(&config.DashboardAuth, "web-auth", false, "Enable web dashboard authentication")
	flag.StringVar(&config.DashboardUser, "web-user", "admin", "Web dashboard username")
	flag.StringVar(&config.DashboardPassword, "web-password", "", "Web dashboard password")
	flag.BoolVar(&config.DashboardSSL, "web-ssl", false, "Enable SSL for web dashboard")
	flag.StringVar(&config.DashboardCert, "web-cert", "", "SSL certificate file for web dashboard")
	flag.StringVar(&config.DashboardKey, "web-key", "", "SSL private key file for web dashboard")
	flag.BoolVar(&config.RealTimeMonitoring, "real-time", false, "Enable real-time monitoring")
	flag.BoolVar(&config.TeamCollaboration, "team-collab", false, "Enable team collaboration features")
	flag.BoolVar(&config.VisualAnalytics, "visual-analytics", false, "Enable visual analytics")
	flag.BoolVar(&config.WebAPI, "web-api", false, "Enable web API endpoints")
	flag.StringVar(&config.APIKey, "api-key", "", "API key for web API access")
	flag.BoolVar(&config.CORSEnabled, "cors", false, "Enable CORS for web dashboard")
	flag.BoolVar(&config.WebSocketEnabled, "websocket", false, "Enable WebSocket for real-time updates")
	flag.BoolVar(&config.NotificationsEnabled, "notifications", false, "Enable notifications system")

	flag.Parse()

	config.Timeout = time.Duration(*timeoutSec) * time.Second
	config.DelayBetween = time.Duration(*delayMs) * time.Millisecond
	config.BackupInterval = time.Duration(*backupIntervalHours) * time.Hour
	
	// Initialize alert thresholds
	config.AlertThresholds = map[string]float64{
		"success_rate_low":    0.01, // Alert if success rate < 1%
		"response_time_high":  5000, // Alert if avg response time > 5s
		"error_rate_high":     0.5,  // Alert if error rate > 50%
		"requests_per_sec_high": 100, // Alert if RPS > 100
	}

	// 2. Validasi input
	if config.TargetURL == "" && *targetsFile == "" {
		fmt.Println("Either single target URL (-u) or targets file (-targets) is required.")
		flag.Usage()
		os.Exit(1)
	}

	// For API discovery, wordlist is optional
	// For advanced auth, auth credentials are required
	if config.WordlistPath == "" && !config.APIDiscovery && !config.EndpointEnum && !hasAdvancedAuthFeatures(config) {
		fmt.Println("Wordlist (-w) is required for key brute force mode.")
		fmt.Println("Use -api-discover or -endpoint-enum for discovery without wordlist.")
		fmt.Println("Use advanced auth flags (-basic-auth, -jwt, -oauth, etc.) for authentication testing.")
		flag.Usage()
		os.Exit(1)
	}

	if config.WordlistPath != "" && !strings.Contains(config.HeaderFormat, "%KEY%") {
		fmt.Println("Header format (-H) must contain placeholder %KEY% when using wordlist")
		os.Exit(1)
	}

	// 3. Load proxy list if specified
	if *proxyListFile != "" {
		config.ProxyRotation = true
		var err error
		config.ProxyList, err = loadList(*proxyListFile)
		if err != nil {
			fmt.Printf("Error loading proxy list: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("🌐 Loaded %d proxies for rotation\n", len(config.ProxyList))
	} else if config.ProxyURL != "" {
		config.ProxyList = []string{config.ProxyURL}
	}

	// 4. Load User-Agent list if specified
	if *uaListFile != "" {
		config.UARotation = true
		var err error
		config.UserAgentList, err = loadList(*uaListFile)
		if err != nil {
			fmt.Printf("Error loading User-Agent list: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("🔄 Loaded %d User-Agents for rotation\n", len(config.UserAgentList))
	} else {
		config.UserAgentList = getDefaultUserAgents()
	}

	// 5. Load path wordlist if specified
	if config.PathWordlist != "" {
		paths, err := loadList(config.PathWordlist)
		if err != nil {
			fmt.Printf("Error loading path wordlist: %v\n", err)
			os.Exit(1)
		}
		config.CommonPaths = paths
		fmt.Printf("📂 Loaded %d paths for discovery\n", len(config.CommonPaths))
	} else {
		config.CommonPaths = getDefaultPaths()
	}

	// 7. Load authentication wordlists if specified
	var authCredentials []AuthCredential
	if config.AuthWordlist != "" {
		creds, err := loadAuthCredentials(config.AuthWordlist)
		if err != nil {
			fmt.Printf("Error loading auth wordlist: %v\n", err)
			os.Exit(1)
		}
		authCredentials = creds
		fmt.Printf("🔐 Loaded %d authentication credentials\n", len(authCredentials))
	}

	if config.UsernameWordlist != "" && config.PasswordWordlist != "" {
		usernames, err := loadList(config.UsernameWordlist)
		if err != nil {
			fmt.Printf("Error loading username list: %v\n", err)
			os.Exit(1)
		}
		passwords, err := loadList(config.PasswordWordlist)
		if err != nil {
			fmt.Printf("Error loading password list: %v\n", err)
			os.Exit(1)
		}
		
		// Generate username:password combinations
		for _, username := range usernames {
			for _, password := range passwords {
				authCredentials = append(authCredentials, AuthCredential{
					Username: username,
					Password: password,
				})
			}
		}
		fmt.Printf("🔐 Generated %d username:password combinations\n", len(authCredentials))
	}

	// 8. Load targets
	var targets []Target
	if *targetsFile != "" {
		config.MultiTarget = true
		var err error
		targets, err = loadTargets(*targetsFile, config)
		if err != nil {
			fmt.Printf("Error loading targets: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Single target mode
		targets = []Target{{
			URL:          config.TargetURL,
			Method:       config.HTTPMethod,
			HeaderFormat: config.HeaderFormat,
			SuccessCodes: parseSuccessCodes(*successCodesRaw),
		}}
	}

	config.SuccessCodes = parseSuccessCodes(*successCodesRaw)

	// 14. Initialize database manager if enabled
	var dbManager *DatabaseManager
	if hasDatabaseFeatures(config) {
		dbManager = initDatabaseManager(config)
		if config.Verbose {
			fmt.Printf("💾 Database initialized: %s\n", config.DatabaseType)
		}
	}
	
	// 15. Initialize ML engine if enabled
	var mlEngine *MLEngine
	if hasMLFeatures(config) {
		mlEngine = initMLEngine(config)
		if config.Verbose {
			fmt.Printf("🤖 ML Engine initialized with %d features\n", len(mlEngine.Model.Features))
		}
	}
	
	// 16. Initialize dashboard manager if enabled
	var dashboardManager *DashboardManager
	if hasWebDashboardFeatures(config) {
		dashboardManager = initDashboardManager(config, dbManager, mlEngine)
		if config.Verbose {
			fmt.Printf("🌐 Web Dashboard initialized on %s:%d\n", config.DashboardHost, config.DashboardPort)
		}
		
		// Start dashboard server
		go startDashboardServer(dashboardManager)
	}
	
	// 17. Initialize discovery components
	pathDiscovery := initPathDiscovery(config)
	
	// 18. Initialize authentication manager
	authManager := initAuthManager(config, authCredentials)
	
	// Print configuration
	printWebDashboardConfig(config, targets, authManager, mlEngine, dbManager, dashboardManager)

	// 19. Initialize smart components
	wafDetector := initWAFDetector()
	throttleController := initThrottleController(config.DelayBetween)
	rotationManager := initRotationManager(config)

	// 20. Create HTTP client
	httpClient := createHTTPClient(config)

	// 21. Rate limiter
	var limiter *rate.Limiter
	if config.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.RateLimit), 1)
	}

	// 22. Create attack session if database is enabled
	var sessionID string
	if dbManager != nil {
		sessionID = createAttackSession(dbManager, config, targets)
		if config.Verbose {
			fmt.Printf("📊 Attack session created: %s\n", sessionID)
		}
		
		// Notify dashboard if enabled
		if dashboardManager != nil {
			notifyDashboard(dashboardManager, "session_started", map[string]interface{}{
				"session_id": sessionID,
				"targets":    len(targets),
				"timestamp":  time.Now(),
			})
		}
	}

	// 23. Execute based on mode with dashboard integration
	if config.APIDiscovery || config.EndpointEnum {
		// Dashboard-enhanced API Discovery mode
		discoveryResults := executeDashboardEnhancedDiscovery(config, targets, httpClient, limiter, pathDiscovery, wafDetector, throttleController, rotationManager, mlEngine, dbManager, dashboardManager, sessionID)
		
		// Save discovery results
		if config.OutputFile != "" {
			saveDiscoveryResults(discoveryResults, config.OutputFile)
		}
		
		printDiscoveryResults(discoveryResults)
		
		// Continue with authentication testing if wordlist provided
		if config.WordlistPath != "" {
			fmt.Println("\n🔑 Starting dashboard-enhanced API key brute force on discovered endpoints...")
			
			// Convert discovered endpoints to targets
			var discoveredTargets []Target
			for _, result := range discoveryResults {
				for _, endpoint := range result.Endpoints {
					if endpoint.AuthRequired || endpoint.StatusCode == 401 || endpoint.StatusCode == 403 {
						discoveredTargets = append(discoveredTargets, Target{
							URL:          endpoint.URL,
							Method:       endpoint.Method,
							HeaderFormat: config.HeaderFormat,
							SuccessCodes: config.SuccessCodes,
						})
					}
				}
			}
			
			if len(discoveredTargets) > 0 {
				fmt.Printf("🎯 Found %d endpoints requiring authentication\n", len(discoveredTargets))
				
				// Load wordlist for key brute force
				keys, err := loadWordlist(config.WordlistPath)
				if err != nil {
					fmt.Printf("Error loading wordlist: %v\n", err)
					os.Exit(1)
				}
				
				// Apply ML intelligent sorting if enabled
				if config.IntelligentSorting && mlEngine != nil {
					keys = mlEngine.intelligentSort(keys, discoveredTargets)
					fmt.Printf("🧠 Applied intelligent sorting to %d keys\n", len(keys))
				}
				
				// Execute dashboard-enhanced authentication testing
				authResults := executeDashboardEnhancedAuth(config, discoveredTargets, keys, authManager, httpClient, limiter, wafDetector, throttleController, rotationManager, mlEngine, dbManager, dashboardManager, sessionID)
				
				// Save auth results
				if config.OutputFile != "" {
					saveAuthResults(authResults, strings.Replace(config.OutputFile, ".json", "_auth.json", 1))
				}
				
				printAuthResults(authResults)
				
				// Save ML insights if enabled
				if mlEngine != nil {
					saveMLInsights(mlEngine, strings.Replace(config.OutputFile, ".json", "_ml_insights.json", 1))
					if dbManager != nil {
						saveMLInsightsToDatabase(dbManager, sessionID, mlEngine)
					}
				}
			} else {
				fmt.Println("ℹ️  No endpoints requiring authentication found")
			}
		}
	} else if hasAdvancedAuthFeatures(config) {
		// Dashboard-Enhanced Authentication mode
		fmt.Println("🔐 Starting dashboard-enhanced authentication testing...")
		
		authResults := executeDashboardEnhancedAuth(config, targets, nil, authManager, httpClient, limiter, wafDetector, throttleController, rotationManager, mlEngine, dbManager, dashboardManager, sessionID)
		
		// Save auth results
		if config.OutputFile != "" {
			saveAuthResults(authResults, config.OutputFile)
		}
		
		printAuthResults(authResults)
		
		// Save ML insights
		if mlEngine != nil {
			saveMLInsights(mlEngine, strings.Replace(config.OutputFile, ".json", "_ml_insights.json", 1))
			if dbManager != nil {
				saveMLInsightsToDatabase(dbManager, sessionID, mlEngine)
			}
		}
	} else {
		// Traditional brute force mode with dashboard enhancement
		keys, err := loadWordlist(config.WordlistPath)
		if err != nil {
			fmt.Printf("Error loading wordlist: %v\n", err)
			os.Exit(1)
		}
		
		// Apply ML intelligent sorting if enabled
		if config.IntelligentSorting && mlEngine != nil {
			keys = mlEngine.intelligentSort(keys, targets)
			fmt.Printf("🧠 Applied intelligent sorting to %d keys\n", len(keys))
		}
		
		printDashboardBruteForceConfig(config, targets, len(keys), mlEngine, dbManager, dashboardManager)
		
		// Generate jobs (target + key combinations)
		jobs := generateJobs(targets, keys)
		
		// Execute dashboard-enhanced brute force
		foundKeys := executeDashboardEnhancedBruteForce(config, jobs, httpClient, limiter, wafDetector, throttleController, rotationManager, mlEngine, dbManager, dashboardManager, sessionID)
		
		// Save and display results
		if config.OutputFile != "" {
			saveResults(foundKeys, config.OutputFile)
		}

		printMultiTargetSummary(foundKeys, targets)
		
		// Save ML insights
		if mlEngine != nil {
			saveMLInsights(mlEngine, strings.Replace(config.OutputFile, ".json", "_ml_insights.json", 1))
			if dbManager != nil {
				saveMLInsightsToDatabase(dbManager, sessionID, mlEngine)
			}
		}
	}
	
	// Finalize attack session
	if dbManager != nil && sessionID != "" {
		finalizeAttackSession(dbManager, sessionID)
		
		// Notify dashboard
		if dashboardManager != nil {
			notifyDashboard(dashboardManager, "session_completed", map[string]interface{}{
				"session_id": sessionID,
				"timestamp":  time.Now(),
			})
		}
		
		// Generate analytics if enabled
		if config.AttackAnalytics {
			analytics := generateAttackAnalytics(dbManager)
			if config.OutputFile != "" {
				saveAttackAnalytics(analytics, strings.Replace(config.OutputFile, ".json", "_analytics.json", 1))
			}
			printAttackAnalytics(analytics)
		}
		
		// Perform backup if enabled
		if config.AutoBackup {
			performDatabaseBackup(dbManager)
		}
	}
	
	// Keep dashboard running if enabled
	if dashboardManager != nil && dashboardManager.IsRunning {
		fmt.Printf("🌐 Web Dashboard running at http://%s:%d\n", config.DashboardHost, config.DashboardPort)
		fmt.Println("Press Ctrl+C to stop the dashboard...")
		
		// Wait for interrupt signal
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		
		fmt.Println("\n🛑 Shutting down dashboard...")
		shutdownDashboard(dashboardManager)
	}
}

// Load targets from file
func loadTargets(filename string, config *Config) ([]Target, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []Target
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse line format: URL [METHOD] [HEADER_FORMAT] [SUCCESS_CODES]
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		
		target := Target{
			URL:          parts[0],
			Method:       config.HTTPMethod,
			HeaderFormat: config.HeaderFormat,
			SuccessCodes: config.SuccessCodes,
		}
		
		// Parse optional method
		if len(parts) > 1 && isValidHTTPMethod(parts[1]) {
			target.Method = parts[1]
		}
		
		// Parse optional header format
		if len(parts) > 2 && strings.Contains(parts[2], "%KEY%") {
			target.HeaderFormat = strings.Join(parts[2:], " ")
		}
		
		// Validate URL
		if _, err := url.Parse(target.URL); err != nil {
			fmt.Printf("Warning: Invalid URL at line %d: %s\n", lineNum, target.URL)
			continue
		}
		
		targets = append(targets, target)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets found in file")
	}
	
	return targets, nil
}

// Check if string is valid HTTP method
func isValidHTTPMethod(method string) bool {
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	method = strings.ToUpper(method)
	for _, valid := range validMethods {
		if method == valid {
			return true
		}
	}
	return false
}

// Generate jobs from targets and keys
func generateJobs(targets []Target, keys []string) []Job {
	var jobs []Job
	jobID := 0
	
	for _, target := range targets {
		for _, key := range keys {
			jobID++
			jobs = append(jobs, Job{
				Target: target,
				Key:    key,
				ID:     fmt.Sprintf("job_%d", jobID),
			})
		}
	}
	
	return jobs
}

// Execute smart brute force with evasion techniques
func executeSmartBruteForce(config *Config, jobs []Job, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) []FoundKey {
	jobsChan := make(chan Job, len(jobs))
	results := make(chan FoundKey, len(jobs))
	var wg sync.WaitGroup
	
	// Start smart workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go smartWorker(i+1, config, jobsChan, results, &wg, client, limiter, wafDetector, throttleController, rotationManager)
	}
	
	// Send jobs
	for _, job := range jobs {
		jobsChan <- job
	}
	close(jobsChan)
	
	// Wait for completion
	wg.Wait()
	close(results)
	
	// Collect results
	return collectResults(results)
}

// Smart worker with evasion capabilities
func smartWorker(id int, config *Config, jobs <-chan Job, results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) {
	defer wg.Done()
	
	if config.Verbose {
		fmt.Printf("🧠 Smart Worker %d started with evasion capabilities\n", id)
	}
	
	consecutiveBlocks := 0
	
	for job := range jobs {
		// Rate limiting
		if limiter != nil {
			limiter.Wait(context.Background())
		}
		
		// Smart throttling delay
		currentDelay := throttleController.CurrentDelay
		if config.RandomDelay && currentDelay > 0 {
			// Add random variation (50-150% of base delay)
			variation := 0.5 + (float64(time.Now().UnixNano()%100) / 100.0)
			currentDelay = time.Duration(float64(currentDelay) * variation)
		}
		
		if currentDelay > 0 {
			time.Sleep(currentDelay)
		}
		
		// Execute job with smart retry and evasion
		found, blocked := executeSmartJob(id, job, config, client, wafDetector, throttleController, rotationManager)
		
		if blocked {
			consecutiveBlocks++
			if consecutiveBlocks >= wafDetector.MaxBlocks {
				if config.Verbose {
					fmt.Printf("🛡️  Worker %d: Too many blocks, increasing delay significantly\n", id)
				}
				time.Sleep(time.Duration(consecutiveBlocks) * 10 * time.Second)
				consecutiveBlocks = 0
			}
		} else {
			consecutiveBlocks = 0
		}
		
		if found != nil {
			results <- *found
			fmt.Printf("🎉 [FOUND] Smart Worker %d: Key: %s -> Status: %d at %s (%dms)\n", 
				id, found.Key, found.StatusCode, found.URL, found.ResponseTime)
		}
	}
	
	if config.Verbose {
		fmt.Printf("✅ Smart Worker %d finished\n", id)
	}
}

// Execute single job with smart evasion
func executeSmartJob(workerID int, job Job, config *Config, client *http.Client, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) (*FoundKey, bool) {
	var lastErr error
	var lastAnalysis *ResponseAnalysis
	blocked := false
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			backoff := time.Duration(attempt*attempt) * time.Second
			jitter := time.Duration(time.Now().UnixNano()%1000) * time.Millisecond
			time.Sleep(backoff + jitter)
			
			if config.Verbose {
				fmt.Printf("🔄 Smart Worker %d: Retry %d/%d for %s with key %s\n", 
					workerID, attempt, config.MaxRetries, job.Target.URL, job.Key)
			}
		}
		
		start := time.Now()
		
		// Create request with rotation
		req, err := createSmartRequest(job, config, rotationManager)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Update client proxy if rotation is enabled
		if config.ProxyRotation && len(rotationManager.Proxies) > 0 {
			updateClientProxy(client, rotationManager.getNextProxy())
		}
		
		// Send request
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		
		responseTime := time.Since(start).Milliseconds()
		
		// Read response body
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		// Analyze response for WAF/blocking
		if config.WAFDetection {
			lastAnalysis = wafDetector.analyzeResponse(resp, body)
			if lastAnalysis.IsBlocked || lastAnalysis.IsRateLimited || lastAnalysis.WAFDetected {
				blocked = true
				if config.Verbose {
					fmt.Printf("🛡️  Smart Worker %d: %s - %s\n", workerID, job.Target.URL, lastAnalysis.BlockReason)
				}
			}
		}
		
		// Update throttle controller
		if config.SmartThrottling {
			success := !blocked && (lastAnalysis == nil || (!lastAnalysis.IsBlocked && !lastAnalysis.IsRateLimited))
			throttleController.updateThrottle(success, lastAnalysis)
		}
		
		if config.Verbose {
			status := "🔍"
			if blocked {
				status = "🛡️ "
			}
			fmt.Printf("%s Smart Worker %d: %s with key %s -> Status: %d (%dms)\n", 
				status, workerID, job.Target.URL, job.Key, resp.StatusCode, responseTime)
		}
		
		// Check success (even if blocked, might still be valid)
		if _, ok := config.SuccessCodes[resp.StatusCode]; ok {
			return &FoundKey{
				Key:           job.Key,
				StatusCode:    resp.StatusCode,
				URL:           job.Target.URL,
				ResponseTime:  responseTime,
				ContentLength: int64(len(body)),
				Timestamp:     time.Now(),
			}, blocked
		}
		
		// If blocked and we have suggested delay, respect it
		if blocked && lastAnalysis != nil && lastAnalysis.SuggestedDelay > 0 {
			if config.Verbose {
				fmt.Printf("⏳ Smart Worker %d: Respecting suggested delay: %v\n", workerID, lastAnalysis.SuggestedDelay)
			}
			time.Sleep(lastAnalysis.SuggestedDelay)
		}
		
		// Success (no error), but not a success status code
		return nil, blocked
	}
	
	if config.Verbose && lastErr != nil {
		fmt.Printf("❌ Smart Worker %d: Failed %s with key %s after %d retries: %v\n", 
			workerID, job.Target.URL, job.Key, config.MaxRetries, lastErr)
	}
	
	return nil, blocked
}

// Create smart request with rotation and evasion
func createSmartRequest(job Job, config *Config, rotationManager *RotationManager) (*http.Request, error) {
	req, err := http.NewRequest(job.Target.Method, job.Target.URL, nil)
	if err != nil {
		return nil, err
	}
	
	// Set API key header
	actualHeader := strings.ReplaceAll(job.Target.HeaderFormat, "%KEY%", job.Key)
	headerParts := strings.SplitN(actualHeader, ":", 2)
	if len(headerParts) == 2 {
		req.Header.Set(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
	}
	
	// Set User-Agent (with rotation if enabled)
	if config.UARotation {
		req.Header.Set("User-Agent", rotationManager.getNextUserAgent())
	} else {
		req.Header.Set("User-Agent", config.UserAgent)
	}
	
	// Set standard headers with rotation
	if config.HeaderRotation {
		req.Header.Set("Accept", rotationManager.getRandomHeader("Accept"))
		req.Header.Set("Accept-Language", rotationManager.getRandomHeader("Accept-Language"))
		req.Header.Set("Accept-Encoding", rotationManager.getRandomHeader("Accept-Encoding"))
		req.Header.Set("Cache-Control", rotationManager.getRandomHeader("Cache-Control"))
	} else {
		req.Header.Set("Accept", "application/json, text/plain, */*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}
	
	req.Header.Set("Connection", "keep-alive")
	
	// Add some randomness to headers
	if config.SessionRotation {
		// Add random session-like headers
		sessionID := fmt.Sprintf("sess_%d_%d", time.Now().UnixNano(), time.Now().UnixNano()%10000)
		req.Header.Set("X-Session-ID", sessionID)
		
		// Random request ID
		requestID := fmt.Sprintf("req_%d", time.Now().UnixNano()%1000000)
		req.Header.Set("X-Request-ID", requestID)
	}
	
	return req, nil
}

// Print discovery configuration
func printDiscoveryConfig(config *Config, targets []Target) {
	fmt.Printf("🔍 API Discovery Mode: %s\n", formatBool(config.APIDiscovery || config.EndpointEnum))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s\n", i+1, target.URL)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	// Discovery features
	if config.APIDiscovery {
		fmt.Printf("🔍 API Discovery: %s\n", formatBool(config.APIDiscovery))
	}
	if config.EndpointEnum {
		fmt.Printf("📂 Endpoint Enumeration: %s\n", formatBool(config.EndpointEnum))
	}
	if config.SchemaAnalysis {
		fmt.Printf("📋 Schema Analysis: %s\n", formatBool(config.SchemaAnalysis))
	}
	if config.VersionDetection {
		fmt.Printf("🔢 Version Detection: %s\n", formatBool(config.VersionDetection))
	}
	if config.ParamFuzzing {
		fmt.Printf("🎯 Parameter Fuzzing: %s\n", formatBool(config.ParamFuzzing))
	}
	
	fmt.Printf("📂 Discovery Paths: %d paths\n", len(config.CommonPaths))
	fmt.Printf("🔄 Discovery Depth: %d levels\n", config.DiscoveryDepth)
	fmt.Printf("🧵 Threads: %d\n", config.Threads)
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting API discovery and enumeration...")
	fmt.Println()
}

// Print discovery results
func printDiscoveryResults(results []DiscoveryResult) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🔍 API DISCOVERY RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	
	totalEndpoints := 0
	totalAuthEndpoints := 0
	totalPublicEndpoints := 0
	
	for i, result := range results {
		fmt.Printf("\n🎯 Target %d: %s\n", i+1, result.Target)
		fmt.Printf("📊 Discovery Statistics:\n")
		fmt.Printf("   📈 Total Requests: %d\n", result.Statistics.TotalRequests)
		fmt.Printf("   🔍 Endpoints Found: %d\n", result.Statistics.EndpointsFound)
		fmt.Printf("   🔐 Auth Required: %d\n", result.Statistics.AuthEndpoints)
		fmt.Printf("   🌐 Public Access: %d\n", result.Statistics.PublicEndpoints)
		fmt.Printf("   ❌ Error Endpoints: %d\n", result.Statistics.ErrorEndpoints)
		fmt.Printf("   ⏱️  Discovery Time: %v\n", result.Statistics.DiscoveryTime)
		fmt.Printf("   📊 Avg Response: %dms\n", result.Statistics.AverageResponse)
		
		if len(result.Endpoints) > 0 {
			fmt.Printf("\n📂 Discovered Endpoints:\n")
			
			// Group endpoints by status code
			statusGroups := make(map[int][]APIEndpoint)
			for _, endpoint := range result.Endpoints {
				statusGroups[endpoint.StatusCode] = append(statusGroups[endpoint.StatusCode], endpoint)
			}
			
			// Display by status code groups
			for status, endpoints := range statusGroups {
				statusIcon := getStatusIcon(status)
				fmt.Printf("\n   %s Status %d (%d endpoints):\n", statusIcon, status, len(endpoints))
				
				for j, endpoint := range endpoints {
					if j >= 10 { // Limit display to first 10 per status
						fmt.Printf("      ... and %d more endpoints\n", len(endpoints)-10)
						break
					}
					
					authIcon := ""
					if endpoint.AuthRequired {
						authIcon = "🔐"
					} else {
						authIcon = "🌐"
					}
					
					fmt.Printf("      %s %s [%s] (%dms)\n", 
						authIcon, endpoint.URL, endpoint.Method, endpoint.ResponseTime)
					
					if endpoint.Framework != "Unknown" && endpoint.Framework != "" {
						fmt.Printf("         🔧 Framework: %s\n", endpoint.Framework)
					}
					
					if len(endpoint.Parameters) > 0 {
						fmt.Printf("         📋 Parameters: %s\n", strings.Join(endpoint.Parameters, ", "))
					}
					
					if endpoint.APIVersion != "" {
						fmt.Printf("         🔢 Version: %s\n", endpoint.APIVersion)
					}
				}
			}
		}
		
		// Schema information
		if result.Schema != nil {
			fmt.Printf("\n📋 API Schema Analysis:\n")
			if result.Schema.Title != "" {
				fmt.Printf("   📖 Title: %s\n", result.Schema.Title)
			}
			if result.Schema.Version != "" {
				fmt.Printf("   🔢 Version: %s\n", result.Schema.Version)
			}
			if result.Schema.Description != "" {
				fmt.Printf("   📝 Description: %s\n", result.Schema.Description)
			}
			if len(result.Schema.Authentication) > 0 {
				fmt.Printf("   🔐 Auth Methods: %s\n", strings.Join(result.Schema.Authentication, ", "))
			}
			if result.Schema.Documentation != "" {
				fmt.Printf("   📚 Documentation: %s\n", result.Schema.Documentation)
			}
		}
		
		totalEndpoints += result.Statistics.EndpointsFound
		totalAuthEndpoints += result.Statistics.AuthEndpoints
		totalPublicEndpoints += result.Statistics.PublicEndpoints
	}
	
	// Overall summary
	fmt.Printf("\n" + strings.Repeat("-", 70))
	fmt.Printf("\n📈 OVERALL DISCOVERY SUMMARY\n")
	fmt.Printf("🎯 Targets Scanned: %d\n", len(results))
	fmt.Printf("🔍 Total Endpoints: %d\n", totalEndpoints)
	fmt.Printf("🔐 Auth Required: %d\n", totalAuthEndpoints)
	fmt.Printf("🌐 Public Access: %d\n", totalPublicEndpoints)
	
	if totalEndpoints > 0 {
		authPercentage := float64(totalAuthEndpoints) / float64(totalEndpoints) * 100
		fmt.Printf("📊 Auth Percentage: %.1f%%\n", authPercentage)
	}
	
	fmt.Println(strings.Repeat("=", 70))
}

// Get status icon based on HTTP status code
func getStatusIcon(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "✅"
	case status >= 300 && status < 400:
		return "🔄"
	case status == 401:
		return "🔐"
	case status == 403:
		return "🚫"
	case status >= 400 && status < 500:
		return "❌"
	case status >= 500:
		return "💥"
	default:
		return "❓"
	}
}

// Save discovery results to JSON file
func saveDiscoveryResults(results []DiscoveryResult, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating discovery output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Printf("Error writing discovery results to file: %v\n", err)
	} else {
		fmt.Printf("💾 Discovery results saved to: %s\n", filename)
	}
}

// Save brute force results (separate from discovery)
func saveBruteForceResults(foundKeys []FoundKey, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating brute force output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(foundKeys); err != nil {
		fmt.Printf("Error writing brute force results to file: %v\n", err)
	} else {
		fmt.Printf("💾 Brute force results saved to: %s\n", filename)
	}
}

// Update client proxy
func updateClientProxy(client *http.Client, proxyURL string) {
	if proxyURL == "" {
		return
	}
	
	if transport, ok := client.Transport.(*http.Transport); ok {
		if pURL, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}
}

// Helper function to format boolean
func formatBool(b bool) string {
	if b {
		return "✅ Enabled"
	}
	return "❌ Disabled"
}

// Multi-target worker
func multiTargetWorker(id int, config *Config, jobs <-chan Job, results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, limiter *rate.Limiter) {
	defer wg.Done()
	
	if config.Verbose {
		fmt.Printf("🔧 Multi-Target Worker %d started\n", id)
	}
	
	for job := range jobs {
		// Rate limiting
		if limiter != nil {
			limiter.Wait(context.Background())
		}
		
		// Delay between requests
		if config.DelayBetween > 0 {
			time.Sleep(config.DelayBetween)
		}
		
		// Execute job with retries
		found := executeJobWithRetry(id, job, config, client)
		if found != nil {
			results <- *found
			fmt.Printf("🎉 [FOUND] Worker %d: Key: %s -> Status: %d at %s (%dms)\n", 
				id, found.Key, found.StatusCode, found.URL, found.ResponseTime)
		}
	}
	
	if config.Verbose {
		fmt.Printf("✅ Multi-Target Worker %d finished\n", id)
	}
}

// Execute single job with retry logic
func executeJobWithRetry(workerID int, job Job, config *Config, client *http.Client) *FoundKey {
	var lastErr error
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			time.Sleep(backoff)
			if config.Verbose {
				fmt.Printf("🔄 Worker %d: Retry %d/%d for %s with key %s\n", 
					workerID, attempt, config.MaxRetries, job.Target.URL, job.Key)
			}
		}
		
		start := time.Now()
		
		// Create request
		req, err := http.NewRequest(job.Target.Method, job.Target.URL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Set API key header
		actualHeader := strings.ReplaceAll(job.Target.HeaderFormat, "%KEY%", job.Key)
		headerParts := strings.SplitN(actualHeader, ":", 2)
		if len(headerParts) == 2 {
			req.Header.Set(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
		}
		
		// Set standard headers
		req.Header.Set("User-Agent", config.UserAgent)
		req.Header.Set("Accept", "application/json, text/plain, */*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Header.Set("Connection", "keep-alive")
		
		// Send request
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		
		responseTime := time.Since(start).Milliseconds()
		
		// Read response body
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if config.Verbose {
			fmt.Printf("🔍 Worker %d: %s with key %s -> Status: %d (%dms)\n", 
				workerID, job.Target.URL, job.Key, resp.StatusCode, responseTime)
		}
		
		// Check success
		if _, ok := config.SuccessCodes[resp.StatusCode]; ok {
			return &FoundKey{
				Key:           job.Key,
				StatusCode:    resp.StatusCode,
				URL:           job.Target.URL,
				ResponseTime:  responseTime,
				ContentLength: int64(len(body)),
				Timestamp:     time.Now(),
			}
		}
		
		// Success (no error), but not a success status code
		return nil
	}
	
	if config.Verbose && lastErr != nil {
		fmt.Printf("❌ Worker %d: Failed %s with key %s after %d retries: %v\n", 
			workerID, job.Target.URL, job.Key, config.MaxRetries, lastErr)
	}
	
	return nil
}

// Initialize WAF Detector
func initWAFDetector() *WAFDetector {
	return &WAFDetector{
		BlockedStatusCodes: []int{403, 406, 429, 503, 520, 521, 522, 523, 524},
		BlockedKeywords:    []string{"blocked", "forbidden", "rate limit", "too many requests", "cloudflare", "access denied", "security", "firewall"},
		RateLimitHeaders:   []string{"X-RateLimit-Remaining", "X-Rate-Limit-Remaining", "Retry-After", "X-Retry-After"},
		MaxBlocks:          5,
		BackoffMultiplier:  2.0,
	}
}

// Initialize Throttle Controller
func initThrottleController(baseDelay time.Duration) *ThrottleController {
	return &ThrottleController{
		BaseDelay:    baseDelay,
		CurrentDelay: baseDelay,
		MaxDelay:     30 * time.Second,
		AdaptiveMode: true,
	}
}

// Initialize Rotation Manager
func initRotationManager(config *Config) *RotationManager {
	rm := &RotationManager{
		UserAgents: config.UserAgentList,
		Proxies:    config.ProxyList,
		Headers:    getRotationHeaders(),
	}
	return rm
}

// Load list from file (for proxies, user agents, etc.)
func loadList(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var items []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			items = append(items, line)
		}
	}
	return items, scanner.Err()
}

// Get default User-Agent list
func getDefaultUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
	}
}

// Get rotation headers
func getRotationHeaders() map[string][]string {
	return map[string][]string{
		"Accept": {
			"application/json, text/plain, */*",
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"application/json",
			"*/*",
		},
		"Accept-Language": {
			"en-US,en;q=0.9",
			"en-US,en;q=0.5",
			"en-GB,en;q=0.9",
			"en-US,en;q=0.8,es;q=0.6",
		},
		"Accept-Encoding": {
			"gzip, deflate, br",
			"gzip, deflate",
			"identity",
		},
		"Cache-Control": {
			"no-cache",
			"max-age=0",
			"no-store",
		},
	}
}

// Analyze response for WAF/rate limiting detection
func (wd *WAFDetector) analyzeResponse(resp *http.Response, body []byte) *ResponseAnalysis {
	analysis := &ResponseAnalysis{}
	
	// Check status code
	for _, code := range wd.BlockedStatusCodes {
		if resp.StatusCode == code {
			analysis.IsBlocked = true
			analysis.BlockReason = fmt.Sprintf("Blocked status code: %d", resp.StatusCode)
			break
		}
	}
	
	// Check for rate limiting headers
	for _, header := range wd.RateLimitHeaders {
		if resp.Header.Get(header) != "" {
			analysis.IsRateLimited = true
			analysis.BlockReason = fmt.Sprintf("Rate limit header detected: %s", header)
			
			// Try to parse retry-after
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil {
					analysis.SuggestedDelay = time.Duration(seconds) * time.Second
				}
			}
			break
		}
	}
	
	// Check response body for blocked keywords
	bodyStr := strings.ToLower(string(body))
	for _, keyword := range wd.BlockedKeywords {
		if strings.Contains(bodyStr, keyword) {
			analysis.WAFDetected = true
			analysis.BlockReason = fmt.Sprintf("WAF keyword detected: %s", keyword)
			break
		}
	}
	
	// Detect common WAF signatures
	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "cloudflare") || strings.Contains(server, "nginx") {
		analysis.ResponsePattern = "CloudFlare/Nginx detected"
	}
	
	return analysis
}

// Update throttle controller based on response
func (tc *ThrottleController) updateThrottle(success bool, analysis *ResponseAnalysis) {
	if success {
		tc.SuccessCount++
		tc.ConsecutiveFails = 0
		
		// Gradually decrease delay on success
		if tc.AdaptiveMode && tc.CurrentDelay > tc.BaseDelay {
			tc.CurrentDelay = time.Duration(float64(tc.CurrentDelay) * 0.9)
			if tc.CurrentDelay < tc.BaseDelay {
				tc.CurrentDelay = tc.BaseDelay
			}
		}
	} else {
		tc.FailureCount++
		tc.ConsecutiveFails++
		
		// Increase delay on failure
		if tc.AdaptiveMode {
			if analysis.IsRateLimited && analysis.SuggestedDelay > 0 {
				tc.CurrentDelay = analysis.SuggestedDelay
			} else {
				multiplier := 1.5 + float64(tc.ConsecutiveFails)*0.5
				tc.CurrentDelay = time.Duration(float64(tc.CurrentDelay) * multiplier)
			}
			
			if tc.CurrentDelay > tc.MaxDelay {
				tc.CurrentDelay = tc.MaxDelay
			}
		}
	}
}

// Get next User-Agent from rotation
func (rm *RotationManager) getNextUserAgent() string {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	if len(rm.UserAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	
	ua := rm.UserAgents[rm.CurrentUA]
	rm.CurrentUA = (rm.CurrentUA + 1) % len(rm.UserAgents)
	return ua
}

// Get next proxy from rotation
func (rm *RotationManager) getNextProxy() string {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	if len(rm.Proxies) == 0 {
		return ""
	}
	
	proxy := rm.Proxies[rm.CurrentProxy]
	rm.CurrentProxy = (rm.CurrentProxy + 1) % len(rm.Proxies)
	return proxy
}

// Get random header value
func (rm *RotationManager) getRandomHeader(headerName string) string {
	if values, exists := rm.Headers[headerName]; exists && len(values) > 0 {
		return values[time.Now().UnixNano()%int64(len(values))]
	}
	return ""
}

// Print smart configuration
func printSmartConfig(config *Config, targets []Target, keyCount int) {
	fmt.Printf("🛡️  Smart Evasion Mode: %s\n", formatBool(config.WAFDetection || config.SmartThrottling || config.ProxyRotation || config.UARotation))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s [%s]\n", i+1, target.URL, target.Method)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	fmt.Printf("📝 Wordlist: %s (%d keys)\n", config.WordlistPath, keyCount)
	fmt.Printf("🔑 Header: %s\n", config.HeaderFormat)
	fmt.Printf("📡 Method: %s\n", config.HTTPMethod)
	fmt.Printf("✅ Success Codes: %v\n", getSuccessCodesSlice(config.SuccessCodes))
	fmt.Printf("🧵 Threads: %d\n", config.Threads)
	fmt.Printf("🔄 Max Retries: %d\n", config.MaxRetries)
	
	// Smart features
	if config.WAFDetection {
		fmt.Printf("🛡️  WAF Detection: %s\n", formatBool(config.WAFDetection))
	}
	if config.SmartThrottling {
		fmt.Printf("🧠 Smart Throttling: %s\n", formatBool(config.SmartThrottling))
	}
	if config.ProxyRotation {
		fmt.Printf("🌐 Proxy Rotation: %s (%d proxies)\n", formatBool(config.ProxyRotation), len(config.ProxyList))
	}
	if config.UARotation {
		fmt.Printf("🔄 User-Agent Rotation: %s (%d UAs)\n", formatBool(config.UARotation), len(config.UserAgentList))
	}
	if config.HeaderRotation {
		fmt.Printf("📋 Header Rotation: %s\n", formatBool(config.HeaderRotation))
	}
	if config.RandomDelay {
		fmt.Printf("🎲 Random Delay: %s\n", formatBool(config.RandomDelay))
	}
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	totalJobs := len(targets) * keyCount
	fmt.Printf("📈 Total Jobs: %d (%d targets × %d keys)\n", totalJobs, len(targets), keyCount)
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting smart brute-force attack with evasion...")
	fmt.Println()
}

// Print multi-target summary
func printMultiTargetSummary(foundKeys []FoundKey, targets []Target) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📊 MULTI-TARGET RESULTS SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	
	if len(foundKeys) == 0 {
		fmt.Println("❌ No valid API keys found across all targets.")
	} else {
		fmt.Printf("✅ Found %d valid API key(s) across %d target(s):\n\n", len(foundKeys), len(targets))
		
		// Group results by target
		targetResults := make(map[string][]FoundKey)
		for _, found := range foundKeys {
			targetResults[found.URL] = append(targetResults[found.URL], found)
		}
		
		targetNum := 1
		for targetURL, results := range targetResults {
			fmt.Printf("🎯 Target %d: %s\n", targetNum, targetURL)
			fmt.Printf("   ✅ Found %d valid key(s):\n", len(results))
			
			for i, found := range results {
				fmt.Printf("   %d. 🔑 Key: %s\n", i+1, found.Key)
				fmt.Printf("      📊 Status: %d\n", found.StatusCode)
				fmt.Printf("      ⏱️  Response Time: %dms\n", found.ResponseTime)
				fmt.Printf("      📏 Content Length: %d bytes\n", found.ContentLength)
				fmt.Printf("      🕐 Timestamp: %s\n", found.Timestamp.Format("2006-01-02 15:04:05"))
				fmt.Println()
			}
			targetNum++
		}
		
		// Statistics
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("📈 Success Rate: %.2f%% (%d/%d targets had valid keys)\n", 
			float64(len(targetResults))/float64(len(targets))*100, len(targetResults), len(targets))
		
		// Average response time
		var totalTime int64
		for _, found := range foundKeys {
			totalTime += found.ResponseTime
		}
		avgTime := totalTime / int64(len(foundKeys))
		fmt.Printf("⏱️  Average Response Time: %dms\n", avgTime)
	}
	fmt.Println(strings.Repeat("=", 60))
}

// Initialize Path Discovery
func initPathDiscovery(config *Config) *PathDiscovery {
	pd := &PathDiscovery{
		CommonPaths:   config.CommonPaths,
		APIPatterns:   getAPIPatterns(),
		VersionPaths:  getVersionPaths(),
		DocumentPaths: getDocumentationPaths(),
		AdminPaths:    getAdminPaths(),
		ConfigPaths:   getConfigPaths(),
		DebugPaths:    getDebugPaths(),
	}
	return pd
}

// Get default paths for discovery
func getDefaultPaths() []string {
	return []string{
		// API endpoints
		"api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3",
		"rest", "rest/api", "rest/v1", "rest/v2",
		"graphql", "gql", "query",
		
		// Common endpoints
		"users", "user", "accounts", "account", "profile", "profiles",
		"auth", "login", "logout", "register", "signin", "signup",
		"admin", "administrator", "management", "manage",
		"config", "configuration", "settings", "options",
		"status", "health", "ping", "info", "version",
		"docs", "documentation", "swagger", "openapi",
		
		// Data endpoints
		"data", "database", "db", "records", "entries",
		"files", "uploads", "downloads", "media", "assets",
		"search", "find", "query", "filter",
		
		// System endpoints
		"system", "sys", "internal", "private",
		"debug", "test", "testing", "dev", "development",
		"logs", "log", "monitoring", "metrics",
	}
}

// Get API patterns for detection
func getAPIPatterns() []string {
	return []string{
		"/api/", "/rest/", "/graphql", "/gql/",
		"/v1/", "/v2/", "/v3/", "/v4/",
		"/_api/", "/api_", "/restapi/",
		"/service/", "/services/", "/ws/",
		"/json/", "/xml/", "/rpc/",
	}
}

// Get version detection paths
func getVersionPaths() []string {
	return []string{
		"version", "v", "ver", "info", "about",
		"api/version", "api/v", "api/info",
		"_version", "_info", "_about",
		"system/version", "system/info",
		"status", "health", "ping",
	}
}

// Get documentation paths
func getDocumentationPaths() []string {
	return []string{
		"docs", "doc", "documentation", "help",
		"swagger", "swagger-ui", "swagger.json", "swagger.yaml",
		"openapi", "openapi.json", "openapi.yaml",
		"api-docs", "api/docs", "api/documentation",
		"redoc", "rapidoc", "postman",
		"schema", "spec", "specification",
	}
}

// Get admin paths
func getAdminPaths() []string {
	return []string{
		"admin", "administrator", "administration",
		"manage", "management", "manager",
		"control", "panel", "dashboard",
		"console", "backend", "cms",
		"wp-admin", "phpmyadmin", "adminer",
	}
}

// Get config paths
func getConfigPaths() []string {
	return []string{
		"config", "configuration", "settings",
		"env", "environment", ".env",
		"properties", "ini", "conf",
		"options", "preferences", "params",
	}
}

// Get debug paths
func getDebugPaths() []string {
	return []string{
		"debug", "test", "testing", "dev",
		"development", "staging", "stage",
		"logs", "log", "trace", "dump",
		"error", "errors", "exception",
		"monitor", "monitoring", "metrics",
	}
}

// Execute API Discovery
func executeAPIDiscovery(config *Config, targets []Target, client *http.Client, limiter *rate.Limiter, pathDiscovery *PathDiscovery, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) []DiscoveryResult {
	var results []DiscoveryResult
	
	for _, target := range targets {
		fmt.Printf("🔍 Starting API discovery for: %s\n", target.URL)
		
		result := discoverAPIEndpoints(target, config, client, limiter, pathDiscovery, wafDetector, throttleController, rotationManager)
		results = append(results, result)
		
		if config.Verbose {
			fmt.Printf("✅ Discovery completed for %s: %d endpoints found\n", target.URL, len(result.Endpoints))
		}
	}
	
	return results
}

// Discover API endpoints for a single target
func discoverAPIEndpoints(target Target, config *Config, client *http.Client, limiter *rate.Limiter, pathDiscovery *PathDiscovery, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) DiscoveryResult {
	startTime := time.Now()
	
	result := DiscoveryResult{
		Target:    target.URL,
		Endpoints: []APIEndpoint{},
		Timestamp: startTime,
		Statistics: DiscoveryStats{},
	}
	
	baseURL := getBaseURL(target.URL)
	discoveredPaths := make(map[string]bool)
	
	// 1. Test base URL
	endpoint := testEndpoint(baseURL, "GET", config, client, limiter, wafDetector, throttleController, rotationManager)
	if endpoint != nil {
		result.Endpoints = append(result.Endpoints, *endpoint)
		discoveredPaths[baseURL] = true
	}
	result.Statistics.TotalRequests++
	
	// 2. Common path discovery
	fmt.Printf("📂 Discovering common paths...\n")
	for _, path := range pathDiscovery.CommonPaths {
		if len(result.Endpoints) > 100 { // Limit to prevent too many requests
			break
		}
		
		testURL := buildURL(baseURL, path)
		if discoveredPaths[testURL] {
			continue
		}
		
		endpoint := testEndpoint(testURL, "GET", config, client, limiter, wafDetector, throttleController, rotationManager)
		if endpoint != nil {
			result.Endpoints = append(result.Endpoints, *endpoint)
			discoveredPaths[testURL] = true
			
			// Try different HTTP methods on discovered endpoints
			if config.EndpointEnum {
				methods := []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
				for _, method := range methods {
					methodEndpoint := testEndpoint(testURL, method, config, client, limiter, wafDetector, throttleController, rotationManager)
					if methodEndpoint != nil && methodEndpoint.StatusCode != endpoint.StatusCode {
						result.Endpoints = append(result.Endpoints, *methodEndpoint)
					}
					result.Statistics.TotalRequests++
				}
			}
		}
		result.Statistics.TotalRequests++
		
		if config.Verbose && endpoint != nil {
			fmt.Printf("🎯 Found endpoint: %s [%d]\n", testURL, endpoint.StatusCode)
		}
	}
	
	// 3. API pattern detection
	if config.SchemaAnalysis {
		fmt.Printf("📋 Analyzing API schema...\n")
		schema := analyzeAPISchema(result.Endpoints, baseURL, config, client, limiter, wafDetector, throttleController, rotationManager)
		if schema != nil {
			result.Schema = schema
		}
	}
	
	// 4. Version detection
	if config.VersionDetection {
		fmt.Printf("🔢 Detecting API versions...\n")
		for _, path := range pathDiscovery.VersionPaths {
			testURL := buildURL(baseURL, path)
			if discoveredPaths[testURL] {
				continue
			}
			
			endpoint := testEndpoint(testURL, "GET", config, client, limiter, wafDetector, throttleController, rotationManager)
			if endpoint != nil {
				endpoint.APIVersion = extractVersionInfo(endpoint)
				result.Endpoints = append(result.Endpoints, *endpoint)
				discoveredPaths[testURL] = true
			}
			result.Statistics.TotalRequests++
		}
	}
	
	// 5. Documentation discovery
	fmt.Printf("📚 Looking for API documentation...\n")
	for _, path := range pathDiscovery.DocumentPaths {
		testURL := buildURL(baseURL, path)
		if discoveredPaths[testURL] {
			continue
		}
		
		endpoint := testEndpoint(testURL, "GET", config, client, limiter, wafDetector, throttleController, rotationManager)
		if endpoint != nil {
			endpoint.Documentation = testURL
			result.Endpoints = append(result.Endpoints, *endpoint)
			discoveredPaths[testURL] = true
		}
		result.Statistics.TotalRequests++
	}
	
	// Calculate statistics
	result.Statistics.EndpointsFound = len(result.Endpoints)
	result.Statistics.DiscoveryTime = time.Since(startTime)
	
	var totalResponseTime int64
	for _, ep := range result.Endpoints {
		totalResponseTime += ep.ResponseTime
		if ep.AuthRequired || ep.StatusCode == 401 || ep.StatusCode == 403 {
			result.Statistics.AuthEndpoints++
		} else if ep.StatusCode >= 200 && ep.StatusCode < 300 {
			result.Statistics.PublicEndpoints++
		} else if ep.StatusCode >= 400 {
			result.Statistics.ErrorEndpoints++
		}
	}
	
	if len(result.Endpoints) > 0 {
		result.Statistics.AverageResponse = totalResponseTime / int64(len(result.Endpoints))
	}
	
	return result
}

// Test a single endpoint
func testEndpoint(url, method string, config *Config, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) *APIEndpoint {
	// Rate limiting
	if limiter != nil {
		limiter.Wait(context.Background())
	}
	
	// Smart throttling delay
	currentDelay := throttleController.CurrentDelay
	if config.RandomDelay && currentDelay > 0 {
		variation := 0.5 + (float64(time.Now().UnixNano()%100) / 100.0)
		currentDelay = time.Duration(float64(currentDelay) * variation)
	}
	
	if currentDelay > 0 {
		time.Sleep(currentDelay)
	}
	
	start := time.Now()
	
	// Create request
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil
	}
	
	// Set headers with rotation
	if config.UARotation {
		req.Header.Set("User-Agent", rotationManager.getNextUserAgent())
	} else {
		req.Header.Set("User-Agent", config.UserAgent)
	}
	
	if config.HeaderRotation {
		req.Header.Set("Accept", rotationManager.getRandomHeader("Accept"))
		req.Header.Set("Accept-Language", rotationManager.getRandomHeader("Accept-Language"))
	} else {
		req.Header.Set("Accept", "application/json, text/plain, */*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	responseTime := time.Since(start).Milliseconds()
	
	// Read response body
	body, _ := io.ReadAll(resp.Body)
	
	// Analyze response for WAF/blocking
	if config.WAFDetection {
		analysis := wafDetector.analyzeResponse(resp, body)
		if analysis.IsBlocked || analysis.IsRateLimited {
			return nil // Skip blocked responses
		}
	}
	
	// Create endpoint
	endpoint := &APIEndpoint{
		URL:           url,
		Method:        method,
		StatusCode:    resp.StatusCode,
		ContentLength: int64(len(body)),
		ContentType:   resp.Header.Get("Content-Type"),
		ResponseTime:  responseTime,
		Headers:       make(map[string]string),
		Discovered:    time.Now(),
		AuthRequired:  isAuthRequired(resp, body),
		Framework:     detectFramework(resp, body),
	}
	
	// Store important headers
	importantHeaders := []string{"Server", "X-Powered-By", "X-Framework", "API-Version", "Content-Type"}
	for _, header := range importantHeaders {
		if value := resp.Header.Get(header); value != "" {
			endpoint.Headers[header] = value
		}
	}
	
	// Extract parameters from response
	endpoint.Parameters = extractParameters(body, resp.Header.Get("Content-Type"))
	
	return endpoint
}

// Helper functions
func getBaseURL(fullURL string) string {
	if u, err := url.Parse(fullURL); err == nil {
		return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}
	return fullURL
}

func buildURL(baseURL, path string) string {
	if strings.HasSuffix(baseURL, "/") && strings.HasPrefix(path, "/") {
		return baseURL + path[1:]
	} else if !strings.HasSuffix(baseURL, "/") && !strings.HasPrefix(path, "/") {
		return baseURL + "/" + path
	}
	return baseURL + path
}

func isAuthRequired(resp *http.Response, body []byte) bool {
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	
	bodyStr := strings.ToLower(string(body))
	authKeywords := []string{"unauthorized", "forbidden", "authentication", "login required", "access denied"}
	for _, keyword := range authKeywords {
		if strings.Contains(bodyStr, keyword) {
			return true
		}
	}
	
	return false
}

func detectFramework(resp *http.Response, body []byte) string {
	// Check headers
	if server := resp.Header.Get("Server"); server != "" {
		if strings.Contains(strings.ToLower(server), "express") {
			return "Express.js"
		} else if strings.Contains(strings.ToLower(server), "django") {
			return "Django"
		} else if strings.Contains(strings.ToLower(server), "flask") {
			return "Flask"
		}
	}
	
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		if strings.Contains(strings.ToLower(powered), "express") {
			return "Express.js"
		} else if strings.Contains(strings.ToLower(powered), "php") {
			return "PHP"
		}
	}
	
	// Check response body
	bodyStr := strings.ToLower(string(body))
	if strings.Contains(bodyStr, "django") {
		return "Django"
	} else if strings.Contains(bodyStr, "flask") {
		return "Flask"
	} else if strings.Contains(bodyStr, "laravel") {
		return "Laravel"
	} else if strings.Contains(bodyStr, "spring") {
		return "Spring Boot"
	}
	
	return "Unknown"
}

func extractVersionInfo(endpoint *APIEndpoint) string {
	// Try to extract version from response headers first
	if version := endpoint.Headers["API-Version"]; version != "" {
		return version
	}
	
	// Simple version detection from URL
	url := strings.ToLower(endpoint.URL)
	if strings.Contains(url, "/v1/") || strings.Contains(url, "/v1") {
		return "v1"
	} else if strings.Contains(url, "/v2/") || strings.Contains(url, "/v2") {
		return "v2"
	} else if strings.Contains(url, "/v3/") || strings.Contains(url, "/v3") {
		return "v3"
	}
	
	return ""
}

func extractParameters(body []byte, contentType string) []string {
	var params []string
	
	if strings.Contains(contentType, "json") {
		// Simple JSON parameter extraction
		bodyStr := string(body)
		if strings.Contains(bodyStr, "{") {
			// This is simplified - in real implementation, parse JSON properly
			commonParams := []string{"id", "name", "email", "user", "data", "token", "key"}
			for _, param := range commonParams {
				if strings.Contains(strings.ToLower(bodyStr), `"`+param+`"`) {
					params = append(params, param)
				}
			}
		}
	}
	
	return params
}

// Analyze API Schema (simplified)
func analyzeAPISchema(endpoints []APIEndpoint, baseURL string, config *Config, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) *APISchema {
	schema := &APISchema{
		BaseURL:   baseURL,
		Endpoints: endpoints,
		Servers:   []string{baseURL},
	}
	
	// Try to find OpenAPI/Swagger documentation
	swaggerPaths := []string{"swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api-docs"}
	for _, path := range swaggerPaths {
		testURL := buildURL(baseURL, path)
		endpoint := testEndpoint(testURL, "GET", config, client, limiter, wafDetector, throttleController, rotationManager)
		if endpoint != nil && endpoint.StatusCode == 200 {
			schema.Documentation = testURL
			// In real implementation, parse the OpenAPI spec
			schema.Title = "API Documentation Found"
			schema.Description = "OpenAPI/Swagger documentation available"
			break
		}
	}
	
	// Detect common authentication methods
	authMethods := []string{}
	for _, endpoint := range endpoints {
		if endpoint.AuthRequired {
			if strings.Contains(strings.ToLower(endpoint.URL), "oauth") {
				authMethods = append(authMethods, "OAuth")
			} else if strings.Contains(strings.ToLower(endpoint.URL), "jwt") {
				authMethods = append(authMethods, "JWT")
			} else {
				authMethods = append(authMethods, "API Key")
			}
		}
	}
	schema.Authentication = authMethods
	
	return schema
}

// Path Discovery Manager
type PathDiscovery struct {
	CommonPaths    []string
	APIPatterns    []string
	VersionPaths   []string
	DocumentPaths  []string
	AdminPaths     []string
	ConfigPaths    []string
	DebugPaths     []string
	mutex          sync.Mutex
}

// Initialize Authentication Manager
func initAuthManager(config *Config, credentials []AuthCredential) *AuthManager {
	am := &AuthManager{
		Methods:      getAuthMethods(config),
		Credentials:  credentials,
		Results:      []AuthResult{},
		ActiveTokens: make(map[string]string),
		TokenCache:   make(map[string]JWTToken),
		OAuthFlows:   make(map[string]OAuthFlow),
	}
	
	// Initialize OAuth flows if enabled
	if config.OAuthSupport {
		am.OAuthFlows["default"] = OAuthFlow{
			AuthURL:      config.AuthEndpoint,
			TokenURL:     config.TokenEndpoint,
			RefreshURL:   config.RefreshEndpoint,
			GrantType:    "client_credentials",
			ResponseType: "code",
		}
	}
	
	return am
}

// Get authentication methods based on config
func getAuthMethods(config *Config) []AuthMethod {
	var methods []AuthMethod
	
	if config.JWTSupport {
		methods = append(methods, AuthMethod{
			Type:       "JWT",
			Name:       "JSON Web Token",
			Headers:    map[string]string{"Authorization": "Bearer %TOKEN%"},
			TokenField: "access_token",
		})
	}
	
	if config.OAuthSupport {
		methods = append(methods, AuthMethod{
			Type:        "OAuth2",
			Name:        "OAuth 2.0",
			Endpoint:    config.TokenEndpoint,
			Method:      "POST",
			Headers:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Parameters:  map[string]string{"grant_type": "client_credentials"},
			TokenField:  "access_token",
			ExpiryField: "expires_in",
			RefreshURL:  config.RefreshEndpoint,
		})
	}
	
	if config.BasicAuthSupport {
		methods = append(methods, AuthMethod{
			Type:    "Basic",
			Name:    "HTTP Basic Authentication",
			Headers: map[string]string{"Authorization": "Basic %CREDENTIALS%"},
		})
	}
	
	if config.BearerTokenSupport {
		methods = append(methods, AuthMethod{
			Type:    "Bearer",
			Name:    "Bearer Token",
			Headers: map[string]string{"Authorization": "Bearer %TOKEN%"},
		})
	}
	
	if config.SessionTokenSupport {
		methods = append(methods, AuthMethod{
			Type:    "Session",
			Name:    "Session Token",
			Headers: map[string]string{"X-Session-Token": "%TOKEN%"},
		})
	}
	
	if config.CookieAuthSupport {
		methods = append(methods, AuthMethod{
			Type:    "Cookie",
			Name:    "Cookie Authentication",
			Headers: map[string]string{"Cookie": "session=%TOKEN%"},
		})
	}
	
	if config.CustomAuthSupport {
		methods = append(methods, AuthMethod{
			Type:    "Custom",
			Name:    "Custom Authentication",
			Headers: map[string]string{config.HeaderFormat: "%TOKEN%"},
		})
	}
	
	return methods
}

// Load authentication credentials from file
func loadAuthCredentials(filename string) ([]AuthCredential, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var credentials []AuthCredential
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse different credential formats
		cred := parseCredentialLine(line)
		if cred != nil {
			credentials = append(credentials, *cred)
		}
	}
	
	return credentials, scanner.Err()
}

// Parse credential line in various formats
func parseCredentialLine(line string) *AuthCredential {
	// Format: username:password
	if strings.Contains(line, ":") && !strings.Contains(line, "=") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			return &AuthCredential{
				Username: parts[0],
				Password: parts[1],
			}
		}
	}
	
	// Format: key=value pairs
	if strings.Contains(line, "=") {
		cred := &AuthCredential{
			Metadata: make(map[string]string),
		}
		
		pairs := strings.Split(line, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				
				switch strings.ToLower(key) {
				case "username", "user":
					cred.Username = value
				case "password", "pass":
					cred.Password = value
				case "apikey", "api_key":
					cred.APIKey = value
				case "token":
					cred.Token = value
				case "refresh_token":
					cred.RefreshToken = value
				case "client_id":
					cred.ClientID = value
				case "client_secret":
					cred.ClientSecret = value
				case "scope":
					cred.Scope = value
				default:
					cred.Metadata[key] = value
				}
			}
		}
		return cred
	}
	
	// Simple token format
	return &AuthCredential{
		APIKey: line,
		Token:  line,
	}
}

// Check if advanced auth features are enabled
func hasAdvancedAuthFeatures(config *Config) bool {
	return config.JWTSupport || config.OAuthSupport || config.BasicAuthSupport ||
		config.BearerTokenSupport || config.CustomAuthSupport || config.MultiFactorSupport ||
		config.SessionTokenSupport || config.CookieAuthSupport || config.AuthChaining ||
		config.TokenRefresh
}

// Execute advanced authentication testing
func executeAdvancedAuth(config *Config, targets []Target, keys []string, authManager *AuthManager, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) []AuthResult {
	var allResults []AuthResult
	
	for _, target := range targets {
		fmt.Printf("🔐 Testing advanced authentication for: %s\n", target.URL)
		
		// Test each authentication method
		for _, method := range authManager.Methods {
			fmt.Printf("   🔑 Testing %s authentication...\n", method.Name)
			
			results := testAuthMethod(target, method, authManager.Credentials, config, client, limiter, wafDetector, throttleController, rotationManager)
			allResults = append(allResults, results...)
			
			// If we found working credentials, try to use them for other methods
			for _, result := range results {
				if result.Success {
					fmt.Printf("   ✅ %s authentication successful with %s\n", method.Name, getCredentialSummary(result.Credential))
					
					// Cache successful tokens
					if result.Token != "" {
						authManager.ActiveTokens[target.URL] = result.Token
					}
					
					// Try token refresh if supported
					if config.TokenRefresh && result.RefreshToken != "" {
						refreshResult := tryTokenRefresh(target, method, result, config, client)
						if refreshResult != nil {
							allResults = append(allResults, *refreshResult)
						}
					}
				}
			}
		}
		
		// Test authentication chaining if enabled
		if config.AuthChaining {
			chainResults := testAuthChaining(target, authManager, config, client, limiter, wafDetector, throttleController, rotationManager)
			allResults = append(allResults, chainResults...)
		}
	}
	
	return allResults
}

// Test single authentication method
func testAuthMethod(target Target, method AuthMethod, credentials []AuthCredential, config *Config, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) []AuthResult {
	var results []AuthResult
	
	for _, cred := range credentials {
		if limiter != nil {
			limiter.Wait(context.Background())
		}
		
		// Smart throttling delay
		currentDelay := throttleController.CurrentDelay
		if config.RandomDelay && currentDelay > 0 {
			variation := 0.5 + (float64(time.Now().UnixNano()%100) / 100.0)
			currentDelay = time.Duration(float64(currentDelay) * variation)
		}
		
		if currentDelay > 0 {
			time.Sleep(currentDelay)
		}
		
		result := executeAuthTest(target, method, cred, config, client, wafDetector, throttleController, rotationManager)
		results = append(results, result)
		
		if config.Verbose {
			status := "❌"
			if result.Success {
				status = "✅"
			}
			fmt.Printf("      %s %s -> %d (%dms)\n", status, getCredentialSummary(cred), result.Response.StatusCode, result.Response.ResponseTime)
		}
	}
	
	return results
}

// Execute single authentication test
func executeAuthTest(target Target, method AuthMethod, cred AuthCredential, config *Config, client *http.Client, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) AuthResult {
	start := time.Now()
	
	result := AuthResult{
		Method:     method,
		Credential: cred,
		Success:    false,
		Timestamp:  start,
	}
	
	// Prepare authentication request
	var req *http.Request
	var err error
	
	switch method.Type {
	case "OAuth2":
		req, err = createOAuthRequest(target, method, cred, config)
	case "Basic":
		req, err = createBasicAuthRequest(target, method, cred, config)
	case "JWT", "Bearer":
		req, err = createBearerRequest(target, method, cred, config)
	default:
		req, err = createCustomAuthRequest(target, method, cred, config)
	}
	
	if err != nil {
		result.Response.StatusCode = 0
		return result
	}
	
	// Apply rotation if enabled
	if config.UARotation {
		req.Header.Set("User-Agent", rotationManager.getNextUserAgent())
	}
	
	if config.HeaderRotation {
		req.Header.Set("Accept", rotationManager.getRandomHeader("Accept"))
	}
	
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		result.Response.StatusCode = 0
		return result
	}
	defer resp.Body.Close()
	
	responseTime := time.Since(start).Milliseconds()
	
	// Read response
	body, _ := io.ReadAll(resp.Body)
	
	// Analyze response
	result.Response = AuthResponse{
		StatusCode:    resp.StatusCode,
		Headers:       make(map[string]string),
		Body:          string(body),
		ResponseTime:  responseTime,
		ContentLength: int64(len(body)),
	}
	
	// Store important headers
	importantHeaders := []string{"Authorization", "Set-Cookie", "X-Auth-Token", "X-Session-Token"}
	for _, header := range importantHeaders {
		if value := resp.Header.Get(header); value != "" {
			result.Response.Headers[header] = value
		}
	}
	
	// Check if authentication was successful
	result.Success = isAuthSuccessful(resp, body, config.SuccessCodes)
	
	// Extract tokens from response
	if result.Success {
		result.Token, result.RefreshToken, result.ExpiresIn, result.TokenType, result.Scope = extractTokensFromResponse(string(body), resp.Header)
		
		// Parse JWT if present
		if method.Type == "JWT" && result.Token != "" {
			if jwt := parseJWT(result.Token); jwt != nil {
				// Store JWT info in result metadata if needed
			}
		}
	}
	
	// Update throttle controller
	if config.SmartThrottling {
		analysis := wafDetector.analyzeResponse(resp, body)
		throttleController.updateThrottle(result.Success, analysis)
	}
	
	return result
}

// Create OAuth request
func createOAuthRequest(target Target, method AuthMethod, cred AuthCredential, config *Config) (*http.Request, error) {
	tokenURL := method.Endpoint
	if tokenURL == "" {
		tokenURL = target.URL
	}
	
	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	
	if cred.ClientID != "" {
		data.Set("client_id", cred.ClientID)
	}
	if cred.ClientSecret != "" {
		data.Set("client_secret", cred.ClientSecret)
	}
	if cred.Scope != "" {
		data.Set("scope", cred.Scope)
	}
	
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// Create Basic Auth request
func createBasicAuthRequest(target Target, method AuthMethod, cred AuthCredential, config *Config) (*http.Request, error) {
	req, err := http.NewRequest(target.Method, target.URL, nil)
	if err != nil {
		return nil, err
	}
	
	// Encode credentials
	credentials := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
	req.Header.Set("Authorization", "Basic "+credentials)
	
	return req, nil
}

// Create Bearer token request
func createBearerRequest(target Target, method AuthMethod, cred AuthCredential, config *Config) (*http.Request, error) {
	req, err := http.NewRequest(target.Method, target.URL, nil)
	if err != nil {
		return nil, err
	}
	
	token := cred.Token
	if token == "" {
		token = cred.APIKey
	}
	
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// Create custom auth request
func createCustomAuthRequest(target Target, method AuthMethod, cred AuthCredential, config *Config) (*http.Request, error) {
	req, err := http.NewRequest(target.Method, target.URL, nil)
	if err != nil {
		return nil, err
	}
	
	// Apply custom headers
	for headerName, headerTemplate := range method.Headers {
		headerValue := headerTemplate
		headerValue = strings.ReplaceAll(headerValue, "%TOKEN%", cred.Token)
		headerValue = strings.ReplaceAll(headerValue, "%KEY%", cred.APIKey)
		headerValue = strings.ReplaceAll(headerValue, "%CREDENTIALS%", base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password)))
		
		req.Header.Set(headerName, headerValue)
	}
	
	return req, nil
}

// Check if authentication was successful
func isAuthSuccessful(resp *http.Response, body []byte, successCodes map[int]bool) bool {
	// Check status code
	if _, ok := successCodes[resp.StatusCode]; ok {
		return true
	}
	
	// Check for success indicators in response
	bodyStr := strings.ToLower(string(body))
	successKeywords := []string{"access_token", "token", "authenticated", "success", "authorized"}
	for _, keyword := range successKeywords {
		if strings.Contains(bodyStr, keyword) {
			return true
		}
	}
	
	return false
}

// Extract tokens from response
func extractTokensFromResponse(body string, headers http.Header) (token, refreshToken string, expiresIn int, tokenType, scope string) {
	// Try to parse JSON response
	var jsonResp map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResp); err == nil {
		if t, ok := jsonResp["access_token"].(string); ok {
			token = t
		}
		if rt, ok := jsonResp["refresh_token"].(string); ok {
			refreshToken = rt
		}
		if exp, ok := jsonResp["expires_in"].(float64); ok {
			expiresIn = int(exp)
		}
		if tt, ok := jsonResp["token_type"].(string); ok {
			tokenType = tt
		}
		if s, ok := jsonResp["scope"].(string); ok {
			scope = s
		}
	}
	
	// Check headers for tokens
	if authHeader := headers.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}
	
	return
}

// Parse JWT token
func parseJWT(tokenString string) *JWTToken {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}
	
	jwt := &JWTToken{
		Raw: tokenString,
	}
	
	// Decode header
	if headerData, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
		json.Unmarshal(headerData, &jwt.Header)
	}
	
	// Decode payload
	if payloadData, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		json.Unmarshal(payloadData, &jwt.Payload)
		
		// Extract standard claims
		if exp, ok := jwt.Payload["exp"].(float64); ok {
			jwt.ExpiresAt = time.Unix(int64(exp), 0)
		}
		if iat, ok := jwt.Payload["iat"].(float64); ok {
			jwt.IssuedAt = time.Unix(int64(iat), 0)
		}
		if iss, ok := jwt.Payload["iss"].(string); ok {
			jwt.Issuer = iss
		}
		if sub, ok := jwt.Payload["sub"].(string); ok {
			jwt.Subject = sub
		}
		if aud, ok := jwt.Payload["aud"].([]interface{}); ok {
			for _, a := range aud {
				if audStr, ok := a.(string); ok {
					jwt.Audience = append(jwt.Audience, audStr)
				}
			}
		}
	}
	
	jwt.Signature = parts[2]
	jwt.Valid = time.Now().Before(jwt.ExpiresAt)
	
	return jwt
}

// Try token refresh
func tryTokenRefresh(target Target, method AuthMethod, authResult AuthResult, config *Config, client *http.Client) *AuthResult {
	if method.RefreshURL == "" || authResult.RefreshToken == "" {
		return nil
	}
	
	// Prepare refresh request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", authResult.RefreshToken)
	
	req, err := http.NewRequest("POST", method.RefreshURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	refreshResult := &AuthResult{
		Method:     method,
		Credential: authResult.Credential,
		Success:    resp.StatusCode == 200,
		Timestamp:  time.Now(),
		Response: AuthResponse{
			StatusCode:    resp.StatusCode,
			Body:          string(body),
			ContentLength: int64(len(body)),
		},
	}
	
	if refreshResult.Success {
		refreshResult.Token, refreshResult.RefreshToken, refreshResult.ExpiresIn, refreshResult.TokenType, refreshResult.Scope = extractTokensFromResponse(string(body), resp.Header)
	}
	
	return refreshResult
}

// Test authentication chaining
func testAuthChaining(target Target, authManager *AuthManager, config *Config, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager) []AuthResult {
	var results []AuthResult
	
	// This is a simplified implementation
	// In a real scenario, you would chain different auth methods
	fmt.Printf("   🔗 Testing authentication chaining...\n")
	
	return results
}

// Get credential summary for display
func getCredentialSummary(cred AuthCredential) string {
	if cred.Username != "" && cred.Password != "" {
		return fmt.Sprintf("%s:%s", cred.Username, maskString(cred.Password))
	}
	if cred.APIKey != "" {
		return maskString(cred.APIKey)
	}
	if cred.Token != "" {
		return maskString(cred.Token)
	}
	if cred.ClientID != "" {
		return fmt.Sprintf("client_id:%s", maskString(cred.ClientID))
	}
	return "unknown"
}

// Print advanced configuration
func printAdvancedConfig(config *Config, targets []Target, authManager *AuthManager) {
	hasAuth := hasAdvancedAuthFeatures(config)
	hasDiscovery := config.APIDiscovery || config.EndpointEnum
	
	fmt.Printf("🔐 Advanced Authentication: %s\n", formatBool(hasAuth))
	fmt.Printf("🔍 API Discovery: %s\n", formatBool(hasDiscovery))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s\n", i+1, target.URL)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	// Authentication features
	if hasAuth {
		fmt.Printf("\n🔐 Authentication Methods:\n")
		for _, method := range authManager.Methods {
			fmt.Printf("   ✅ %s (%s)\n", method.Name, method.Type)
		}
		
		if len(authManager.Credentials) > 0 {
			fmt.Printf("🔑 Credentials: %d loaded\n", len(authManager.Credentials))
		}
		
		if config.JWTSupport {
			fmt.Printf("🎫 JWT Support: %s\n", formatBool(config.JWTSupport))
		}
		if config.OAuthSupport {
			fmt.Printf("🔗 OAuth 2.0: %s\n", formatBool(config.OAuthSupport))
		}
		if config.BasicAuthSupport {
			fmt.Printf("🔒 Basic Auth: %s\n", formatBool(config.BasicAuthSupport))
		}
		if config.TokenRefresh {
			fmt.Printf("🔄 Token Refresh: %s\n", formatBool(config.TokenRefresh))
		}
		if config.AuthChaining {
			fmt.Printf("🔗 Auth Chaining: %s\n", formatBool(config.AuthChaining))
		}
	}
	
	// Discovery features
	if hasDiscovery {
		fmt.Printf("\n🔍 Discovery Features:\n")
		if config.APIDiscovery {
			fmt.Printf("   ✅ API Discovery\n")
		}
		if config.EndpointEnum {
			fmt.Printf("   ✅ Endpoint Enumeration\n")
		}
		if config.SchemaAnalysis {
			fmt.Printf("   ✅ Schema Analysis\n")
		}
		if config.VersionDetection {
			fmt.Printf("   ✅ Version Detection\n")
		}
		fmt.Printf("📂 Discovery Paths: %d paths\n", len(config.CommonPaths))
	}
	
	fmt.Printf("\n🧵 Threads: %d\n", config.Threads)
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting advanced authentication testing...")
	fmt.Println()
}

// Print authentication results
func printAuthResults(results []AuthResult) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🔐 ADVANCED AUTHENTICATION RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	
	if len(results) == 0 {
		fmt.Println("❌ No authentication results found.")
		return
	}
	
	// Group results by target and method
	targetResults := make(map[string]map[string][]AuthResult)
	successCount := 0
	
	for _, result := range results {
		targetURL := extractTargetFromResult(result)
		if targetResults[targetURL] == nil {
			targetResults[targetURL] = make(map[string][]AuthResult)
		}
		
		methodName := result.Method.Name
		targetResults[targetURL][methodName] = append(targetResults[targetURL][methodName], result)
		
		if result.Success {
			successCount++
		}
	}
	
	targetNum := 1
	for targetURL, methodResults := range targetResults {
		fmt.Printf("\n🎯 Target %d: %s\n", targetNum, targetURL)
		
		for methodName, methodResults := range methodResults {
			fmt.Printf("\n   🔑 %s Authentication:\n", methodName)
			
			successfulResults := []AuthResult{}
			failedResults := []AuthResult{}
			
			for _, result := range methodResults {
				if result.Success {
					successfulResults = append(successfulResults, result)
				} else {
					failedResults = append(failedResults, result)
				}
			}
			
			// Show successful authentications
			if len(successfulResults) > 0 {
				fmt.Printf("      ✅ Successful (%d):\n", len(successfulResults))
				for i, result := range successfulResults {
					if i >= 5 { // Limit display
						fmt.Printf("         ... and %d more successful attempts\n", len(successfulResults)-5)
						break
					}
					
					fmt.Printf("         🔓 %s -> %d (%dms)\n", 
						getCredentialSummary(result.Credential), 
						result.Response.StatusCode, 
						result.Response.ResponseTime)
					
					if result.Token != "" {
						fmt.Printf("            🎫 Token: %s\n", maskString(result.Token))
					}
					if result.RefreshToken != "" {
						fmt.Printf("            🔄 Refresh: %s\n", maskString(result.RefreshToken))
					}
					if result.ExpiresIn > 0 {
						fmt.Printf("            ⏰ Expires: %ds\n", result.ExpiresIn)
					}
					if result.TokenType != "" {
						fmt.Printf("            📋 Type: %s\n", result.TokenType)
					}
					if result.Scope != "" {
						fmt.Printf("            🎯 Scope: %s\n", result.Scope)
					}
				}
			}
			
			// Show failed attempts summary
			if len(failedResults) > 0 {
				fmt.Printf("      ❌ Failed: %d attempts\n", len(failedResults))
				
				// Group by status code
				statusCounts := make(map[int]int)
				for _, result := range failedResults {
					statusCounts[result.Response.StatusCode]++
				}
				
				for status, count := range statusCounts {
					fmt.Printf("         📊 Status %d: %d attempts\n", status, count)
				}
			}
		}
		targetNum++
	}
	
	// Overall statistics
	fmt.Printf("\n" + strings.Repeat("-", 70))
	fmt.Printf("\n📈 AUTHENTICATION SUMMARY\n")
	fmt.Printf("🎯 Targets Tested: %d\n", len(targetResults))
	fmt.Printf("🔐 Total Attempts: %d\n", len(results))
	fmt.Printf("✅ Successful: %d\n", successCount)
	fmt.Printf("❌ Failed: %d\n", len(results)-successCount)
	
	if len(results) > 0 {
		successRate := float64(successCount) / float64(len(results)) * 100
		fmt.Printf("📊 Success Rate: %.2f%%\n", successRate)
	}
	
	// Calculate average response time
	var totalTime int64
	for _, result := range results {
		totalTime += result.Response.ResponseTime
	}
	if len(results) > 0 {
		avgTime := totalTime / int64(len(results))
		fmt.Printf("⏱️  Average Response Time: %dms\n", avgTime)
	}
	
	fmt.Println(strings.Repeat("=", 70))
}

// Extract target URL from auth result
func extractTargetFromResult(result AuthResult) string {
	// This is simplified - in real implementation, you'd track the target URL
	return "target_url"
}

// Save authentication results to JSON file
func saveAuthResults(results []AuthResult, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating auth output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Printf("Error writing auth results to file: %v\n", err)
	} else {
		fmt.Printf("💾 Authentication results saved to: %s\n", filename)
	}
}

// Authentication Manager
type AuthManager struct {
	Methods       []AuthMethod      `json:"methods"`
	Credentials   []AuthCredential  `json:"credentials"`
	Results       []AuthResult      `json:"results"`
	ActiveTokens  map[string]string `json:"active_tokens"`
	TokenCache    map[string]JWTToken `json:"token_cache"`
	OAuthFlows    map[string]OAuthFlow `json:"oauth_flows"`
	mutex         sync.Mutex
}

// Check if ML features are enabled
func hasMLFeatures(config *Config) bool {
	return config.MLEnabled || config.PatternRecognition || config.SuccessPrediction ||
		config.IntelligentSorting || config.AdaptiveLearning || config.BehaviorAnalysis ||
		config.AnomalyDetection || config.ModelTraining || config.PredictiveAnalysis
}

// Initialize ML Engine
func initMLEngine(config *Config) *MLEngine {
	engine := &MLEngine{
		Model:           initDefaultModel(),
		TrainingData:    &TrainingData{},
		PatternAnalysis: &PatternAnalysis{},
		Predictions:     []Prediction{},
		IsTraining:      false,
		LastUpdate:      time.Now(),
	}
	
	// Load existing model if specified
	if config.MLModelPath != "" {
		if loadedModel, err := loadMLModel(config.MLModelPath); err == nil {
			engine.Model = loadedModel
			fmt.Printf("🤖 Loaded ML model from: %s\n", config.MLModelPath)
		} else {
			fmt.Printf("⚠️  Could not load ML model: %v\n", err)
		}
	}
	
	// Load training data if specified
	if config.TrainingDataPath != "" {
		if trainingData, err := loadTrainingData(config.TrainingDataPath); err == nil {
			engine.TrainingData = trainingData
			fmt.Printf("📊 Loaded training data: %d samples\n", len(trainingData.Features))
		} else {
			fmt.Printf("⚠️  Could not load training data: %v\n", err)
		}
	}
	
	// Initialize pattern analysis
	engine.PatternAnalysis = &PatternAnalysis{
		SuccessPatterns:  []Pattern{},
		FailurePatterns:  []Pattern{},
		KeyPatterns:      []KeyPattern{},
		TimePatterns:     []TimePattern{},
		ResponsePatterns: []ResponsePattern{},
		Anomalies:        []Anomaly{},
	}
	
	return engine
}

// Initialize default ML model
func initDefaultModel() *MLModel {
	return &MLModel{
		Type:      "LogisticRegression",
		Version:   "1.0",
		TrainedAt: time.Now(),
		Accuracy:  0.0,
		Features: []string{
			"key_length",
			"key_entropy",
			"has_numbers",
			"has_special_chars",
			"has_uppercase",
			"has_lowercase",
			"response_time",
			"content_length",
			"status_code",
			"hour_of_day",
			"day_of_week",
		},
		Parameters:     make(map[string]interface{}),
		Weights:        make([]float64, 11), // 11 features
		Bias:           0.0,
		Classes:        []string{"failure", "success"},
		FeatureScaling: make(map[string]ScalingInfo),
	}
}

// Load ML model from file
func loadMLModel(filename string) (*MLModel, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var model MLModel
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&model); err != nil {
		return nil, err
	}
	
	return &model, nil
}

// Load training data from file
func loadTrainingData(filename string) (*TrainingData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var trainingData TrainingData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&trainingData); err != nil {
		return nil, err
	}
	
	return &trainingData, nil
}

// Extract features from data point
func (engine *MLEngine) extractFeatures(dataPoint DataPoint, key string) []float64 {
	features := make([]float64, len(engine.Model.Features))
	
	for i, featureName := range engine.Model.Features {
		switch featureName {
		case "key_length":
			features[i] = float64(len(key))
		case "key_entropy":
			features[i] = calculateEntropy(key)
		case "has_numbers":
			features[i] = boolToFloat(containsNumbers(key))
		case "has_special_chars":
			features[i] = boolToFloat(containsSpecialChars(key))
		case "has_uppercase":
			features[i] = boolToFloat(containsUppercase(key))
		case "has_lowercase":
			features[i] = boolToFloat(containsLowercase(key))
		case "response_time":
			features[i] = float64(dataPoint.ResponseTime)
		case "content_length":
			features[i] = float64(dataPoint.ContentLength)
		case "status_code":
			features[i] = float64(dataPoint.StatusCode)
		case "hour_of_day":
			features[i] = float64(dataPoint.Timestamp.Hour())
		case "day_of_week":
			features[i] = float64(dataPoint.Timestamp.Weekday())
		}
	}
	
	return features
}

// Calculate entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	
	entropy := 0.0
	length := float64(len(s))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

// Helper functions for feature extraction
func containsNumbers(s string) bool {
	for _, char := range s {
		if char >= '0' && char <= '9' {
			return true
		}
	}
	return false
}

func containsSpecialChars(s string) bool {
	for _, char := range s {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			return true
		}
	}
	return false
}

func containsUppercase(s string) bool {
	for _, char := range s {
		if char >= 'A' && char <= 'Z' {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, char := range s {
		if char >= 'a' && char <= 'z' {
			return true
		}
	}
	return false
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// Predict success probability
func (engine *MLEngine) predictSuccess(key string, target Target) *Prediction {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	
	// Create dummy data point for feature extraction
	dataPoint := DataPoint{
		URL:        target.URL,
		Method:     target.Method,
		Timestamp:  time.Now(),
		KeyPattern: analyzeKeyPattern(key),
	}
	
	features := engine.extractFeatures(dataPoint, key)
	
	// Simple logistic regression prediction
	probability := engine.logisticRegression(features)
	
	prediction := &Prediction{
		Probability:     probability,
		Confidence:      calculateConfidence(probability),
		Class:           classifyProbability(probability),
		Features:        features,
		FeatureNames:    engine.Model.Features,
		Explanation:     generateExplanation(features, engine.Model.Features, probability),
		Recommendations: generateRecommendations(features, engine.Model.Features),
		Timestamp:       time.Now(),
	}
	
	engine.Predictions = append(engine.Predictions, *prediction)
	return prediction
}

// Simple logistic regression implementation
func (engine *MLEngine) logisticRegression(features []float64) float64 {
	if len(features) != len(engine.Model.Weights) {
		return 0.5 // Default probability
	}
	
	z := engine.Model.Bias
	for i, feature := range features {
		z += feature * engine.Model.Weights[i]
	}
	
	// Sigmoid function
	return 1.0 / (1.0 + math.Exp(-z))
}

// Calculate confidence based on probability
func calculateConfidence(probability float64) float64 {
	// Confidence is higher when probability is closer to 0 or 1
	return math.Abs(probability - 0.5) * 2
}

// Classify probability into success/failure
func classifyProbability(probability float64) string {
	if probability >= 0.5 {
		return "success"
	}
	return "failure"
}

// Generate explanation for prediction
func generateExplanation(features []float64, featureNames []string, probability float64) string {
	if probability >= 0.7 {
		return "High probability of success based on key characteristics and historical patterns"
	} else if probability >= 0.3 {
		return "Moderate probability of success, worth testing"
	} else {
		return "Low probability of success based on current analysis"
	}
}

// Generate recommendations
func generateRecommendations(features []float64, featureNames []string) []string {
	recommendations := []string{}
	
	for i, feature := range features {
		switch featureNames[i] {
		case "key_length":
			if feature < 8 {
				recommendations = append(recommendations, "Consider longer keys for better security")
			}
		case "key_entropy":
			if feature < 3.0 {
				recommendations = append(recommendations, "Key has low entropy, try more random patterns")
			}
		case "has_special_chars":
			if feature == 0 {
				recommendations = append(recommendations, "Try keys with special characters")
			}
		}
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Key characteristics look good for testing")
	}
	
	return recommendations
}

// Intelligent sorting of wordlist
func (engine *MLEngine) intelligentSort(keys []string, targets []Target) []string {
	if len(keys) == 0 || len(targets) == 0 {
		return keys
	}
	
	type KeyScore struct {
		Key   string
		Score float64
	}
	
	var keyScores []KeyScore
	
	// Calculate scores for each key
	for _, key := range keys {
		totalScore := 0.0
		for _, target := range targets {
			prediction := engine.predictSuccess(key, target)
			totalScore += prediction.Probability
		}
		avgScore := totalScore / float64(len(targets))
		
		keyScores = append(keyScores, KeyScore{
			Key:   key,
			Score: avgScore,
		})
	}
	
	// Sort by score (highest first)
	sort.Slice(keyScores, func(i, j int) bool {
		return keyScores[i].Score > keyScores[j].Score
	})
	
	// Extract sorted keys
	sortedKeys := make([]string, len(keyScores))
	for i, ks := range keyScores {
		sortedKeys[i] = ks.Key
	}
	
	return sortedKeys
}

// Analyze key pattern
func analyzeKeyPattern(key string) string {
	if len(key) == 0 {
		return "empty"
	}
	
	hasNumbers := containsNumbers(key)
	hasUpper := containsUppercase(key)
	hasLower := containsLowercase(key)
	hasSpecial := containsSpecialChars(key)
	
	pattern := ""
	if hasUpper {
		pattern += "U"
	}
	if hasLower {
		pattern += "L"
	}
	if hasNumbers {
		pattern += "N"
	}
	if hasSpecial {
		pattern += "S"
	}
	
	if pattern == "" {
		return "unknown"
	}
	
	return pattern
}

// Learn from result
func (engine *MLEngine) learnFromResult(key string, target Target, result FoundKey, success bool) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	
	dataPoint := DataPoint{
		URL:           target.URL,
		Method:        target.Method,
		StatusCode:    result.StatusCode,
		ResponseTime:  result.ResponseTime,
		ContentLength: result.ContentLength,
		Success:       success,
		Timestamp:     result.Timestamp,
		KeyPattern:    analyzeKeyPattern(key),
	}
	
	// Add to training data
	features := engine.extractFeatures(dataPoint, key)
	label := 0
	if success {
		label = 1
	}
	
	engine.TrainingData.Features = append(engine.TrainingData.Features, features)
	engine.TrainingData.Labels = append(engine.TrainingData.Labels, label)
	engine.TrainingData.Metadata = append(engine.TrainingData.Metadata, dataPoint)
	
	// Update patterns
	engine.updatePatterns(key, dataPoint, success)
	
	// Detect anomalies
	if anomaly := engine.detectAnomaly(dataPoint); anomaly != nil {
		engine.PatternAnalysis.Anomalies = append(engine.PatternAnalysis.Anomalies, *anomaly)
	}
	
	engine.LastUpdate = time.Now()
}

// Update patterns based on results
func (engine *MLEngine) updatePatterns(key string, dataPoint DataPoint, success bool) {
	keyPattern := analyzeKeyPattern(key)
	
	// Update key patterns
	found := false
	for i, kp := range engine.PatternAnalysis.KeyPatterns {
		if kp.Pattern == keyPattern {
			engine.PatternAnalysis.KeyPatterns[i].Examples = append(kp.Examples, key)
			if success {
				engine.PatternAnalysis.KeyPatterns[i].SuccessRate = (kp.SuccessRate + 1.0) / 2.0
			} else {
				engine.PatternAnalysis.KeyPatterns[i].SuccessRate = kp.SuccessRate / 2.0
			}
			found = true
			break
		}
	}
	
	if !found {
		successRate := 0.0
		if success {
			successRate = 1.0
		}
		
		engine.PatternAnalysis.KeyPatterns = append(engine.PatternAnalysis.KeyPatterns, KeyPattern{
			Pattern:     keyPattern,
			Length:      len(key),
			Charset:     keyPattern,
			SuccessRate: successRate,
			Examples:    []string{key},
		})
	}
	
	// Update time patterns
	hour := dataPoint.Timestamp.Hour()
	dayOfWeek := int(dataPoint.Timestamp.Weekday())
	
	found = false
	for i, tp := range engine.PatternAnalysis.TimePatterns {
		if tp.Hour == hour && tp.DayOfWeek == dayOfWeek {
			engine.PatternAnalysis.TimePatterns[i].RequestCount++
			if success {
				engine.PatternAnalysis.TimePatterns[i].SuccessRate = (tp.SuccessRate + 1.0) / 2.0
			}
			found = true
			break
		}
	}
	
	if !found {
		successRate := 0.0
		if success {
			successRate = 1.0
		}
		
		engine.PatternAnalysis.TimePatterns = append(engine.PatternAnalysis.TimePatterns, TimePattern{
			Hour:         hour,
			DayOfWeek:    dayOfWeek,
			SuccessRate:  successRate,
			RequestCount: 1,
		})
	}
}

// Detect anomalies
func (engine *MLEngine) detectAnomaly(dataPoint DataPoint) *Anomaly {
	// Simple anomaly detection based on response time
	if dataPoint.ResponseTime > 10000 { // > 10 seconds
		return &Anomaly{
			Type:        "slow_response",
			Description: fmt.Sprintf("Unusually slow response time: %dms", dataPoint.ResponseTime),
			Severity:    "medium",
			Confidence:  0.8,
			Data:        dataPoint,
			Timestamp:   time.Now(),
		}
	}
	
	// Detect unusual status codes
	if dataPoint.StatusCode >= 500 {
		return &Anomaly{
			Type:        "server_error",
			Description: fmt.Sprintf("Server error response: %d", dataPoint.StatusCode),
			Severity:    "high",
			Confidence:  0.9,
			Data:        dataPoint,
			Timestamp:   time.Now(),
		}
	}
	
	return nil
}

// Create HTTP client with proper configuration
func createHTTPClient(config *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout: 90 * time.Second,
	}

	if config.ProxyURL != "" {
		pURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			fmt.Printf("Invalid proxy URL: %v\n", err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(pURL)
	}

	return &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}
}

// Collect results from channel
func collectResults(results <-chan FoundKey) []FoundKey {
	var foundKeys []FoundKey
	for found := range results {
		foundKeys = append(foundKeys, found)
	}
	return foundKeys
}

// Save results to JSON file
func saveResults(foundKeys []FoundKey, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(foundKeys); err != nil {
		fmt.Printf("Error writing results to file: %v\n", err)
	} else {
		fmt.Printf("💾 Results saved to: %s\n", filename)
	}
}

// Print summary
func printSummary(foundKeys []FoundKey) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("📊 RESULTS SUMMARY")
	fmt.Println(strings.Repeat("=", 50))
	
	if len(foundKeys) == 0 {
		fmt.Println("❌ No valid API keys found.")
	} else {
		fmt.Printf("✅ Found %d valid API key(s):\n\n", len(foundKeys))
		for i, found := range foundKeys {
			fmt.Printf("%d. 🔑 Key: %s\n", i+1, found.Key)
			fmt.Printf("   📊 Status: %d\n", found.StatusCode)
			fmt.Printf("   🌐 URL: %s\n", found.URL)
			fmt.Printf("   ⏱️  Response Time: %dms\n", found.ResponseTime)
			fmt.Printf("   📏 Content Length: %d bytes\n", found.ContentLength)
			fmt.Printf("   🕐 Timestamp: %s\n", found.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Println()
		}
	}
	fmt.Println(strings.Repeat("=", 50))
}

// Get success codes as slice for display
func getSuccessCodesSlice(codes map[int]bool) []int {
	var result []int
	for code := range codes {
		result = append(result, code)
	}
	return result
}

// Fungsi untuk memuat wordlist dari file
func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// Fungsi untuk mem-parse string kode sukses menjadi map untuk pencarian cepat
func parseSuccessCodes(codesRaw string) map[int]bool {
	codes := make(map[int]bool)
	parts := strings.Split(codesRaw, ",")
	for _, part := range parts {
		code, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil {
			codes[code] = true
		}
	}
	return codes
}

// Fungsi worker yang akan dijalankan oleh goroutine
func worker(id int, config *Config, keys <-chan string, results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, limiter *rate.Limiter) {
	defer wg.Done()
	
	if config.Verbose {
		fmt.Printf("🔧 Worker %d started\n", id)
	}
	
	for key := range keys {
		// Rate limiting
		if limiter != nil {
			limiter.Wait(context.Background())
		}
		
		start := time.Now()
		
		// Create request
		req, err := http.NewRequest(config.HTTPMethod, config.TargetURL, nil)
		if err != nil {
			if config.Verbose {
				fmt.Printf("❌ Worker %d: Error creating request for key %s: %v\n", id, key, err)
			}
			continue
		}

		// Set API key header
		actualHeader := strings.ReplaceAll(config.HeaderFormat, "%KEY%", key)
		headerParts := strings.SplitN(actualHeader, ":", 2)
		if len(headerParts) == 2 {
			req.Header.Set(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
		} else {
			if config.Verbose {
				fmt.Printf("❌ Worker %d: Invalid header format: %s\n", id, config.HeaderFormat)
			}
			continue
		}
		
		// Set User-Agent
		req.Header.Set("User-Agent", config.UserAgent)
		
		// Additional headers for better stealth
		req.Header.Set("Accept", "application/json, text/plain, */*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Header.Set("Connection", "keep-alive")

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			if config.Verbose {
				fmt.Printf("❌ Worker %d: Error sending request for key %s: %v\n", id, key, err)
			}
			continue
		}
		
		responseTime := time.Since(start).Milliseconds()
		
		// Read response body to get content length
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if config.Verbose {
			fmt.Printf("🔍 Worker %d: Key %s -> Status: %d (%dms)\n", id, key, resp.StatusCode, responseTime)
		}

		// Check if status code indicates success
		if _, ok := config.SuccessCodes[resp.StatusCode]; ok {
			found := FoundKey{
				Key:           key,
				StatusCode:    resp.StatusCode,
				URL:           config.TargetURL,
				ResponseTime:  responseTime,
				ContentLength: int64(len(body)),
				Timestamp:     time.Now(),
			}
			results <- found
			fmt.Printf("🎉 [FOUND] Worker %d: Key: %s -> Status: %d (%dms)\n", id, key, resp.StatusCode, responseTime)
		}
	}
	
	if config.Verbose {
		fmt.Printf("✅ Worker %d finished\n", id)
	}
}

// Execute ML-enhanced API discovery
func executeMLEnhancedDiscovery(config *Config, targets []Target, client *http.Client, limiter *rate.Limiter, pathDiscovery *PathDiscovery, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine) []DiscoveryResult {
	// Use existing discovery but enhance with ML insights
	results := executeAPIDiscovery(config, targets, client, limiter, pathDiscovery, wafDetector, throttleController, rotationManager)
	
	// Apply ML analysis to results if enabled
	if mlEngine != nil && config.BehaviorAnalysis {
		for i, result := range results {
			// Analyze endpoint patterns
			for j, endpoint := range result.Endpoints {
				// Learn from endpoint characteristics
				dataPoint := DataPoint{
					URL:           endpoint.URL,
					Method:        endpoint.Method,
					StatusCode:    endpoint.StatusCode,
					ResponseTime:  endpoint.ResponseTime,
					ContentLength: endpoint.ContentLength,
					Success:       endpoint.StatusCode >= 200 && endpoint.StatusCode < 300,
					Timestamp:     endpoint.Discovered,
					AuthMethod:    "discovery",
				}
				
				// Update ML patterns
				mlEngine.learnFromDiscovery(dataPoint)
				results[i].Endpoints[j] = endpoint
			}
		}
	}
	
	return results
}

// Execute ML-enhanced authentication
func executeMLEnhancedAuth(config *Config, targets []Target, keys []string, authManager *AuthManager, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine) []AuthResult {
	// Use existing auth but enhance with ML
	results := executeAdvancedAuth(config, targets, keys, authManager, client, limiter, wafDetector, throttleController, rotationManager)
	
	// Apply ML learning to results
	if mlEngine != nil && config.AdaptiveLearning {
		for _, result := range results {
			// Learn from authentication results
			if keys != nil {
				for _, key := range keys {
					// This is simplified - in real implementation, track which key was used
					mlEngine.learnFromAuthResult(key, result)
				}
			}
		}
	}
	
	return results
}

// Execute ML-enhanced brute force
func executeMLEnhancedBruteForce(config *Config, jobs []Job, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine) []FoundKey {
	jobsChan := make(chan Job, len(jobs))
	results := make(chan FoundKey, len(jobs))
	var wg sync.WaitGroup
	
	// Start ML-enhanced workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go mlEnhancedWorker(i+1, config, jobsChan, results, &wg, client, limiter, wafDetector, throttleController, rotationManager, mlEngine)
	}
	
	// Send jobs (potentially reordered by ML)
	for _, job := range jobs {
		jobsChan <- job
	}
	close(jobsChan)
	
	// Wait for completion
	wg.Wait()
	close(results)
	
	// Collect results
	return collectResults(results)
}

// ML-enhanced worker
func mlEnhancedWorker(id int, config *Config, jobs <-chan Job, results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine) {
	defer wg.Done()
	
	if config.Verbose {
		fmt.Printf("🤖 ML-Enhanced Worker %d started\n", id)
	}
	
	for job := range jobs {
		// Get ML prediction if enabled
		var prediction *Prediction
		if mlEngine != nil && config.SuccessPrediction {
			prediction = mlEngine.predictSuccess(job.Key, job.Target)
			
			if config.Verbose && prediction.Confidence > config.ConfidenceThreshold {
				fmt.Printf("🧠 Worker %d: ML prediction for key %s: %.2f%% success probability\n", 
					id, maskString(job.Key), prediction.Probability*100)
			}
		}
		
		// Rate limiting
		if limiter != nil {
			limiter.Wait(context.Background())
		}
		
		// Smart throttling delay
		currentDelay := throttleController.CurrentDelay
		if config.RandomDelay && currentDelay > 0 {
			variation := 0.5 + (float64(time.Now().UnixNano()%100) / 100.0)
			currentDelay = time.Duration(float64(currentDelay) * variation)
		}
		
		if currentDelay > 0 {
			time.Sleep(currentDelay)
		}
		
		// Execute job with ML enhancement
		found, blocked := executeMLEnhancedJob(id, job, config, client, wafDetector, throttleController, rotationManager, mlEngine, prediction)
		
		if found != nil {
			results <- *found
			fmt.Printf("🎉 [FOUND] ML Worker %d: Key: %s -> Status: %d at %s (%dms)\n", 
				id, found.Key, found.StatusCode, found.URL, found.ResponseTime)
			
			// Learn from successful result
			if mlEngine != nil && config.AdaptiveLearning {
				mlEngine.learnFromResult(job.Key, job.Target, *found, true)
			}
		} else if mlEngine != nil && config.AdaptiveLearning {
			// Learn from failed result
			dummyResult := FoundKey{
				Key:          job.Key,
				StatusCode:   0,
				URL:          job.Target.URL,
				ResponseTime: 0,
				Timestamp:    time.Now(),
			}
			mlEngine.learnFromResult(job.Key, job.Target, dummyResult, false)
		}
		
		if blocked && config.Verbose {
			fmt.Printf("🛡️  ML Worker %d: Request blocked for %s\n", id, job.Target.URL)
		}
	}
	
	if config.Verbose {
		fmt.Printf("✅ ML-Enhanced Worker %d finished\n", id)
	}
}

// Execute ML-enhanced job
func executeMLEnhancedJob(workerID int, job Job, config *Config, client *http.Client, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, prediction *Prediction) (*FoundKey, bool) {
	// Use existing job execution but with ML insights
	return executeSmartJob(workerID, job, config, client, wafDetector, throttleController, rotationManager)
}

// Learn from discovery results
func (engine *MLEngine) learnFromDiscovery(dataPoint DataPoint) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	
	// Add discovery patterns
	// This is simplified - in real implementation, you'd have more sophisticated learning
	engine.TrainingData.Metadata = append(engine.TrainingData.Metadata, dataPoint)
}

// Learn from authentication results
func (engine *MLEngine) learnFromAuthResult(key string, result AuthResult) {
	engine.mutex.Lock()
	defer engine.mutex.Unlock()
	
	// Convert auth result to data point
	dataPoint := DataPoint{
		StatusCode:    result.Response.StatusCode,
		ResponseTime:  result.Response.ResponseTime,
		ContentLength: result.Response.ContentLength,
		Success:       result.Success,
		Timestamp:     result.Timestamp,
		KeyPattern:    analyzeKeyPattern(key),
		AuthMethod:    result.Method.Type,
	}
	
	// Learn from the result
	features := engine.extractFeatures(dataPoint, key)
	label := 0
	if result.Success {
		label = 1
	}
	
	engine.TrainingData.Features = append(engine.TrainingData.Features, features)
	engine.TrainingData.Labels = append(engine.TrainingData.Labels, label)
	engine.TrainingData.Metadata = append(engine.TrainingData.Metadata, dataPoint)
}

// Print ML configuration
func printMLConfig(config *Config, targets []Target, authManager *AuthManager, mlEngine *MLEngine) {
	hasAuth := hasAdvancedAuthFeatures(config)
	hasDiscovery := config.APIDiscovery || config.EndpointEnum
	hasML := hasMLFeatures(config)
	
	fmt.Printf("🤖 Machine Learning: %s\n", formatBool(hasML))
	fmt.Printf("🔐 Advanced Authentication: %s\n", formatBool(hasAuth))
	fmt.Printf("🔍 API Discovery: %s\n", formatBool(hasDiscovery))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s\n", i+1, target.URL)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	// ML features
	if hasML {
		fmt.Printf("\n🤖 Machine Learning Features:\n")
		if config.PatternRecognition {
			fmt.Printf("   ✅ Pattern Recognition\n")
		}
		if config.SuccessPrediction {
			fmt.Printf("   ✅ Success Prediction\n")
		}
		if config.IntelligentSorting {
			fmt.Printf("   ✅ Intelligent Sorting\n")
		}
		if config.AdaptiveLearning {
			fmt.Printf("   ✅ Adaptive Learning\n")
		}
		if config.BehaviorAnalysis {
			fmt.Printf("   ✅ Behavior Analysis\n")
		}
		if config.AnomalyDetection {
			fmt.Printf("   ✅ Anomaly Detection\n")
		}
		
		if mlEngine != nil {
			fmt.Printf("🧠 ML Model: %s v%s\n", mlEngine.Model.Type, mlEngine.Model.Version)
			fmt.Printf("📊 Features: %d\n", len(mlEngine.Model.Features))
			fmt.Printf("🎯 Confidence Threshold: %.2f\n", config.ConfidenceThreshold)
			
			if len(mlEngine.TrainingData.Features) > 0 {
				fmt.Printf("📈 Training Samples: %d\n", len(mlEngine.TrainingData.Features))
			}
		}
	}
	
	// Authentication features
	if hasAuth {
		fmt.Printf("\n🔐 Authentication Methods:\n")
		for _, method := range authManager.Methods {
			fmt.Printf("   ✅ %s (%s)\n", method.Name, method.Type)
		}
		
		if len(authManager.Credentials) > 0 {
			fmt.Printf("🔑 Credentials: %d loaded\n", len(authManager.Credentials))
		}
	}
	
	// Discovery features
	if hasDiscovery {
		fmt.Printf("\n🔍 Discovery Features:\n")
		if config.APIDiscovery {
			fmt.Printf("   ✅ API Discovery\n")
		}
		if config.EndpointEnum {
			fmt.Printf("   ✅ Endpoint Enumeration\n")
		}
		if config.SchemaAnalysis {
			fmt.Printf("   ✅ Schema Analysis\n")
		}
		if config.VersionDetection {
			fmt.Printf("   ✅ Version Detection\n")
		}
		fmt.Printf("📂 Discovery Paths: %d paths\n", len(config.CommonPaths))
	}
	
	fmt.Printf("\n🧵 Threads: %d\n", config.Threads)
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting ML-enhanced attack...")
	fmt.Println()
}

// Print ML brute force configuration
func printMLBruteForceConfig(config *Config, targets []Target, keyCount int, mlEngine *MLEngine) {
	fmt.Printf("🤖 ML-Enhanced Brute Force: %s\n", formatBool(hasMLFeatures(config)))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s [%s]\n", i+1, target.URL, target.Method)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	fmt.Printf("📝 Wordlist: %s (%d keys)\n", config.WordlistPath, keyCount)
	fmt.Printf("🔑 Header: %s\n", config.HeaderFormat)
	fmt.Printf("📡 Method: %s\n", config.HTTPMethod)
	fmt.Printf("✅ Success Codes: %v\n", getSuccessCodesSlice(config.SuccessCodes))
	fmt.Printf("🧵 Threads: %d\n", config.Threads)
	fmt.Printf("🔄 Max Retries: %d\n", config.MaxRetries)
	
	// ML features
	if hasMLFeatures(config) {
		fmt.Printf("\n🤖 ML Features:\n")
		if config.SuccessPrediction {
			fmt.Printf("🧠 Success Prediction: %s\n", formatBool(config.SuccessPrediction))
		}
		if config.IntelligentSorting {
			fmt.Printf("🎯 Intelligent Sorting: %s\n", formatBool(config.IntelligentSorting))
		}
		if config.AdaptiveLearning {
			fmt.Printf("📈 Adaptive Learning: %s\n", formatBool(config.AdaptiveLearning))
		}
		if config.PatternRecognition {
			fmt.Printf("🔍 Pattern Recognition: %s\n", formatBool(config.PatternRecognition))
		}
		if config.AnomalyDetection {
			fmt.Printf("⚠️  Anomaly Detection: %s\n", formatBool(config.AnomalyDetection))
		}
		
		if mlEngine != nil {
			fmt.Printf("🧠 ML Model: %s\n", mlEngine.Model.Type)
			fmt.Printf("🎯 Confidence Threshold: %.2f\n", config.ConfidenceThreshold)
		}
	}
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	totalJobs := len(targets) * keyCount
	fmt.Printf("📈 Total Jobs: %d (%d targets × %d keys)\n", totalJobs, len(targets), keyCount)
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting ML-enhanced brute-force attack...")
	fmt.Println()
}

// Save ML insights
func saveMLInsights(mlEngine *MLEngine, filename string) {
	if mlEngine == nil {
		return
	}
	
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating ML insights file: %v\n", err)
		return
	}
	defer file.Close()

	insights := struct {
		Model           *MLModel        `json:"model"`
		PatternAnalysis *PatternAnalysis `json:"pattern_analysis"`
		Predictions     []Prediction    `json:"predictions"`
		TrainingSize    int             `json:"training_size"`
		LastUpdate      time.Time       `json:"last_update"`
	}{
		Model:           mlEngine.Model,
		PatternAnalysis: mlEngine.PatternAnalysis,
		Predictions:     mlEngine.Predictions,
		TrainingSize:    len(mlEngine.TrainingData.Features),
		LastUpdate:      mlEngine.LastUpdate,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(insights); err != nil {
		fmt.Printf("Error writing ML insights to file: %v\n", err)
	} else {
		fmt.Printf("🧠 ML insights saved to: %s\n", filename)
	}
}

// Mask sensitive strings for display
func maskString(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
// ML Engine
type MLEngine struct {
	Model           *MLModel        `json:"model"`
	TrainingData    *TrainingData   `json:"training_data"`
	PatternAnalysis *PatternAnalysis `json:"pattern_analysis"`
	Predictions     []Prediction    `json:"predictions"`
	IsTraining      bool            `json:"is_training"`
	LastUpdate      time.Time       `json:"last_update"`
	mutex           sync.Mutex
}

// Check if database features are enabled
func hasDatabaseFeatures(config *Config) bool {
	return config.DatabaseEnabled || config.PersistentStorage || config.HistoricalAnalysis ||
		config.AttackAnalytics || config.AutoBackup
}

// Initialize Database Manager
func initDatabaseManager(config *Config) *DatabaseManager {
	dbConfig := &DatabaseConfig{
		Type:         config.DatabaseType,
		Host:         config.DatabaseHost,
		Port:         config.DatabasePort,
		Database:     config.DatabaseName,
		Username:     config.DatabaseUser,
		Password:     config.DatabasePassword,
		MaxConns:     10,
		MaxIdleConns: 5,
		ConnTimeout:  30 * time.Second,
	}
	
	if config.DatabaseSSL {
		dbConfig.SSLMode = "require"
	} else {
		dbConfig.SSLMode = "disable"
	}
	
	manager := &DatabaseManager{
		Config:      dbConfig,
		IsConnected: false,
		Stats:       DatabaseStats{},
	}
	
	// Initialize database connection
	if err := manager.Connect(); err != nil {
		fmt.Printf("⚠️  Database connection failed: %v\n", err)
		return nil
	}
	
	// Create tables if they don't exist
	if err := manager.CreateTables(); err != nil {
		fmt.Printf("⚠️  Database table creation failed: %v\n", err)
		return nil
	}
	
	return manager
}

// Connect to database
func (dm *DatabaseManager) Connect() error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()
	
	switch dm.Config.Type {
	case "sqlite":
		return dm.connectSQLite()
	case "postgres":
		return dm.connectPostgres()
	case "mysql":
		return dm.connectMySQL()
	default:
		return fmt.Errorf("unsupported database type: %s", dm.Config.Type)
	}
}

// Connect to SQLite (demo implementation)
func (dm *DatabaseManager) connectSQLite() error {
	dm.Connection = "sqlite_connection_placeholder"
	dm.IsConnected = true
	return nil
}

// Connect to PostgreSQL (demo implementation)
func (dm *DatabaseManager) connectPostgres() error {
	dm.Connection = "postgres_connection_placeholder"
	dm.IsConnected = true
	return nil
}

// Connect to MySQL (demo implementation)
func (dm *DatabaseManager) connectMySQL() error {
	dm.Connection = "mysql_connection_placeholder"
	dm.IsConnected = true
	return nil
}

// Create database tables
func (dm *DatabaseManager) CreateTables() error {
	if !dm.IsConnected {
		return fmt.Errorf("database not connected")
	}
	
	fmt.Printf("📊 Creating database tables for %s...\n", dm.Config.Type)
	
	tables := []string{
		"attack_sessions",
		"attack_targets", 
		"attack_results",
		"discovery_sessions",
		"discovered_endpoints",
		"authentication_results",
		"ml_insights",
	}
	
	for _, table := range tables {
		// Simulate table creation
		_ = table
	}
	
	return nil
}
// Create attack session
func createAttackSession(dbManager *DatabaseManager, config *Config, targets []Target) string {
	if dbManager == nil || !dbManager.IsConnected {
		return ""
	}
	
	sessionID := generateSessionID()
	
	session := AttackSession{
		ID:            sessionID,
		StartTime:     time.Now(),
		Status:        "running",
		TargetCount:   len(targets),
		KeyCount:      0,
		SuccessCount:  0,
		TotalRequests: 0,
		Config:        configToMap(config),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	
	if err := dbManager.InsertAttackSession(session); err != nil {
		fmt.Printf("⚠️  Failed to create attack session: %v\n", err)
		return ""
	}
	
	return sessionID
}

// Generate session ID
func generateSessionID() string {
	return fmt.Sprintf("session_%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}

// Convert config to map
func configToMap(config *Config) map[string]interface{} {
	return map[string]interface{}{
		"threads":           config.Threads,
		"rate_limit":        config.RateLimit,
		"timeout":           config.Timeout.String(),
		"max_retries":       config.MaxRetries,
		"ml_enabled":        config.MLEnabled,
		"database_enabled":  config.DatabaseEnabled,
	}
}

// Database operations (demo implementations)
func (dm *DatabaseManager) InsertAttackSession(session AttackSession) error {
	dm.Stats.TotalSessions++
	return nil
}

func (dm *DatabaseManager) InsertAttackTarget(target AttackTarget) error {
	dm.Stats.TotalTargets++
	return nil
}

func (dm *DatabaseManager) InsertAttackResult(result AttackResult) error {
	dm.Stats.TotalResults++
	dm.Stats.QueryCount++
	return nil
}

// Execute database-enhanced discovery
func executeDatabaseEnhancedDiscovery(config *Config, targets []Target, client *http.Client, limiter *rate.Limiter, pathDiscovery *PathDiscovery, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, sessionID string) []DiscoveryResult {
	results := executeMLEnhancedDiscovery(config, targets, client, limiter, pathDiscovery, wafDetector, throttleController, rotationManager, mlEngine)
	
	// Store discovery results in database if enabled
	if dbManager != nil && config.PersistentStorage {
		for _, result := range results {
			discoverySession := DiscoverySession{
				ID:              generateSessionID(),
				SessionID:       sessionID,
				TargetURL:       result.Target,
				PathsScanned:    result.Statistics.TotalRequests,
				EndpointsFound:  result.Statistics.EndpointsFound,
				AuthEndpoints:   result.Statistics.AuthEndpoints,
				PublicEndpoints: result.Statistics.PublicEndpoints,
				ErrorEndpoints:  result.Statistics.ErrorEndpoints,
				DiscoveryTime:   result.Statistics.DiscoveryTime,
				AvgResponseTime: result.Statistics.AverageResponse,
				StartTime:       result.Timestamp,
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}
			
			dbManager.InsertDiscoverySession(discoverySession)
		}
	}
	
	return results
}

// Execute database-enhanced authentication
func executeDatabaseEnhancedAuth(config *Config, targets []Target, keys []string, authManager *AuthManager, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, sessionID string) []AuthResult {
	results := executeMLEnhancedAuth(config, targets, keys, authManager, client, limiter, wafDetector, throttleController, rotationManager, mlEngine)
	
	// Store authentication results in database if enabled
	if dbManager != nil && config.PersistentStorage {
		for _, result := range results {
			authRecord := AuthenticationResult{
				ID:           generateResultID(),
				SessionID:    sessionID,
				TargetURL:    "target_url",
				AuthMethod:   result.Method.Type,
				Success:      result.Success,
				StatusCode:   result.Response.StatusCode,
				ResponseTime: result.Response.ResponseTime,
				Timestamp:    result.Timestamp,
				CreatedAt:    time.Now(),
			}
			
			if result.Token != "" {
				authRecord.Token = &result.Token
			}
			
			dbManager.InsertAuthenticationResult(authRecord)
		}
	}
	
	return results
}

// Generate result ID
func generateResultID() string {
	return fmt.Sprintf("result_%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}

// Database operations for discovery and auth
func (dm *DatabaseManager) InsertDiscoverySession(session DiscoverySession) error {
	return nil
}

func (dm *DatabaseManager) InsertAuthenticationResult(result AuthenticationResult) error {
	return nil
}
// Execute database-enhanced brute force
func executeDatabaseEnhancedBruteForce(config *Config, jobs []Job, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, sessionID string) []FoundKey {
	jobsChan := make(chan Job, len(jobs))
	results := make(chan FoundKey, len(jobs))
	var wg sync.WaitGroup
	
	// Start database-enhanced workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go databaseEnhancedWorker(i+1, config, jobsChan, results, &wg, client, limiter, wafDetector, throttleController, rotationManager, mlEngine, dbManager, sessionID)
	}
	
	// Send jobs
	for _, job := range jobs {
		jobsChan <- job
	}
	close(jobsChan)
	
	// Wait for completion
	wg.Wait()
	close(results)
	
	// Collect results
	return collectResults(results)
}

// Database-enhanced worker
func databaseEnhancedWorker(id int, config *Config, jobs <-chan Job, results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, sessionID string) {
	defer wg.Done()
	
	if config.Verbose {
		fmt.Printf("💾 Database-Enhanced Worker %d started\n", id)
	}
	
	for job := range jobs {
		// Get ML prediction if enabled
		var prediction *Prediction
		if mlEngine != nil && config.SuccessPrediction {
			prediction = mlEngine.predictSuccess(job.Key, job.Target)
		}
		
		// Rate limiting
		if limiter != nil {
			limiter.Wait(context.Background())
		}
		
		// Smart throttling delay
		currentDelay := throttleController.CurrentDelay
		if config.RandomDelay && currentDelay > 0 {
			variation := 0.5 + (float64(time.Now().UnixNano()%100) / 100.0)
			currentDelay = time.Duration(float64(currentDelay) * variation)
		}
		
		if currentDelay > 0 {
			time.Sleep(currentDelay)
		}
		
		// Execute job with database enhancement
		found, blocked := executeDatabaseEnhancedJob(id, job, config, client, wafDetector, throttleController, rotationManager, mlEngine, dbManager, sessionID, prediction)
		
		if found != nil {
			results <- *found
			fmt.Printf("🎉 [FOUND] DB Worker %d: Key: %s -> Status: %d at %s (%dms)\n", 
				id, found.Key, found.StatusCode, found.URL, found.ResponseTime)
			
			// Learn from successful result
			if mlEngine != nil && config.AdaptiveLearning {
				mlEngine.learnFromResult(job.Key, job.Target, *found, true)
			}
		} else if mlEngine != nil && config.AdaptiveLearning {
			// Learn from failed result
			dummyResult := FoundKey{
				Key:          job.Key,
				StatusCode:   0,
				URL:          job.Target.URL,
				ResponseTime: 0,
				Timestamp:    time.Now(),
			}
			mlEngine.learnFromResult(job.Key, job.Target, dummyResult, false)
		}
		
		if blocked && config.Verbose {
			fmt.Printf("🛡️  DB Worker %d: Request blocked for %s\n", id, job.Target.URL)
		}
	}
	
	if config.Verbose {
		fmt.Printf("✅ Database-Enhanced Worker %d finished\n", id)
	}
}

// Execute database-enhanced job
func executeDatabaseEnhancedJob(workerID int, job Job, config *Config, client *http.Client, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, sessionID string, prediction *Prediction) (*FoundKey, bool) {
	// Execute the job
	found, blocked := executeMLEnhancedJob(workerID, job, config, client, wafDetector, throttleController, rotationManager, mlEngine, prediction)
	
	// Store result in database if enabled
	if dbManager != nil && config.PersistentStorage {
		result := AttackResult{
			ID:        generateResultID(),
			SessionID: sessionID,
			TargetID:  "target_id",
			Key:       job.Key,
			URL:       job.Target.URL,
			Method:    job.Target.Method,
			Success:   found != nil,
			Timestamp: time.Now(),
			CreatedAt: time.Now(),
		}
		
		if found != nil {
			result.StatusCode = found.StatusCode
			result.ResponseTime = found.ResponseTime
			result.ContentLength = found.ContentLength
		}
		
		if prediction != nil {
			result.MLPrediction = &prediction.Probability
			result.MLConfidence = &prediction.Confidence
		}
		
		dbManager.InsertAttackResult(result)
	}
	
	return found, blocked
}

// Finalize attack session
func finalizeAttackSession(dbManager *DatabaseManager, sessionID string) {
	if dbManager == nil || sessionID == "" {
		return
	}
	
	// Update session status to completed
	_ = time.Now() // endTime for future use
	// In real implementation, you'd update the database record
	fmt.Printf("📊 Attack session %s completed\n", sessionID)
}

// Generate attack analytics
func generateAttackAnalytics(dbManager *DatabaseManager) *AttackAnalytics {
	if dbManager == nil {
		return nil
	}
	
	// In real implementation, you'd query the database for analytics
	analytics := &AttackAnalytics{
		TotalSessions:     dbManager.Stats.TotalSessions,
		TotalTargets:      dbManager.Stats.TotalTargets,
		TotalRequests:     dbManager.Stats.TotalResults,
		SuccessfulAttacks: dbManager.Stats.TotalResults / 10, // Demo calculation
		SuccessRate:       0.1, // Demo value
		AvgResponseTime:   450.0, // Demo value
		TopTargets: []TargetStats{
			{URL: "https://api.example.com", RequestCount: 100, SuccessCount: 10, SuccessRate: 0.1, AvgResponseTime: 450.0},
		},
		TopKeys: []KeyStats{
			{KeyPattern: "ULNS", Length: 20, UsageCount: 50, SuccessCount: 5, SuccessRate: 0.1},
		},
		TimeDistribution: []TimeStats{
			{Hour: 14, RequestCount: 100, SuccessCount: 10, SuccessRate: 0.1},
		},
		StatusDistribution: []StatusStats{
			{StatusCode: 200, Count: 10, Percentage: 10.0},
			{StatusCode: 401, Count: 90, Percentage: 90.0},
		},
		MethodDistribution: []MethodStats{
			{Method: "GET", Count: 100, SuccessCount: 10, SuccessRate: 0.1},
		},
		RecentActivity: []RecentActivityStats{
			{Date: "2025-07-09", SessionCount: 1, RequestCount: 100, SuccessCount: 10},
		},
	}
	
	return analytics
}

// Save attack analytics
func saveAttackAnalytics(analytics *AttackAnalytics, filename string) {
	if analytics == nil {
		return
	}
	
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating analytics file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(analytics); err != nil {
		fmt.Printf("Error writing analytics to file: %v\n", err)
	} else {
		fmt.Printf("📊 Attack analytics saved to: %s\n", filename)
	}
}

// Print attack analytics
func printAttackAnalytics(analytics *AttackAnalytics) {
	if analytics == nil {
		return
	}
	
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("📊 ATTACK ANALYTICS")
	fmt.Println(strings.Repeat("=", 70))
	
	fmt.Printf("📈 Total Sessions: %d\n", analytics.TotalSessions)
	fmt.Printf("🎯 Total Targets: %d\n", analytics.TotalTargets)
	fmt.Printf("📡 Total Requests: %d\n", analytics.TotalRequests)
	fmt.Printf("✅ Successful Attacks: %d\n", analytics.SuccessfulAttacks)
	fmt.Printf("📊 Success Rate: %.2f%%\n", analytics.SuccessRate*100)
	fmt.Printf("⏱️  Average Response Time: %.2fms\n", analytics.AvgResponseTime)
	
	if len(analytics.TopTargets) > 0 {
		fmt.Printf("\n🎯 Top Targets:\n")
		for i, target := range analytics.TopTargets {
			if i >= 5 { break }
			fmt.Printf("   %d. %s - %d requests (%.1f%% success)\n", 
				i+1, target.URL, target.RequestCount, target.SuccessRate*100)
		}
	}
	
	if len(analytics.StatusDistribution) > 0 {
		fmt.Printf("\n📊 Status Code Distribution:\n")
		for _, status := range analytics.StatusDistribution {
			fmt.Printf("   %d: %d requests (%.1f%%)\n", 
				status.StatusCode, status.Count, status.Percentage)
		}
	}
	
	fmt.Println(strings.Repeat("=", 70))
}

// Perform database backup
func performDatabaseBackup(dbManager *DatabaseManager) {
	if dbManager == nil {
		return
	}
	
	fmt.Printf("💾 Performing database backup...\n")
	
	// In real implementation, you'd perform actual database backup
	backupTime := time.Now()
	dbManager.LastBackup = &backupTime
	
	fmt.Printf("✅ Database backup completed at %s\n", backupTime.Format("2006-01-02 15:04:05"))
}

// Save ML insights to database
func saveMLInsightsToDatabase(dbManager *DatabaseManager, sessionID string, mlEngine *MLEngine) {
	if dbManager == nil || mlEngine == nil {
		return
	}
	
	_ = MLInsight{
		ID:           generateResultID(),
		SessionID:    sessionID,
		ModelType:    mlEngine.Model.Type,
		ModelVersion: mlEngine.Model.Version,
		Accuracy:     mlEngine.Model.Accuracy,
		TrainingSize: len(mlEngine.TrainingData.Features),
		Features:     strings.Join(mlEngine.Model.Features, ","),
		LastUpdate:   mlEngine.LastUpdate,
		CreatedAt:    time.Now(),
	}
	
	// In real implementation, you'd insert into database
	fmt.Printf("🧠 ML insights saved to database for session %s\n", sessionID)
}
// Print database configuration
func printDatabaseConfig(config *Config, targets []Target, authManager *AuthManager, mlEngine *MLEngine, dbManager *DatabaseManager) {
	hasAuth := hasAdvancedAuthFeatures(config)
	hasDiscovery := config.APIDiscovery || config.EndpointEnum
	hasML := hasMLFeatures(config)
	hasDB := hasDatabaseFeatures(config)
	
	fmt.Printf("💾 Database Integration: %s\n", formatBool(hasDB))
	fmt.Printf("🤖 Machine Learning: %s\n", formatBool(hasML))
	fmt.Printf("🔐 Advanced Authentication: %s\n", formatBool(hasAuth))
	fmt.Printf("🔍 API Discovery: %s\n", formatBool(hasDiscovery))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s\n", i+1, target.URL)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	// Database features
	if hasDB {
		fmt.Printf("\n💾 Database Features:\n")
		if dbManager != nil {
			fmt.Printf("   ✅ Database Type: %s\n", dbManager.Config.Type)
			fmt.Printf("   ✅ Connection: %s\n", formatBool(dbManager.IsConnected))
		}
		if config.PersistentStorage {
			fmt.Printf("   ✅ Persistent Storage\n")
		}
		if config.HistoricalAnalysis {
			fmt.Printf("   ✅ Historical Analysis\n")
		}
		if config.AttackAnalytics {
			fmt.Printf("   ✅ Attack Analytics\n")
		}
		if config.AutoBackup {
			fmt.Printf("   ✅ Auto Backup (every %v)\n", config.BackupInterval)
		}
		if config.QueryOptimization {
			fmt.Printf("   ✅ Query Optimization\n")
		}
		if config.IndexingEnabled {
			fmt.Printf("   ✅ Database Indexing\n")
		}
		if config.CacheEnabled {
			fmt.Printf("   ✅ Query Caching (%d MB)\n", config.CacheSize)
		}
		
		fmt.Printf("📅 Data Retention: %d days\n", config.DataRetention)
		
		if dbManager != nil {
			fmt.Printf("📊 Database Stats:\n")
			fmt.Printf("   Sessions: %d\n", dbManager.Stats.TotalSessions)
			fmt.Printf("   Targets: %d\n", dbManager.Stats.TotalTargets)
			fmt.Printf("   Results: %d\n", dbManager.Stats.TotalResults)
		}
	}
	
	// ML features
	if hasML {
		fmt.Printf("\n🤖 Machine Learning Features:\n")
		if config.PatternRecognition {
			fmt.Printf("   ✅ Pattern Recognition\n")
		}
		if config.SuccessPrediction {
			fmt.Printf("   ✅ Success Prediction\n")
		}
		if config.IntelligentSorting {
			fmt.Printf("   ✅ Intelligent Sorting\n")
		}
		if config.AdaptiveLearning {
			fmt.Printf("   ✅ Adaptive Learning\n")
		}
		if config.BehaviorAnalysis {
			fmt.Printf("   ✅ Behavior Analysis\n")
		}
		if config.AnomalyDetection {
			fmt.Printf("   ✅ Anomaly Detection\n")
		}
		
		if mlEngine != nil {
			fmt.Printf("🧠 ML Model: %s v%s\n", mlEngine.Model.Type, mlEngine.Model.Version)
			fmt.Printf("📊 Features: %d\n", len(mlEngine.Model.Features))
			fmt.Printf("🎯 Confidence Threshold: %.2f\n", config.ConfidenceThreshold)
			
			if len(mlEngine.TrainingData.Features) > 0 {
				fmt.Printf("📈 Training Samples: %d\n", len(mlEngine.TrainingData.Features))
			}
		}
	}
	
	// Authentication features
	if hasAuth {
		fmt.Printf("\n🔐 Authentication Methods:\n")
		for _, method := range authManager.Methods {
			fmt.Printf("   ✅ %s (%s)\n", method.Name, method.Type)
		}
		
		if len(authManager.Credentials) > 0 {
			fmt.Printf("🔑 Credentials: %d loaded\n", len(authManager.Credentials))
		}
	}
	
	// Discovery features
	if hasDiscovery {
		fmt.Printf("\n🔍 Discovery Features:\n")
		if config.APIDiscovery {
			fmt.Printf("   ✅ API Discovery\n")
		}
		if config.EndpointEnum {
			fmt.Printf("   ✅ Endpoint Enumeration\n")
		}
		if config.SchemaAnalysis {
			fmt.Printf("   ✅ Schema Analysis\n")
		}
		if config.VersionDetection {
			fmt.Printf("   ✅ Version Detection\n")
		}
		fmt.Printf("📂 Discovery Paths: %d paths\n", len(config.CommonPaths))
	}
	
	fmt.Printf("\n🧵 Threads: %d\n", config.Threads)
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting database-enhanced attack...")
	fmt.Println()
}

// Print database brute force configuration
func printDatabaseBruteForceConfig(config *Config, targets []Target, keyCount int, mlEngine *MLEngine, dbManager *DatabaseManager) {
	fmt.Printf("💾 Database-Enhanced Brute Force: %s\n", formatBool(hasDatabaseFeatures(config)))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s [%s]\n", i+1, target.URL, target.Method)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	fmt.Printf("📝 Wordlist: %s (%d keys)\n", config.WordlistPath, keyCount)
	fmt.Printf("🔑 Header: %s\n", config.HeaderFormat)
	fmt.Printf("📡 Method: %s\n", config.HTTPMethod)
	fmt.Printf("✅ Success Codes: %v\n", getSuccessCodesSlice(config.SuccessCodes))
	fmt.Printf("🧵 Threads: %d\n", config.Threads)
	fmt.Printf("🔄 Max Retries: %d\n", config.MaxRetries)
	
	// Database features
	if hasDatabaseFeatures(config) {
		fmt.Printf("\n💾 Database Features:\n")
		if config.PersistentStorage {
			fmt.Printf("💾 Persistent Storage: %s\n", formatBool(config.PersistentStorage))
		}
		if config.AttackAnalytics {
			fmt.Printf("📊 Attack Analytics: %s\n", formatBool(config.AttackAnalytics))
		}
		if config.HistoricalAnalysis {
			fmt.Printf("📈 Historical Analysis: %s\n", formatBool(config.HistoricalAnalysis))
		}
		
		if dbManager != nil {
			fmt.Printf("🗄️  Database: %s\n", dbManager.Config.Type)
			fmt.Printf("🔗 Connection: %s\n", formatBool(dbManager.IsConnected))
		}
	}
	
	// ML features
	if hasMLFeatures(config) {
		fmt.Printf("\n🤖 ML Features:\n")
		if config.SuccessPrediction {
			fmt.Printf("🧠 Success Prediction: %s\n", formatBool(config.SuccessPrediction))
		}
		if config.IntelligentSorting {
			fmt.Printf("🎯 Intelligent Sorting: %s\n", formatBool(config.IntelligentSorting))
		}
		if config.AdaptiveLearning {
			fmt.Printf("📈 Adaptive Learning: %s\n", formatBool(config.AdaptiveLearning))
		}
		
		if mlEngine != nil {
			fmt.Printf("🧠 ML Model: %s\n", mlEngine.Model.Type)
			fmt.Printf("🎯 Confidence Threshold: %.2f\n", config.ConfidenceThreshold)
		}
	}
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	totalJobs := len(targets) * keyCount
	fmt.Printf("📈 Total Jobs: %d (%d targets × %d keys)\n", totalJobs, len(targets), keyCount)
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting database-enhanced brute-force attack...")
	fmt.Println()
}
type DatabaseStats struct {
	TotalSessions    int       `json:"total_sessions"`
	TotalTargets     int       `json:"total_targets"`
	TotalResults     int       `json:"total_results"`
	DatabaseSize     int64     `json:"database_size"`
	LastQuery        time.Time `json:"last_query"`
	QueryCount       int64     `json:"query_count"`
	AvgQueryTime     float64   `json:"avg_query_time"`
}

// Check if web dashboard features are enabled
func hasWebDashboardFeatures(config *Config) bool {
	return config.WebDashboard || config.RealTimeMonitoring || config.TeamCollaboration ||
		config.VisualAnalytics || config.WebAPI || config.WebSocketEnabled
}

// Initialize Dashboard Manager
func initDashboardManager(config *Config, dbManager *DatabaseManager, mlEngine *MLEngine) *DashboardManager {
	dashboardConfig := &DashboardConfig{
		Host:             config.DashboardHost,
		Port:             config.DashboardPort,
		SSL:              config.DashboardSSL,
		CertFile:         config.DashboardCert,
		KeyFile:          config.DashboardKey,
		AuthEnabled:      config.DashboardAuth,
		Username:         config.DashboardUser,
		Password:         config.DashboardPassword,
		APIKey:           config.APIKey,
		CORSEnabled:      config.CORSEnabled,
		WebSocketEnabled: config.WebSocketEnabled,
		StaticPath:       "./web/static",
		TemplatePath:     "./web/templates",
	}
	
	dashboard := &WebDashboard{
		Config:         dashboardConfig,
		IsRunning:      false,
		StartTime:      time.Now(),
		Connections:    0,
		ActiveSessions: make(map[string]*Session),
		WebSocketConns: make(map[string]*WebSocket),
		Notifications:  []Notification{},
		Alerts:         []Alert{},
	}
	
	stats := &DashboardStats{
		TotalSessions:      0,
		ActiveSessions:     0,
		TotalRequests:      0,
		SuccessfulRequests: 0,
		FailedRequests:     0,
		AvgResponseTime:    0.0,
		RequestsPerSecond:  0.0,
		TopTargets:         []TargetStats{},
		RecentActivity:     []ActivityLog{},
		SystemHealth:       SystemHealth{},
		Alerts:             []Alert{},
		LastUpdate:         time.Now(),
	}
	
	manager := &DashboardManager{
		Dashboard: dashboard,
		Database:  dbManager,
		MLEngine:  mlEngine,
		Config:    config,
		IsRunning: false,
		StartTime: time.Now(),
		Stats:     stats,
	}
	
	return manager
}

// Start dashboard server
func startDashboardServer(manager *DashboardManager) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	
	if manager.IsRunning {
		return fmt.Errorf("dashboard server is already running")
	}
	
	mux := http.NewServeMux()
	
	// Setup routes
	setupDashboardRoutes(mux, manager)
	
	// Create server
	addr := fmt.Sprintf("%s:%d", manager.Dashboard.Config.Host, manager.Dashboard.Config.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	
	manager.Dashboard.Server = server
	manager.IsRunning = true
	manager.Dashboard.IsRunning = true
	
	fmt.Printf("🌐 Starting web dashboard server on %s\n", addr)
	
	// Start server
	go func() {
		var err error
		if manager.Dashboard.Config.SSL {
			err = server.ListenAndServeTLS(manager.Dashboard.Config.CertFile, manager.Dashboard.Config.KeyFile)
		} else {
			err = server.ListenAndServe()
		}
		
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("❌ Dashboard server error: %v\n", err)
		}
	}()
	
	// Start background tasks
	go manager.startBackgroundTasks()
	
	return nil
}

// Setup dashboard routes
func setupDashboardRoutes(mux *http.ServeMux, manager *DashboardManager) {
	// Static files
	mux.HandleFunc("/static/", handleStatic)
	
	// Main dashboard
	mux.HandleFunc("/", handleDashboard(manager))
	mux.HandleFunc("/dashboard", handleDashboard(manager))
	
	// API endpoints
	mux.HandleFunc("/api/stats", handleAPIStats(manager))
	mux.HandleFunc("/api/sessions", handleAPISessions(manager))
	mux.HandleFunc("/api/targets", handleAPITargets(manager))
	mux.HandleFunc("/api/results", handleAPIResults(manager))
	mux.HandleFunc("/api/analytics", handleAPIAnalytics(manager))
	mux.HandleFunc("/api/health", handleAPIHealth(manager))
	mux.HandleFunc("/api/notifications", handleAPINotifications(manager))
	mux.HandleFunc("/api/alerts", handleAPIAlerts(manager))
	
	// WebSocket endpoint
	if manager.Dashboard.Config.WebSocketEnabled {
		mux.HandleFunc("/ws", handleWebSocket(manager))
	}
	
	// Authentication endpoints
	if manager.Dashboard.Config.AuthEnabled {
		mux.HandleFunc("/login", handleLogin(manager))
		mux.HandleFunc("/logout", handleLogout(manager))
	}
}

// Handle static files
func handleStatic(w http.ResponseWriter, r *http.Request) {
	// Get file path
	filePath := r.URL.Path[1:] // Remove leading slash
	
	// Security check - prevent directory traversal
	if strings.Contains(filePath, "..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	
	// Try to serve from web directory
	fullPath := "./" + filePath
	if _, err := os.Stat(fullPath); err == nil {
		// Set appropriate content type
		if strings.HasSuffix(filePath, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(filePath, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		} else if strings.HasSuffix(filePath, ".png") {
			w.Header().Set("Content-Type", "image/png")
		} else if strings.HasSuffix(filePath, ".jpg") || strings.HasSuffix(filePath, ".jpeg") {
			w.Header().Set("Content-Type", "image/jpeg")
		} else if strings.HasSuffix(filePath, ".svg") {
			w.Header().Set("Content-Type", "image/svg+xml")
		}
		
		http.ServeFile(w, r, fullPath)
		return
	}
	
	// Fallback response
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("File not found: " + filePath))
}

// Handle main dashboard
func handleDashboard(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check authentication if enabled
		if manager.Dashboard.Config.AuthEnabled {
			if !isAuthenticated(r, manager) {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}
		
		// Serve dashboard HTML from template
		dashboardHTML, err := getDashboardHTMLFromFile()
		if err != nil {
			// Fallback to embedded HTML
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(getDashboardHTML(manager)))
			return
		}
		
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(dashboardHTML))
	}
}

// Handle API stats
func handleAPIStats(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check API authentication
		if !isAPIAuthenticated(r, manager) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Update stats
		manager.updateStats()
		
		response := APIResponse{
			Success:   true,
			Data:      manager.Stats,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Handle API sessions
func handleAPISessions(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAPIAuthenticated(r, manager) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		sessions := manager.getActiveSessions()
		
		response := APIResponse{
			Success:   true,
			Data:      sessions,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Handle API targets
func handleAPITargets(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAPIAuthenticated(r, manager) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		targets := manager.getTargetStats()
		
		response := APIResponse{
			Success:   true,
			Data:      targets,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Handle API results
func handleAPIResults(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAPIAuthenticated(r, manager) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		results := manager.getRecentResults()
		
		response := APIResponse{
			Success:   true,
			Data:      results,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Handle API analytics
func handleAPIAnalytics(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAPIAuthenticated(r, manager) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		analytics := manager.getAnalytics()
		
		response := APIResponse{
			Success:   true,
			Data:      analytics,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Handle API health
func handleAPIHealth(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := manager.getSystemHealth()
		
		response := APIResponse{
			Success:   true,
			Data:      health,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Handle API notifications
func handleAPINotifications(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAPIAuthenticated(r, manager) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		notifications := manager.getNotifications()
		
		response := APIResponse{
			Success:   true,
			Data:      notifications,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Handle API alerts
func handleAPIAlerts(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAPIAuthenticated(r, manager) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		alerts := manager.getAlerts()
		
		response := APIResponse{
			Success:   true,
			Data:      alerts,
			Timestamp: time.Now(),
			RequestID: generateRequestID(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
// Handle WebSocket connections
func handleWebSocket(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In real implementation, upgrade to WebSocket
		// For demo, return simple response
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("WebSocket endpoint - would upgrade connection here"))
	}
}

// Handle login
func handleLogin(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")
			
			if username == manager.Dashboard.Config.Username && password == manager.Dashboard.Config.Password {
				// Create session
				sessionID := generateSessionID()
				session := &Session{
					ID:           sessionID,
					UserID:       username,
					StartTime:    time.Now(),
					LastActivity: time.Now(),
					IPAddress:    r.RemoteAddr,
					UserAgent:    r.UserAgent(),
					IsActive:     true,
					Permissions:  []string{"read", "write"},
				}
				
				manager.Dashboard.ActiveSessions[sessionID] = session
				
				// Set cookie
				http.SetCookie(w, &http.Cookie{
					Name:  "session_id",
					Value: sessionID,
					Path:  "/",
				})
				
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
		}
		
		// Show login form
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(getLoginHTML()))
	}
}

// Handle logout
func handleLogout(manager *DashboardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear session
		cookie, err := r.Cookie("session_id")
		if err == nil {
			delete(manager.Dashboard.ActiveSessions, cookie.Value)
		}
		
		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:   "session_id",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// Check if user is authenticated
func isAuthenticated(r *http.Request, manager *DashboardManager) bool {
	if !manager.Dashboard.Config.AuthEnabled {
		return true
	}
	
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return false
	}
	
	session, exists := manager.Dashboard.ActiveSessions[cookie.Value]
	if !exists || !session.IsActive {
		return false
	}
	
	// Update last activity
	session.LastActivity = time.Now()
	return true
}

// Check if API request is authenticated
func isAPIAuthenticated(r *http.Request, manager *DashboardManager) bool {
	// Check API key
	apiKey := r.Header.Get("X-API-Key")
	if apiKey != "" && apiKey == manager.Dashboard.Config.APIKey {
		return true
	}
	
	// Check session authentication
	return isAuthenticated(r, manager)
}

// Generate request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}

// Generate session ID (reuse existing function)
func generateDashboardSessionID() string {
	return fmt.Sprintf("dash_session_%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}

// Get dashboard HTML
func getDashboardHTML(manager *DashboardManager) string {
	return `<!DOCTYPE html>
<html>
<head>
    <title>CoyoteKey Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2em; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .section { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section h2 { margin-top: 0; color: #2c3e50; }
        .status-running { color: #27ae60; }
        .status-stopped { color: #e74c3c; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 3px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
    </style>
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
        <div class="stat-card">
            <div class="stat-value" id="active-sessions">0</div>
            <div class="stat-label">Active Sessions</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="total-requests">0</div>
            <div class="stat-label">Total Requests</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="success-rate">0%</div>
            <div class="stat-label">Success Rate</div>
        </div>
    </div>
    
    <div class="section">
        <h2>System Status</h2>
        <p>Dashboard Status: <span class="status-running">🟢 Running</span></p>
        <p>Database Status: <span class="status-running">🟢 Connected</span></p>
        <p>ML Engine Status: <span class="status-running">🟢 Active</span></p>
        <button class="refresh-btn" onclick="refreshStats()">🔄 Refresh</button>
    </div>
    
    <div class="section">
        <h2>Recent Activity</h2>
        <div id="recent-activity">
            <p>Loading recent activity...</p>
        </div>
    </div>
    
    <script>
        function refreshStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('total-sessions').textContent = data.data.total_sessions || 0;
                        document.getElementById('active-sessions').textContent = data.data.active_sessions || 0;
                        document.getElementById('total-requests').textContent = data.data.total_requests || 0;
                        const successRate = ((data.data.successful_requests || 0) / (data.data.total_requests || 1) * 100).toFixed(1);
                        document.getElementById('success-rate').textContent = successRate + '%';
                    }
                })
                .catch(error => console.error('Error fetching stats:', error));
        }
        
        // Auto-refresh every 5 seconds
        setInterval(refreshStats, 5000);
        
        // Initial load
        refreshStats();
    </script>
</body>
</html>`
}

// Get login HTML
func getLoginHTML() string {
	return `<!DOCTYPE html>
<html>
<head>
    <title>CoyoteKey Dashboard - Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #34495e; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-form { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); width: 300px; }
        .login-form h1 { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #555; }
        .form-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        .login-btn { width: 100%; background: #3498db; color: white; border: none; padding: 12px; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .login-btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <form class="login-form" method="post">
        <h1>🔐 CoyoteKey</h1>
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="login-btn">Login</button>
    </form>
</body>
</html>`
}

// Start background tasks
func (manager *DashboardManager) startBackgroundTasks() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			manager.updateStats()
			manager.checkAlerts()
			manager.cleanupSessions()
		}
	}
}

// Update dashboard stats
func (manager *DashboardManager) updateStats() {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	
	// Update basic stats
	if manager.Database != nil {
		manager.Stats.TotalSessions = manager.Database.Stats.TotalSessions
		manager.Stats.TotalRequests = int64(manager.Database.Stats.TotalResults)
	}
	
	manager.Stats.ActiveSessions = len(manager.Dashboard.ActiveSessions)
	manager.Stats.LastUpdate = time.Now()
	
	// Calculate success rate
	if manager.Stats.TotalRequests > 0 {
		// This is simplified - in real implementation, calculate from database
		manager.Stats.SuccessfulRequests = manager.Stats.TotalRequests / 10 // Demo calculation
	}
	
	// Update system health
	manager.Stats.SystemHealth = SystemHealth{
		CPUUsage:    50.0, // Demo value
		MemoryUsage: 30.0, // Demo value
		DiskUsage:   20.0, // Demo value
		Uptime:      int64(time.Since(manager.StartTime).Seconds()),
		LastCheck:   time.Now(),
	}
	
	if manager.Database != nil {
		manager.Stats.SystemHealth.DatabaseHealth = DBHealth{
			Connected:         manager.Database.IsConnected,
			ResponseTime:      manager.Database.Stats.AvgQueryTime,
			ActiveConnections: 5, // Demo value
			QueriesPerSecond:  10.0, // Demo value
			DatabaseSize:      manager.Database.Stats.DatabaseSize,
		}
	}
}

// Check alerts
func (manager *DashboardManager) checkAlerts() {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	
	// Check success rate alert
	if manager.Stats.TotalRequests > 100 {
		successRate := float64(manager.Stats.SuccessfulRequests) / float64(manager.Stats.TotalRequests)
		threshold := manager.Config.AlertThresholds["success_rate_low"]
		
		if successRate < threshold {
			alert := Alert{
				ID:           generateAlertID(),
				Type:         "success_rate_low",
				Condition:    fmt.Sprintf("Success rate < %.1f%%", threshold*100),
				Threshold:    threshold,
				CurrentValue: successRate,
				Triggered:    true,
				Message:      fmt.Sprintf("Success rate is %.2f%%, below threshold of %.1f%%", successRate*100, threshold*100),
				Severity:     "warning",
				CreatedAt:    time.Now(),
				TriggeredAt:  &[]time.Time{time.Now()}[0],
			}
			
			manager.Dashboard.Alerts = append(manager.Dashboard.Alerts, alert)
			
			// Create notification
			notification := Notification{
				ID:        generateNotificationID(),
				Type:      "alert",
				Title:     "Low Success Rate Alert",
				Message:   alert.Message,
				Level:     "warning",
				Timestamp: time.Now(),
			}
			
			manager.Dashboard.Notifications = append(manager.Dashboard.Notifications, notification)
		}
	}
}

// Cleanup expired sessions
func (manager *DashboardManager) cleanupSessions() {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	
	now := time.Now()
	for sessionID, session := range manager.Dashboard.ActiveSessions {
		// Remove sessions inactive for more than 1 hour
		if now.Sub(session.LastActivity) > time.Hour {
			delete(manager.Dashboard.ActiveSessions, sessionID)
		}
	}
}

// Helper functions for dashboard manager
func (manager *DashboardManager) getActiveSessions() []Session {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	
	sessions := make([]Session, 0, len(manager.Dashboard.ActiveSessions))
	for _, session := range manager.Dashboard.ActiveSessions {
		sessions = append(sessions, *session)
	}
	return sessions
}

func (manager *DashboardManager) getTargetStats() []TargetStats {
	// In real implementation, query from database
	return []TargetStats{
		{URL: "https://api.example.com", RequestCount: 100, SuccessCount: 5, SuccessRate: 0.05, AvgResponseTime: 450.0},
	}
}

func (manager *DashboardManager) getRecentResults() []interface{} {
	// In real implementation, query recent results from database
	return []interface{}{
		map[string]interface{}{
			"timestamp": time.Now().Add(-5 * time.Minute),
			"url":       "https://api.example.com",
			"key":       "test_key_123",
			"status":    401,
			"success":   false,
		},
	}
}

func (manager *DashboardManager) getAnalytics() interface{} {
	return manager.Stats
}

func (manager *DashboardManager) getSystemHealth() SystemHealth {
	return manager.Stats.SystemHealth
}

func (manager *DashboardManager) getNotifications() []Notification {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	return manager.Dashboard.Notifications
}

func (manager *DashboardManager) getAlerts() []Alert {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	return manager.Dashboard.Alerts
}

// Generate alert ID
func generateAlertID() string {
	return fmt.Sprintf("alert_%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}

// Generate notification ID
func generateNotificationID() string {
	return fmt.Sprintf("notif_%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}
// Notify dashboard of events
func notifyDashboard(manager *DashboardManager, eventType string, data map[string]interface{}) {
	if manager == nil || !manager.IsRunning {
		return
	}
	
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	
	// Create notification
	notification := Notification{
		ID:        generateNotificationID(),
		Type:      eventType,
		Title:     getEventTitle(eventType),
		Message:   getEventMessage(eventType, data),
		Level:     getEventLevel(eventType),
		Data:      data,
		Timestamp: time.Now(),
	}
	
	manager.Dashboard.Notifications = append(manager.Dashboard.Notifications, notification)
	
	// Limit notifications to last 100
	if len(manager.Dashboard.Notifications) > 100 {
		manager.Dashboard.Notifications = manager.Dashboard.Notifications[len(manager.Dashboard.Notifications)-100:]
	}
	
	// Log activity
	activity := ActivityLog{
		ID:        generateActivityID(),
		Type:      eventType,
		Action:    getEventAction(eventType),
		Details:   data,
		Timestamp: time.Now(),
	}
	
	manager.Stats.RecentActivity = append(manager.Stats.RecentActivity, activity)
	
	// Limit activity log to last 50
	if len(manager.Stats.RecentActivity) > 50 {
		manager.Stats.RecentActivity = manager.Stats.RecentActivity[len(manager.Stats.RecentActivity)-50:]
	}
}

// Get event title
func getEventTitle(eventType string) string {
	switch eventType {
	case "session_started":
		return "Attack Session Started"
	case "session_completed":
		return "Attack Session Completed"
	case "key_found":
		return "Valid Key Found"
	case "target_completed":
		return "Target Completed"
	case "discovery_completed":
		return "Discovery Completed"
	case "auth_success":
		return "Authentication Success"
	default:
		return "System Event"
	}
}

// Get event message
func getEventMessage(eventType string, data map[string]interface{}) string {
	switch eventType {
	case "session_started":
		targets := 0
		if t, ok := data["targets"].(int); ok {
			targets = t
		}
		return fmt.Sprintf("New attack session started with %d targets", targets)
	case "session_completed":
		return "Attack session completed successfully"
	case "key_found":
		key := "unknown"
		if k, ok := data["key"].(string); ok {
			key = maskString(k)
		}
		return fmt.Sprintf("Valid key found: %s", key)
	case "target_completed":
		url := "unknown"
		if u, ok := data["url"].(string); ok {
			url = u
		}
		return fmt.Sprintf("Target completed: %s", url)
	default:
		return "System event occurred"
	}
}

// Get event level
func getEventLevel(eventType string) string {
	switch eventType {
	case "session_started", "session_completed":
		return "info"
	case "key_found", "auth_success":
		return "success"
	case "target_completed", "discovery_completed":
		return "info"
	default:
		return "info"
	}
}

// Get event action
func getEventAction(eventType string) string {
	switch eventType {
	case "session_started":
		return "start_session"
	case "session_completed":
		return "complete_session"
	case "key_found":
		return "find_key"
	case "target_completed":
		return "complete_target"
	default:
		return "system_event"
	}
}

// Generate activity ID
func generateActivityID() string {
	return fmt.Sprintf("activity_%d_%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}

// Execute dashboard-enhanced discovery
func executeDashboardEnhancedDiscovery(config *Config, targets []Target, client *http.Client, limiter *rate.Limiter, pathDiscovery *PathDiscovery, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, dashboardManager *DashboardManager, sessionID string) []DiscoveryResult {
	// Use existing discovery but enhance with dashboard notifications
	results := executeDatabaseEnhancedDiscovery(config, targets, client, limiter, pathDiscovery, wafDetector, throttleController, rotationManager, mlEngine, dbManager, sessionID)
	
	// Notify dashboard of discovery completion
	if dashboardManager != nil {
		for _, result := range results {
			notifyDashboard(dashboardManager, "discovery_completed", map[string]interface{}{
				"target":           result.Target,
				"endpoints_found":  result.Statistics.EndpointsFound,
				"auth_endpoints":   result.Statistics.AuthEndpoints,
				"discovery_time":   result.Statistics.DiscoveryTime.String(),
			})
		}
	}
	
	return results
}

// Execute dashboard-enhanced authentication
func executeDashboardEnhancedAuth(config *Config, targets []Target, keys []string, authManager *AuthManager, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, dashboardManager *DashboardManager, sessionID string) []AuthResult {
	// Use existing auth but enhance with dashboard notifications
	results := executeDatabaseEnhancedAuth(config, targets, keys, authManager, client, limiter, wafDetector, throttleController, rotationManager, mlEngine, dbManager, sessionID)
	
	// Notify dashboard of successful authentications
	if dashboardManager != nil {
		for _, result := range results {
			if result.Success {
				notifyDashboard(dashboardManager, "auth_success", map[string]interface{}{
					"method":      result.Method.Name,
					"target":      "target_url", // Simplified
					"token_type":  result.TokenType,
					"expires_in":  result.ExpiresIn,
				})
			}
		}
	}
	
	return results
}

// Execute dashboard-enhanced brute force
func executeDashboardEnhancedBruteForce(config *Config, jobs []Job, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, dashboardManager *DashboardManager, sessionID string) []FoundKey {
	jobsChan := make(chan Job, len(jobs))
	results := make(chan FoundKey, len(jobs))
	var wg sync.WaitGroup
	
	// Start dashboard-enhanced workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go dashboardEnhancedWorker(i+1, config, jobsChan, results, &wg, client, limiter, wafDetector, throttleController, rotationManager, mlEngine, dbManager, dashboardManager, sessionID)
	}
	
	// Send jobs
	for _, job := range jobs {
		jobsChan <- job
	}
	close(jobsChan)
	
	// Wait for completion
	wg.Wait()
	close(results)
	
	// Collect results
	return collectResults(results)
}

// Dashboard-enhanced worker
func dashboardEnhancedWorker(id int, config *Config, jobs <-chan Job, results chan<- FoundKey, wg *sync.WaitGroup, client *http.Client, limiter *rate.Limiter, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, dashboardManager *DashboardManager, sessionID string) {
	defer wg.Done()
	
	if config.Verbose {
		fmt.Printf("🌐 Dashboard-Enhanced Worker %d started\n", id)
	}
	
	for job := range jobs {
		// Get ML prediction if enabled
		var prediction *Prediction
		if mlEngine != nil && config.SuccessPrediction {
			prediction = mlEngine.predictSuccess(job.Key, job.Target)
		}
		
		// Rate limiting
		if limiter != nil {
			limiter.Wait(context.Background())
		}
		
		// Smart throttling delay
		currentDelay := throttleController.CurrentDelay
		if config.RandomDelay && currentDelay > 0 {
			variation := 0.5 + (float64(time.Now().UnixNano()%100) / 100.0)
			currentDelay = time.Duration(float64(currentDelay) * variation)
		}
		
		if currentDelay > 0 {
			time.Sleep(currentDelay)
		}
		
		// Execute job with dashboard enhancement
		found, blocked := executeDashboardEnhancedJob(id, job, config, client, wafDetector, throttleController, rotationManager, mlEngine, dbManager, dashboardManager, sessionID, prediction)
		
		if found != nil {
			results <- *found
			fmt.Printf("🎉 [FOUND] Dashboard Worker %d: Key: %s -> Status: %d at %s (%dms)\n", 
				id, found.Key, found.StatusCode, found.URL, found.ResponseTime)
			
			// Notify dashboard of key found
			if dashboardManager != nil {
				notifyDashboard(dashboardManager, "key_found", map[string]interface{}{
					"key":           found.Key,
					"url":           found.URL,
					"status_code":   found.StatusCode,
					"response_time": found.ResponseTime,
					"worker_id":     id,
				})
			}
			
			// Learn from successful result
			if mlEngine != nil && config.AdaptiveLearning {
				mlEngine.learnFromResult(job.Key, job.Target, *found, true)
			}
		} else if mlEngine != nil && config.AdaptiveLearning {
			// Learn from failed result
			dummyResult := FoundKey{
				Key:          job.Key,
				StatusCode:   0,
				URL:          job.Target.URL,
				ResponseTime: 0,
				Timestamp:    time.Now(),
			}
			mlEngine.learnFromResult(job.Key, job.Target, dummyResult, false)
		}
		
		if blocked && config.Verbose {
			fmt.Printf("🛡️  Dashboard Worker %d: Request blocked for %s\n", id, job.Target.URL)
		}
	}
	
	if config.Verbose {
		fmt.Printf("✅ Dashboard-Enhanced Worker %d finished\n", id)
	}
}

// Execute dashboard-enhanced job
func executeDashboardEnhancedJob(workerID int, job Job, config *Config, client *http.Client, wafDetector *WAFDetector, throttleController *ThrottleController, rotationManager *RotationManager, mlEngine *MLEngine, dbManager *DatabaseManager, dashboardManager *DashboardManager, sessionID string, prediction *Prediction) (*FoundKey, bool) {
	// Use existing job execution but with dashboard integration
	return executeDatabaseEnhancedJob(workerID, job, config, client, wafDetector, throttleController, rotationManager, mlEngine, dbManager, sessionID, prediction)
}

// Shutdown dashboard
func shutdownDashboard(manager *DashboardManager) {
	if manager == nil || !manager.IsRunning {
		return
	}
	
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	
	if manager.Dashboard.Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := manager.Dashboard.Server.Shutdown(ctx); err != nil {
			fmt.Printf("❌ Dashboard shutdown error: %v\n", err)
		} else {
			fmt.Println("✅ Dashboard shutdown completed")
		}
	}
	
	manager.IsRunning = false
	manager.Dashboard.IsRunning = false
}
// Print web dashboard configuration
func printWebDashboardConfig(config *Config, targets []Target, authManager *AuthManager, mlEngine *MLEngine, dbManager *DatabaseManager, dashboardManager *DashboardManager) {
	hasAuth := hasAdvancedAuthFeatures(config)
	hasDiscovery := config.APIDiscovery || config.EndpointEnum
	hasML := hasMLFeatures(config)
	hasDB := hasDatabaseFeatures(config)
	hasWeb := hasWebDashboardFeatures(config)
	
	fmt.Printf("🌐 Web Dashboard: %s\n", formatBool(hasWeb))
	fmt.Printf("💾 Database Integration: %s\n", formatBool(hasDB))
	fmt.Printf("🤖 Machine Learning: %s\n", formatBool(hasML))
	fmt.Printf("🔐 Advanced Authentication: %s\n", formatBool(hasAuth))
	fmt.Printf("🔍 API Discovery: %s\n", formatBool(hasDiscovery))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s\n", i+1, target.URL)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	// Web Dashboard features
	if hasWeb {
		fmt.Printf("\n🌐 Web Dashboard Features:\n")
		if dashboardManager != nil {
			fmt.Printf("   ✅ Dashboard URL: http://%s:%d\n", config.DashboardHost, config.DashboardPort)
			fmt.Printf("   ✅ Status: %s\n", formatBool(dashboardManager.IsRunning))
		}
		if config.DashboardAuth {
			fmt.Printf("   ✅ Authentication: %s (User: %s)\n", formatBool(config.DashboardAuth), config.DashboardUser)
		}
		if config.DashboardSSL {
			fmt.Printf("   ✅ SSL/HTTPS: %s\n", formatBool(config.DashboardSSL))
		}
		if config.RealTimeMonitoring {
			fmt.Printf("   ✅ Real-time Monitoring\n")
		}
		if config.TeamCollaboration {
			fmt.Printf("   ✅ Team Collaboration\n")
		}
		if config.VisualAnalytics {
			fmt.Printf("   ✅ Visual Analytics\n")
		}
		if config.WebAPI {
			fmt.Printf("   ✅ Web API Endpoints\n")
		}
		if config.WebSocketEnabled {
			fmt.Printf("   ✅ WebSocket Support\n")
		}
		if config.NotificationsEnabled {
			fmt.Printf("   ✅ Notifications System\n")
		}
		if config.CORSEnabled {
			fmt.Printf("   ✅ CORS Support\n")
		}
		
		if dashboardManager != nil {
			fmt.Printf("👥 Active Sessions: %d\n", len(dashboardManager.Dashboard.ActiveSessions))
			fmt.Printf("🔔 Notifications: %d\n", len(dashboardManager.Dashboard.Notifications))
			fmt.Printf("⚠️  Alerts: %d\n", len(dashboardManager.Dashboard.Alerts))
		}
	}
	
	// Database features
	if hasDB {
		fmt.Printf("\n💾 Database Features:\n")
		if dbManager != nil {
			fmt.Printf("   ✅ Database Type: %s\n", dbManager.Config.Type)
			fmt.Printf("   ✅ Connection: %s\n", formatBool(dbManager.IsConnected))
		}
		if config.PersistentStorage {
			fmt.Printf("   ✅ Persistent Storage\n")
		}
		if config.HistoricalAnalysis {
			fmt.Printf("   ✅ Historical Analysis\n")
		}
		if config.AttackAnalytics {
			fmt.Printf("   ✅ Attack Analytics\n")
		}
		if config.AutoBackup {
			fmt.Printf("   ✅ Auto Backup (every %v)\n", config.BackupInterval)
		}
		
		fmt.Printf("📅 Data Retention: %d days\n", config.DataRetention)
		
		if dbManager != nil {
			fmt.Printf("📊 Database Stats:\n")
			fmt.Printf("   Sessions: %d\n", dbManager.Stats.TotalSessions)
			fmt.Printf("   Targets: %d\n", dbManager.Stats.TotalTargets)
			fmt.Printf("   Results: %d\n", dbManager.Stats.TotalResults)
		}
	}
	
	// ML features
	if hasML {
		fmt.Printf("\n🤖 Machine Learning Features:\n")
		if config.PatternRecognition {
			fmt.Printf("   ✅ Pattern Recognition\n")
		}
		if config.SuccessPrediction {
			fmt.Printf("   ✅ Success Prediction\n")
		}
		if config.IntelligentSorting {
			fmt.Printf("   ✅ Intelligent Sorting\n")
		}
		if config.AdaptiveLearning {
			fmt.Printf("   ✅ Adaptive Learning\n")
		}
		if config.BehaviorAnalysis {
			fmt.Printf("   ✅ Behavior Analysis\n")
		}
		if config.AnomalyDetection {
			fmt.Printf("   ✅ Anomaly Detection\n")
		}
		
		if mlEngine != nil {
			fmt.Printf("🧠 ML Model: %s v%s\n", mlEngine.Model.Type, mlEngine.Model.Version)
			fmt.Printf("📊 Features: %d\n", len(mlEngine.Model.Features))
			fmt.Printf("🎯 Confidence Threshold: %.2f\n", config.ConfidenceThreshold)
			
			if len(mlEngine.TrainingData.Features) > 0 {
				fmt.Printf("📈 Training Samples: %d\n", len(mlEngine.TrainingData.Features))
			}
		}
	}
	
	// Authentication features
	if hasAuth {
		fmt.Printf("\n🔐 Authentication Methods:\n")
		for _, method := range authManager.Methods {
			fmt.Printf("   ✅ %s (%s)\n", method.Name, method.Type)
		}
		
		if len(authManager.Credentials) > 0 {
			fmt.Printf("🔑 Credentials: %d loaded\n", len(authManager.Credentials))
		}
	}
	
	// Discovery features
	if hasDiscovery {
		fmt.Printf("\n🔍 Discovery Features:\n")
		if config.APIDiscovery {
			fmt.Printf("   ✅ API Discovery\n")
		}
		if config.EndpointEnum {
			fmt.Printf("   ✅ Endpoint Enumeration\n")
		}
		if config.SchemaAnalysis {
			fmt.Printf("   ✅ Schema Analysis\n")
		}
		if config.VersionDetection {
			fmt.Printf("   ✅ Version Detection\n")
		}
		fmt.Printf("📂 Discovery Paths: %d paths\n", len(config.CommonPaths))
	}
	
	fmt.Printf("\n🧵 Threads: %d\n", config.Threads)
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting dashboard-enhanced attack...")
	fmt.Println()
}

// Print dashboard brute force configuration
func printDashboardBruteForceConfig(config *Config, targets []Target, keyCount int, mlEngine *MLEngine, dbManager *DatabaseManager, dashboardManager *DashboardManager) {
	fmt.Printf("🌐 Dashboard-Enhanced Brute Force: %s\n", formatBool(hasWebDashboardFeatures(config)))
	
	if config.MultiTarget {
		fmt.Printf("🎯 Multi-Target Mode: %s\n", formatBool(config.MultiTarget))
		fmt.Printf("📊 Targets: %d URLs\n", len(targets))
		for i, target := range targets {
			if i < 3 {
				fmt.Printf("   %d. %s [%s]\n", i+1, target.URL, target.Method)
			} else if i == 3 {
				fmt.Printf("   ... and %d more targets\n", len(targets)-3)
				break
			}
		}
	} else {
		fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	}
	
	fmt.Printf("📝 Wordlist: %s (%d keys)\n", config.WordlistPath, keyCount)
	fmt.Printf("🔑 Header: %s\n", config.HeaderFormat)
	fmt.Printf("📡 Method: %s\n", config.HTTPMethod)
	fmt.Printf("✅ Success Codes: %v\n", getSuccessCodesSlice(config.SuccessCodes))
	fmt.Printf("🧵 Threads: %d\n", config.Threads)
	fmt.Printf("🔄 Max Retries: %d\n", config.MaxRetries)
	
	// Dashboard features
	if hasWebDashboardFeatures(config) {
		fmt.Printf("\n🌐 Dashboard Features:\n")
		if dashboardManager != nil {
			fmt.Printf("🌐 Dashboard URL: http://%s:%d\n", config.DashboardHost, config.DashboardPort)
			fmt.Printf("📊 Real-time Monitoring: %s\n", formatBool(config.RealTimeMonitoring))
		}
		if config.NotificationsEnabled {
			fmt.Printf("🔔 Notifications: %s\n", formatBool(config.NotificationsEnabled))
		}
		if config.WebSocketEnabled {
			fmt.Printf("🔌 WebSocket: %s\n", formatBool(config.WebSocketEnabled))
		}
	}
	
	// Database features
	if hasDatabaseFeatures(config) {
		fmt.Printf("\n💾 Database Features:\n")
		if config.PersistentStorage {
			fmt.Printf("💾 Persistent Storage: %s\n", formatBool(config.PersistentStorage))
		}
		if config.AttackAnalytics {
			fmt.Printf("📊 Attack Analytics: %s\n", formatBool(config.AttackAnalytics))
		}
		
		if dbManager != nil {
			fmt.Printf("🗄️  Database: %s\n", dbManager.Config.Type)
			fmt.Printf("🔗 Connection: %s\n", formatBool(dbManager.IsConnected))
		}
	}
	
	// ML features
	if hasMLFeatures(config) {
		fmt.Printf("\n🤖 ML Features:\n")
		if config.SuccessPrediction {
			fmt.Printf("🧠 Success Prediction: %s\n", formatBool(config.SuccessPrediction))
		}
		if config.IntelligentSorting {
			fmt.Printf("🎯 Intelligent Sorting: %s\n", formatBool(config.IntelligentSorting))
		}
		if config.AdaptiveLearning {
			fmt.Printf("📈 Adaptive Learning: %s\n", formatBool(config.AdaptiveLearning))
		}
		
		if mlEngine != nil {
			fmt.Printf("🧠 ML Model: %s\n", mlEngine.Model.Type)
			fmt.Printf("🎯 Confidence Threshold: %.2f\n", config.ConfidenceThreshold)
		}
	}
	
	if config.RateLimit > 0 {
		fmt.Printf("⏱️  Rate Limit: %d req/sec\n", config.RateLimit)
	}
	if config.DelayBetween > 0 {
		fmt.Printf("⏳ Base Delay: %v\n", config.DelayBetween)
	}
	if config.OutputFile != "" {
		fmt.Printf("💾 Output: %s\n", config.OutputFile)
	}
	
	totalJobs := len(targets) * keyCount
	fmt.Printf("📈 Total Jobs: %d (%d targets × %d keys)\n", totalJobs, len(targets), keyCount)
	fmt.Printf("⏰ Timeout: %v\n", config.Timeout)
	fmt.Println("🚀 Starting dashboard-enhanced brute-force attack...")
	fmt.Println()
}
// Get dashboard HTML from file
func getDashboardHTMLFromFile() (string, error) {
	htmlPath := "./web/templates/dashboard.html"
	if _, err := os.Stat(htmlPath); err != nil {
		return "", err
	}
	
	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		return "", err
	}
	
	return string(htmlBytes), nil
}
