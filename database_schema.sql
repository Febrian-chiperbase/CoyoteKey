-- CoyoteKey Database Schema
-- This file contains the database schema for all supported database types

-- ============================================================================
-- SQLite Schema
-- ============================================================================

-- Attack Sessions Table
CREATE TABLE IF NOT EXISTS attack_sessions (
    id TEXT PRIMARY KEY,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    status TEXT NOT NULL DEFAULT 'running',
    target_count INTEGER NOT NULL DEFAULT 0,
    key_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    duration INTEGER, -- in milliseconds
    config TEXT, -- JSON configuration
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Attack Targets Table
CREATE TABLE IF NOT EXISTS attack_targets (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    header_format TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    success_count INTEGER NOT NULL DEFAULT 0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    first_success DATETIME,
    last_tested DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES attack_sessions(id)
);

-- Attack Results Table
CREATE TABLE IF NOT EXISTS attack_results (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    key_value TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_time INTEGER NOT NULL, -- in milliseconds
    content_length INTEGER NOT NULL DEFAULT 0,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    headers TEXT, -- JSON headers
    error_message TEXT,
    ml_prediction REAL,
    ml_confidence REAL,
    timestamp DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES attack_sessions(id),
    FOREIGN KEY (target_id) REFERENCES attack_targets(id)
);

-- Discovery Sessions Table
CREATE TABLE IF NOT EXISTS discovery_sessions (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    paths_scanned INTEGER NOT NULL DEFAULT 0,
    endpoints_found INTEGER NOT NULL DEFAULT 0,
    auth_endpoints INTEGER NOT NULL DEFAULT 0,
    public_endpoints INTEGER NOT NULL DEFAULT 0,
    error_endpoints INTEGER NOT NULL DEFAULT 0,
    discovery_time INTEGER NOT NULL, -- in milliseconds
    avg_response_time INTEGER NOT NULL DEFAULT 0,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES attack_sessions(id)
);

-- Discovered Endpoints Table
CREATE TABLE IF NOT EXISTS discovered_endpoints (
    id TEXT PRIMARY KEY,
    discovery_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    status_code INTEGER NOT NULL,
    content_length INTEGER NOT NULL DEFAULT 0,
    content_type TEXT,
    response_time INTEGER NOT NULL,
    auth_required BOOLEAN NOT NULL DEFAULT FALSE,
    framework TEXT,
    api_version TEXT,
    parameters TEXT, -- JSON parameters
    headers TEXT, -- JSON headers
    discovered DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (discovery_id) REFERENCES discovery_sessions(id)
);

-- Authentication Results Table
CREATE TABLE IF NOT EXISTS authentication_results (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    username TEXT,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    status_code INTEGER NOT NULL,
    response_time INTEGER NOT NULL,
    token TEXT,
    refresh_token TEXT,
    expires_in INTEGER,
    token_type TEXT,
    scope TEXT,
    error_message TEXT,
    timestamp DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES attack_sessions(id)
);

-- ML Insights Table
CREATE TABLE IF NOT EXISTS ml_insights (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    model_type TEXT NOT NULL,
    model_version TEXT NOT NULL,
    accuracy REAL NOT NULL DEFAULT 0.0,
    training_size INTEGER NOT NULL DEFAULT 0,
    features TEXT, -- JSON features array
    patterns TEXT, -- JSON patterns
    anomalies TEXT, -- JSON anomalies
    predictions TEXT, -- JSON predictions
    last_update DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES attack_sessions(id)
);

-- ============================================================================
-- Indexes for Performance Optimization
-- ============================================================================

-- Attack Results Indexes
CREATE INDEX IF NOT EXISTS idx_attack_results_session_id ON attack_results(session_id);
CREATE INDEX IF NOT EXISTS idx_attack_results_timestamp ON attack_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_results_success ON attack_results(success);
CREATE INDEX IF NOT EXISTS idx_attack_results_status_code ON attack_results(status_code);
CREATE INDEX IF NOT EXISTS idx_attack_results_url ON attack_results(url);

-- Attack Sessions Indexes
CREATE INDEX IF NOT EXISTS idx_attack_sessions_start_time ON attack_sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_attack_sessions_status ON attack_sessions(status);

-- Attack Targets Indexes
CREATE INDEX IF NOT EXISTS idx_attack_targets_session_id ON attack_targets(session_id);
CREATE INDEX IF NOT EXISTS idx_attack_targets_url ON attack_targets(url);

-- Discovery Sessions Indexes
CREATE INDEX IF NOT EXISTS idx_discovery_sessions_session_id ON discovery_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_discovery_sessions_target_url ON discovery_sessions(target_url);

-- Discovered Endpoints Indexes
CREATE INDEX IF NOT EXISTS idx_discovered_endpoints_discovery_id ON discovered_endpoints(discovery_id);
CREATE INDEX IF NOT EXISTS idx_discovered_endpoints_url ON discovered_endpoints(url);
CREATE INDEX IF NOT EXISTS idx_discovered_endpoints_status_code ON discovered_endpoints(status_code);

-- Authentication Results Indexes
CREATE INDEX IF NOT EXISTS idx_authentication_results_session_id ON authentication_results(session_id);
CREATE INDEX IF NOT EXISTS idx_authentication_results_auth_method ON authentication_results(auth_method);
CREATE INDEX IF NOT EXISTS idx_authentication_results_success ON authentication_results(success);

-- ML Insights Indexes
CREATE INDEX IF NOT EXISTS idx_ml_insights_session_id ON ml_insights(session_id);
CREATE INDEX IF NOT EXISTS idx_ml_insights_model_type ON ml_insights(model_type);

-- ============================================================================
-- PostgreSQL Schema (Differences from SQLite)
-- ============================================================================

-- For PostgreSQL, replace TEXT PRIMARY KEY with:
-- id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

-- For PostgreSQL, replace DATETIME with TIMESTAMP
-- For PostgreSQL, replace BOOLEAN with BOOLEAN (same)
-- For PostgreSQL, replace INTEGER with INTEGER (same)
-- For PostgreSQL, replace REAL with REAL (same)

-- Example PostgreSQL table:
/*
CREATE TABLE IF NOT EXISTS attack_sessions_pg (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    target_count INTEGER NOT NULL DEFAULT 0,
    key_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    duration BIGINT, -- in milliseconds
    config JSONB, -- PostgreSQL native JSON
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
*/

-- ============================================================================
-- MySQL Schema (Differences from SQLite)
-- ============================================================================

-- For MySQL, replace TEXT PRIMARY KEY with:
-- id VARCHAR(36) PRIMARY KEY,

-- For MySQL, replace DATETIME with DATETIME (same)
-- For MySQL, replace BOOLEAN with BOOLEAN (same)
-- For MySQL, replace INTEGER with INT (similar)
-- For MySQL, replace REAL with FLOAT (similar)

-- Example MySQL table:
/*
CREATE TABLE IF NOT EXISTS attack_sessions_mysql (
    id VARCHAR(36) PRIMARY KEY,
    start_time DATETIME NOT NULL,
    end_time DATETIME NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    target_count INT NOT NULL DEFAULT 0,
    key_count INT NOT NULL DEFAULT 0,
    success_count INT NOT NULL DEFAULT 0,
    total_requests INT NOT NULL DEFAULT 0,
    duration BIGINT NULL, -- in milliseconds
    config JSON, -- MySQL native JSON
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
*/

-- ============================================================================
-- Common Queries for Analytics
-- ============================================================================

-- Get attack session summary
/*
SELECT 
    s.id,
    s.start_time,
    s.end_time,
    s.status,
    s.target_count,
    s.success_count,
    s.total_requests,
    ROUND(CAST(s.success_count AS FLOAT) / NULLIF(s.total_requests, 0) * 100, 2) as success_rate
FROM attack_sessions s
ORDER BY s.start_time DESC;
*/

-- Get top successful targets
/*
SELECT 
    t.url,
    t.method,
    COUNT(r.id) as total_requests,
    SUM(CASE WHEN r.success = 1 THEN 1 ELSE 0 END) as successful_requests,
    ROUND(AVG(r.response_time), 2) as avg_response_time
FROM attack_targets t
LEFT JOIN attack_results r ON t.id = r.target_id
GROUP BY t.url, t.method
ORDER BY successful_requests DESC, total_requests DESC;
*/

-- Get status code distribution
/*
SELECT 
    status_code,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM attack_results), 2) as percentage
FROM attack_results
GROUP BY status_code
ORDER BY count DESC;
*/

-- Get hourly attack distribution
/*
SELECT 
    strftime('%H', timestamp) as hour,
    COUNT(*) as request_count,
    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count
FROM attack_results
GROUP BY strftime('%H', timestamp)
ORDER BY hour;
*/

-- Get ML model performance
/*
SELECT 
    model_type,
    model_version,
    accuracy,
    training_size,
    last_update
FROM ml_insights
ORDER BY last_update DESC;
*/
