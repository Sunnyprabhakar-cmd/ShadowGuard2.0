-- Migration 001: Baseline Legacy Threat Logs
-- Preserves complete backward compatibility with Shadow Guard 1.0

CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    migration_name VARCHAR(255) NOT NULL UNIQUE,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_logs (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50),
    action VARCHAR(50),
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_logs_timestamp ON threat_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_threat_logs_type ON threat_logs (type);

INSERT INTO schema_migrations (migration_name) 
VALUES ('001_baseline_threat_logs') 
ON CONFLICT (migration_name) DO NOTHING;
