-- ============================================================================
-- Shadow Guard 2.0 - Master Database Initialization & Migrations
-- Executes all schema versions sequentially with migration tracking
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Migration Tracking Table
CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    migration_name VARCHAR(255) NOT NULL UNIQUE,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 1. BASELINE V1 SCHEMA: threat_logs
-- ============================================================================
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

-- ============================================================================
-- 2. V2 CORE RELATIONAL ENTITIES
-- ============================================================================

-- Honeypot Instances
CREATE TABLE IF NOT EXISTS honeypot_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    listen_ports INTEGER[] NOT NULL,
    config JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Honeypot Events (Privacy Preserving - Zero Passwords / Hashes)
CREATE TABLE IF NOT EXISTS honeypot_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    honeypot_id UUID REFERENCES honeypot_instances(id) ON DELETE SET NULL,
    event_type VARCHAR(60) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_port INTEGER NOT NULL,
    protocol VARCHAR(20) DEFAULT 'TCP',
    session_id VARCHAR(100),
    username VARCHAR(100),
    auth_outcome VARCHAR(20),
    session_metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Suricata NIDS Events
CREATE TABLE IF NOT EXISTS suricata_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(30) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_ip VARCHAR(45) NOT NULL,
    dst_port INTEGER,
    protocol VARCHAR(20),
    signature_id BIGINT,
    signature_name TEXT,
    category TEXT,
    severity INTEGER,
    payload_metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Attacker Profiles
CREATE TABLE IF NOT EXISTS attacker_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ip VARCHAR(45) NOT NULL UNIQUE,
    risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0.00,
    threat_level VARCHAR(20) NOT NULL DEFAULT 'low',
    total_connections INTEGER NOT NULL DEFAULT 1,
    honeypot_sessions INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Attacker Observations
CREATE TABLE IF NOT EXISTS attacker_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES attacker_profiles(id) ON DELETE CASCADE,
    observation_type VARCHAR(60) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Threat Intel Cache
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    indicator_value VARCHAR(255) PRIMARY KEY,
    indicator_type VARCHAR(30) NOT NULL,
    reputation_score INTEGER NOT NULL DEFAULT 0,
    provider VARCHAR(50) NOT NULL,
    raw_report JSONB DEFAULT '{}'::jsonb,
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Correlated Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attacker_profile_id UUID REFERENCES attacker_profiles(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    aggregate_confidence NUMERIC(4, 3) NOT NULL DEFAULT 0.500,
    summary TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Incident Events
CREATE TABLE IF NOT EXISTS incident_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_source VARCHAR(40) NOT NULL,
    event_ref_id UUID NOT NULL,
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- MITRE ATT&CK Catalog
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id VARCHAR(30) PRIMARY KEY,
    tactic VARCHAR(50) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description TEXT
);

-- Attack Chains
CREATE TABLE IF NOT EXISTS attack_chains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    primary_target_ip VARCHAR(45),
    chain_confidence NUMERIC(4, 3) NOT NULL DEFAULT 0.500,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Attack Chain Stages (Observed vs Inferred vs Suspected)
CREATE TABLE IF NOT EXISTS attack_chain_stages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_chain_id UUID NOT NULL REFERENCES attack_chains(id) ON DELETE CASCADE,
    stage_order INTEGER NOT NULL,
    tactic VARCHAR(50) NOT NULL,
    technique_id VARCHAR(30) REFERENCES mitre_techniques(technique_id) ON DELETE SET NULL,
    technique_name VARCHAR(150) NOT NULL,
    certainty VARCHAR(20) NOT NULL CHECK (certainty IN ('OBSERVED', 'INFERRED', 'SUSPECTED')),
    confidence NUMERIC(4, 3) NOT NULL DEFAULT 0.500,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- SOAR Playbook Executions
CREATE TABLE IF NOT EXISTS playbook_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    playbook_name VARCHAR(100) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'running',
    trigger_reason TEXT,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Response Actions (with Time-Limited Expiration Lease)
CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID REFERENCES playbook_executions(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL,
    target_entity VARCHAR(100) NOT NULL,
    command_executed TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    lease_duration_seconds INTEGER DEFAULT 3600,
    expires_at TIMESTAMP WITH TIME ZONE,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Response Approvals
CREATE TABLE IF NOT EXISTS response_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id UUID NOT NULL UNIQUE REFERENCES response_actions(id) ON DELETE CASCADE,
    approver_role VARCHAR(50) NOT NULL DEFAULT 'Security Analyst',
    approved_by VARCHAR(100),
    status VARCHAR(30) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    decision_reason TEXT,
    decided_at TIMESTAMP WITH TIME ZONE
);

-- Deception Deployments
CREATE TABLE IF NOT EXISTS deception_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    decoy_type VARCHAR(50) NOT NULL,
    target_port INTEGER NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Security Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor VARCHAR(100) NOT NULL DEFAULT 'system',
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(150) NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Service Metrics
CREATE TABLE IF NOT EXISTS service_metrics (
    id BIGSERIAL PRIMARY KEY,
    service_name VARCHAR(60) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(12, 4) NOT NULL,
    labels JSONB DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (migration_name) 
VALUES ('002_schema_v2_core') 
ON CONFLICT (migration_name) DO NOTHING;

-- ============================================================================
-- 3. INDEXES, SEED DATA & BACKWARD COMPATIBLE VIEWS
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_honeypot_events_src_ip_time ON honeypot_events (src_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_honeypot_events_type ON honeypot_events (event_type);

CREATE INDEX IF NOT EXISTS idx_suricata_events_src_ip_time ON suricata_events (src_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_suricata_events_sig_id ON suricata_events (signature_id);

CREATE INDEX IF NOT EXISTS idx_attacker_profiles_ip ON attacker_profiles (source_ip);
CREATE INDEX IF NOT EXISTS idx_attacker_profiles_risk ON attacker_profiles (risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_status_time ON incidents (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);

CREATE INDEX IF NOT EXISTS idx_attack_chain_stages_chain ON attack_chain_stages (attack_chain_id, stage_order ASC);
CREATE INDEX IF NOT EXISTS idx_attack_chain_stages_certainty ON attack_chain_stages (certainty);

CREATE INDEX IF NOT EXISTS idx_response_actions_active_lease ON response_actions (expires_at) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_threat_intel_expires ON threat_intel_cache (expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_attacker_obs_evidence ON attacker_observations USING gin (evidence);
CREATE INDEX IF NOT EXISTS idx_attack_chain_stages_evidence ON attack_chain_stages USING gin (evidence);

-- Seed Base MITRE Techniques
INSERT INTO mitre_techniques (technique_id, tactic, name, description)
VALUES 
    ('T1046', 'Reconnaissance', 'Network Service Discovery', 'Probing target hosts on specific ports to determine service availability.'),
    ('T1595', 'Reconnaissance', 'Active Scanning', 'Executing automated port scans and vulnerability scans.'),
    ('T1110', 'Credential Access', 'Brute Force', 'Automated guessing of credentials across authentication endpoints.'),
    ('T1110.001', 'Credential Access', 'Password Guessing', 'Systematic testing of passwords for existing account names.'),
    ('T1059', 'Execution', 'Command and Scripting Interpreter', 'Execution of arbitrary system shell commands on target host.'),
    ('T1059.004', 'Execution', 'Unix Shell', 'Executing commands via interactive sh, bash, or dash shell.'),
    ('T1498', 'Impact', 'Network Denial of Service', 'Flooding targeted host network interfaces with volumetric traffic.'),
    ('T1498.001', 'Impact', 'Direct Network Flood', 'Direct UDP, ICMP or SYN flood without intermediary reflection.'),
    ('T1048', 'Exfiltration', 'Exfiltration Over Alternative Protocol', 'Exfiltrating confidential data over unapproved or unusual protocols.'),
    ('T1041', 'Exfiltration', 'Exfiltration Over C2 Channel', 'Transferring collected host data through existing command and control channel.'),
    ('T1071', 'Command and Control', 'Application Layer Protocol', 'Communicating with external controller using standard application protocols (HTTP/DNS).'),
    ('T1573', 'Command and Control', 'Encrypted Channel', 'Hiding C2 communications inside encrypted transport layers like TLS.'),
    ('T1203', 'Execution', 'Exploitation for Client Execution', 'Exploiting client software vulnerabilities via malicious payload processing.'),
    ('T1068', 'Privilege Escalation', 'Exploitation for Privilege Escalation', 'Exploiting kernel or daemon vulnerabilities to gain root or elevated permissions.')
ON CONFLICT (technique_id) DO UPDATE 
SET name = EXCLUDED.name, description = EXCLUDED.description;

-- Seed Default Honeypot Decoy Instances
INSERT INTO honeypot_instances (name, type, status, listen_ports, config)
VALUES
    ('cowrie-ssh-decoy', 'cowrie_ssh', 'active', ARRAY[2222], '{"banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "auth_mode": "interactive"}'::jsonb),
    ('cowrie-telnet-decoy', 'cowrie_telnet', 'active', ARRAY[2223], '{"prompt": "login: ", "auth_mode": "interactive"}'::jsonb),
    ('opencanary-multi-decoy', 'opencanary_multi', 'active', ARRAY[8080, 2121, 3306], '{"services": ["http", "ftp", "mysql"]}'::jsonb),
    ('dionaea-malware-decoy', 'dionaea_malware', 'active', ARRAY[445, 1433], '{"quarantine_dir": "/quarantine"}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Backward-Compatible Unified View
CREATE OR REPLACE VIEW v_legacy_threat_logs AS
SELECT 
    id::TEXT AS id,
    type,
    action,
    details,
    timestamp
FROM threat_logs
UNION ALL
SELECT 
    i.id AS id,
    COALESCE(i.title, 'incident') AS type,
    CASE 
        WHEN i.status = 'contained' THEN 'block'
        WHEN i.status = 'open' AND i.severity IN ('critical', 'high') THEN 'alert'
        ELSE 'monitor'
    END AS action,
    jsonb_build_object(
        'incident_id', i.id,
        'title', i.title,
        'severity', i.severity,
        'status', i.status,
        'confidence', i.aggregate_confidence,
        'summary', i.summary,
        'sourceIp', p.source_ip
    ) AS details,
    i.created_at AS timestamp
FROM incidents i
LEFT JOIN attacker_profiles p ON i.attacker_profile_id = p.id;

INSERT INTO schema_migrations (migration_name) 
VALUES ('003_indexes_and_views') 
ON CONFLICT (migration_name) DO NOTHING;
