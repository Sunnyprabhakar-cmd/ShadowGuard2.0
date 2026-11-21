-- Migration 002: Shadow Guard 2.0 Core Relational Schema
-- Implements normalized entities for Deception, NIDS, Profiling, Correlation, and SOAR

-- 1. Honeypot Instances
CREATE TABLE IF NOT EXISTS honeypot_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL, -- 'cowrie_ssh', 'cowrie_telnet', 'opencanary_multi', 'dionaea_malware'
    status VARCHAR(30) NOT NULL DEFAULT 'active', -- 'active', 'disabled', 'maintenance'
    listen_ports INTEGER[] NOT NULL,
    config JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Honeypot Events (Privacy Preserving - Zero Passwords / Hashes)
CREATE TABLE IF NOT EXISTS honeypot_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    honeypot_id UUID REFERENCES honeypot_instances(id) ON DELETE SET NULL,
    event_type VARCHAR(60) NOT NULL, -- 'login_attempt', 'command_entered', 'port_probe', 'session_close'
    src_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_port INTEGER NOT NULL,
    protocol VARCHAR(20) DEFAULT 'TCP',
    session_id VARCHAR(100),
    username VARCHAR(100), -- username only, no passwords
    auth_outcome VARCHAR(20), -- 'FAILED', 'SUCCESS'
    session_metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Suricata NIDS Events
CREATE TABLE IF NOT EXISTS suricata_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(30) NOT NULL, -- 'alert', 'dns', 'http', 'tls', 'flow'
    src_ip VARCHAR(45) NOT NULL,
    src_port INTEGER,
    dst_ip VARCHAR(45) NOT NULL,
    dst_port INTEGER,
    protocol VARCHAR(20),
    signature_id BIGINT,
    signature_name TEXT,
    category TEXT,
    severity INTEGER, -- 1=High, 2=Medium, 3=Low
    payload_metadata JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Attacker Profiles (Longitudinal Source Behavioral State)
CREATE TABLE IF NOT EXISTS attacker_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ip VARCHAR(45) NOT NULL UNIQUE,
    risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0.00, -- 0.00 to 100.00
    threat_level VARCHAR(20) NOT NULL DEFAULT 'low', -- 'low', 'medium', 'high', 'critical'
    total_connections INTEGER NOT NULL DEFAULT 1,
    honeypot_sessions INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(30) NOT NULL DEFAULT 'active', -- 'active', 'monitored', 'contained', 'whitelisted'
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Attacker Behavioral Observations
CREATE TABLE IF NOT EXISTS attacker_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES attacker_profiles(id) ON DELETE CASCADE,
    observation_type VARCHAR(60) NOT NULL, -- 'port_scan', 'credential_stuffing', 'honeypot_command', 'exfil_spike'
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Threat Intelligence Cache
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    indicator_value VARCHAR(255) PRIMARY KEY, -- IP, domain, or file SHA256
    indicator_type VARCHAR(30) NOT NULL, -- 'ip', 'domain', 'sha256'
    reputation_score INTEGER NOT NULL DEFAULT 0, -- 0 (benign) to 100 (hostile)
    provider VARCHAR(50) NOT NULL, -- 'abuseipdb', 'virustotal', 'alienvault', 'offline_heuristic'
    raw_report JSONB DEFAULT '{}'::jsonb,
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- 7. Correlated Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attacker_profile_id UUID REFERENCES attacker_profiles(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- 'critical', 'high', 'medium', 'low'
    status VARCHAR(30) NOT NULL DEFAULT 'open', -- 'open', 'investigating', 'contained', 'resolved', 'false_positive'
    aggregate_confidence NUMERIC(4, 3) NOT NULL DEFAULT 0.500, -- 0.000 to 1.000
    summary TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Incident Event Links
CREATE TABLE IF NOT EXISTS incident_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_source VARCHAR(40) NOT NULL, -- 'honeypot', 'suricata', 'ml_detection', 'traffic_capture'
    event_ref_id UUID NOT NULL,
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. MITRE ATT&CK Techniques Catalog
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id VARCHAR(30) PRIMARY KEY, -- e.g. 'T1046', 'T1110.001', 'T1048'
    tactic VARCHAR(50) NOT NULL, -- e.g. 'Reconnaissance', 'Initial Access', 'Execution', 'Exfiltration'
    name VARCHAR(150) NOT NULL,
    description TEXT
);

-- 10. Attack Chains
CREATE TABLE IF NOT EXISTS attack_chains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
    primary_target_ip VARCHAR(45),
    chain_confidence NUMERIC(4, 3) NOT NULL DEFAULT 0.500,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 11. Attack Chain Stages (Observed vs Inferred vs Suspected)
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

-- 12. SOAR Playbook Executions
CREATE TABLE IF NOT EXISTS playbook_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    playbook_name VARCHAR(100) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'running', -- 'running', 'completed', 'failed', 'reverted'
    trigger_reason TEXT,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 13. Automated Response Actions with Time-Limited Leases
CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID REFERENCES playbook_executions(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL, -- 'iptables_block', 'quarantine_host', 'deploy_decoy', 'alert_soc'
    target_entity VARCHAR(100) NOT NULL, -- IP or hostname
    command_executed TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'active', -- 'pending_approval', 'active', 'expired', 'rolled_back', 'failed'
    lease_duration_seconds INTEGER DEFAULT 3600, -- default 1 hour expiration lease
    expires_at TIMESTAMP WITH TIME ZONE,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 14. Response Approval Gates (Two-Man Rule for High-Impact Actions)
CREATE TABLE IF NOT EXISTS response_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id UUID NOT NULL UNIQUE REFERENCES response_actions(id) ON DELETE CASCADE,
    approver_role VARCHAR(50) NOT NULL DEFAULT 'Security Analyst',
    approved_by VARCHAR(100),
    status VARCHAR(30) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    decision_reason TEXT,
    decided_at TIMESTAMP WITH TIME ZONE
);

-- 15. Dynamic Deception Deployments
CREATE TABLE IF NOT EXISTS deception_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    decoy_type VARCHAR(50) NOT NULL,
    target_port INTEGER NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'active', -- 'active', 'withdrawn', 'failed'
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 16. Security Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor VARCHAR(100) NOT NULL DEFAULT 'system',
    action VARCHAR(100) NOT NULL, -- 'RULE_HOT_RELOAD', 'IP_BLOCK_ENFORCED', 'ACTION_ROLLED_BACK'
    resource VARCHAR(150) NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 17. Service Telemetry Metrics (Local In-Postgres Persistence)
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
