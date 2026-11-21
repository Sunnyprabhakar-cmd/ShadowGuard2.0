-- Migration 003: Indexes, Seed Data & Backward-Compatible Views

-- 1. High-Performance Indexes
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

-- GIN Indexes for fast JSONB querying
CREATE INDEX IF NOT EXISTS idx_attacker_obs_evidence ON attacker_observations USING gin (evidence);
CREATE INDEX IF NOT EXISTS idx_attack_chain_stages_evidence ON attack_chain_stages USING gin (evidence);

-- 2. Seed Base MITRE ATT&CK Techniques
INSERT INTO mitre_techniques (technique_id, tactic, name, description)
VALUES 
    ('T1046', 'Reconnaissance', 'Network Service Discovery', 'Probing target hosts on specific ports to determine service availability.'),
    ('T1595', 'Reconnaissance', 'Active Scanning', 'Executing automated port scans and vulnerability vulnerability scans.'),
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

-- 3. Seed Default Honeypot Decoy Instances
INSERT INTO honeypot_instances (name, type, status, listen_ports, config)
VALUES
    ('cowrie-ssh-decoy', 'cowrie_ssh', 'active', ARRAY[2222], '{"banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "auth_mode": "interactive"}'::jsonb),
    ('cowrie-telnet-decoy', 'cowrie_telnet', 'active', ARRAY[2223], '{"prompt": "login: ", "auth_mode": "interactive"}'::jsonb),
    ('opencanary-multi-decoy', 'opencanary_multi', 'active', ARRAY[8080, 2121, 3306], '{"services": ["http", "ftp", "mysql"]}'::jsonb),
    ('dionaea-malware-decoy', 'dionaea_malware', 'active', ARRAY[445, 1433], '{"quarantine_dir": "/quarantine"}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- 4. Backward-Compatible Unified View
-- Maps all new incidents and legacy logs into a unified view for legacy analytics
CREATE OR REPLACE VIEW v_legacy_threat_logs AS
SELECT 
    id,
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
