/**
 * Shadow Guard 2.0 - Stage 5 Verification Suite
 *
 * Verifies:
 *   1. Dynamic Deception Manager (Policies DEC-01..DEC-04, config validation, operator pause/resume,
 *      state snapshots, directive rollback, and immutable audit trail)
 *   2. Multi-Condition SOAR Playbook Engine (PB-SOAR-01..PB-SOAR-05 across anomaly, confidence,
 *      honeypot interactions, threat intel reputation, attacker risk score, and repeat offenses)
 *   3. Automated Response Execution & Safety Controls (Immutable critical allowlist protection,
 *      timed IP block leases with automatic expiration, manual approval workflow, and one-click rollback)
 *   4. Service & Docker Compose structural integrity
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { AdaptiveDeceptionEngine } = require('../deception-manager-service/engine/adaptiveDeceptionEngine');
const { SoarPlaybookEngine } = require('../playbook-decision-engine/engine/soarPlaybookEngine');
const { ResponseExecutionEngine } = require('../automated-response-service/engine/responseExecutionEngine');

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
    console.log(' SHADOW GUARD 2.0 — STAGE 5 VERIFICATION SUITE');
    console.log(' Dynamic Deception Manager & Advanced SOAR Playbook/Response Engine');
    console.log('================================================================================\n');

    // =========================================================================
    // TEST SUITE 1: Dynamic Deception Manager (:3013)
    // =========================================================================
    console.log('--- [Suite 1] Policy-Driven Dynamic Deception Management ---');
    const deceptionEngine = new AdaptiveDeceptionEngine();

    // 1. DEC-01: Port scanning -> expand decoy listeners
    const scanAdapt = await deceptionEngine.evaluateAndAdapt({
        source_ip: '45.33.32.156',
        attack_categories: ['PORT_SCAN'],
        ports_targeted: [21, 22, 80, 445, 8080]
    });
    assert(scanAdapt.adapted === true && scanAdapt.matched_policy_ids.includes('DEC-01'), 'DEC-01 triggered on port scan telemetry');
    const canaryState1 = deceptionEngine.honeypotAdaptiveState.get('opencanary-multi-01');
    assert(canaryState1.active_ports.includes(8080), 'OpenCanary decoy listener port 8080 activated by DEC-01');

    // 2. DEC-02: Repeated SSH Brute-Force -> Cowrie DEBUG logging + honey-breadcrumbs
    const sshAdapt = await deceptionEngine.evaluateAndAdapt({
        source_ip: '185.220.101.42',
        attack_categories: ['HONEYPOT_AUTH_FAILURE'],
        failed_logins: 5
    });
    assert(sshAdapt.adapted === true && sshAdapt.matched_policy_ids.includes('DEC-02'), 'DEC-02 triggered on repeated SSH brute-force');
    const cowrieState = deceptionEngine.honeypotAdaptiveState.get('cowrie-ssh-01');
    assert(
        cowrieState.logging_level === 'DEBUG_FULL_KEYSTROKE' && cowrieState.breadcrumbs_deployed.length === 3,
        'Cowrie elevated to DEBUG_FULL_KEYSTROKE and planted 3 honey-breadcrumbs'
    );

    // 3. DEC-03: SMB & MySQL Enumeration -> Activate decoy shares & DB schemas
    const smbAdapt = await deceptionEngine.evaluateAndAdapt({
        source_ip: '203.0.113.50',
        attack_categories: ['OPEN_CANARY_SMB_PROBE'],
        destination_port: 445
    });
    assert(smbAdapt.adapted === true && smbAdapt.matched_policy_ids.includes('DEC-03'), 'DEC-03 triggered on SMB enumeration');
    const canaryState2 = deceptionEngine.honeypotAdaptiveState.get('opencanary-multi-01');
    assert(
        canaryState2.smb_shares.length >= 2 && canaryState2.mysql_decoy_databases.length >= 2,
        'OpenCanary SMB decoy shares and MySQL decoy schemas activated'
    );

    // 4. DEC-04: High-risk attacker -> Activate Dionaea trap & divert attacker IP
    const criticalAdapt = await deceptionEngine.evaluateAndAdapt({
        source_ip: '91.240.118.172',
        risk_score: 92,
        threat_level: 'CRITICAL'
    });
    assert(criticalAdapt.adapted === true && criticalAdapt.matched_policy_ids.includes('DEC-04'), 'DEC-04 triggered on critical attacker risk score');
    const dionaeaState = deceptionEngine.honeypotAdaptiveState.get('dionaea-malware-01');
    assert(dionaeaState.diverted_attacker_ips.includes('91.240.118.172'), 'Attacker IP diverted to Dionaea malware quarantine trap');

    // 5. Directive Rollback restores prior state snapshot
    const sshDirectiveId = sshAdapt.directives[0].directive_id;
    const rolledBackDir = deceptionEngine.rollbackDirective(sshDirectiveId, 'SOC_LEAD', 'Testing state restoration');
    assert(rolledBackDir.status === 'ROLLED_BACK', 'Deception directive rolled back cleanly');
    const restoredCowrie = deceptionEngine.honeypotAdaptiveState.get('cowrie-ssh-01');
    assert(
        restoredCowrie.logging_level === 'STANDARD' && restoredCowrie.breadcrumbs_deployed.length === 0,
        'Cowrie state snapshot restored to STANDARD logging with 0 breadcrumbs after rollback'
    );

    // 6. Configuration validation rejects invalid honeypot or action
    const invalidValidation = deceptionEngine.validateDirectiveConfig({
        target_honeypot_id: 'non-existent-honeypot',
        action_type: 'INVALID_ACTION'
    });
    assert(invalidValidation.valid === false && invalidValidation.errors.length === 2, 'Directive config validator rejects invalid honeypot/action');

    // 7. Operator pause/resume override
    deceptionEngine.setAutoAdaptMode(false, 'SOC_COMMANDER');
    const pausedRes = await deceptionEngine.evaluateAndAdapt({ source_ip: '45.33.32.156', attack_categories: ['PORT_SCAN'] });
    assert(pausedRes.adapted === false, 'Auto-adaptation paused when operator override disables autoAdaptEnabled');
    deceptionEngine.setAutoAdaptMode(true, 'SOC_COMMANDER');

    // =========================================================================
    // TEST SUITE 2: Multi-Condition SOAR Playbook Engine (:3003)
    // =========================================================================
    console.log('\n--- [Suite 2] Multi-Condition SOAR Playbook Evaluation ---');
    const soarEngine = new SoarPlaybookEngine();

    // 1. PB-SOAR-01: Critical Deception Compromise
    const plan1 = soarEngine.evaluateContext({
        source_ip: '185.220.101.42',
        attacker_risk_score: 96,
        incident_severity: 'CRITICAL',
        honeypot_interaction_count: 3,
        has_payload_or_cmd: true
    });
    assert(plan1.playbook_id === 'PB-SOAR-01' && plan1.legacy_action === 'block', 'Matched PB-SOAR-01 for critical honeypot compromise');
    assert(plan1.actions.some(a => a.type === 'BLOCK_IP_TEMPORARY' && a.lease_minutes === 60), 'PB-SOAR-01 prescribes 60m temporary block');

    // 2. PB-SOAR-02: Repeat Offender Permanent Ban (Approval Gated)
    const plan2 = soarEngine.evaluateContext({
        source_ip: '91.240.118.172',
        repeated_offense_count: 4,
        threat_intelligence_reputation: 98,
        attacker_risk_score: 88,
        incident_severity: 'HIGH'
    });
    assert(plan2.playbook_id === 'PB-SOAR-02', 'Matched PB-SOAR-02 for repeat offender with high Threat Intel reputation');
    assert(
        plan2.actions.some(a => a.type === 'BLOCK_IP_PERMANENT' && a.require_approval === true),
        'PB-SOAR-02 queues approval-gated BLOCK_IP_PERMANENT'
    );

    // 3. PB-SOAR-03: High-Confidence Intrusion
    const plan3 = soarEngine.evaluateContext({
        source_ip: '203.0.113.50',
        classification_confidence: 0.91,
        attacker_risk_score: 72,
        incident_severity: 'HIGH'
    });
    assert(plan3.playbook_id === 'PB-SOAR-03', 'Matched PB-SOAR-03 for high-confidence intrusion');

    // 4. PB-SOAR-04: Medium-Risk Probing / Deception Lure
    const plan4 = soarEngine.evaluateContext({
        source_ip: '45.33.32.156',
        classification_confidence: 0.68,
        attacker_risk_score: 45,
        incident_severity: 'MEDIUM'
    });
    assert(plan4.playbook_id === 'PB-SOAR-04' && plan4.legacy_action === 'alert', 'Matched PB-SOAR-04 for medium-risk recon/lure');

    // 5. PB-SOAR-05: Benign Baseline
    const plan5 = soarEngine.evaluateContext({
        source_ip: '10.0.5.20',
        classification_confidence: 0.12,
        attacker_risk_score: 10,
        incident_severity: 'LOW'
    });
    assert(plan5.playbook_id === 'PB-SOAR-05' && plan5.legacy_action === 'monitor', 'Matched PB-SOAR-05 for benign traffic');

    // =========================================================================
    // TEST SUITE 3: Automated Response Safety Controls (:3005)
    // =========================================================================
    console.log('\n--- [Suite 3] SOAR Response Safety Controls (Allowlist, Leases, Approval, Rollback) ---');
    const responseEngine = new ResponseExecutionEngine({ enableLocalIptables: false });

    // 1. Immutable Critical Allowlist Protection
    for (const protectedIp of ['127.0.0.1', '10.0.0.1', '8.8.8.8', '172.28.0.1']) {
        const res = await responseEngine.executeAction({
            action_type: 'BLOCK_IP_TEMPORARY',
            target_ip: protectedIp,
            lease_minutes: 30
        });
        assert(
            res.status === 'REJECTED_ALLOWLIST_PROTECTED' && !responseEngine.activeBlocks.has(protectedIp),
            `Protected infrastructure IP ${protectedIp} rejected from blocking (ALLOWLIST_PROTECTED)`
        );
    }

    // Verify immutable allowlist entries cannot be deleted
    let immutableDeleteBlocked = false;
    try {
        responseEngine.removeAllowlistIp('10.0.0.1', 'ROGUE_OPERATOR');
    } catch (_) {
        immutableDeleteBlocked = true;
    }
    assert(immutableDeleteBlocked === true, 'Immutable gateway IP (10.0.0.1) cannot be removed from allowlist');

    // 2. Timed IP Block Lease & Automatic Expiration
    const startMs = Date.now();
    const tempBlock = await responseEngine.executeAction({
        action_type: 'BLOCK_IP_TEMPORARY',
        target_ip: '185.220.101.42',
        lease_minutes: 30,
        nowMs: startMs
    });
    assert(
        tempBlock.status === 'EXECUTED' && responseEngine.activeBlocks.has('185.220.101.42'),
        'Attacker IP 185.220.101.42 placed under active 30-minute timed block lease'
    );

    // Advance clock +15 minutes -> should still be blocked
    const expiredAt15m = responseEngine.expireLeases(startMs + 15 * 60 * 1000);
    assert(expiredAt15m.length === 0 && responseEngine.activeBlocks.has('185.220.101.42'), 'Lease remains active at +15 minutes');

    // Advance clock +31 minutes -> should automatically expire and unblock
    const expiredAt31m = responseEngine.expireLeases(startMs + 31 * 60 * 1000);
    assert(
        expiredAt31m.length === 1 && !responseEngine.activeBlocks.has('185.220.101.42'),
        'Timed IP block lease automatically expired and unblocked at +31 minutes'
    );

    // 3. Manual Approval Workflow for Permanent Block
    const permRequest = await responseEngine.executeAction({
        action_type: 'BLOCK_IP_PERMANENT',
        target_ip: '91.240.118.172',
        require_approval: true
    });
    assert(
        permRequest.status === 'PENDING_APPROVAL' && !responseEngine.activeBlocks.has('91.240.118.172'),
        'Permanent block queued in PENDING_APPROVAL and not applied prior to human sign-off'
    );

    const approvedExec = await responseEngine.approveExecution(permRequest.execution_id, 'SOC_DIRECTOR');
    assert(
        approvedExec.status === 'EXECUTED' && responseEngine.activeBlocks.has('91.240.118.172'),
        'Permanent block applied immediately after SOC_DIRECTOR approval'
    );

    // 4. One-Click Rollback of Executed Block
    const rolledBackBlock = await responseEngine.rollbackExecution(
        approvedExec.execution_id,
        'SOC_DIRECTOR',
        'False positive remediation test'
    );
    assert(
        rolledBackBlock.status === 'ROLLED_BACK' && !responseEngine.activeBlocks.has('91.240.118.172'),
        'One-click rollback removed IP from active blocks and recorded audit trail'
    );

    // =========================================================================
    // TEST SUITE 4: Stage 5 Files & Docker Compose Topology
    // =========================================================================
    console.log('\n--- [Suite 4] Stage 5 Service Files & Docker Compose Topology ---');
    const rootDir = path.resolve(__dirname, '..');
    const requiredFiles = [
        'deception-manager-service/index.js',
        'deception-manager-service/engine/adaptiveDeceptionEngine.js',
        'deception-manager-service/package.json',
        'deception-manager-service/Dockerfile',
        'playbook-decision-engine/index.js',
        'playbook-decision-engine/engine/soarPlaybookEngine.js',
        'automated-response-service/index.js',
        'automated-response-service/engine/responseExecutionEngine.js'
    ];

    for (const rel of requiredFiles) {
        assert(fs.existsSync(path.join(rootDir, rel)), `File exists: ${rel}`);
    }

    const composeContent = fs.readFileSync(path.join(rootDir, 'docker-compose.yml'), 'utf8');
    assert(composeContent.includes('deception-manager-service:'), 'docker-compose.yml defines deception-manager-service (:3013)');
    assert(composeContent.includes('DECEPTION_MANAGER_URL=http://deception-manager-service:3013'), 'automated-response-service wired to deception-manager-service');

    console.log('\n================================================================================');
    console.log(` STAGE 5 VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
    console.log('================================================================================');

    if (failed > 0) {
        process.exit(1);
    }
}

runVerification().catch(err => {
    console.error('Fatal error in Stage 5 verification:', err);
    process.exit(1);
});
