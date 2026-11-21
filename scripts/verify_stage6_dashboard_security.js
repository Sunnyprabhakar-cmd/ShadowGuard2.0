/**
 * Shadow Guard 2.0 - Stage 6 Verification Suite
 *
 * Verifies:
 *   1. Security Hardening (HMAC-SHA256 JWT issuance/verification, RBAC hierarchy VIEWER/SOC_ANALYST/ADMIN,
 *      API-key authentication, rate-limiting 429 enforcement, and security audit trail)
 *   2. Observability (Prometheus exposition format `/metrics` counters & gauges)
 *   3. Unified 8-Page SOC Command Center Aggregator & Live Multi-Stage Intrusion Simulation
 *   4. React Dashboard UI & API Gateway structural verification
 */

'use strict';

const fs = require('fs');
const path = require('path');

const { SecurityAndObservabilityManager } = require('../shared/lib/securityAndObservability');
const { SocCommandCenterAggregator } = require('../threat-dashboard-service/socDataAggregator');

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
    console.log(' SHADOW GUARD 2.0 — STAGE 6 VERIFICATION SUITE');
    console.log(' 8-Page SOC Command Center, RBAC/JWT Security Hardening & Prometheus Metrics');
    console.log('================================================================================\n');

    // =========================================================================
    // TEST SUITE 1: JWT/HMAC Auth, RBAC & Rate-Limiting
    // =========================================================================
    console.log('--- [Suite 1] Security Hardening (JWT, RBAC, API-Key & Rate-Limiting) ---');
    const secMgr = new SecurityAndObservabilityManager({
        jwtSecret: 'test-secret-key-2026',
        serviceApiKey: 'test-internal-api-key',
        strictAuth: true,
        rateLimitMax: 3
    });

    const analystToken = secMgr.issueToken({ sub: 'alice', role: 'SOC_ANALYST' }, 3600);
    const verifiedAnalyst = secMgr.verifyToken(analystToken);
    assert(
        verifiedAnalyst.valid === true && verifiedAnalyst.claims.sub === 'alice' && verifiedAnalyst.claims.role === 'SOC_ANALYST',
        'Issued HMAC-SHA256 JWT token verified with valid signature and claims'
    );

    const tamperedCheck = secMgr.verifyToken(analystToken + 'tampered');
    assert(tamperedCheck.valid === false && tamperedCheck.reason === 'invalid_signature', 'Tampered JWT signature rejected');

    const expiredToken = secMgr.issueToken({ sub: 'bob', role: 'VIEWER' }, -10);
    const expiredCheck = secMgr.verifyToken(expiredToken);
    assert(expiredCheck.valid === false && expiredCheck.reason === 'token_expired', 'Expired JWT token rejected');

    // RBAC hierarchy checks
    assert(secMgr.hasRolePermission('ADMIN', 'SOC_ANALYST') === true, 'ADMIN satisfies SOC_ANALYST requirement');
    assert(secMgr.hasRolePermission('SOC_ANALYST', 'ADMIN') === false, 'SOC_ANALYST denied ADMIN-only requirement');
    assert(secMgr.hasRolePermission('VIEWER', 'SOC_ANALYST') === false, 'VIEWER denied SOC_ANALYST requirement');

    // Middleware simulation for RBAC
    const adminMw = secMgr.requireRole('ADMIN');
    let statusSent = null;
    let nextCalled = false;
    adminMw(
        { headers: { authorization: `Bearer ${analystToken}` }, path: '/api/v2/soc/approvals/1/approve', ip: '10.0.0.5' },
        { status: (code) => ({ json: () => { statusSent = code; } }) },
        () => { nextCalled = true; }
    );
    assert(statusSent === 403 && nextCalled === false, 'RBAC middleware returns HTTP 403 when SOC_ANALYST calls ADMIN route');

    // Middleware simulation for valid X-API-Key
    statusSent = null;
    nextCalled = false;
    adminMw(
        { headers: { 'x-api-key': 'test-internal-api-key' }, path: '/api/v2/soc/approvals/1/approve', ip: '10.0.0.5' },
        { status: (code) => ({ json: () => { statusSent = code; } }) },
        () => { nextCalled = true; }
    );
    assert(nextCalled === true, 'Valid X-API-Key grants internal service authentication');

    // Rate limiter test (limit = 3 per minute)
    const rlMw = secMgr.rateLimitMiddleware();
    const statuses = [];
    for (let i = 0; i < 4; i++) {
        let code = 200;
        rlMw(
            { ip: '192.0.2.99', path: '/api/v2/soc/overview' },
            {
                setHeader: () => {},
                status: (c) => ({ json: () => { code = c; } })
            },
            () => {}
        );
        statuses.push(code);
    }
    assert(
        statuses[0] === 200 && statuses[2] === 200 && statuses[3] === 429,
        'Rate limiter allows requests within quota (3) and returns HTTP 429 on burst overflow'
    );

    // =========================================================================
    // TEST SUITE 2: Prometheus Observability (`/metrics`)
    // =========================================================================
    console.log('\n--- [Suite 2] Prometheus Exposition Metrics (`/metrics`) ---');
    const promText = secMgr.formatPrometheusMetrics({
        events_processed: 1240,
        threats_detected: 42,
        honeypot_interactions: 225,
        active_incidents: 3,
        attacker_profiles: 3,
        active_ip_blocks: 2,
        active_deception_directives: 3,
        active_connections: 2,
        service_health: {
            traffic_capture: { status: 'healthy' },
            honeypot_manager: { status: 'healthy' }
        }
    });

    assert(promText.includes('shadowguard_events_processed_total 1240'), 'Prometheus counter shadowguard_events_processed_total formatted');
    assert(promText.includes('shadowguard_honeypot_interactions_total 225'), 'Prometheus counter shadowguard_honeypot_interactions_total formatted');
    assert(promText.includes('shadowguard_active_incidents_gauge 3'), 'Prometheus gauge shadowguard_active_incidents_gauge formatted');
    assert(promText.includes('shadowguard_service_up{service="honeypot_manager"} 1'), 'Per-service health gauge formatted');

    // =========================================================================
    // TEST SUITE 3: Unified 8-Page SOC Command Center Aggregator & Simulation
    // =========================================================================
    console.log('\n--- [Suite 3] Unified SOC Command Center Data Aggregator & Live Intrusion Simulation ---');
    const socAgg = new SocCommandCenterAggregator();
    const snapBefore = socAgg.getUnifiedSnapshot();

    assert(snapBefore.honeypots.length === 3, 'All 3 multi-type honeypot sensors (Cowrie, OpenCanary, Dionaea) present');
    assert(snapBefore.attacker_profiles.length === 3, '3 enriched Attacker Profiles with explainable risk scores present');
    assert(snapBefore.incidents.length === 3, '3 multi-source correlated incidents present');
    assert(snapBefore.attack_chains.length === 2, '2 reconstructed MITRE ATT&CK kill chains with OBSERVED/INFERRED/SUSPECTED tiers present');
    assert(snapBefore.threat_intel.length === 5, '5 Threat Intelligence IOCs (IP, Domain, SHA-256) present');
    assert(snapBefore.adaptive_directives.length === 3, '3 active Adaptive Deception directives present');
    assert(snapBefore.soar_block_leases.length === 2, '2 active timed SOAR IP block leases present');
    assert(snapBefore.soar_pending_approvals.length === 1, '1 pending permanent ban in manual approval queue');
    assert(snapBefore.allowlist.length === 6, '6 immutable critical infrastructure allowlist IPs present');

    const simResult = socAgg.simulateMultiStageAttack('ssh_compromise');
    const snapAfter = socAgg.getUnifiedSnapshot();
    assert(
        Boolean(simResult.incident && simResult.attack_chain && simResult.soar_block),
        'Live multi-stage attack simulation creates correlated incident, MITRE attack chain, and SOAR block lease'
    );
    assert(snapAfter.incidents.length === 4 && snapAfter.attack_chains.length === 3, 'SOC snapshot dynamically reflects newly injected intrusion');

    // =========================================================================
    // TEST SUITE 4: Dashboard Frontend & Gateway Route Verification
    // =========================================================================
    console.log('\n--- [Suite 4] Dashboard Frontend & Gateway Route Verification ---');
    const rootDir = path.resolve(__dirname, '..');
    const serverCode = fs.readFileSync(path.join(rootDir, 'threat-dashboard-service/server.js'), 'utf8');
    const appCode = fs.readFileSync(path.join(rootDir, 'threat-dashboard-service/public/app.js'), 'utf8');
    const cssCode = fs.readFileSync(path.join(rootDir, 'threat-dashboard-service/public/styles.css'), 'utf8');

    assert(serverCode.includes("app.get('/api/v2/soc/overview'"), 'server.js exposes GET /api/v2/soc/overview');
    assert(serverCode.includes("app.post('/api/v2/soc/simulate-attack'"), 'server.js exposes POST /api/v2/soc/simulate-attack');
    assert(serverCode.includes("app.post('/api/v2/auth/token'"), 'server.js exposes POST /api/v2/auth/token');
    assert(serverCode.includes("app.get('/metrics'"), 'server.js exposes GET /metrics for Prometheus');

    for (const tabId of ['overview', 'honeypots', 'attackers', 'incidents', 'attack_chains', 'threat_intel', 'soar', 'system_audit']) {
        assert(appCode.includes(`'${tabId}'`), `React dashboard app.js implements SOC Command Center module '${tabId}'`);
    }
    assert(cssCode.includes('.soc-module-nav') && cssCode.includes('.certainty-badge'), 'styles.css includes SOC 2.0 styling');

    console.log('\n================================================================================');
    console.log(` STAGE 6 VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
    console.log('================================================================================');

    if (failed > 0) {
        process.exit(1);
    }
}

runVerification().catch(err => {
    console.error('Fatal error in Stage 6 verification:', err);
    process.exit(1);
});
