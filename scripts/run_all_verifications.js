/**
 * Shadow Guard 2.0 - Master End-to-End Verification & Research Benchmark Runner
 *
 * Executes all stage verification suites sequentially:
 *   - Stage 2: Foundation (PostgreSQL 2.0 Migrations, Event Contract v2, RabbitMQ Client)
 *   - Stage 3: Ingestion & Deception (Suricata EVE, Cowrie, OpenCanary, Dionaea, Honeypot Manager)
 *   - Stage 4: Intelligence & Correlation (Threat Intel, Attacker Profiling, Sliding-Window Correlation, Attack Chains)
 *   - Stage 5: Adaptive Deception & SOAR (Deception Manager DEC-01..04, SOAR Playbooks, Allowlist, Leases, Rollback)
 *   - Stage 6: 8-Page SOC Dashboard, JWT/RBAC Security Hardening & Prometheus Metrics
 *   - Stage 7: Reproducible 500-Event x 10-Scenario x 4-Cohort Ablation Benchmark
 */

'use strict';

const { execFileSync } = require('child_process');
const path = require('path');

const SUITES = [
    { stage: 'Stage 2', name: 'Foundation (Migrations, Event Contract v2 & RabbitMQ)', script: 'verify_stage2_foundation.js' },
    { stage: 'Stage 3', name: 'Suricata NIDS & Multi-Type Honeypot Infrastructure', script: 'verify_stage3_deception.js' },
    { stage: 'Stage 4', name: 'Threat Intel, Attacker Profiling, Correlation & Attack Chains', script: 'verify_stage4_intelligence.js' },
    { stage: 'Stage 5', name: 'Dynamic Deception Manager & Advanced SOAR Engine', script: 'verify_stage5_soar_deception.js' },
    { stage: 'Stage 6', name: '8-Page SOC Command Center, RBAC/JWT & Prometheus Metrics', script: 'verify_stage6_dashboard_security.js' },
    { stage: 'Stage 7', name: 'Reproducible 500-Event Research Ablation Benchmark', script: 'evaluate_research_cohorts.js' },
    { stage: 'AE Stg 1', name: 'Canonical 69-Feature Schema, Provenance & Cross-Language Parity', script: 'verify_feature_schema_and_dataset_stage1.js' },
    { stage: 'AE Stg 2', name: 'PyTorch Autoencoder Training, P97 Calibration & Artifacts', script: 'verify_autoencoder_stage2.js' },
    { stage: 'AE Stg 3', name: 'Autoencoder Inference, Tri-Model Fusion & Guardrails', script: 'verify_autoencoder_stage3.js' },
    { stage: 'AE Stg 4', name: 'SOC Dashboard Tri-Model Integration, Safety, RBAC & Benchmark', script: 'verify_autoencoder_stage4.js' },
    { stage: 'AE Stg 5', name: 'Cohort E Benchmark, Scientific Validity, Thesis & Viva Guide', script: 'verify_autoencoder_stage5.js' },
    { stage: 'XAI Stg 1', name: 'Model-Specific XAI Core (Official TreeSHAP, IF Perturb, AE MSE)', script: 'verify_xai_stage1.js' },
    { stage: 'XAI Stg 2', name: 'Unified Tri-Model Explanation Engine & 384-Flow Invariance', script: 'verify_xai_stage2.js' },
    { stage: 'XAI Stg 3', name: 'XAI Backend API Gateway, RBAC, Audit & PostgreSQL Migration', script: 'verify_xai_stage3.js' },
    { stage: 'XAI Stg 4', name: 'SOC Dashboard Module 11 (Explainable AI & Threat Reasoning)', script: 'verify_xai_stage4.js' },
    { stage: 'XAI Stg 5', name: 'XAI Scientific Evaluation, Stability, Performance & Regression', script: 'verify_xai_stage5.js' },
    { stage: 'Demo S1', name: 'Controllable Demo Simulator Service & Isolation', script: 'verify_demo_simulator_stage1.js' },
    { stage: 'Demo S2', name: 'Pipeline Context Propagation & Demo Safety Guardrails', script: 'verify_demo_simulator_stage2.js' },
    { stage: 'Demo S3', name: 'Dashboard Proxy, Session Store & Live WebSocket Stream', script: 'verify_demo_simulator_stage3.js' },
    { stage: 'Demo S4', name: 'SOC Dashboard UI (Module 12: Demo Traffic Simulator)', script: 'verify_demo_simulator_stage4.js' }
];

function runAll() {
    console.log('================================================================================');
    console.log(' SHADOW GUARD 2.0 — MASTER VERIFICATION & RESEARCH EVALUATION SUITE');
    console.log('================================================================================\n');

    let totalPassed = 0;
    let totalFailed = 0;
    const summaryRows = [];

    for (const s of SUITES) {
        const scriptPath = path.join(__dirname, s.script);
        try {
            const out = execFileSync(process.execPath, [scriptPath], { encoding: 'utf8' });
            const match = out.match(/(?:SUMMARY|RESULTS):\s*(\d+)\s*PASSED,\s*(\d+)\s*FAILED/i);
            const passed = match ? Number(match[1]) : 0;
            const failed = match ? Number(match[2]) : 0;
            totalPassed += passed;
            totalFailed += failed;
            summaryRows.push({ stage: s.stage, name: s.name, passed, failed, status: 'PASSED' });
            console.log(`  [PASS] ${s.stage.padEnd(8)} | ${s.name.padEnd(58)} | ${passed} passed, ${failed} failed`);
        } catch (err) {
            totalFailed += 1;
            summaryRows.push({ stage: s.stage, name: s.name, passed: 0, failed: 1, status: 'FAILED' });
            console.error(`  [FAIL] ${s.stage.padEnd(8)} | ${s.name} -> ${err.message}`);
        }
    }

    console.log('\n================================================================================');
    console.log(` GRAND TOTAL ACROSS ALL STAGES: ${totalPassed} PASSED, ${totalFailed} FAILED`);
    console.log('================================================================================');

    if (totalFailed > 0) {
        process.exit(1);
    }
}

runAll();
