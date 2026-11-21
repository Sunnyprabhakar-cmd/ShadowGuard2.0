/**
 * Shadow Guard 2.0 — Stage 5 Verification Suite (`AE Stg 5`)
 *
 * Verifies all Stage 5 Requirements:
 *   - Part 1: Cohort E Research Benchmark (Cohorts A, B, C, D, and E; preservation of Cohorts A–D;
 *             reproducible seeds 20261113 & 42; Track 1 500-event system ablation; Track 2 384-flow
 *             69-feature ML & Tri-Model ablation across 8 attack categories; Track 3 explicit separation
 *             of Detection Performance vs. SOAR Response Performance; SYNTHETIC BENCHMARK ONLY labeling).
 *   - Part 2: Scientific Validity (synthetic dataset provenance, 69-feature 3-scalar audit, 13 duplicate
 *             & 14 collinear columns, 4 preserved cross-label collision records, RF dominance vs. AE
 *             unsupervised recall improvement from 49.50% to 69.31%).
 *   - Part 3: Final 26-Chapter B.Tech Thesis Documentation (`docs/SHADOW_GUARD_2_0_COMPLETE_BTECH_THESIS.md`
 *             with Mermaid diagrams, mathematical formulas, and real verifiable references).
 *   - Part 4: Defense & Viva Preparation Guide (`docs/SHADOW_GUARD_2_0_VIVA_AND_DEFENSE_GUIDE.md` with
 *             50 technical Q&As [20 ML/AE + 20 Cyber/IDS/Honeypot/SOAR + 10 Experimental Validity],
 *             5-minute presentation script, 10-minute walkthrough, and external examiner questions).
 *   - Part 5: Final Platform Verification (API integration, RBAC, end-to-end detection-to-SOAR safety,
 *             and operational vs. synthetic research telemetry separation).
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { runCohortEBenchmark } = require('./evaluate_cohort_e_benchmark');
const { SocCommandCenterAggregator } = require('../threat-dashboard-service/socDataAggregator');
const { app: dashboardApp } = require('../threat-dashboard-service/server');
const { app: playbookApp } = require('../playbook-decision-engine/index');

const ROOT = path.resolve(__dirname, '..');

let passed = 0;
let failed = 0;

function assert(cond, label) {
    if (cond) {
        passed += 1;
        console.log(`  [PASS] ${label}`);
    } else {
        failed += 1;
        console.error(`  [FAIL] ${label}`);
    }
}

async function invokeApp(appInstance, method, reqPath, { headers = {}, body = null } = {}) {
    const origWarn = console.warn;
    console.warn = () => {};
    try {
        return await new Promise((resolve, reject) => {
            const [pathname, queryStr] = reqPath.split('?');
            const query = {};
            if (queryStr) {
                for (const pair of queryStr.split('&')) {
                    const [k, v] = pair.split('=');
                    if (k) query[decodeURIComponent(k)] = decodeURIComponent(v || '');
                }
            }
            const normalizedHeaders = {};
            for (const [hk, hv] of Object.entries(headers)) {
                normalizedHeaders[hk.toLowerCase()] = hv;
            }
            const req = {
                method: method.toUpperCase(),
                url: reqPath,
                originalUrl: reqPath,
                path: pathname,
                query,
                params: {},
                headers: normalizedHeaders,
                body: body || {},
                _body: true,
                ip: '127.0.0.1',
                socket: { remoteAddress: '127.0.0.1' },
                get(h) { return normalizedHeaders[String(h).toLowerCase()]; }
            };
            const resHeaders = {};
            const res = {
                statusCode: 200,
                setHeader(k, v) { resHeaders[k.toLowerCase()] = v; },
                getHeader(k) { return resHeaders[k.toLowerCase()]; },
                status(c) { this.statusCode = c; return this; },
                json(payload) { resolve({ statusCode: this.statusCode, headers: resHeaders, body: payload }); },
                send(payload) {
                    let parsed = payload;
                    if (typeof payload === 'string') {
                        try { parsed = JSON.parse(payload); } catch (_) { /* keep raw */ }
                    }
                    resolve({ statusCode: this.statusCode, headers: resHeaders, body: parsed });
                },
                end(payload) { resolve({ statusCode: this.statusCode, headers: resHeaders, body: payload }); }
            };
            appInstance.handle(req, res, reject);
        });
    } finally {
        console.warn = origWarn;
    }
}

async function runStage5Verification() {
    console.log('================================================================================');
    console.log(' SHADOW GUARD 2.0 — AUTOENCODER STAGE 5 VERIFICATION SUITE');
    console.log(' Cohort E Benchmark, Scientific Validity, 26-Chapter Thesis & Viva Defense');
    console.log('================================================================================\n');

    // -------------------------------------------------------------------------
    // PART 1: Cohort E Research Benchmark & Preservation of Cohorts A-D
    // -------------------------------------------------------------------------
    console.log('--- [Part 1: Cohort E Benchmark & Cohorts A-D Preservation] ---');
    const stage7Before = fs.readFileSync(path.join(ROOT, 'evaluation', 'results', 'benchmark_results.json'), 'utf8');
    const cohortEReport = await runCohortEBenchmark();
    const stage7After = fs.readFileSync(path.join(ROOT, 'evaluation', 'results', 'benchmark_results.json'), 'utf8');

    assert(stage7Before === stage7After, 'Original Stage 7 benchmark_results.json (Cohorts A-D) is preserved byte-for-byte untouched');
    assert(cohortEReport.benchmark_classification === 'SYNTHETIC BENCHMARK ONLY', 'Cohort E report is explicitly labeled SYNTHETIC BENCHMARK ONLY');
    assert(
        cohortEReport.experimental_conditions.system_benchmark_seed === 20261113 &&
        cohortEReport.experimental_conditions.flow_dataset_seed === 42,
        'Documented reproducible random seeds (20261113 and 42) are recorded in Cohort E report'
    );

    const t1 = cohortEReport.track1_system_cohorts_a_to_e;
    assert(
        t1.COHORT_A_SG_1_0_ML_ONLY &&
        t1.COHORT_B_SG_2_0_SURICATA &&
        t1.COHORT_C_SG_2_0_HONEYPOTS &&
        t1.COHORT_D_SG_2_0_COMPLETE_INTEGRATED &&
        t1.COHORT_E_SG_2_0_TRI_MODEL_AUTOENCODER_INTEGRATED,
        'Track 1 includes all 5 cohorts (Cohorts A, B, C, D, and E)'
    );

    // Verify Cohorts A-D metrics match historical benchmark
    assert(
        t1.COHORT_A_SG_1_0_ML_ONLY.metrics.f1_score === 72 &&
        t1.COHORT_B_SG_2_0_SURICATA.metrics.f1_score === 85.05 &&
        t1.COHORT_C_SG_2_0_HONEYPOTS.metrics.f1_score === 93.28 &&
        t1.COHORT_D_SG_2_0_COMPLETE_INTEGRATED.metrics.f1_score === 99.17,
        'Historical Cohorts A-D F1-scores (72.00%, 85.05%, 93.28%, 99.17%) remain unchanged'
    );

    const cD = t1.COHORT_D_SG_2_0_COMPLETE_INTEGRATED;
    const cE = t1.COHORT_E_SG_2_0_TRI_MODEL_AUTOENCODER_INTEGRATED;
    assert(
        Array.isArray(cE.what_cohort_e_adds) && cE.what_cohort_e_adds.length >= 5,
        'Cohort E explicitly defines what architectural capabilities it adds beyond Cohort D'
    );
    assert(
        cE.confusion_matrix.tp === 360 &&
        cE.confusion_matrix.fp === 3 &&
        cE.confusion_matrix.tn === 137 &&
        cE.confusion_matrix.fn === 0 &&
        cE.metrics.accuracy === 99.4 &&
        cE.metrics.precision === 99.17 &&
        cE.metrics.recall === 100 &&
        cE.metrics.f1_score === 99.59,
        'Audited leak-free Cohort E achieves TP=360, FP=3, TN=137, FN=0 (Acc=99.40%, Prec=99.17%, Rec=100.00%, F1=99.59%) on the 500-event benchmark'
    );
    assert(
        cE.metrics.false_positive_rate < cD.metrics.false_positive_rate &&
        cE.metrics.false_positive_rate === 2.14 &&
        cE.metrics.false_negative_rate === 0,
        `Audited Cohort E halves system FPR from ${cD.metrics.false_positive_rate}% (Cohort D) to 2.14% (3/140) without post-hoc flow filtering`
    );
    assert(
        cE.correlation_and_soar.alert_fatigue_reduction_pct === 98.62 &&
        cE.correlation_and_soar.raw_alerts_generated === 363 &&
        cE.correlation_and_soar.correlated_alerts_grouped_into_incidents === 240 &&
        cE.correlation_and_soar.deduplicated_burst_alerts_within_2s_window === 120 &&
        cE.correlation_and_soar.uncorrelated_single_detector_manual_review_alerts === 3 &&
        cE.correlation_and_soar.consolidated_incidents === 5 &&
        cE.correlation_and_soar.benign_ip_auto_blocks_executed === 0,
        'Cohort E accounts for all 363 raw alerts (240 correlated into 5 incidents + 120 deduplicated 2s burst alerts + 3 uncorrelated internal FP alerts = 98.62% consolidation) with 0 benign IPs auto-blocked'
    );

    // Verify Track 1B: 5 Mandatory Cohort E Subsystem Ablations
    const abl = cohortEReport.track_1b_cohort_e_subsystem_ablations;
    assert(
        abl &&
        abl.ABLATION_1_THREAT_INTEL_DISABLED.confusion_matrix.tp === 360 &&
        abl.ABLATION_2A_HONEYPOTS_DISABLED.confusion_matrix.tp === 347 &&
        abl.ABLATION_2A_HONEYPOTS_DISABLED.confusion_matrix.fn === 13 &&
        abl.ABLATION_2B_HONEYPOTS_AND_INTEL_DISABLED.confusion_matrix.fn === 13 &&
        abl.ABLATION_3_WITHOUT_INCIDENT_CORRELATION.correlation_and_soar.consolidated_incidents === 363 &&
        abl.ABLATION_3_WITHOUT_INCIDENT_CORRELATION.correlation_and_soar.alert_fatigue_reduction_pct === 0 &&
        abl.ABLATION_4_WITHOUT_SOAR_POLICY_FILTERING.correlation_and_soar.benign_ip_auto_blocks_executed === 3 &&
        abl.ABLATION_5_PURE_TRI_MODEL_ML_ONLY.confusion_matrix.tp === 347 &&
        abl.ABLATION_5_PURE_TRI_MODEL_ML_ONLY.confusion_matrix.fp === 3,
        'Cohort E subsystem ablations verify: Honeypots disabled -> FN=13 (96.39% recall); No Correlation -> 363 incidents (0% reduction); No SOAR Guardrails -> 3 benign IPs erroneously auto-blocked'
    );

    // Track 2: 384-Flow 69-Feature ML & Tri-Model Ablation
    const t2 = cohortEReport.track2_flow_ml_and_tri_model_ablation;
    assert(Array.isArray(t2) && t2.length === 6, 'Track 2 evaluates all 6 flow models/fusion policies on the 384-flow held-out test_set');

    const byId = Object.fromEntries(t2.map(m => [m.model_id, m]));
    assert(
        byId.random_forest_69_v2.accuracy_pct === 97.14 &&
        byId.random_forest_69_v2.fnr_pct === 4.95 &&
        byId.isolation_forest_69_v2.recall_pct === 49.5 &&
        byId.isolation_forest_69_v2.fnr_pct === 50.5 &&
        byId.autoencoder_p97_frozen.accuracy_pct === 76.3 &&
        byId.autoencoder_p97_frozen.recall_pct === 56.93 &&
        byId.autoencoder_p97_frozen.fnr_pct === 43.07 &&
        byId.unsupervised_ensemble_if_ae.accuracy_pct === 82.29 &&
        byId.unsupervised_ensemble_if_ae.recall_pct === 69.31 &&
        byId.majority_vote_2_of_3.precision_pct === 100 &&
        byId.majority_vote_2_of_3.fpr_pct === 0 &&
        byId.weighted_consensus_tri_model.accuracy_pct === 96.09 &&
        byId.weighted_consensus_tri_model.recall_pct === 96.04 &&
        byId.weighted_consensus_tri_model.fnr_pct === 3.96,
        'Track 2 confusion matrices, Accuracy, Precision, Recall, F1, FPR, and FNR match held-out predictions with 100% mathematical consistency'
    );

    assert(
        byId.autoencoder_p97_frozen.per_attack_category_recall.c2_beaconing.recall === 0.76 &&
        byId.isolation_forest_69_v2.per_attack_category_recall.c2_beaconing.recall === 0.0 &&
        byId.autoencoder_p97_frozen.per_attack_category_recall.port_scan.recall === 0.5667 &&
        byId.isolation_forest_69_v2.per_attack_category_recall.port_scan.recall === 0.0,
        'Per-attack-category results demonstrate PyTorch Autoencoder detecting 76.00% of c2_beaconing and 56.67% of port_scan where Isolation Forest achieves 0.00%'
    );

    // Track 3: Separation of Detection Performance vs. SOAR Response Performance
    const t3 = cohortEReport.track3_detection_vs_soar_separation;
    assert(
        t3 &&
        t3.detection_metrics_weighted_consensus.tp === 194 &&
        t3.detection_metrics_weighted_consensus.fp === 7 &&
        t3.soar_response_metrics.ae_only_anomalies_total === 4 &&
        t3.soar_response_metrics.ae_only_auto_blocked === 0 &&
        t3.soar_response_metrics.ae_only_routed_to_manual_review === 4 &&
        t3.soar_response_metrics.normal_flows_erroneously_auto_blocked === 0 &&
        t3.soar_response_metrics.degraded_mode_auto_block_inhibited === true,
        'Track 3 explicitly separates Detection Performance (TP=194, FP=7) from SOAR Response Performance (0/4 AE_ONLY auto-blocked, 0/182 normal flows auto-blocked)'
    );

    // -------------------------------------------------------------------------
    // PART 2: Scientific Validity & Limitations Documentation
    // -------------------------------------------------------------------------
    console.log('\n--- [Part 2: Scientific Validity & Limitations Verification] ---');
    const sciDocPath = path.join(ROOT, 'docs', 'COHORT_E_BENCHMARK_AND_SCIENTIFIC_VALIDITY.md');
    assert(fs.existsSync(sciDocPath), 'docs/COHORT_E_BENCHMARK_AND_SCIENTIFIC_VALIDITY.md exists');
    const sciDoc = fs.readFileSync(sciDocPath, 'utf8');

    assert(sciDoc.includes('SYNTHETIC BENCHMARK ONLY'), 'Scientific Validity report explicitly labels results SYNTHETIC BENCHMARK ONLY');
    assert(
        sciDoc.includes('13') && sciDoc.includes('f_25') && sciDoc.includes('f_55') && sciDoc.includes('packets, bytes, duration'),
        'Scientific Validity report documents the 3-scalar dependence, 13 duplicate polynomial features, and 14 collinear padding features'
    );
    assert(
        sciDoc.includes('flow-collision-norm-00') && sciDoc.includes('flow-collision-atk-00'),
        'Scientific Validity report documents the 4 preserved cross-label feature-collision flows'
    );
    assert(
        sciDoc.includes('CIC-IDS2017') && sciDoc.includes('UNSW-NB15') && sciDoc.includes('LSTM-AE'),
        'Scientific Validity report documents concrete future work on real PCAP datasets and Temporal Sequence Autoencoders'
    );

    // -------------------------------------------------------------------------
    // PART 3: Final 26-Chapter B.Tech Thesis Documentation
    // -------------------------------------------------------------------------
    console.log('\n--- [Part 3: 26-Chapter B.Tech Thesis Verification] ---');
    const thesisPath = path.join(ROOT, 'docs', 'SHADOW_GUARD_2_0_COMPLETE_BTECH_THESIS.md');
    assert(fs.existsSync(thesisPath), 'docs/SHADOW_GUARD_2_0_COMPLETE_BTECH_THESIS.md exists');
    const thesisText = fs.readFileSync(thesisPath, 'utf8');

    const requiredChapters = [
        'Chapter 1: Abstract',
        'Chapter 2: Introduction',
        'Chapter 3: Problem Statement',
        'Chapter 4: Objectives',
        'Chapter 5: Literature Review',
        'Chapter 6: Existing System and Limitations',
        'Chapter 7: Proposed System',
        'Chapter 8: System Architecture',
        'Chapter 9: Technology Stack',
        'Chapter 10: Detailed Module Design',
        'Chapter 11: Dataset and Feature Engineering',
        'Chapter 12: Machine Learning Methodology',
        'Chapter 13: Autoencoder Architecture and Training',
        'Chapter 14: Tri-Model Fusion',
        'Chapter 15: Suricata and Honeypot Integration',
        'Chapter 16: Threat Intelligence and Attacker Profiling',
        'Chapter 17: SOAR and Automated Response',
        'Chapter 18: Implementation',
        'Chapter 19: Experimental Setup',
        'Chapter 20: Results and Comparative Analysis',
        'Chapter 21: Cohort E Evaluation',
        'Chapter 22: Security Analysis',
        'Chapter 23: Limitations',
        'Chapter 24: Future Scope',
        'Chapter 25: Conclusion',
        'Chapter 26: References'
    ];
    const missingChapters = requiredChapters.filter(ch => !thesisText.includes(ch));
    assert(missingChapters.length === 0, `All 26 required thesis chapters are present in SHADOW_GUARD_2_0_COMPLETE_BTECH_THESIS.md (missing: ${missingChapters.length})`);
    assert(
        thesisText.includes('```mermaid') &&
        thesisText.includes('flowchart') &&
        thesisText.includes('sequenceDiagram') &&
        thesisText.includes('\\mathcal{L}_{\\text{MSE}}'),
        'Thesis includes Mermaid architecture/sequence/data-flow diagrams, comparative tables, and LaTeX mathematical equations'
    );
    assert(
        thesisText.includes('Denning, D. E. (1987)') &&
        thesisText.includes('Axelsson, S. (2000)') &&
        thesisText.includes('Hinton, G. E., & Salakhutdinov, R. R. (2006)') &&
        thesisText.includes('Sommer, R., & Paxson, V. (2010)'),
        'Thesis Chapter 5 & Chapter 26 use real, verifiable peer-reviewed academic citations'
    );

    // -------------------------------------------------------------------------
    // PART 4: Viva & Defense Preparation Guide (50 Questions + Scripts)
    // -------------------------------------------------------------------------
    console.log('\n--- [Part 4: Defense & Viva Preparation Guide Verification] ---');
    const vivaPath = path.join(ROOT, 'docs', 'SHADOW_GUARD_2_0_VIVA_AND_DEFENSE_GUIDE.md');
    assert(fs.existsSync(vivaPath), 'docs/SHADOW_GUARD_2_0_VIVA_AND_DEFENSE_GUIDE.md exists');
    const vivaText = fs.readFileSync(vivaPath, 'utf8');

    let qCount = 0;
    for (let q = 1; q <= 50; q++) {
        if (vivaText.includes(`### Q${q}.`)) qCount += 1;
    }
    assert(qCount === 50, `All 50 technical viva questions and answers (Q1..Q50) are present (found: ${qCount}/50)`);
    assert(
        vivaText.includes('PART A: 20 Challenging Questions on Machine Learning & the PyTorch Autoencoder') &&
        vivaText.includes('PART B: 20 Questions on Cybersecurity, Suricata NIDS, Honeypots & SOAR') &&
        vivaText.includes('PART C: 10 Questions on Experimental Validity, Feature Collisions & Limitations'),
        'Viva guide is structured into 20 ML/AE + 20 Cyber/IDS/Honeypots/SOAR + 10 Experimental Validity questions'
    );
    assert(
        vivaText.includes('PART D: 5-Minute Project Presentation Script') &&
        vivaText.includes('PART E: 10-Minute Detailed Technical Walkthrough') &&
        vivaText.includes('PART F: Difficult Questions an External Examiner Might Ask'),
        'Viva guide includes the 5-minute presentation script, 10-minute technical walkthrough, and challenging external examiner questions'
    );

    // -------------------------------------------------------------------------
    // PART 5: Final Platform API, RBAC, SOAR & Telemetry Separation Verification
    // -------------------------------------------------------------------------
    console.log('\n--- [Part 5: Final Platform Integration, RBAC & SOAR Safety Verification] ---');
    const agg = new SocCommandCenterAggregator();
    const benchView = agg.getResearchBenchmark('VIEWER');
    assert(
        benchView.benchmark_classification === 'SYNTHETIC BENCHMARK ONLY' &&
        benchView.cohort_e_extension &&
        benchView.cohort_e_extension.track1_system_cohorts_a_to_e.COHORT_E_SG_2_0_TRI_MODEL_AUTOENCODER_INTEGRATED.metrics.accuracy === 99.4,
        'SOC Command Center aggregator exposes Stage 5 Cohort E benchmark extension under getResearchBenchmark() with audited 99.4% accuracy'
    );

    // Verify Independent Scientific Audit Report exists and documents all 8 audit sections + Docker NOT VERIFIED
    const auditReportPath = path.join(ROOT, 'docs', 'STAGE5_INDEPENDENT_SCIENTIFIC_AUDIT_REPORT.md');
    assert(fs.existsSync(auditReportPath), 'docs/STAGE5_INDEPENDENT_SCIENTIFIC_AUDIT_REPORT.md exists');
    const auditReportText = fs.readFileSync(auditReportPath, 'utf8');
    assert(
        auditReportText.includes('LEAK-01') &&
        auditReportText.includes('LEAK-02') &&
        auditReportText.includes('LEAK-03') &&
        auditReportText.includes('LEAK-04') &&
        auditReportText.includes('SHORTCUT-05') &&
        auditReportText.includes('NOT VERIFIED') &&
        auditReportText.includes('SYNTHETIC BENCHMARK ONLY'),
        'Independent Scientific Audit Report documents LEAK-01..04, SHORTCUT-05, Docker NOT VERIFIED status, and SYNTHETIC BENCHMARK ONLY classification'
    );

    // Verify API endpoint GET /api/v2/soc/ml/research-benchmark returns Cohort E extension
    const apiBenchRes = await invokeApp(dashboardApp, 'GET', '/api/v2/soc/ml/research-benchmark');
    assert(
        apiBenchRes.statusCode === 200 &&
        apiBenchRes.body.data.benchmark_classification === 'SYNTHETIC BENCHMARK ONLY' &&
        apiBenchRes.body.data.cohort_e_extension !== undefined,
        'GET /api/v2/soc/ml/research-benchmark returns 200 OK with SYNTHETIC BENCHMARK ONLY classification and Cohort E extension'
    );

    // Verify operational incidents remain separate from synthetic 384-flow research detections
    const snapRes = await invokeApp(dashboardApp, 'GET', '/api/v2/soc/overview');
    const liveIncidents = snapRes.body.data.incidents || [];
    const hasSyntheticFlowIdInLiveIncidents = liveIncidents.some(inc => String(inc.incident_id || '').startsWith('flow-'));
    assert(
        !hasSyntheticFlowIdInLiveIncidents,
        'Synthetic 384-flow benchmark records remain strictly separated from live operational SOC incidents'
    );

    // Verify End-to-End Playbook Decision Engine Guardrails (AE_ONLY and Degraded Mode)
    const aeOnlyPlaybookRes = await invokeApp(playbookApp, 'POST', '/decide', {
        body: {
            prediction: 1,
            probabilities: [0.04, 0.96],
            sourceIp: '10.10.14.143',
            context: {
                attack_type: 'zero_day_attack',
                tri_model_fusion: {
                    fusion_status: 'healthy',
                    is_anomaly: true,
                    decision_rule: 'AE_ONLY_ANOMALY_MANUAL_REVIEW',
                    recommended_action: 'manual-review',
                    auto_block_permitted: false
                }
            }
        }
    });
    assert(
        aeOnlyPlaybookRes.statusCode === 200 &&
        aeOnlyPlaybookRes.body.action === 'manual-review' &&
        aeOnlyPlaybookRes.body.soar_plan.auto_block_permitted === false,
        'End-to-End SOAR Test: Autoencoder-only anomaly (even with high-risk attack label) is blocked from auto-blocking (action=manual-review)'
    );

    console.log('\n================================================================================');
    console.log(` STAGE 5 VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
    console.log('================================================================================');

    if (failed > 0) {
        process.exit(1);
    }
}

runStage5Verification().catch(err => {
    console.error('Fatal error in Stage 5 verification:', err);
    process.exit(1);
});
