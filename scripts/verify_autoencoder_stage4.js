/**
 * Shadow Guard 2.0 — Autoencoder Stage 4 Verification Suite (SOC Dashboard Integration)
 * =====================================================================================
 * Verifies:
 *   1. Detection Dashboard APIs (`/api/v2/soc/ml/overview`, `/api/models`):
 *      - Random Forest predictions, Isolation Forest anomaly scores, PyTorch Autoencoder MSE
 *      - Configured Autoencoder threshold P97 = 0.503670 and percentile ('P97') + P95/P99 tiers
 *      - Individual model status ('healthy' / 'degraded'), fusion policy, severity distribution,
 *        and 8-window chronological detection timeline.
 *   2. Explainable Detection (`/api/v2/soc/ml/detections`, `/api/v2/soc/ml/detections/:flowId`):
 *      - Reconstruction error (MSE), top-5 contributing Autoencoder features, Random Forest
 *        attack probability, Isolation Forest anomaly score, model agreement/disagreement,
 *        and decision rule.
 *      - Explicit semantic distinction between probabilities and anomaly scores.
 *   3. SOC Analyst Interface & Evaluation Views (`/api/v2/soc/ml/evaluation`, `/api/v2/soc/ml/manual-review`):
 *      - False-positive (7 flows), false-negative (8 flows), and cross-label feature-collision (4 flows)
 *        evaluation views.
 *      - Manual-review queue for the 4 Autoencoder-only (`AE_ONLY`) and 4 `IF_ONLY` anomalies.
 *   4. Safety Guardrails, RBAC & Degraded-State Handling:
 *      - Autoencoder-only (`AE_ONLY`) anomalies NEVER independently authorize IP blocking
 *        (attempting `AUTO_BLOCK_IP` on an `AE_ONLY` item returns HTTP 422 `rejected_by_safety_policy`
 *        with `auto_block_executed: false` and records `AE_ONLY_AUTOBLOCK_PREVENTED`).
 *      - `VIEWER` role is blocked (`HTTP 403`) from manual-review mutations, fusion-policy changes,
 *        degraded-mode simulation, and model reload, and never receives internal model file paths or secrets.
 *      - `SOC_ANALYST` (`ANALYST`) role can review manual queue items and switch fusion policies,
 *        but is blocked (`HTTP 403`) from `ADMIN`-only model reload and degraded-mode endpoints.
 *      - Partial and full degraded-model states visibly update engine status, inhibit auto-blocking,
 *        and route detections to `manual-review`.
 *   5. 6-Model Research & Benchmark View (`/api/v2/soc/ml/research-benchmark`):
 *      - Compares Random Forest, Isolation Forest, Autoencoder (P97/P95/P99), IF + AE Unsupervised
 *        Ensemble (82.29% Acc), Majority Vote (2-of-3, 83.33% Acc), and Weighted Consensus (96.09% Acc).
 *      - Explicitly labeled `SYNTHETIC BENCHMARK ONLY`.
 *   6. Frontend React UI (`app.js`, `styles.css`) structural & component verification.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const { app, securityManager } = require('../threat-dashboard-service/server');

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

/**
 * Dispatch an HTTP request through the Express `app` pipeline (works in both sandboxed and
 * unsandboxed environments without requiring outbound loopback TCP sockets).
 */
function dispatchExpressRequest(method, urlPath, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = new EventEmitter();
    req.method = method.toUpperCase();
    req.url = urlPath;
    req.originalUrl = urlPath;
    req.path = urlPath.split('?')[0];
    req.ip = '127.0.0.1';
    req.connection = { remoteAddress: '127.0.0.1' };
    req.socket = { remoteAddress: '127.0.0.1' };

    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = v;
    }
    if (body !== null && !normalizedHeaders['content-type']) {
      normalizedHeaders['content-type'] = 'application/json';
    }
    req.headers = normalizedHeaders;
    req.body = body !== null ? body : {};
    req._body = true; // Signal body-parser that body is already parsed
    req.get = (name) => normalizedHeaders[String(name).toLowerCase()];
    req.header = req.get;

    const res = new EventEmitter();
    res.statusCode = 200;
    res.headers = {};
    res.locals = {};
    res.setHeader = (k, v) => {
      res.headers[String(k).toLowerCase()] = v;
    };
    res.getHeader = (k) => res.headers[String(k).toLowerCase()];
    res.removeHeader = (k) => {
      delete res.headers[String(k).toLowerCase()];
    };
    res.status = (code) => {
      res.statusCode = code;
      return res;
    };
    res.json = (obj) => {
      res.setHeader('content-type', 'application/json');
      resolve({ statusCode: res.statusCode, headers: res.headers, body: obj });
      return res;
    };
    res.send = (payload) => {
      if (typeof payload === 'object' && payload !== null && !Buffer.isBuffer(payload)) {
        return res.json(payload);
      }
      try {
        const parsed = JSON.parse(String(payload));
        resolve({ statusCode: res.statusCode, headers: res.headers, body: parsed });
      } catch (_) {
        resolve({ statusCode: res.statusCode, headers: res.headers, body: String(payload) });
      }
      return res;
    };
    res.end = (chunk) => {
      resolve({ statusCode: res.statusCode, headers: res.headers, body: chunk ? String(chunk) : null });
    };

    try {
      app.handle(req, res, (err) => {
        if (err) reject(err);
      });
    } catch (err) {
      reject(err);
    }
  });
}

async function main() {
  console.log('================================================================================');
  console.log(' SHADOW GUARD 2.0 — AUTOENCODER STAGE 4 VERIFICATION SUITE');
  console.log(' SOC Command Center Tri-Model Detection, Explainability, Safety, RBAC & Benchmark');
  console.log('================================================================================\n');

  // Issue JWT tokens for VIEWER, SOC_ANALYST (ANALYST), and ADMIN
  const viewerToken = securityManager.issueToken({ sub: 'viewer-user', role: 'VIEWER' }, 3600);
  const analystToken = securityManager.issueToken({ sub: 'analyst-user', role: 'SOC_ANALYST' }, 3600);
  const adminToken = securityManager.issueToken({ sub: 'admin-user', role: 'ADMIN' }, 3600);

  const viewerAuth = { Authorization: `Bearer ${viewerToken}` };
  const analystAuth = { Authorization: `Bearer ${analystToken}` };
  const adminAuth = { Authorization: `Bearer ${adminToken}` };

  // ===========================================================================
  // 1. Detection Dashboard & Model Health Overview
  // ===========================================================================
  console.log('--- 1. Detection Dashboard Overview & Model Health (/api/v2/soc/ml/overview) ---');
  const overviewRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/overview', {
    headers: viewerAuth
  });
  assert(overviewRes.statusCode === 200 && overviewRes.body.status === 'success', 'GET /api/v2/soc/ml/overview returns HTTP 200 for VIEWER');

  const ov = overviewRes.body.data;
  const mh = ov.models_health || {};
  assert(
    mh.random_forest?.status === 'healthy' &&
      mh.isolation_forest?.status === 'healthy' &&
      mh.autoencoder?.status === 'healthy',
    'All 3 models (Random Forest, Isolation Forest, PyTorch Autoencoder) report healthy status'
  );
  assert(
    mh.autoencoder?.model_id === 'ae-pytorch-v2.0.0' &&
      mh.autoencoder?.configured_percentile === 'P97' &&
      Math.abs(mh.autoencoder?.configured_threshold - 0.50367) < 1e-6 &&
      Math.abs(mh.autoencoder?.thresholds?.P95?.value - 0.409105) < 1e-6 &&
      Math.abs(mh.autoencoder?.thresholds?.P99?.value - 0.645935) < 1e-6,
    'Autoencoder overview exposes configured P97=0.503670 threshold plus P95=0.409105 and P99=0.645935 tiers'
  );

  const sevDist = ov.test_set_summary?.severity_distribution || {};
  const sevTotal = Object.values(sevDist).reduce((a, b) => a + Number(b), 0);
  assert(
    sevTotal === 384 &&
      Array.isArray(ov.detection_timeline) &&
      ov.detection_timeline.length === 8 &&
      ov.detection_timeline.reduce((s, w) => s + w.total_flows, 0) === 384,
    'Anomaly severity distribution and 8-window detection timeline account for all 384 held-out flows'
  );

  const legacyModelsRes = await dispatchExpressRequest('GET', '/api/models');
  assert(
    legacyModelsRes.statusCode === 200 &&
      Boolean(legacyModelsRes.body.random_forest && legacyModelsRes.body.isolation_forest && legacyModelsRes.body.autoencoder),
    'Legacy GET /api/models includes Random Forest, Isolation Forest, and PyTorch Autoencoder'
  );

  // Verify no internal file paths or secrets leaked to VIEWER
  const rawOverviewStr = JSON.stringify(ov);
  assert(
    !rawOverviewStr.includes('D:\\') &&
      !rawOverviewStr.includes('d:\\') &&
      !rawOverviewStr.includes('/app/models') &&
      !rawOverviewStr.includes('shadowguard-v2-hmac-secret') &&
      !rawOverviewStr.includes('artifact_path') &&
      !rawOverviewStr.includes('dataset_path'),
    'VIEWER response is sanitized of internal model file paths and secrets'
  );

  // ===========================================================================
  // 2. Explainable Detection & Score Semantics Distinction
  // ===========================================================================
  console.log('\n--- 2. Explainable Detection & Score vs. Probability Semantics (/api/v2/soc/ml/detections) ---');
  const detRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/detections?limit=60', {
    headers: viewerAuth
  });
  assert(
    detRes.statusCode === 200 && Array.isArray(detRes.body.data?.detections) && detRes.body.data.detections.length >= 50,
    'GET /api/v2/soc/ml/detections returns explainable flow detections'
  );

  const sampleFlow = detRes.body.data.detections[0];
  assert(
    sampleFlow.models?.random_forest?.metric_type === 'PROBABILITY' &&
      sampleFlow.models?.isolation_forest?.metric_type === 'ANOMALY_SCORE' &&
      sampleFlow.models?.autoencoder?.metric_type === 'RECONSTRUCTION_ERROR_MSE' &&
      Boolean(sampleFlow.score_semantics?.random_forest_attack_probability) &&
      Boolean(sampleFlow.score_semantics?.isolation_forest_raw_decision_score) &&
      Boolean(sampleFlow.score_semantics?.autoencoder_reconstruction_error),
    'Flow detection payload explicitly distinguishes RF attack probability from IF anomaly score and AE MSE'
  );

  assert(
    Array.isArray(sampleFlow.models?.autoencoder?.top_contributing_features) &&
      sampleFlow.models.autoencoder.top_contributing_features.length === 5 &&
      typeof sampleFlow.models.autoencoder.top_contributing_features[0].feature_name === 'string' &&
      typeof sampleFlow.models.autoencoder.top_contributing_features[0].squared_error === 'number' &&
      typeof sampleFlow.models.autoencoder.top_contributing_features[0].error_share === 'number',
    'Each flow includes top-5 contributing Autoencoder features with squared error and error share'
  );

  assert(
    Array.isArray(sampleFlow.tri_model_decision?.models_agreeing_on_anomaly) &&
      typeof sampleFlow.tri_model_decision?.agreement_pattern === 'string' &&
      typeof sampleFlow.tri_model_decision?.decision_rule === 'string' &&
      typeof sampleFlow.tri_model_decision?.recommended_action === 'string',
    'Each flow displays model agreement/disagreement pattern, decision rule, and recommended action'
  );

  // Individual Flow Dossier inspection
  const dossierRes = await dispatchExpressRequest(
    'GET',
    `/api/v2/soc/ml/detections/${sampleFlow.flow_id}`,
    { headers: viewerAuth }
  );
  assert(
    dossierRes.statusCode === 200 &&
      dossierRes.body.data?.flow?.flow_id === sampleFlow.flow_id &&
      dossierRes.body.data?.explainability_summary?.distinction_note.includes('probability') &&
      dossierRes.body.data?.explainability_summary?.top_contributing_features?.length === 5,
    'GET /api/v2/soc/ml/detections/:flowId returns complete individual flow investigation dossier'
  );

  // ===========================================================================
  // 3. False-Positive, False-Negative & Feature-Collision Evaluation Views
  // ===========================================================================
  console.log('\n--- 3. FP, FN & Feature-Collision Evaluation Views (/api/v2/soc/ml/evaluation) ---');
  const evalRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/evaluation', {
    headers: viewerAuth
  });
  const evData = evalRes.body.data;
  assert(
    evalRes.statusCode === 200 &&
      evData.benchmark_classification === 'SYNTHETIC BENCHMARK ONLY' &&
      Array.isArray(evData.false_positives) &&
      evData.false_positives.length === 7 &&
      Array.isArray(evData.false_negatives) &&
      evData.false_negatives.length === 8 &&
      Array.isArray(evData.feature_collisions) &&
      evData.feature_collisions.length === 4,
    'Evaluation view returns exact 7 False Positives, 8 False Negatives, and 4 Cross-Label Feature Collisions'
  );

  // ===========================================================================
  // 4. Manual-Review Queue, Safety Guardrails & RBAC Enforcement
  // ===========================================================================
  console.log('\n--- 4. Manual-Review Queue, AE-Only Safety Lock & RBAC Enforcement ---');
  const mrevRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/manual-review', {
    headers: viewerAuth
  });
  const mrev = mrevRes.body.data;
  assert(
    mrevRes.statusCode === 200 &&
      mrev.ae_only_items_count === 4 &&
      mrev.total_queue_items === 8 &&
      mrev.queue.filter((x) => x.is_autoencoder_only).every((x) => x.auto_block_permitted === false),
    'Manual-review queue contains all 4 AE_ONLY anomalies with auto_block_permitted=false'
  );

  // RBAC Check 1: VIEWER cannot mutate manual-review queue
  const viewerMutateRes = await dispatchExpressRequest(
    'POST',
    '/api/v2/soc/ml/manual-review/flow-norm-00258/decision',
    {
      headers: viewerAuth,
      body: { decision: 'DISMISS_FALSE_POSITIVE', analyst_notes: 'Viewer attempt' }
    }
  );
  assert(
    viewerMutateRes.statusCode === 403,
    'RBAC blocks VIEWER (HTTP 403) from submitting manual-review decisions'
  );

  // RBAC Check 2: VIEWER cannot reload models or change degraded state
  const viewerReloadRes = await dispatchExpressRequest('POST', '/api/v2/soc/ml/reload', {
    headers: viewerAuth
  });
  assert(
    viewerReloadRes.statusCode === 403,
    'RBAC blocks VIEWER (HTTP 403) from triggering model reload'
  );

  // RBAC Check 3: SOC_ANALYST cannot trigger ADMIN-only model reload or degraded-mode simulation
  const analystReloadRes = await dispatchExpressRequest('POST', '/api/v2/soc/ml/reload', {
    headers: analystAuth
  });
  const analystDegRes = await dispatchExpressRequest('POST', '/api/v2/soc/ml/degraded-mode', {
    headers: analystAuth,
    body: { degraded_models: ['isolation_forest'] }
  });
  assert(
    analystReloadRes.statusCode === 403 && analystDegRes.statusCode === 403,
    'RBAC blocks SOC_ANALYST (HTTP 403) from ADMIN-only model reload and degraded-mode simulation'
  );

  // Safety Check: Even ADMIN / SOC_ANALYST cannot authorize an automatic IP block on an AE_ONLY anomaly
  const aeOnlyBlockAttempt = await dispatchExpressRequest(
    'POST',
    '/api/v2/soc/ml/manual-review/flow-norm-00258/decision',
    {
      headers: analystAuth,
      body: { decision: 'AUTO_BLOCK_IP', analyst_notes: 'Attempt auto-block on AE_ONLY flow' }
    }
  );
  assert(
    aeOnlyBlockAttempt.statusCode === 422 &&
      aeOnlyBlockAttempt.body.status === 'rejected_by_safety_policy' &&
      aeOnlyBlockAttempt.body.auto_block_executed === false,
    'Safety Lock rejects (HTTP 422) independent IP auto-blocking on Autoencoder-only anomaly flow-norm-00258'
  );

  // Valid Analyst Manual-Review Decisions (Dismiss FP & Escalate to Incident without auto-block)
  const dismissRes = await dispatchExpressRequest(
    'POST',
    '/api/v2/soc/ml/manual-review/flow-norm-00366/decision',
    {
      headers: analystAuth,
      body: { decision: 'DISMISS_FALSE_POSITIVE', analyst_notes: 'Confirmed benign HTTP burst' }
    }
  );
  assert(
    dismissRes.statusCode === 200 &&
      dismissRes.body.data?.item?.review_status === 'DISMISS_FALSE_POSITIVE' &&
      dismissRes.body.data?.auto_block_executed === false,
    'SOC_ANALYST can dismiss AE_ONLY false positive flow-norm-00366 with audit trail'
  );

  const escalateRes = await dispatchExpressRequest(
    'POST',
    '/api/v2/soc/ml/manual-review/flow-norm-00639/decision',
    {
      headers: analystAuth,
      body: { decision: 'ESCALATE_TO_INCIDENT', analyst_notes: 'Escalate for secondary correlation' }
    }
  );
  assert(
    escalateRes.statusCode === 200 &&
      escalateRes.body.data?.item?.review_status === 'ESCALATE_TO_INCIDENT' &&
      escalateRes.body.data?.auto_block_executed === false &&
      Boolean(escalateRes.body.data?.created_incident?.incident_id),
    'SOC_ANALYST can escalate AE_ONLY anomaly to non-blocking investigation incident'
  );

  // Verify immutable audit log recorded all 3 manual review events (1 rejected block + 2 valid decisions)
  const mrevAfterRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/manual-review', {
    headers: viewerAuth
  });
  assert(
    mrevAfterRes.body.data?.audit_log?.length >= 3 &&
      mrevAfterRes.body.data.audit_log.every((a) => a.auto_block_executed === false),
    'Manual-review audit trail records all analyst actions and rejected auto-block attempts with auto_block_executed=false'
  );

  // ===========================================================================
  // 5. Degraded-Mode Simulation & ADMIN Model Reload
  // ===========================================================================
  console.log('\n--- 5. Degraded-State Visibility, Fail-Safe Routing & ADMIN Model Reload ---');
  const partialDegRes = await dispatchExpressRequest('POST', '/api/v2/soc/ml/degraded-mode', {
    headers: adminAuth,
    body: { degraded_models: ['isolation_forest'], reason: 'if_artifact_missing_test' }
  });
  assert(
    partialDegRes.statusCode === 200 &&
      partialDegRes.body.data?.engine_status === 'partially_degraded' &&
      partialDegRes.body.data?.models_health?.isolation_forest?.status === 'degraded',
    'ADMIN can simulate partially_degraded state when Isolation Forest is unavailable'
  );

  const detPartialRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/detections?limit=20', {
    headers: viewerAuth
  });
  assert(
    detPartialRes.body.data?.engine_status === 'partially_degraded' &&
      detPartialRes.body.data.detections.every(
        (d) => d.tri_model_decision.auto_block_permitted === false && d.tri_model_decision.recommended_action !== 'block'
      ),
    'In partially_degraded state, all flow detections inhibit auto-blocking (auto_block_permitted=false)'
  );

  const fullDegRes = await dispatchExpressRequest('POST', '/api/v2/soc/ml/degraded-mode', {
    headers: adminAuth,
    body: {
      degraded_models: ['random_forest', 'isolation_forest', 'autoencoder'],
      reason: 'all_models_offline_test'
    }
  });
  const detFullRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/detections?limit=10', {
    headers: viewerAuth
  });
  assert(
    fullDegRes.body.data?.engine_status === 'degraded' &&
      detFullRes.body.data.detections.every(
        (d) =>
          d.tri_model_decision.final_decision === 'degraded' &&
          d.tri_model_decision.recommended_action === 'manual-review' &&
          d.tri_model_decision.auto_block_permitted === false
      ),
    'In full degraded state, all detections report final_decision=degraded and route to manual-review'
  );

  const reloadAdminRes = await dispatchExpressRequest('POST', '/api/v2/soc/ml/reload', {
    headers: adminAuth
  });
  assert(
    reloadAdminRes.statusCode === 200 &&
      reloadAdminRes.body.data?.status === 'reloaded' &&
      reloadAdminRes.body.data?.engine_status === 'healthy',
    'ADMIN model reload restores engine_status=healthy across all 3 models'
  );

  // ===========================================================================
  // 6. Research & Benchmark View (SYNTHETIC BENCHMARK ONLY)
  // ===========================================================================
  console.log('\n--- 6. Six-Model Synthetic Benchmark & Research View (/api/v2/soc/ml/research-benchmark) ---');
  const benchRes = await dispatchExpressRequest('GET', '/api/v2/soc/ml/research-benchmark', {
    headers: viewerAuth
  });
  const bench = benchRes.body.data;
  assert(
    benchRes.statusCode === 200 &&
      bench.benchmark_classification === 'SYNTHETIC BENCHMARK ONLY' &&
      bench.scientific_disclaimer.includes('SYNTHETIC BENCHMARK ONLY'),
    'Research benchmark endpoint explicitly labels all results SYNTHETIC BENCHMARK ONLY'
  );

  const modelsMap = {};
  for (const m of bench.models_comparison || []) {
    modelsMap[m.model_id] = m;
  }
  assert(
    Object.keys(modelsMap).length === 6 &&
      modelsMap.random_forest_69_v2?.accuracy_pct === 97.14 &&
      modelsMap.isolation_forest_69_v2?.accuracy_pct === 72.92 &&
      modelsMap.autoencoder_p97_frozen?.accuracy_pct === 76.3 &&
      modelsMap.unsupervised_ensemble_if_ae?.accuracy_pct === 82.29 &&
      modelsMap.majority_vote_2_of_3?.accuracy_pct === 83.33 &&
      modelsMap.weighted_consensus_tri_model?.accuracy_pct === 96.09,
    'All 6 required models/ensembles present with exact verified test_set accuracies (including 82.29% for IF+AE)'
  );

  assert(
    Boolean(bench.autoencoder_threshold_sweep?.P95) &&
      Boolean(bench.autoencoder_threshold_sweep?.P97) &&
      Boolean(bench.autoencoder_threshold_sweep?.P99) &&
      bench.feature_mathematics_audit?.duplicate_polynomial_columns_count === 13 &&
      bench.feature_mathematics_audit?.collinear_padding_columns_count === 14,
    'Research view includes P95/P97/P99 threshold sweep and 69-feature mathematical redundancy audit'
  );

  // ===========================================================================
  // 7. React Dashboard Frontend & Styles Verification
  // ===========================================================================
  console.log('\n--- 7. React Dashboard UI & CSS Verification (app.js & styles.css) ---');
  const rootDir = path.resolve(__dirname, '..');
  const appCode = fs.readFileSync(path.join(rootDir, 'threat-dashboard-service/public/app.js'), 'utf8');
  const cssCode = fs.readFileSync(path.join(rootDir, 'threat-dashboard-service/public/styles.css'), 'utf8');

  assert(
    appCode.includes("id: 'tri_model'") && appCode.includes("id: 'ml_benchmark'"),
    "React dashboard app.js includes 'tri_model' and 'ml_benchmark' navigation modules"
  );
  assert(
    appCode.includes('Metric Semantics Distinction (Probabilities vs. Anomaly Scores)') &&
      appCode.includes('AUTO-BLOCK FORBIDDEN') &&
      appCode.includes('SYNTHETIC BENCHMARK ONLY') &&
      appCode.includes('Explainable Tri-Model Flow Investigation Dossier'),
    'React dashboard app.js renders score-vs-probability distinction, AE-only safety lock, flow dossier modal, and SYNTHETIC BENCHMARK ONLY banner'
  );
  assert(
    cssCode.includes('.soc-degraded-banner') && cssCode.includes('.soc-module-nav'),
    'styles.css includes degraded-state fail-safe banner and SOC module navigation styling'
  );

  console.log('\n================================================================================');
  console.log(` AUTOENCODER STAGE 4 VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================================');

  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal error in Autoencoder Stage 4 verification:', err);
  process.exit(1);
});
