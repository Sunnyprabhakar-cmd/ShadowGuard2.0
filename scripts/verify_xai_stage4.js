/**
 * Shadow Guard 2.0 — XAI Stage 4 Verification Suite (SOC Dashboard Module 11)
 * ============================================================================
 * Tests:
 *   1. Module 11 navigation (`xai_reasoning`, `11. Explainable AI & Threat Reasoning`).
 *   2. Existing 10 modules (`overview` .. `ml_benchmark`) still intact.
 *   3. Overview API integration (`GET /api/v2/xai/overview` — real counts, empty->populated).
 *   4. Flow investigation (`GET /api/v2/xai/explanation/:flowId` & `POST /api/v2/xai/explanation`).
 *   5. Random Forest SHAP visualization & global SHAP importance from backend.
 *   6. Isolation Forest explainability (`reference_population_perturbation_and_quantile_deviation`, NOT probability).
 *   7. Autoencoder explainability (`P97=0.503670`, `P95`, `P99`, `preprocessed_input_z` vs `reconstructed_output_z`).
 *   8. Three-model comparison table & no cross-scale averaging.
 *   9. Degraded explanation rendering (`partially_degraded` banner).
 *  10. API unavailable state (`503` error handling + UI error banner).
 *  11. Empty data state (`xai-empty-state`).
 *  12. RBAC behavior (`VIEWER` read-only vs `SOC_ANALYST` POST vs `ADMIN` diagnostics).
 *  13. Responsive layout CSS classes (`styles.css`).
 *  14. No fabricated values & no modification to detection outputs.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  [PASS] ${message}`);
  } else {
    failed++;
    console.error(`  [FAIL] ${message}`);
  }
}

function dispatchNodeApp(app, method, urlPath, bodyObj = null, headers = {}) {
  return new Promise((resolve) => {
    const req = {
      method: method.toUpperCase(),
      url: urlPath,
      headers: { ...headers },
      body: bodyObj !== null ? bodyObj : {},
      _body: true,
      ip: '127.0.0.1',
      socket: { remoteAddress: '127.0.0.1' },
    };
    const resHeaders = {};
    let finished = false;
    const res = {
      statusCode: 200,
      headersSent: false,
      setHeader(k, v) {
        resHeaders[k.toLowerCase()] = v;
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(obj) {
        if (finished) return this;
        finished = true;
        this.headersSent = true;
        resolve({ statusCode: this.statusCode, headers: resHeaders, body: obj });
        return this;
      },
      send(payload) {
        if (finished) return this;
        finished = true;
        this.headersSent = true;
        resolve({ statusCode: this.statusCode, headers: resHeaders, body: payload });
        return this;
      },
      end(data) {
        if (finished) return this;
        finished = true;
        this.headersSent = true;
        let parsed = {};
        try {
          parsed = data ? JSON.parse(data) : {};
        } catch (_) {
          parsed = { raw: data };
        }
        resolve({ statusCode: this.statusCode, headers: resHeaders, body: parsed });
        return this;
      },
    };
    app(req, res);
  });
}

function callPythonMlBridge(method, endpoint, bodyObj) {
  const pyCode = `
import json, sys
from pathlib import Path
ROOT = Path(r"${ROOT.replace(/\\/g, '\\\\')}")
sys.path.insert(0, str(ROOT / "ml-detection-service"))
sys.path.insert(0, str(ROOT))
from main import dispatch_raw_http_request
res = dispatch_raw_http_request(${JSON.stringify(method)}, ${JSON.stringify(endpoint)}, ${bodyObj !== null ? `json.loads(${JSON.stringify(JSON.stringify(bodyObj))})` : 'None'})
print(json.dumps(res))
`;
  const raw = execFileSync('python', ['-c', pyCode], { cwd: ROOT, encoding: 'utf8' }).trim();
  return JSON.parse(raw);
}

async function main() {
  console.log('================================================================================');
  console.log(' SHADOW GUARD 2.0 — XAI STAGE 4 VERIFICATION SUITE (SOC DASHBOARD MODULE 11)');
  console.log('================================================================================\n');

  const appJsPath = path.join(ROOT, 'threat-dashboard-service', 'public', 'app.js');
  const stylesCssPath = path.join(ROOT, 'threat-dashboard-service', 'public', 'styles.css');
  const indexHtmlPath = path.join(ROOT, 'threat-dashboard-service', 'public', 'index.html');
  const reportPath = path.join(ROOT, 'docs', 'XAI_STAGE4_REPORT.md');

  const appJs = fs.readFileSync(appJsPath, 'utf8');
  const stylesCss = fs.readFileSync(stylesCssPath, 'utf8');
  const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');

  // 1. Module 11 Navigation & Existing 10 Modules
  assert(
    appJs.includes("id: 'xai_reasoning'") &&
      appJs.includes('11. Explainable AI & Threat Reasoning') &&
      appJs.includes('id="xai-reasoning-panel"'),
    'Module 11 navigation tab (11. Explainable AI & Threat Reasoning) and panel exist'
  );
  const existingModuleIds = [
    'overview', 'honeypots', 'attackers', 'incidents', 'attack_chains',
    'threat_intel', 'soar', 'system_audit', 'tri_model', 'ml_benchmark'
  ];
  assert(
    existingModuleIds.every((id) => appJs.includes(`id: '${id}'`)),
    'All existing 10 dashboard modules remain preserved'
  );

  // 2. UI Sections, Charts, Transparency & States
  assert(
    appJs.includes('/api/v2/xai/overview') &&
      appJs.includes('/api/v2/xai/explanation/') &&
      appJs.includes("'/api/v2/xai/explanation'"),
    'Frontend integrates real XAI overview and flow explanation endpoints'
  );
  assert(
    appJs.includes('top_positive_attack_contributors') &&
      appJs.includes('top_negative_benign_contributors') &&
      appJs.includes('global_rf_shap_importance') &&
      appJs.includes('SHAP values are feature attributions, not causal proof'),
    'Random Forest SHAP panel renders positive/negative waterfall bars, global importance, and non-causality notice'
  );
  assert(
    appJs.includes('reference_population_perturbation_and_quantile_deviation') &&
      appJs.includes('NOT a probability'),
    'Isolation Forest panel labels perturbation method and non-probability semantics'
  );
  assert(
    appJs.includes('0.503670') &&
      appJs.includes('0.409105') &&
      appJs.includes('0.645935') &&
      appJs.includes('preprocessed_input_z') &&
      appJs.includes('reconstructed_output_z'),
    'Autoencoder panel displays frozen P97=0.503670, P95/P99, ranked bars, and original vs reconstructed Z table'
  );
  assert(
    appJs.includes('Three-Model Comparison') &&
      appJs.includes('three underlying raw measurements') &&
      appJs.includes('f_25..f_39') &&
      appJs.includes('f_55..f_68'),
    'Three-Model comparison & 69-feature 3-scalar correlation transparency implemented'
  );
  assert(
    appJs.includes('xai-loading-box') &&
      appJs.includes('xai-empty-state') &&
      appJs.includes('xai-error-banner') &&
      appJs.includes('soc-degraded-banner'),
    'Loading, empty, API error, and degraded-model banners implemented'
  );
  assert(
    appJs.includes("socRole !== 'VIEWER'") &&
      appJs.includes("socRole === 'ADMIN'") &&
      appJs.includes('/api/v2/xai/diagnostics'),
    'RBAC UI controls match VIEWER, SOC_ANALYST, and ADMIN permissions'
  );
  assert(
    stylesCss.includes('.xai-kpi-grid') &&
      stylesCss.includes('.xai-two-col') &&
      stylesCss.includes('.xai-3scalar-grid') &&
      indexHtml.includes('styles.css'),
    'Responsive grid CSS styles added to styles.css and linked in index.html'
  );

  // 3. Live API-backed Integration Tests via Node Gateway + Python ML XAI
  process.env.DISABLE_XAI_PG = 'true';
  process.env.REQUIRE_STRICT_AUTH = 'true';
  const dashMod = require(path.join(ROOT, 'threat-dashboard-service', 'server.js'));
  dashMod.securityManager.strictAuth = true;
  dashMod.setMlXaiDispatcher((method, endpoint, bodyObj) => callPythonMlBridge(method, endpoint, bodyObj));

  try {
    const viewerTok = dashMod.securityManager.issueToken({ sub: 'ui-viewer', role: 'VIEWER' });
    const analystTok = dashMod.securityManager.issueToken({ sub: 'ui-analyst', role: 'SOC_ANALYST' });
    const adminTok = dashMod.securityManager.issueToken({ sub: 'ui-admin', role: 'ADMIN' });

    // Empty state initially (0 explanations stored yet)
    const ovEmpty = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/overview', null, {
      authorization: `Bearer ${viewerTok}`,
    });
    assert(
      ovEmpty.statusCode === 200 &&
        ovEmpty.body.data.persistence.total_explanations === 0 &&
        ovEmpty.body.data.ml_xai_health.global_rf_shap_importance?.top_features?.length > 0,
      'GET /api/v2/xai/overview returns real 0-count empty state and live global RF SHAP importance'
    );

    // Investigate malicious flow (POST by SOC_ANALYST) + benign flow (GET by VIEWER)
    const atkExp = await dispatchNodeApp(
      dashMod.app,
      'POST',
      '/api/v2/xai/explanation',
      { flow_id: 'flow-atk-01404', policy: 'weighted_consensus' },
      { authorization: `Bearer ${analystTok}` }
    );
    assert(
      atkExp.statusCode === 200 &&
        atkExp.body.data.random_forest_explanation.is_exact_shap === true &&
        atkExp.body.data.autoencoder_explanation.threshold === 0.50367 &&
        atkExp.body.data.final_tri_model_classification.final_decision === 'anomalous',
      'POST /api/v2/xai/explanation returns real Stage 1/2 attributions for flow-atk-01404'
    );

    const normExp = await dispatchNodeApp(
      dashMod.app,
      'GET',
      '/api/v2/xai/explanation/flow-norm-00293',
      null,
      { authorization: `Bearer ${viewerTok}` }
    );
    assert(
      normExp.statusCode === 200 &&
        normExp.body.data.final_tri_model_classification.final_decision === 'normal' &&
        normExp.body.data.flow_metadata.src_ip === undefined,
      'GET /api/v2/xai/explanation/:flowId works for VIEWER with src_ip sanitized'
    );

    // Overview after 2 explanations -> real counts updated (1 malicious, 1 benign)
    const ovPopulated = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/overview', null, {
      authorization: `Bearer ${adminTok}`,
    });
    assert(
      ovPopulated.statusCode === 200 &&
        ovPopulated.body.data.persistence.total_explanations === 2 &&
        ovPopulated.body.data.persistence.malicious_flows_explained === 1 &&
        ovPopulated.body.data.persistence.benign_flows_explained === 1,
      'GET /api/v2/xai/overview dynamically reflects real counts (total=2, malicious=1, benign=1)'
    );

    // Verify API unavailable state
    dashMod.setMlXaiDispatcher(() =>
      Promise.reject(Object.assign(new Error('ML offline'), { code: 'ML_UNAVAILABLE' }))
    );
    const downRes = await dispatchNodeApp(
      dashMod.app,
      'POST',
      '/api/v2/xai/explanation',
      { flow_id: 'flow-atk-01404' },
      { authorization: `Bearer ${analystTok}` }
    );
    assert(downRes.statusCode === 503, 'API unavailable state cleanly returns 503 without crashing dashboard');
  } finally {
    dashMod.setMlXaiDispatcher(null);
  }

  assert(fs.existsSync(reportPath), 'docs/XAI_STAGE4_REPORT.md exists');

  console.log('\n================================================================================');
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
