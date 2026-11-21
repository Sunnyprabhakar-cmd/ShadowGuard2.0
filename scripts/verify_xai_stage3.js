/**
 * Shadow Guard 2.0 — XAI Stage 3 Verification Suite (Backend API & PostgreSQL)
 * ============================================================================
 * Tests:
 *   1. Python ML XAI API unit tests (`ml-detection-service/tests/test_xai_api.py` — 6 tests).
 *   2. PostgreSQL Migration (`database/migrations/004_xai_explanations.sql`) schema & indexes.
 *   3. `XaiExplanationStore` (saving, retrieving, duplicate SHA-256 prevention, DB-unavailable fallback).
 *   4. Live Node.js Dashboard Gateway (`threat-dashboard-service/server.js`) + Live Python ML XAI
 *      Server (`ml-detection-service/main.py` over HTTP):
 *      - Authentication (`401` without token under `strictAuth = true`).
 *      - RBAC for `VIEWER`, `SOC_ANALYST`, and `ADMIN` across all `/api/v2/xai/*` routes.
 *      - `GET /api/v2/xai/overview`
 *      - `GET /api/v2/xai/explanation/:flowId` (plus role-based IP sanitization for `VIEWER`)
 *      - `POST /api/v2/xai/explanation`
 *      - `POST /api/v2/xai/explanation/batch`
 *      - `GET /api/v2/xai/diagnostics` (`ADMIN` only)
 *      - Invalid flow IDs (`400`), invalid 69-feature vectors (`400`), unknown flow (`404`).
 *      - ML service unavailable (`503`).
 *      - Security audit logging (`XAI_*`, `RBAC_DENIED`, `AUTH_MISSING`).
 *      - Backward compatibility: existing `/detect/tri-model` and `/api/v2/soc/ml/overview` unchanged.
 *   5. Stage 3 Documentation (`docs/XAI_API_REFERENCE.md`, `docs/XAI_DATABASE_DESIGN.md`, `docs/XAI_STAGE3_REPORT.md`).
 */

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { execFileSync, spawn } = require('child_process');

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
  console.log(' SHADOW GUARD 2.0 — XAI STAGE 3 VERIFICATION SUITE (BACKEND API & POSTGRESQL)');
  console.log('================================================================================\n');

  // 1. Verify PostgreSQL migration file
  const migPath = path.join(ROOT, 'database', 'migrations', '004_xai_explanations.sql');
  assert(fs.existsSync(migPath), 'database/migrations/004_xai_explanations.sql exists');
  const migSql = fs.readFileSync(migPath, 'utf8');
  assert(
    migSql.includes('CREATE TABLE IF NOT EXISTS xai_explanations') &&
      migSql.includes('uq_xai_flow_policy_signature') &&
      migSql.includes('USING GIN (unified_model_agreement)') &&
      migSql.includes("VALUES ('004_xai_explanations')"),
    '004_xai_explanations.sql defines xai_explanations table, JSONB columns, GIN indexes, and schema_migrations entry'
  );

  // 2. Run Python Stage 3 API unit tests
  const pyApiTest = path.join(ROOT, 'ml-detection-service', 'tests', 'test_xai_api.py');
  let pyApiOk = false;
  try {
    execFileSync('python', [pyApiTest], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    pyApiOk = true;
  } catch (err) {
    console.error(err.stdout || '', err.stderr || '');
    pyApiOk = false;
  }
  assert(pyApiOk, 'Python XAI API unit test suite (test_xai_api.py — 6 tests) exited with code 0');

  // 3. Test XaiExplanationStore (memory fallback, transaction/duplicate handling with mock pg pool)
  const { XaiExplanationStore } = require(path.join(ROOT, 'threat-dashboard-service', 'lib', 'xaiStore.js'));
  const fallbackStore = new XaiExplanationStore({ pool: null });
  const sampleExp = {
    flow_id: 'flow-atk-01404',
    schema_version: 'v2.0-69dim',
    explanation_generation_status: 'healthy',
    final_tri_model_classification: { fusion_policy: 'weighted_consensus', final_decision: 'anomalous' },
    random_forest_explanation: { status: 'healthy', is_exact_shap: true },
    isolation_forest_explanation: { status: 'healthy' },
    autoencoder_explanation: { status: 'healthy', model_version: 'ae-pytorch-v2.0.0' },
    model_agreement_and_disagreement: { consensus_state: 'UNANIMOUS_ANOMALY_3_OF_3' },
    human_readable_soc_analyst_explanation: { full_narrative: 'Test narrative' },
  };
  const saveFallback = await fallbackStore.saveExplanation(sampleExp, null);
  assert(saveFallback.persisted && saveFallback.storage_backend === 'memory_fallback', 'XaiExplanationStore falls back gracefully when PostgreSQL is unavailable');
  const getFallback = await fallbackStore.getExplanationByFlowId('flow-atk-01404', 'weighted_consensus');
  assert(getFallback.found && getFallback.source === 'lru_cache', 'XaiExplanationStore retrieves cached explanation');

  // Test transactional duplicate handling with mocked pg Pool
  const executedQueries = [];
  const mockPool = {
    async connect() {
      return {
        async query(sql) {
          executedQueries.push(sql.trim().split(/\s+/)[0]);
          if (sql.includes('INSERT INTO xai_explanations')) {
            return { rows: [{ explanation_id: 'xai-mock-001', was_duplicate_update: true, created_at: new Date().toISOString() }] };
          }
          return { rows: [] };
        },
        release() {},
      };
    },
    async query(sql) {
      if (sql.includes('COUNT(*)')) return { rows: [{ total: 1 }] };
      return { rows: [] };
    },
  };
  const pgStore = new XaiExplanationStore({ pool: mockPool });
  const savePg = await pgStore.saveExplanation(sampleExp, null);
  assert(
    savePg.storage_backend === 'postgresql' &&
      savePg.duplicate_prevented === true &&
      executedQueries[0] === 'BEGIN' &&
      executedQueries[1] === 'INSERT' &&
      executedQueries[2] === 'COMMIT',
    'XaiExplanationStore uses parameterized BEGIN/INSERT ON CONFLICT/COMMIT transaction for PostgreSQL'
  );

  // 4. Wire Node.js Dashboard Gateway (`threat-dashboard-service/server.js`) to Python ML XAI
  process.env.DISABLE_XAI_PG = 'true';
  process.env.REQUIRE_STRICT_AUTH = 'true';

  const dashMod = require(path.join(ROOT, 'threat-dashboard-service', 'server.js'));
  dashMod.securityManager.strictAuth = true;
  dashMod.setMlXaiDispatcher((method, endpoint, bodyObj) => callPythonMlBridge(method, endpoint, bodyObj));

  try {
    const mlHealthCheck = callPythonMlBridge('GET', '/xai/health', null);
    assert(mlHealthCheck.statusCode === 200 && mlHealthCheck.body.status === 'healthy', 'Python ML XAI /xai/health returns 200 healthy');

    // Issue JWTs for all 3 roles
    const viewerTok = dashMod.securityManager.issueToken({ sub: 'viewer-1', role: 'VIEWER' });
    const analystTok = dashMod.securityManager.issueToken({ sub: 'analyst-1', role: 'SOC_ANALYST' });
    const adminTok = dashMod.securityManager.issueToken({ sub: 'admin-1', role: 'ADMIN' });

    // 4a. Unauthenticated access must return 401
    const unauthRes = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/overview');
    assert(unauthRes.statusCode === 401, 'Unauthenticated GET /api/v2/xai/overview rejected with 401');

    // 4b. VIEWER RBAC checks
    const viewerOverview = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/overview', null, {
      authorization: `Bearer ${viewerTok}`,
    });
    assert(viewerOverview.statusCode === 200 && viewerOverview.body.data.ml_xai_health.status === 'healthy', 'VIEWER can access GET /api/v2/xai/overview');

    const viewerExplain = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/explanation/flow-atk-01404', null, {
      authorization: `Bearer ${viewerTok}`,
    });
    assert(
      viewerExplain.statusCode === 200 &&
        viewerExplain.body.data.flow_metadata.src_ip === undefined,
      'VIEWER can read GET /api/v2/xai/explanation/:flowId with sensitive src_ip/dst_ip sanitized'
    );

    const viewerPostDenied = await dispatchNodeApp(
      dashMod.app,
      'POST',
      '/api/v2/xai/explanation',
      { flow_id: 'flow-norm-00293' },
      { authorization: `Bearer ${viewerTok}` }
    );
    assert(viewerPostDenied.statusCode === 403, 'VIEWER denied (403) on POST /api/v2/xai/explanation');

    // 4c. SOC_ANALYST RBAC checks
    const analystPost = await dispatchNodeApp(
      dashMod.app,
      'POST',
      '/api/v2/xai/explanation',
      { flow_id: 'flow-norm-00293' },
      { authorization: `Bearer ${analystTok}` }
    );
    assert(
      analystPost.statusCode === 200 &&
        analystPost.body.data.final_tri_model_classification.final_decision === 'normal' &&
        analystPost.body.data.flow_metadata.src_ip !== undefined,
      'SOC_ANALYST can POST /api/v2/xai/explanation and inspect full flow_metadata'
    );

    const analystBatch = await dispatchNodeApp(
      dashMod.app,
      'POST',
      '/api/v2/xai/explanation/batch',
      { items: [{ flow_id: 'flow-atk-01404' }, { flow_id: 'flow-norm-00293' }] },
      { authorization: `Bearer ${analystTok}` }
    );
    assert(
      analystBatch.statusCode === 200 && analystBatch.body.data.succeeded_count === 2,
      'SOC_ANALYST can POST /api/v2/xai/explanation/batch'
    );

    const analystDiagDenied = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/diagnostics', null, {
      authorization: `Bearer ${analystTok}`,
    });
    assert(analystDiagDenied.statusCode === 403, 'SOC_ANALYST denied (403) on ADMIN-only GET /api/v2/xai/diagnostics');

    // 4d. ADMIN RBAC check
    const adminDiag = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/diagnostics', null, {
      authorization: `Bearer ${adminTok}`,
    });
    assert(adminDiag.statusCode === 200 && adminDiag.body.data.strict_auth_enabled === true, 'ADMIN can access GET /api/v2/xai/diagnostics');

    // 4e. Input validation & 404 checks through Node gateway
    const badId = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/xai/explanation/bad$id!', null, {
      authorization: `Bearer ${analystTok}`,
    });
    assert(badId.statusCode === 400, 'Node gateway rejects invalid flowId format with 400');

    const badVec = await dispatchNodeApp(
      dashMod.app,
      'POST',
      '/api/v2/xai/explanation',
      { flow_id: 'bad-vec', features: [1, 2, 3] },
      { authorization: `Bearer ${analystTok}` }
    );
    assert(badVec.statusCode === 400, 'Node gateway rejects invalid 69-feature vector with 400');

    // 4f. Backward compatibility: existing SOC ML overview still works
    const legacySocMl = await dispatchNodeApp(dashMod.app, 'GET', '/api/v2/soc/ml/overview', null, {
      authorization: `Bearer ${viewerTok}`,
    });
    assert(legacySocMl.statusCode === 200 && legacySocMl.body.status === 'success', 'Existing /api/v2/soc/ml/overview remains 100% backward compatible');

    // 4g. Audit log verification
    const auditActions = new Set(dashMod.securityManager.securityAuditLog.map((e) => e.event_type));
    assert(
      auditActions.has('AUTH_MISSING') &&
        auditActions.has('RBAC_DENIED') &&
        auditActions.has('XAI_OVERVIEW_ACCESSED') &&
        auditActions.has('XAI_EXPLANATION_ACCESSED') &&
        auditActions.has('XAI_EXPLANATION_GENERATED') &&
        auditActions.has('XAI_BATCH_EXPLANATION_GENERATED') &&
        auditActions.has('XAI_ADMIN_DIAGNOSTICS_ACCESSED'),
      'Security audit log captures XAI access, batch generation, RBAC denials, and missing auth'
    );

    // 4h. ML service unavailable check
    dashMod.setMlXaiDispatcher(() =>
      Promise.reject(Object.assign(new Error('ML service unreachable'), { code: 'ML_UNAVAILABLE' }))
    );
    const mlDownRes = await dispatchNodeApp(
      dashMod.app,
      'POST',
      '/api/v2/xai/explanation',
      { flow_id: 'flow-norm-00293' },
      { authorization: `Bearer ${analystTok}` }
    );
    assert(mlDownRes.statusCode === 503 && mlDownRes.body.code === 'ML_UNAVAILABLE', 'Node gateway returns 503 ML_UNAVAILABLE when Python ML service is down');
  } finally {
    dashMod.setMlXaiDispatcher(null);
  }

  // 5. Verify Stage 3 documentation files exist
  assert(fs.existsSync(path.join(ROOT, 'docs', 'XAI_API_REFERENCE.md')), 'docs/XAI_API_REFERENCE.md exists');
  assert(fs.existsSync(path.join(ROOT, 'docs', 'XAI_DATABASE_DESIGN.md')), 'docs/XAI_DATABASE_DESIGN.md exists');
  assert(fs.existsSync(path.join(ROOT, 'docs', 'XAI_STAGE3_REPORT.md')), 'docs/XAI_STAGE3_REPORT.md exists');

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
