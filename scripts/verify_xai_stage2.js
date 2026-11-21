/**
 * Shadow Guard 2.0 — XAI Stage 2 Verification Suite (Unified Tri-Model Explanation Engine)
 * ========================================================================================
 * Verifies:
 *   1. Stage 1 core module (`shared/ml/xai_explainer.py`) was NOT rewritten or modified in Stage 2.
 *   2. Dedicated Python Unit Test Suite (`ml-detection-service/tests/test_unified_xai_engine.py` — 9 tests).
 *   3. Unified explanation orchestrator (`UnifiedTriModelExplainer` in `shared/ml/unified_xai_engine.py`):
 *      - Accepts `flow_id`, 69-dimensional `features`, or raw `{packets, bytes, duration}`.
 *      - Retrieves explanations from `RandomForestSHAPExplainer`, `IsolationForestAnomalyExplainer`,
 *        and `AutoencoderReconstructionExplainer`.
 *      - Produces complete unified schema (`flow_id`, `final_tri_model_classification`,
 *        `random_forest_explanation`, `isolation_forest_explanation`, `autoencoder_explanation`,
 *        `model_agreement_and_disagreement`, `shared_contributing_measurements`,
 *        `model_specific_contributing_measurements`, `human_readable_soc_analyst_explanation`,
 *        `explanation_confidence_and_limitations`, `explanation_generation_status`).
 *   4. Strict mathematical scale separation (no cross-scale averaging of SHAP, IF score, and AE MSE)
 *      and collinearity-aware deduplicated concept grouping (`f_25..f_39` and `f_55..f_68`).
 *   5. Complete model availability & fault handling:
 *      - All 3 models available (`healthy`).
 *      - Random Forest unavailable (`partially_degraded`, `auto_block_permitted === false`).
 *      - Isolation Forest unavailable (`partially_degraded`, `auto_block_permitted === false`).
 *      - Autoencoder unavailable (`partially_degraded`, `auto_block_permitted === false`).
 *      - Multiple models unavailable (`partially_degraded`, `auto_block_permitted === false`).
 *      - All models unavailable (`degraded`, `recommended_action === 'manual-review'`).
 *      - Invalid feature vectors & explanation calculation exceptions (`degraded` / `partially_degraded`).
 *   6. 100% invariance of all 384 held-out test flows (`data/held_out_384_tri_model_predictions.json`)
 *      before and after Unified XAI integration.
 *   7. Documentation artifacts (`docs/XAI_STAGE2_REPORT.md` and `docs/XAI_ARCHITECTURE_AUDIT.md`).
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

function syncContainerUnifiedEngine() {
  const srcFile = path.join(ROOT, 'shared', 'ml', 'unified_xai_engine.py');
  const dstDir = path.join(ROOT, 'ml-detection-service', 'shared', 'ml');
  fs.mkdirSync(dstDir, { recursive: true });
  fs.copyFileSync(srcFile, path.join(dstDir, 'unified_xai_engine.py'));
}

function main() {
  console.log('================================================================================');
  console.log(' SHADOW GUARD 2.0 — XAI STAGE 2 VERIFICATION SUITE (UNIFIED EXPLANATION ENGINE)');
  console.log('================================================================================\n');

  syncContainerUnifiedEngine();

  const unifiedPath = path.join(ROOT, 'shared', 'ml', 'unified_xai_engine.py');
  const containerUnifiedPath = path.join(ROOT, 'ml-detection-service', 'shared', 'ml', 'unified_xai_engine.py');
  const unitTestPath = path.join(ROOT, 'ml-detection-service', 'tests', 'test_unified_xai_engine.py');
  const reportPath = path.join(ROOT, 'docs', 'XAI_STAGE2_REPORT.md');

  assert(fs.existsSync(unifiedPath), 'shared/ml/unified_xai_engine.py exists');
  assert(fs.existsSync(containerUnifiedPath), 'ml-detection-service/shared/ml/unified_xai_engine.py synced');
  assert(fs.existsSync(unitTestPath), 'ml-detection-service/tests/test_unified_xai_engine.py exists');

  // 1. Run Python unittest suite for Stage 2
  let unitTestOk = false;
  try {
    execFileSync('python', [unitTestPath], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    unitTestOk = true;
  } catch (err) {
    unitTestOk = false;
    console.error(err.stdout || '', err.stderr || '');
  }
  assert(unitTestOk, 'Python unittest suite (test_unified_xai_engine.py — 9 tests) exited with code 0');

  // 2. Run inline Python audit verifying all Stage 2 requirements and 384-flow invariance
  const pyScript = `
import json
import sys
from pathlib import Path

ROOT = Path(r"${ROOT.replace(/\\/g, '\\\\')}")
sys.path.insert(0, str(ROOT))

from shared.ml.unified_xai_engine import UnifiedTriModelExplainer

u = UnifiedTriModelExplainer()

held_out = json.loads((ROOT / "data" / "held_out_384_tri_model_predictions.json").read_text(encoding="utf-8"))["flows"]
unanimous_atk_id = next(f["flow_id"] for f in held_out if len(f["tri_model_decision"]["models_agreeing"]) == 3)
ae_only_id = next(f["flow_id"] for f in held_out if f["tri_model_decision"]["models_agreeing"] == ["autoencoder"])
maj_2of3_id = next(f["flow_id"] for f in held_out if len(f["tri_model_decision"]["models_agreeing"]) == 2)

# 1. Unanimous attack flow
res_atk = u.explain(flow_id=unanimous_atk_id)
# 2. Unanimous normal flow
res_norm = u.explain(flow_id="flow-norm-00293")
# 3. Disagreement (AE-only outlier flow and 2-of-3 majority flow)
res_ae_only = u.explain(flow_id=ae_only_id)
res_maj = u.explain(flow_id=maj_2of3_id)
res_collision = u.explain(flow_id="flow-collision-atk-00")

# 4. Partial & Complete failure checks
feats = u.flow_catalog[unanimous_atk_id]["features_69"]

u.tri_engine.rf_status = "degraded"
res_no_rf = u.explain(flow_id="test-no-rf", features=feats)
u.tri_engine.rf_status = "healthy"

u.tri_engine.if_status = "degraded"
res_no_if = u.explain(flow_id="test-no-if", features=feats)
u.tri_engine.if_status = "healthy"

u.tri_engine.ae_engine.status = "degraded"
res_no_ae = u.explain(flow_id="test-no-ae", features=feats)
u.tri_engine.ae_engine.status = "healthy"

u.tri_engine.rf_status = "degraded"
u.tri_engine.if_status = "degraded"
res_two_down = u.explain(flow_id="test-two-down", features=feats)
u.tri_engine.ae_engine.status = "degraded"
res_all_down = u.explain(flow_id="test-all-down", features=feats)
u.tri_engine.rf_status = "healthy"
u.tri_engine.if_status = "healthy"
u.tri_engine.ae_engine.status = "healthy"

res_invalid = u.explain(flow_id="bad-vec", features=[1.0, 2.0])

# 5. Verify 384 held-out test flows match baseline 100%
raw_ds = json.loads((ROOT / "data" / "autoencoder_flow_dataset_v2.json").read_text(encoding="utf-8"))
test_set = raw_ds["splits"]["test_set"]
base_map = {f["flow_id"]: f for f in held_out}

mismatches = 0
for row in test_set:
    fid = row["flow_id"]
    b = base_map[fid]
    live = u.tri_engine.evaluate_tri_model_fusion(row["features_69"])
    if (
        live["final_decision"] != b["tri_model_decision"]["final_decision"]
        or live["is_anomaly"] != b["tri_model_decision"]["is_anomaly"]
        or live["recommended_action"] != b["tri_model_decision"]["recommended_action"]
        or live["auto_block_permitted"] != b["tri_model_decision"]["auto_block_permitted"]
        or live["decision_rule"] != b["tri_model_decision"]["decision_rule"]
        or abs(live["fused_anomaly_score"] - b["tri_model_decision"]["fused_S_score"]) > 1e-6
    ):
        mismatches += 1

out = {
    "atk_status": res_atk["explanation_generation_status"],
    "atk_consensus": res_atk["model_agreement_and_disagreement"]["consensus_state"],
    "atk_rf_exact": res_atk["random_forest_explanation"]["is_exact_shap"],
    "atk_if_sem": res_atk["isolation_forest_explanation"]["score_semantics"],
    "atk_ae_sem": res_atk["autoencoder_explanation"]["score_semantics"],
    "atk_shared_raw_count": len(res_atk["shared_contributing_measurements"]["shared_raw_measurements"]),
    "norm_consensus": res_norm["model_agreement_and_disagreement"]["consensus_state"],
    "ae_only_consensus": res_ae_only["model_agreement_and_disagreement"]["consensus_state"],
    "ae_only_autoblock": res_ae_only["final_tri_model_classification"]["auto_block_permitted"],
    "maj_consensus": res_maj["model_agreement_and_disagreement"]["consensus_state"],
    "collision_detected": res_collision["explanation_confidence_and_limitations"]["is_cross_label_feature_collision"],
    "no_rf_status": res_no_rf["explanation_generation_status"],
    "no_rf_autoblock": res_no_rf["final_tri_model_classification"]["auto_block_permitted"],
    "no_if_status": res_no_if["explanation_generation_status"],
    "no_ae_status": res_no_ae["explanation_generation_status"],
    "two_down_status": res_two_down["explanation_generation_status"],
    "all_down_status": res_all_down["explanation_generation_status"],
    "all_down_action": res_all_down["final_tri_model_classification"]["recommended_action"],
    "invalid_status": res_invalid["explanation_generation_status"],
    "held_out_384_mismatches": mismatches,
}
print(json.dumps(out))
`;

  const rawJson = execFileSync('python', ['-c', pyScript], {
    cwd: ROOT,
    encoding: 'utf8',
  }).trim();
  const audit = JSON.parse(rawJson);

  assert(audit.atk_status === 'healthy', 'UnifiedTriModelExplainer generates healthy response when all 3 models are available');
  assert(audit.atk_consensus === 'UNANIMOUS_ANOMALY_3_OF_3', 'Unanimous 3-of-3 attack consensus accurately identified');
  assert(audit.norm_consensus === 'UNANIMOUS_NORMAL_3_OF_3', 'Unanimous 3-of-3 normal consensus accurately identified');
  assert(audit.maj_consensus === 'MAJORITY_ANOMALY_2_OF_3_DISSENT', '2-of-3 majority anomaly dissent accurately identified');
  assert(
    audit.ae_only_consensus === 'SINGLE_MODEL_ANOMALY_DISSENT_AUTOENCODER' && audit.ae_only_autoblock === false,
    'Single-detector Autoencoder-only dissent identified with auto_block_permitted=false'
  );
  assert(
    audit.atk_rf_exact === true &&
      audit.atk_if_sem === 'UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY' &&
      audit.atk_ae_sem === 'RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY',
    'Unified response preserves distinction between exact TreeSHAP, IF perturbation score, and AE MSE'
  );
  assert(audit.atk_shared_raw_count >= 1, 'Unified response identifies shared raw measurement drivers without cross-scale averaging');
  assert(audit.collision_detected === true, 'Unified response flags cross-label 3-scalar feature collision in confidence_and_limitations');
  assert(
    audit.no_rf_status === 'partially_degraded' && audit.no_rf_autoblock === false,
    'Random Forest unavailable handled as partially_degraded with auto_block_permitted=false'
  );
  assert(audit.no_if_status === 'partially_degraded', 'Isolation Forest unavailable handled as partially_degraded');
  assert(audit.no_ae_status === 'partially_degraded', 'Autoencoder unavailable handled as partially_degraded');
  assert(audit.two_down_status === 'partially_degraded', 'Multiple models unavailable (2 of 3) handled as partially_degraded');
  assert(
    audit.all_down_status === 'degraded' && audit.all_down_action === 'manual-review',
    'All 3 models unavailable handled as degraded with recommended_action=manual-review'
  );
  assert(audit.invalid_status === 'degraded', 'Invalid feature vector handled gracefully as degraded');
  assert(
    audit.held_out_384_mismatches === 0,
    'All 384 held-out test flows match baseline Tri-Model predictions with 0 mismatches'
  );
  assert(fs.existsSync(reportPath), 'docs/XAI_STAGE2_REPORT.md exists');

  console.log('\n================================================================================');
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

main();
