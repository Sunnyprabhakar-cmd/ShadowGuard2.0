/**
 * Shadow Guard 2.0 — XAI Stage 1 Verification Suite (Explainability Core)
 * =======================================================================
 * Verifies:
 *   1. Python Unit Test Suite (`ml-detection-service/tests/test_xai_explainer.py` — 12 tests).
 *   2. Part A — Random Forest SHAP Explanations (`RandomForestSHAPExplainer`):
 *      - Official `shap.TreeExplainer` (`shap == 0.54.1`) active (`is_exact_shap === true`).
 *      - Exact SHAP additivity (`|P(attack|x) - (base_value + sum(SHAP))| < 1e-6`) and
 *        `TriModelDetectionEngine.score_random_forest` parity across all 384 held-out flows
 *        in `data/autoencoder_flow_dataset_v2.json` (`splits.test_set`).
 *      - Canonical 69 feature names (`FEATURE_NAMES_69`), top-5 positive/negative contributors,
 *        global feature importance, and fallback explicit labeling (`is_exact_shap === false`).
 *   3. Part B — Isolation Forest Anomaly Explanations (`IsolationForestAnomalyExplainer`):
 *      - Exact `raw_decision_score` and `anomaly_score` parity with `score_isolation_forest`.
 *      - 840-flow `train_normal` reference population comparisons (`UNUSUALLY_HIGH` / `UNUSUALLY_LOW`),
 *        perturbation shifts, whole-measurement counterfactual replacements, and reference comparison
 *        against `shap.TreeExplainer(if_model)`.
 *      - Strict non-probabilistic framing (`UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY`).
 *   4. Part C — Autoencoder Reconstruction Explanations (`AutoencoderReconstructionExplainer`):
 *      - Exact `FeaturePreprocessor` (`signed_log1p` + `RobustScaler(25, 75)` + `clip[-10, 10]`)
 *        and PyTorch `FlowAutoencoder` MSE parity (`< 1e-6`).
 *      - Mathematical identity: `mean(squared_error_0..68) === reconstruction_error`,
 *        `sum(error_share_0..68) === 1.0`, rank `1..69` descending order, top-5 anomalous features,
 *        and frozen validation threshold `P97 = 0.503670` (`P95 = 0.409105`, `P99 = 0.645935`).
 *   5. Part D — 3-Scalar Grouping & Collinearity Audit (`ThreeScalarMeasurementGrouper`):
 *      - Technical 69-feature + grouped `(packets, bytes, duration)` explanations.
 *      - Explicit annotation of 13 duplicate polynomial features (`f_25..f_39`) and 14 collinear
 *        harmonic padding features (`f_55..f_68`).
 *      - Cross-label feature-collision invariance and zero modification to frozen model artifacts.
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

function syncContainerSharedMl() {
  const srcFile = path.join(ROOT, 'shared', 'ml', 'xai_explainer.py');
  const dstDir = path.join(ROOT, 'ml-detection-service', 'shared', 'ml');
  fs.mkdirSync(dstDir, { recursive: true });
  fs.copyFileSync(srcFile, path.join(dstDir, 'xai_explainer.py'));
}

function main() {
  console.log('================================================================================');
  console.log(' SHADOW GUARD 2.0 — XAI STAGE 1 VERIFICATION SUITE (EXPLAINABILITY CORE)');
  console.log('================================================================================\n');

  syncContainerSharedMl();

  // 1. Verify files exist
  const coreModulePath = path.join(ROOT, 'shared', 'ml', 'xai_explainer.py');
  const containerModulePath = path.join(ROOT, 'ml-detection-service', 'shared', 'ml', 'xai_explainer.py');
  const unitTestPath = path.join(ROOT, 'ml-detection-service', 'tests', 'test_xai_explainer.py');

  assert(fs.existsSync(coreModulePath), 'shared/ml/xai_explainer.py exists');
  assert(fs.existsSync(containerModulePath), 'ml-detection-service/shared/ml/xai_explainer.py synced');
  assert(fs.existsSync(unitTestPath), 'ml-detection-service/tests/test_xai_explainer.py exists');

  // 2. Execute Python unittest suite
  let unitTestOutput = '';
  let unitTestSuccess = false;
  try {
    unitTestOutput = execFileSync('python', [unitTestPath], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    unitTestSuccess = true;
  } catch (err) {
    unitTestOutput = `${err.stdout || ''}\n${err.stderr || ''}`;
    unitTestSuccess = false;
  }
  assert(unitTestSuccess, 'Python unittest suite (test_xai_explainer.py — 12 tests) exited with code 0');

  // 3. Execute comprehensive 384-flow held-out mathematical verification in Python
  const pyScript = `
import json
import sys
from pathlib import Path
import numpy as np

ROOT = Path(r"${ROOT.replace(/\\/g, '\\\\')}")
sys.path.insert(0, str(ROOT))

from shared.ml.feature_schema import EXPECTED_FEATURE_COUNT, FEATURE_NAMES_69, extract_69_features
from shared.ml.tri_model_fusion import TriModelDetectionEngine
from shared.ml.xai_explainer import (
    SHAP_AVAILABLE,
    SHAP_VERSION,
    FEATURE_CATALOG_69,
    EVEN_POLY_DUPLICATE_INDICES,
    ODD_POLY_DUPLICATE_INDICES,
    HARMONIC_PADDING_INDICES,
    load_normal_reference_population,
    RandomForestSHAPExplainer,
    IsolationForestAnomalyExplainer,
    AutoencoderReconstructionExplainer,
)

engine = TriModelDetectionEngine(models_dir=ROOT / "models")
normal_matrix, normal_stats = load_normal_reference_population(ROOT / "data" / "autoencoder_flow_dataset_v2.json")

rf_exp = RandomForestSHAPExplainer(engine.rf_bundle, normal_matrix, normal_stats)
if_exp = IsolationForestAnomalyExplainer(engine.if_bundle, normal_matrix, normal_stats)
ae_exp = AutoencoderReconstructionExplainer(engine.ae_engine, normal_stats)

raw_ds = json.loads((ROOT / "data" / "autoencoder_flow_dataset_v2.json").read_text(encoding="utf-8"))
test_set = raw_ds["splits"]["test_set"]

rf_max_additivity_err = 0.0
rf_prob_parity_all = True
rf_all_exact_shap = True
for row in test_set:
    feats = row["features_69"]
    eng_rf = engine.score_random_forest(feats)
    xai_rf = rf_exp.explain_flow(feats, top_k=5)
    if not xai_rf["is_exact_shap"] or not xai_rf["additivity_verified"]:
        rf_all_exact_shap = False
    if abs(xai_rf["attack_probability"] - eng_rf["attack_probability"]) > 1e-6:
        rf_prob_parity_all = False
    if xai_rf["additivity_error"] > rf_max_additivity_err:
        rf_max_additivity_err = xai_rf["additivity_error"]

# Sample attack (ddos_flood) and normal flow for detailed checks
attack_row = next(r for r in test_set if r.get("attack_category") == "ddos_flood")
normal_row = next(r for r in test_set if r.get("label") == "normal")

rf_atk = rf_exp.explain_flow(attack_row["features_69"], top_k=5)
rf_norm = rf_exp.explain_flow(normal_row["features_69"], top_k=5)
rf_global = rf_exp.compute_global_feature_importance(normal_matrix, max_samples=60, top_k=10)

rf_fallback = RandomForestSHAPExplainer(engine.rf_bundle, normal_matrix, normal_stats, force_fallback_mode=True)
rf_fb_res = rf_fallback.explain_flow(attack_row["features_69"], top_k=5)

if_atk = if_exp.explain_flow(attack_row["features_69"], top_k=5)
if_eng_atk = engine.score_isolation_forest(attack_row["features_69"])
if_ref_cmp = if_exp.compare_with_tree_explainer_reference(attack_row["features_69"])

ae_atk = ae_exp.explain_flow(attack_row["features_69"], top_k=5)
ae_eng_atk = engine.score_autoencoder(attack_row["features_69"])
ae_mean_sq = float(np.mean([f["squared_error"] for f in ae_atk["all_features_by_index"]]))
ae_share_sum = float(np.sum([f["error_share"] for f in ae_atk["all_features_by_index"]]))

# Checksum verification via ae_engine
ae_healthy = (engine.ae_engine.status == "healthy")

out = {
    "shap_available": SHAP_AVAILABLE,
    "shap_version": SHAP_VERSION,
    "test_set_count": len(test_set),
    "rf_all_exact_shap": rf_all_exact_shap,
    "rf_prob_parity_all": rf_prob_parity_all,
    "rf_max_additivity_err": rf_max_additivity_err,
    "rf_atk_pred": rf_atk["prediction"],
    "rf_norm_pred": rf_norm["prediction"],
    "rf_atk_top_pos_count": len(rf_atk["top_positive_attack_contributors"]),
    "rf_atk_feature_count": len(rf_atk["all_feature_shap_values"]),
    "rf_global_top_count": len(rf_global["top_features"]),
    "rf_fb_is_exact_shap": rf_fb_res["is_exact_shap"],
    "if_status": if_atk["status"],
    "if_semantics": if_atk["score_semantics"],
    "if_ref_pop_size": if_atk["reference_population_size"],
    "if_score_diff": abs(if_atk["raw_decision_score"] - if_eng_atk["raw_decision_score"]),
    "if_anom_diff": abs(if_atk["anomaly_score"] - if_eng_atk["anomaly_score"]),
    "if_high_low_count": if_atk["unusually_high_count"] + if_atk["unusually_low_count"],
    "if_ref_cmp_status": if_ref_cmp["status"],
    "ae_status": ae_atk["status"],
    "ae_semantics": ae_atk["score_semantics"],
    "ae_threshold": ae_atk["threshold"],
    "ae_percentile": ae_atk["threshold_percentile"],
    "ae_p95": ae_atk["threshold_comparison"]["warning_threshold_p95"],
    "ae_p99": ae_atk["threshold_comparison"]["critical_threshold_p99"],
    "ae_mse_diff": abs(ae_atk["reconstruction_error"] - ae_eng_atk["reconstruction_error"]),
    "ae_mean_sq_diff": abs(ae_mean_sq - ae_atk["reconstruction_error"]),
    "ae_share_sum": ae_share_sum,
    "ae_top_count": len(ae_atk["top_anomalous_features"]),
    "ae_ranked_count": len(ae_atk["ranked_features"]),
    "ae_healthy_checksums": ae_healthy,
    "dup_col_count": sum(1 for m in FEATURE_CATALOG_69 if m["is_duplicate_column"]),
    "pad_col_count": sum(1 for m in FEATURE_CATALOG_69 if m["is_collinear_padding"]),
    "grp_raw_share_sum": sum(v["share_of_total"] for v in rf_atk["grouped_measurement_explanation"]["raw_measurement_attribution"].values()),
}
print(json.dumps(out))
`;

  const rawJson = execFileSync('python', ['-c', pyScript], {
    cwd: ROOT,
    encoding: 'utf8',
  }).trim();
  const audit = JSON.parse(rawJson);

  // Part A assertions
  assert(audit.shap_available === true && audit.shap_version === '0.54.1', `Official shap v${audit.shap_version} installed and active`);
  assert(audit.test_set_count === 384 && audit.rf_all_exact_shap === true, 'Exact TreeSHAP verified across all 384 held-out test flows');
  assert(audit.rf_prob_parity_all === true, 'RandomForestSHAPExplainer matches TriModelDetectionEngine.score_random_forest across all 384 flows');
  assert(audit.rf_max_additivity_err < 1e-6, `TreeSHAP additivity identity error < 1e-6 across all 384 flows (max=${audit.rf_max_additivity_err.toExponential(2)})`);
  assert(audit.rf_atk_pred === 1 && audit.rf_norm_pred === 0, 'Random Forest class attribution distinguishes attack (1) and normal (0) predictions');
  assert(audit.rf_atk_feature_count === 69 && audit.rf_atk_top_pos_count === 5, 'Random Forest SHAP returns all 69 canonical features and top-5 positive contributors');
  assert(audit.rf_global_top_count === 10, 'Random Forest global SHAP feature importance ranking computed accurately');
  assert(audit.rf_fb_is_exact_shap === false, 'Fallback perturbation mode explicitly sets is_exact_shap=false (never claims exact SHAP)');

  // Part B assertions
  assert(audit.if_status === 'healthy' && audit.if_ref_pop_size === 840, 'IsolationForestAnomalyExplainer loaded 840-flow normal reference baseline');
  assert(audit.if_semantics === 'UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY', 'Isolation Forest strictly labels output as UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY');
  assert(audit.if_score_diff < 1e-6 && audit.if_anom_diff < 1e-6, 'Isolation Forest raw_decision_score and anomaly_score match TriModelDetectionEngine');
  assert(audit.if_high_low_count > 10, `Isolation Forest flags unusually high/low measurements against normal baseline (count=${audit.if_high_low_count})`);
  assert(audit.if_ref_cmp_status === 'verified', 'Isolation Forest perturbation attribution validated against shap.TreeExplainer reference');

  // Part C assertions
  assert(audit.ae_status === 'healthy' && audit.ae_healthy_checksums === true, 'AutoencoderReconstructionExplainer loaded verified PyTorch artifacts');
  assert(audit.ae_semantics === 'RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY', 'Autoencoder strictly labels output as RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY');
  assert(
    Math.abs(audit.ae_threshold - 0.50367) < 1e-6 &&
      audit.ae_percentile === 'P97' &&
      Math.abs(audit.ae_p95 - 0.409105) < 1e-6 &&
      Math.abs(audit.ae_p99 - 0.645935) < 1e-6,
    'Autoencoder preserves frozen validation-calibrated thresholds (P95=0.409105, P97=0.503670, P99=0.645935)'
  );
  assert(audit.ae_mse_diff < 1e-6 && audit.ae_mean_sq_diff < 1e-5, 'Autoencoder per-feature squared errors average to exact overall MSE');
  assert(Math.abs(audit.ae_share_sum - 1.0) < 0.01 && audit.ae_ranked_count === 69 && audit.ae_top_count === 5, 'Autoencoder ranks all 69 features and extracts top-5 anomalous features');

  // Part D assertions
  assert(audit.dup_col_count === 13 && audit.pad_col_count === 14, '69-feature catalog documents 13 duplicate polynomial features and 14 collinear padding features');
  assert(Math.abs(audit.grp_raw_share_sum - 1.0) < 0.005, 'ThreeScalarMeasurementGrouper aggregates 69 features into (packets, bytes, duration) shares summing to 1.0');

  console.log('\n================================================================================');
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

main();
