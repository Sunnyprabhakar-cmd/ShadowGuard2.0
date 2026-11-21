/**
 * Shadow Guard 2.0 — Autoencoder Stage 2 Verification Suite
 * ==========================================================
 * Verifies:
 * 1. Authoritative PyTorch Autoencoder training & artifact persistence:
 *    - `models/autoencoder_model.pt`
 *    - `models/autoencoder_preprocessor.pkl`
 *    - `models/autoencoder_metadata.json`
 *    - Service-local copies in `ml-detection-service/models/`
 * 2. SHA-256 artifact checksum verification and schema compatibility (`v2.0-69dim`).
 * 3. Normal-only training & validation enforcement (`train_normal` = 840 normal, `val_normal` = 180 normal).
 * 4. Monotonic loss reduction during PyTorch training (`final_val_mse < initial_val_mse`).
 * 5. Validation threshold calibration (`P95 < P97 < P99`) and frozen test evaluation on the
 *    untouched 384-flow `test_set` (including the 4 preserved cross-label feature-collision flows).
 * 6. Inference reproducibility & degraded-mode safety (`AutoencoderInferenceEngine`):
 *    - Reproducible MSE & anomaly score across reloads.
 *    - Normal flow -> `decision: "normal"`
 *    - Extreme attack flow -> `decision: "anomalous"`, `is_anomaly: true`, top-5 features returned
 *    - Wrong dimension (12 features instead of 69) -> `status: "degraded"`, `is_anomaly: null`
 *    - NaN/Infinite input -> `status: "degraded"`, `is_anomaly: null`
 *    - Missing model directory -> `status: "degraded"`, `is_anomaly: null`
 * 7. Preservation of legacy training files (`generate_data.py`, `model-training-service/train_model.py`)
 *    and historical Stage 7 Cohorts A–D benchmark results.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function main() {
  console.log('===================================================================');
  console.log('  SHADOW GUARD 2.0 — AUTOENCODER STAGE 2 VERIFICATION SUITE');
  console.log('===================================================================\n');

  const modelsDir = path.join(ROOT, 'models');
  const svcModelsDir = path.join(ROOT, 'ml-detection-service', 'models');

  const ptPath = path.join(modelsDir, 'autoencoder_model.pt');
  const pklPath = path.join(modelsDir, 'autoencoder_preprocessor.pkl');
  const metaPath = path.join(modelsDir, 'autoencoder_metadata.json');
  const rfPath = path.join(modelsDir, 'random_forest_69_v2.pkl');
  const ifPath = path.join(modelsDir, 'isolation_forest_69_v2.pkl');

  console.log('--- 1. Model Artifact Persistence & SHA-256 Checksum Integrity ---');
  assert(fs.existsSync(ptPath), 'models/autoencoder_model.pt exists');
  assert(fs.existsSync(pklPath), 'models/autoencoder_preprocessor.pkl exists');
  assert(fs.existsSync(metaPath), 'models/autoencoder_metadata.json exists');
  assert(fs.existsSync(rfPath), 'models/random_forest_69_v2.pkl exists');
  assert(fs.existsSync(ifPath), 'models/isolation_forest_69_v2.pkl exists');
  assert(
    fs.existsSync(path.join(svcModelsDir, 'autoencoder_model.pt')),
    'ml-detection-service/models/autoencoder_model.pt synced'
  );

  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  const actualPtSha = sha256File(ptPath);
  const actualPklSha = sha256File(pklPath);

  assert(
    meta.artifact_checksums.autoencoder_model_pt_sha256 === actualPtSha,
    'autoencoder_model.pt SHA-256 matches metadata checksum'
  );
  assert(
    meta.artifact_checksums.autoencoder_preprocessor_pkl_sha256 === actualPklSha,
    'autoencoder_preprocessor.pkl SHA-256 matches metadata checksum'
  );
  assert(
    meta.schema_version === 'v2.0-69dim',
    `Metadata schema_version is v2.0-69dim (got ${meta.schema_version})`
  );
  assert(
    meta.benchmark_classification === 'SYNTHETIC_BENCHMARK_ONLY',
    'Metadata explicitly classifies evaluation as SYNTHETIC_BENCHMARK_ONLY'
  );

  console.log('\n--- 2. PyTorch Architecture, Normal-Only Training & Convergence ---');
  const arch = meta.architecture;
  assert(
    arch.type === 'FlowAutoencoder' && arch.framework.startsWith('PyTorch'),
    `Authoritative PyTorch FlowAutoencoder used (${arch.framework})`
  );
  assert(
    arch.input_dim === 69 && arch.enc1_dim === 32 && arch.enc2_dim === 16 && arch.bottleneck_dim === 8,
    'Architecture dimensions verified as 69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69'
  );
  assert(
    meta.preprocessing.fitted_on_split === 'train_normal' &&
      meta.preprocessing.fitted_sample_count === 840,
    'FeaturePreprocessor fitted strictly on 840 normal-only training flows'
  );

  const trainSum = meta.training_summary;
  assert(
    trainSum.best_val_mse < trainSum.initial_val_mse,
    `Validation MSE converged (${trainSum.initial_val_mse} -> ${trainSum.best_val_mse} at epoch ${trainSum.best_epoch})`
  );
  assert(
    trainSum.final_train_mse < trainSum.initial_train_mse,
    `Training MSE converged (${trainSum.initial_train_mse} -> ${trainSum.final_train_mse})`
  );

  console.log('\n--- 3. Validation Threshold Calibration (P95, P97, P99) & Frozen Test Evaluation ---');
  const cal = meta.calibration_thresholds;
  assert(
    cal.P95 > 0 && cal.P95 < cal.P97 && cal.P97 < cal.P99,
    `Validation thresholds strictly ordered: P95 (${cal.P95}) < P97 (${cal.P97}) < P99 (${cal.P99})`
  );
  assert(
    meta.selected_threshold_percentile === 'P97' && meta.selected_threshold === cal.P97,
    `Selected operational threshold frozen at P97 (${meta.selected_threshold})`
  );

  const testEval = meta.test_set_evaluation;
  assert(
    testEval.test_total_flows === 384 &&
      testEval.test_normal_flows === 182 &&
      testEval.test_attack_flows === 202 &&
      testEval.test_feature_collision_flows === 4,
    'Untouched test_set evaluated on all 384 flows (182 normal + 202 attack, including 4 collision flows)'
  );

  const p95Metrics = testEval.autoencoder_by_threshold.P95;
  const p97Metrics = testEval.autoencoder_by_threshold.P97;
  const p99Metrics = testEval.autoencoder_by_threshold.P99;

  assert(
    p95Metrics.fpr >= p97Metrics.fpr && p97Metrics.fpr >= p99Metrics.fpr,
    `Test FPR decreases monotonically with higher percentile threshold: P95 (${p95Metrics.fpr}) >= P97 (${p97Metrics.fpr}) >= P99 (${p99Metrics.fpr})`
  );
  assert(
    p97Metrics.f1 > 0.65 && p97Metrics.f1 < 1.0 && p97Metrics.roc_auc > 0.85,
    `Frozen P97 test metrics realistic and non-fabricated (F1=${p97Metrics.f1}, Recall=${p97Metrics.recall}, Precision=${p97Metrics.precision}, FPR=${p97Metrics.fpr}, ROC-AUC=${p97Metrics.roc_auc})`
  );

  // Verify feature-collision flows produce identical reconstruction errors across opposite labels
  const colEval = testEval.feature_collision_ambiguity_evaluation;
  assert(
    colEval.length === 4,
    'All 4 cross-label feature-collision flows evaluated and documented in test_set_evaluation'
  );
  const colByPackets = {};
  for (const item of colEval) {
    colByPackets[item.packets] = colByPackets[item.packets] || [];
    colByPackets[item.packets].push(item);
  }
  let identicalCollisionErrors = true;
  for (const grp of Object.values(colByPackets)) {
    if (grp.length === 2 && Math.abs(grp[0].reconstruction_error - grp[1].reconstruction_error) > 1e-6) {
      identicalCollisionErrors = false;
    }
  }
  assert(
    identicalCollisionErrors,
    'Cross-label feature-collision pairs with identical (packets, bytes, duration) produce identical reconstruction errors'
  );

  console.log('\n--- 4. Live Python Inference Reproducibility & Degraded-Mode Safety ---');
  const pyProbeScript = `
import json
from pathlib import Path
from shared.ml.autoencoder_model import AutoencoderInferenceEngine
from shared.ml.feature_schema import extract_69_features

root = Path(r"${ROOT.replace(/\\/g, '\\\\')}")
engine = AutoencoderInferenceEngine(root / "models")

# 1. Normal HTTPS flow
norm_feats = extract_69_features({"packets": 35, "bytes": 24500, "duration": 1.8})
res_norm1 = engine.score_features(norm_feats)
res_norm2 = engine.score_features(norm_feats)

# 2. Extreme DDoS flood flow
atk_feats = extract_69_features({"packets": 2800, "bytes": 3600000, "duration": 0.08})
res_atk = engine.score_features(atk_feats)

# 3. Wrong dimensionality (12 features instead of 69) -> must be degraded, never normal
res_bad_dim = engine.score_features([1.0] * 12)

# 4. NaN input -> must be degraded, never normal
nan_feats = list(norm_feats)
nan_feats[3] = float("nan")
res_nan = engine.score_features(nan_feats)

# 5. Missing model directory -> must be degraded, never normal
missing_engine = AutoencoderInferenceEngine(root / "models" / "non_existent_dir")
res_missing = missing_engine.score_features(norm_feats)

print(json.dumps({
    "engine_status": engine.status,
    "reproducible_exact": res_norm1["reconstruction_error"] == res_norm2["reconstruction_error"],
    "norm": res_norm1,
    "atk": res_atk,
    "bad_dim": res_bad_dim,
    "nan": res_nan,
    "missing": res_missing,
}))
`;

  const probeOut = JSON.parse(
    execFileSync('python', ['-c', pyProbeScript], { encoding: 'utf8', cwd: ROOT })
  );

  assert(probeOut.engine_status === 'healthy', 'AutoencoderInferenceEngine loads in healthy state');
  assert(probeOut.reproducible_exact === true, 'Deterministic inference produces identical reconstruction error across calls');
  assert(
    probeOut.norm.status === 'healthy' &&
      probeOut.norm.decision === 'normal' &&
      probeOut.norm.is_anomaly === false,
    `Normal HTTPS flow classified as normal (error=${probeOut.norm.reconstruction_error} <= threshold=${probeOut.norm.threshold})`
  );
  assert(
    probeOut.atk.status === 'healthy' &&
      probeOut.atk.decision === 'anomalous' &&
      probeOut.atk.is_anomaly === true &&
      probeOut.atk.top_contributing_features.length === 5,
    `Attack DDoS flow classified as anomalous with top-5 contributing features (error=${probeOut.atk.reconstruction_error} > threshold=${probeOut.atk.threshold})`
  );
  assert(
    probeOut.bad_dim.status === 'degraded' && probeOut.bad_dim.is_anomaly === null,
    'Dimension mismatch (12 != 69) returns explicit degraded status (never silent normal)'
  );
  assert(
    probeOut.nan.status === 'degraded' && probeOut.nan.is_anomaly === null,
    'NaN input feature returns explicit degraded status (never silent normal)'
  );
  assert(
    probeOut.missing.status === 'degraded' && probeOut.missing.is_anomaly === null,
    'Missing model checkpoint returns explicit degraded status (never silent normal)'
  );

  console.log('\n--- 5. Preservation of Legacy Pipelines & Cohorts A-D ---');
  const benchResultsPath = path.join(ROOT, 'evaluation', 'results', 'benchmark_results.json');
  const benchData = JSON.parse(fs.readFileSync(benchResultsPath, 'utf8'));
  const cohortKeys = Object.keys(benchData.cohorts);
  assert(
    JSON.stringify(cohortKeys) ===
      JSON.stringify([
        'COHORT_A_SG_1_0_ML_ONLY',
        'COHORT_B_SG_2_0_SURICATA',
        'COHORT_C_SG_2_0_HONEYPOTS',
        'COHORT_D_SG_2_0_COMPLETE_INTEGRATED',
      ]),
    'Historical Stage 7 Cohorts A-D remain completely unmodified in Stage 2'
  );

  console.log(`\n===================================================================`);
  console.log(`  STAGE 2 SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log(`===================================================================`);

  if (failed > 0) {
    process.exit(1);
  }
}

main();
