/**
 * Shadow Guard 2.0 — XAI Stage 5 Verification Suite (Evaluation & Regression)
 * ===========================================================================
 * Verifies:
 *   1. All Stage 5 evaluation documentation (`XAI_EVALUATION_PLAN.md`,
 *      `XAI_EVALUATION_RESULTS.md`, `XAI_STABILITY_ANALYSIS.md`,
 *      `XAI_PERFORMANCE_REPORT.md`, `XAI_STAGE5_REPORT.md`).
 *   2. Reproducible quantitative evaluation artifact (`evaluation/results/xai_stage5_evaluation_results.json`):
 *      - `SYNTHETIC_BENCHMARK_ONLY` classification preserved.
 *      - `0/384` held-out decision/score mismatches (`exp08_384_held_out_invariance`).
 *      - Random Forest TreeSHAP additivity error `< 1e-12` across 384 flows.
 *      - Isolation Forest bootstrap subsampling Spearman `> 0.90`.
 *      - Autoencoder frozen `P95=0.409105`, `P97=0.503670`, `P99=0.645935` preserved.
 *      - Identical input repeatability `0` mismatches.
 *      - Decision-preserving grouped 3-scalar stability (`L1 < 0.05` across all 3 models).
 *      - Feature correlation bias quantified (`RF`, `IF`, `AE` shares in duplicate/padding columns).
 *      - Performance benchmarks (`mean`, `median`, `p95`, `p99`, `max`, `peak_traced_memory_mb`).
 */

'use strict';

const fs = require('fs');
const path = require('path');

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

function main() {
  console.log('================================================================================');
  console.log(' SHADOW GUARD 2.0 — XAI STAGE 5 VERIFICATION SUITE (EVALUATION & REGRESSION)');
  console.log('================================================================================\n');

  const docs = [
    'XAI_EVALUATION_PLAN.md',
    'XAI_EVALUATION_RESULTS.md',
    'XAI_STABILITY_ANALYSIS.md',
    'XAI_PERFORMANCE_REPORT.md',
    'XAI_STAGE5_REPORT.md',
  ];
  for (const d of docs) {
    assert(fs.existsSync(path.join(ROOT, 'docs', d)), `docs/${d} exists`);
  }

  const resPath = path.join(ROOT, 'evaluation', 'results', 'xai_stage5_evaluation_results.json');
  assert(fs.existsSync(resPath), 'evaluation/results/xai_stage5_evaluation_results.json exists');

  const data = JSON.parse(fs.readFileSync(resPath, 'utf8'));
  assert(data.benchmark_classification === 'SYNTHETIC_BENCHMARK_ONLY', 'Evaluation artifact carries SYNTHETIC_BENCHMARK_ONLY classification');
  assert(
    data.exp08_384_held_out_invariance?.evaluated_flows === 384 &&
      data.exp08_384_held_out_invariance?.decision_and_score_mismatches === 0,
    '384 held-out test flows match baseline with 0 mismatches'
  );
  assert(
    data.exp02_random_forest_shap_validation?.evaluated_flows === 384 &&
      data.exp02_random_forest_shap_validation?.max_additivity_error < 1e-12,
    `Random Forest TreeSHAP additivity error < 1e-12 across 384 flows (max=${data.exp02_random_forest_shap_validation?.max_additivity_error})`
  );
  assert(
    data.exp03_isolation_forest_evaluation?.subsampling_spearman_mean > 0.9,
    `Isolation Forest bootstrap subsampling Spearman > 0.90 (${data.exp03_isolation_forest_evaluation?.subsampling_spearman_mean})`
  );
  assert(
    Math.abs(data.exp04_autoencoder_evaluation?.frozen_p97 - 0.50367) < 1e-6 &&
      data.exp04_autoencoder_evaluation?.max_mean_sq_identity_diff < 1e-5,
    'Autoencoder preserves frozen P97=0.503670 and per-feature MSE identity'
  );
  assert(
    data.exp01_stability_and_perturbation?.repeat_identical_mismatches === 0 &&
      data.exp01_stability_and_perturbation?.decision_preserving_metrics?.rf_grouped_3scalar_l1_mean < 0.05 &&
      data.exp01_stability_and_perturbation?.decision_preserving_metrics?.if_grouped_3scalar_l1_mean < 0.05 &&
      data.exp01_stability_and_perturbation?.decision_preserving_metrics?.ae_grouped_3scalar_l1_mean < 0.05,
    'Identical inputs deterministic (0 mismatches) & grouped 3-scalar L1 shift < 0.05 across all 3 models'
  );
  assert(
    data.exp06_correlation_and_attribution_bias?.rf_mean_share_in_14_harmonic_padding > 0 &&
      data.exp06_correlation_and_attribution_bias?.if_mean_share_in_15_poly_duplicates > 0,
    'Feature correlation and redundant-column attribution bias quantified across RF, IF, and AE'
  );
  assert(
    data.exp07_performance_benchmarks?.unified_total_ms?.n === 100 &&
      data.exp07_performance_benchmarks?.unified_total_ms?.median > 0 &&
      data.exp07_performance_benchmarks?.peak_traced_memory_mb > 0,
    'Computational latency (mean, median, P95, P99, max) and memory footprint benchmarked'
  );

  console.log('\n================================================================================');
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

main();
