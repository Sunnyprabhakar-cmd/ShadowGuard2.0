"""
Shadow Guard 2.0 — XAI Stage 5 Reproducible Quantitative Evaluation Script
==========================================================================
Executes Experiments EXP-01 through EXP-08 on the frozen models and 384 held-out
test flows (`data/autoencoder_flow_dataset_v2.json`), writing exact measured
results to `evaluation/results/xai_stage5_evaluation_results.json`.

Strictly read-only: never modifies models, thresholds, fusion policy, or Cohorts A-E.
"""

from __future__ import annotations

import json
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
from scipy.stats import spearmanr

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.ml.feature_schema import EXPECTED_FEATURE_COUNT, extract_69_features  # noqa: E402
from shared.ml.tri_model_fusion import TriModelDetectionEngine  # noqa: E402
from shared.ml.unified_xai_engine import UnifiedTriModelExplainer  # noqa: E402
from shared.ml.xai_explainer import (  # noqa: E402
    EVEN_POLY_DUPLICATE_INDICES,
    HARMONIC_PADDING_INDICES,
    IsolationForestAnomalyExplainer,
    ODD_POLY_DUPLICATE_INDICES,
)


def jaccard_top_k(list_a: List[str], list_b: List[str]) -> float:
    sa, sb = set(list_a), set(list_b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / float(len(sa | sb))


def safe_spearman(vec_a: List[float], vec_b: List[float]) -> float:
    if len(vec_a) < 2 or len(vec_b) < 2:
        return 1.0
    if np.std(vec_a) < 1e-12 and np.std(vec_b) < 1e-12:
        return 1.0
    if np.std(vec_a) < 1e-12 or np.std(vec_b) < 1e-12:
        return 0.0
    rho, _ = spearmanr(vec_a, vec_b)
    return float(rho) if np.isfinite(rho) else 0.0


def percentile_stats(samples: List[float]) -> Dict[str, Any]:
    if not samples:
        return {"n": 0, "mean": 0.0, "median": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    arr = np.asarray(samples, dtype=np.float64)
    return {
        "n": len(samples),
        "mean": round(float(np.mean(arr)), 4),
        "median": round(float(np.percentile(arr, 50.0)), 4),
        "p95": round(float(np.percentile(arr, 95.0)), 4),
        "p99": round(float(np.percentile(arr, 99.0)), 4) if len(samples) >= 20 else None,
        "max": round(float(np.max(arr)), 4),
    }


def main() -> None:
    t_start = time.perf_counter()
    dataset_path = REPO_ROOT / "data" / "autoencoder_flow_dataset_v2.json"
    held_out_path = REPO_ROOT / "data" / "held_out_384_tri_model_predictions.json"
    out_path = REPO_ROOT / "evaluation" / "results" / "xai_stage5_evaluation_results.json"

    raw_ds = json.loads(dataset_path.read_text(encoding="utf-8"))
    test_set: List[Dict[str, Any]] = raw_ds["splits"]["test_set"]
    baseline_flows = {
        f["flow_id"]: f
        for f in json.loads(held_out_path.read_text(encoding="utf-8"))["flows"]
    }

    tri_engine = TriModelDetectionEngine(models_dir=REPO_ROOT / "models")
    unified = UnifiedTriModelExplainer(
        tri_engine=tri_engine,
        models_dir=REPO_ROOT / "models",
        dataset_path=dataset_path,
    )

    # Stratified 60-flow and 30-flow subsets (seed=42)
    rng = random.Random(42)
    normals = [r for r in test_set if r.get("label") == "normal"]
    attacks = [r for r in test_set if r.get("label") == "attack"]
    strat_60 = rng.sample(normals, 30) + rng.sample(attacks, 30)
    strat_30 = strat_60[:15] + strat_60[30:45]

    # =========================================================================
    # EXP-02, EXP-04, EXP-05, EXP-08: Full 384-Flow Evaluation & Invariance
    # =========================================================================
    rf_additivity_errors: List[float] = []
    rf_attack_probs: List[float] = []
    ae_mse_errors: List[float] = []
    ae_identity_diffs: List[float] = []
    consensus_counts: Dict[str, int] = {}
    decision_mismatches = 0
    rf_latencies: List[float] = []
    if_latencies: List[float] = []
    ae_latencies: List[float] = []
    unified_latencies: List[float] = []

    for idx, row in enumerate(test_set):
        fid = row["flow_id"]
        res = unified.explain(flow_id=fid, features=row["features_69"], policy="weighted_consensus", top_k=5)

        rf_e = res["individual_model_explanations_full"]["random_forest"]
        if_e = res["individual_model_explanations_full"]["isolation_forest"]
        ae_e = res["individual_model_explanations_full"]["autoencoder"]

        rf_additivity_errors.append(float(rf_e["additivity_error"]))
        rf_attack_probs.append(float(rf_e["attack_probability"]))
        ae_mse_errors.append(float(ae_e["reconstruction_error"]))
        mean_sq = float(np.mean([f["squared_error"] for f in ae_e["all_features_by_index"]]))
        ae_identity_diffs.append(abs(mean_sq - float(ae_e["reconstruction_error"])))

        c_state = res["model_agreement_and_disagreement"]["consensus_state"]
        consensus_counts[c_state] = consensus_counts.get(c_state, 0) + 1

        if idx < 100:
            rf_latencies.append(float(rf_e["explanation_latency_ms"]))
            if_latencies.append(float(if_e["explanation_latency_ms"]))
            ae_latencies.append(float(ae_e["explanation_latency_ms"]))
            unified_latencies.append(float(res["total_explanation_latency_ms"]))

        # Verify 100% invariance vs held_out_384_tri_model_predictions.json
        base = baseline_flows[fid]
        cls = res["final_tri_model_classification"]
        if (
            cls["final_decision"] != base["tri_model_decision"]["final_decision"]
            or cls["is_anomaly"] != base["tri_model_decision"]["is_anomaly"]
            or cls["recommended_action"] != base["tri_model_decision"]["recommended_action"]
            or cls["auto_block_permitted"] != base["tri_model_decision"]["auto_block_permitted"]
            or abs(rf_e["attack_probability"] - base["models"]["random_forest"]["attack_probability"]) > 1.5e-6
            or abs(if_e["raw_decision_score"] - base["models"]["isolation_forest"]["raw_decision_score"]) > 1.5e-6
            or abs(ae_e["reconstruction_error"] - base["models"]["autoencoder"]["reconstruction_error"]) > 1.5e-6
        ):
            decision_mismatches += 1

    # =========================================================================
    # EXP-01: Explanation Stability Under Small Input Perturbations (+/-5%)
    # =========================================================================
    # Separate decision-preserving vs decision-boundary-crossing perturbations
    stability_same_dec = {"rf_jaccard": [], "rf_spearman": [], "if_jaccard": [], "if_spearman": [], "ae_jaccard": [], "ae_spearman": [], "rf_grouped_l1": [], "if_grouped_l1": [], "ae_grouped_l1": []}
    stability_cross_dec = {"count": 0, "rf_jaccard": [], "if_jaccard": [], "ae_jaccard": []}
    repeat_identical_diffs = 0

    for row in strat_30:
        p0, b0, d0 = float(row["packets"]), float(row["bytes"]), float(row["duration"])
        base_res = unified.explain(flow_id=row["flow_id"], features=row["features_69"], top_k=5)
        rep_res = unified.explain(flow_id=row["flow_id"], features=row["features_69"], top_k=5)
        if base_res["random_forest_explanation"] != rep_res["random_forest_explanation"]:
            repeat_identical_diffs += 1

        base_rf_vec = [f["shap_value_attack"] for f in base_res["individual_model_explanations_full"]["random_forest"]["all_feature_shap_values"]]
        base_if_vec = [f["effective_isolation_influence"] for f in base_res["individual_model_explanations_full"]["isolation_forest"]["all_feature_comparisons"]]
        base_ae_vec = [f["squared_error"] for f in base_res["individual_model_explanations_full"]["autoencoder"]["all_features_by_index"]]

        base_rf_top = [f["feature_name"] for f in base_res["random_forest_explanation"]["top_positive_attack_contributors"][:5]]
        base_if_top = [f["feature_name"] for f in base_res["isolation_forest_explanation"]["top_influential_features"][:5]]
        base_ae_top = [f["feature_name"] for f in base_res["autoencoder_explanation"]["top_anomalous_features"][:5]]

        base_rf_grp = [base_res["random_forest_explanation"]["raw_measurement_attribution"][k]["share_of_total"] for k in ("packets", "bytes", "duration")]
        base_if_grp = [base_res["isolation_forest_explanation"]["raw_measurement_attribution"][k]["share_of_total"] for k in ("packets", "bytes", "duration")]
        base_ae_grp = [base_res["autoencoder_explanation"]["raw_measurement_attribution"][k]["share_of_total"] for k in ("packets", "bytes", "duration")]

        # Perturbations: +5% packets, +5% bytes, +5% duration
        pert_variants = [
            ("packets_plus5", {"packets": max(1.0, round(p0 * 1.05)), "bytes": b0, "duration": d0}),
            ("bytes_plus5", {"packets": p0, "bytes": max(1.0, round(b0 * 1.05)), "duration": d0}),
            ("duration_plus5", {"packets": p0, "bytes": b0, "duration": round(max(0.001, d0 * 1.05), 6)}),
        ]

        for tag, raw_p in pert_variants:
            p_feats = extract_69_features(raw_p)
            p_res = unified.explain(flow_id=f"{row['flow_id']}-{tag}", features=p_feats, top_k=5)

            p_rf_top = [f["feature_name"] for f in p_res["random_forest_explanation"]["top_positive_attack_contributors"][:5]]
            p_if_top = [f["feature_name"] for f in p_res["isolation_forest_explanation"]["top_influential_features"][:5]]
            p_ae_top = [f["feature_name"] for f in p_res["autoencoder_explanation"]["top_anomalous_features"][:5]]

            dec_same = (
                p_res["final_tri_model_classification"]["final_decision"]
                == base_res["final_tri_model_classification"]["final_decision"]
            )
            if dec_same:
                p_rf_vec = [f["shap_value_attack"] for f in p_res["individual_model_explanations_full"]["random_forest"]["all_feature_shap_values"]]
                p_if_vec = [f["effective_isolation_influence"] for f in p_res["individual_model_explanations_full"]["isolation_forest"]["all_feature_comparisons"]]
                p_ae_vec = [f["squared_error"] for f in p_res["individual_model_explanations_full"]["autoencoder"]["all_features_by_index"]]

                p_rf_grp = [p_res["random_forest_explanation"]["raw_measurement_attribution"][k]["share_of_total"] for k in ("packets", "bytes", "duration")]
                p_if_grp = [p_res["isolation_forest_explanation"]["raw_measurement_attribution"][k]["share_of_total"] for k in ("packets", "bytes", "duration")]
                p_ae_grp = [p_res["autoencoder_explanation"]["raw_measurement_attribution"][k]["share_of_total"] for k in ("packets", "bytes", "duration")]

                stability_same_dec["rf_jaccard"].append(jaccard_top_k(base_rf_top, p_rf_top))
                stability_same_dec["rf_spearman"].append(safe_spearman(base_rf_vec, p_rf_vec))
                stability_same_dec["if_jaccard"].append(jaccard_top_k(base_if_top, p_if_top))
                stability_same_dec["if_spearman"].append(safe_spearman(base_if_vec, p_if_vec))
                stability_same_dec["ae_jaccard"].append(jaccard_top_k(base_ae_top, p_ae_top))
                stability_same_dec["ae_spearman"].append(safe_spearman(base_ae_vec, p_ae_vec))

                stability_same_dec["rf_grouped_l1"].append(float(np.sum(np.abs(np.array(base_rf_grp) - np.array(p_rf_grp)))))
                stability_same_dec["if_grouped_l1"].append(float(np.sum(np.abs(np.array(base_if_grp) - np.array(p_if_grp)))))
                stability_same_dec["ae_grouped_l1"].append(float(np.sum(np.abs(np.array(base_ae_grp) - np.array(p_ae_grp)))))
            else:
                stability_cross_dec["count"] += 1
                stability_cross_dec["rf_jaccard"].append(jaccard_top_k(base_rf_top, p_rf_top))
                stability_cross_dec["if_jaccard"].append(jaccard_top_k(base_if_top, p_if_top))
                stability_cross_dec["ae_jaccard"].append(jaccard_top_k(base_ae_top, p_ae_top))

    # =========================================================================
    # EXP-03: Isolation Forest Reference-Population Subsampling Sensitivity
    # =========================================================================
    full_norm_mat = unified.normal_matrix
    sub_idx = np.random.default_rng(42).choice(len(full_norm_mat), size=420, replace=False)
    sub_mat = full_norm_mat[sub_idx]
    sub_stats = {}
    for j in range(EXPECTED_FEATURE_COUNT):
        p25, p50, p75 = np.percentile(sub_mat[:, j], [25, 50, 75])
        p05, p95 = np.percentile(sub_mat[:, j], [5, 95])
        iqr = p75 - p25
        sub_stats[j] = {
            "median": float(p50),
            "iqr": float(iqr) if iqr > 1e-9 else float(max(np.std(sub_mat[:, j]), 1e-6)),
            "p05": float(p05),
            "p25": float(p25),
            "p75": float(p75),
            "p95": float(p95),
            "mean": float(np.mean(sub_mat[:, j])),
            "std": float(np.std(sub_mat[:, j])),
        }
    if_sub_exp = IsolationForestAnomalyExplainer(tri_engine.if_bundle, sub_mat, sub_stats)
    if_sub_spearman: List[float] = []
    if_sub_jaccard: List[float] = []
    for row in strat_30:
        full_if = unified.if_explainer.explain_flow(row["features_69"], top_k=5)
        sub_if = if_sub_exp.explain_flow(row["features_69"], top_k=5)
        v1 = [f["effective_isolation_influence"] for f in full_if["all_feature_comparisons"]]
        v2 = [f["effective_isolation_influence"] for f in sub_if["all_feature_comparisons"]]
        t1 = [f["feature_name"] for f in full_if["top_influential_features"][:5]]
        t2 = [f["feature_name"] for f in sub_if["top_influential_features"][:5]]
        if_sub_spearman.append(safe_spearman(v1, v2))
        if_sub_jaccard.append(jaccard_top_k(t1, t2))

    # =========================================================================
    # EXP-06: Feature Correlation & Attribution Bias (69 vs 3 Scalars)
    # =========================================================================
    dup_poly_indices = set(EVEN_POLY_DUPLICATE_INDICES) | set(ODD_POLY_DUPLICATE_INDICES)
    collinear_pad_indices = set(HARMONIC_PADDING_INDICES)
    rf_dup_shares, rf_pad_shares = [], []
    if_dup_shares, if_pad_shares = [], []
    ae_dup_shares, ae_pad_shares = [], []

    for row in strat_60:
        res = unified.explain(flow_id=row["flow_id"], features=row["features_69"], top_k=5)
        rf_all = res["individual_model_explanations_full"]["random_forest"]["all_feature_shap_values"]
        if_all = res["individual_model_explanations_full"]["isolation_forest"]["all_feature_comparisons"]
        ae_all = res["individual_model_explanations_full"]["autoencoder"]["all_features_by_index"]

        rf_tot = sum(f["abs_shap_value"] for f in rf_all) or 1e-12
        rf_dup_shares.append(sum(f["abs_shap_value"] for f in rf_all if f["feature_index"] in dup_poly_indices) / rf_tot)
        rf_pad_shares.append(sum(f["abs_shap_value"] for f in rf_all if f["feature_index"] in collinear_pad_indices) / rf_tot)

        if_tot = sum(abs(f["effective_isolation_influence"]) for f in if_all) or 1e-12
        if_dup_shares.append(sum(abs(f["effective_isolation_influence"]) for f in if_all if f["feature_index"] in dup_poly_indices) / if_tot)
        if_pad_shares.append(sum(abs(f["effective_isolation_influence"]) for f in if_all if f["feature_index"] in collinear_pad_indices) / if_tot)

        ae_tot = sum(f["squared_error"] for f in ae_all) or 1e-12
        ae_dup_shares.append(sum(f["squared_error"] for f in ae_all if f["feature_index"] in dup_poly_indices) / ae_tot)
        ae_pad_shares.append(sum(f["squared_error"] for f in ae_all if f["feature_index"] in collinear_pad_indices) / ae_tot)

    # =========================================================================
    # EXP-07: Batch Performance & Memory Footprint (20-flow batch)
    # =========================================================================
    tracemalloc.start()
    t_b0 = time.perf_counter()
    for row in strat_30[:20]:
        _ = unified.explain(flow_id=row["flow_id"], features=row["features_69"], top_k=5)
    batch_20_ms = (time.perf_counter() - t_b0) * 1000.0
    _, peak_mem_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    results = {
        "benchmark_classification": "SYNTHETIC_BENCHMARK_ONLY",
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
        "exp01_stability_and_perturbation": {
            "tested_base_flows": len(strat_30),
            "perturbation_variants_per_flow": 3,
            "repeat_identical_mismatches": repeat_identical_diffs,
            "decision_preserving_cases_count": len(stability_same_dec["rf_jaccard"]),
            "decision_preserving_metrics": {
                "rf_top5_jaccard_mean": round(float(np.mean(stability_same_dec["rf_jaccard"])), 4),
                "rf_spearman_mean": round(float(np.mean(stability_same_dec["rf_spearman"])), 4),
                "rf_grouped_3scalar_l1_mean": round(float(np.mean(stability_same_dec["rf_grouped_l1"])), 4),
                "if_top5_jaccard_mean": round(float(np.mean(stability_same_dec["if_jaccard"])), 4),
                "if_spearman_mean": round(float(np.mean(stability_same_dec["if_spearman"])), 4),
                "if_grouped_3scalar_l1_mean": round(float(np.mean(stability_same_dec["if_grouped_l1"])), 4),
                "ae_top5_jaccard_mean": round(float(np.mean(stability_same_dec["ae_jaccard"])), 4),
                "ae_spearman_mean": round(float(np.mean(stability_same_dec["ae_spearman"])), 4),
                "ae_grouped_3scalar_l1_mean": round(float(np.mean(stability_same_dec["ae_grouped_l1"])), 4),
            },
            "boundary_crossing_cases_count": stability_cross_dec["count"],
            "boundary_crossing_metrics": {
                "rf_top5_jaccard_mean": round(float(np.mean(stability_cross_dec["rf_jaccard"])), 4) if stability_cross_dec["rf_jaccard"] else None,
                "if_top5_jaccard_mean": round(float(np.mean(stability_cross_dec["if_jaccard"])), 4) if stability_cross_dec["if_jaccard"] else None,
                "ae_top5_jaccard_mean": round(float(np.mean(stability_cross_dec["ae_jaccard"])), 4) if stability_cross_dec["ae_jaccard"] else None,
            },
        },
        "exp02_random_forest_shap_validation": {
            "evaluated_flows": len(test_set),
            "max_additivity_error": float(np.max(rf_additivity_errors)),
            "mean_additivity_error": float(np.mean(rf_additivity_errors)),
            "attack_prob_mean": round(float(np.mean(rf_attack_probs)), 4),
            "attack_prob_std": round(float(np.std(rf_attack_probs)), 4),
        },
        "exp03_isolation_forest_evaluation": {
            "tested_flows_subsampling": len(strat_30),
            "full_reference_size": 840,
            "bootstrap_reference_size": 420,
            "subsampling_spearman_mean": round(float(np.mean(if_sub_spearman)), 4),
            "subsampling_top5_jaccard_mean": round(float(np.mean(if_sub_jaccard)), 4),
        },
        "exp04_autoencoder_evaluation": {
            "evaluated_flows": len(test_set),
            "frozen_p95": 0.409105,
            "frozen_p97": 0.503670,
            "frozen_p99": 0.645935,
            "max_mean_sq_identity_diff": float(np.max(ae_identity_diffs)),
            "test_mse_mean": round(float(np.mean(ae_mse_errors)), 6),
            "test_mse_median": round(float(np.median(ae_mse_errors)), 6),
            "test_mse_p95": round(float(np.percentile(ae_mse_errors, 95.0)), 6),
        },
        "exp05_unified_consensus_breakdown": {
            "evaluated_flows": len(test_set),
            "consensus_state_counts": consensus_counts,
        },
        "exp06_correlation_and_attribution_bias": {
            "evaluated_flows": len(strat_60),
            "rf_mean_share_in_15_poly_duplicates": round(float(np.mean(rf_dup_shares)), 4),
            "rf_mean_share_in_14_harmonic_padding": round(float(np.mean(rf_pad_shares)), 4),
            "if_mean_share_in_15_poly_duplicates": round(float(np.mean(if_dup_shares)), 4),
            "if_mean_share_in_14_harmonic_padding": round(float(np.mean(if_pad_shares)), 4),
            "ae_mean_share_in_15_poly_duplicates": round(float(np.mean(ae_dup_shares)), 4),
            "ae_mean_share_in_14_harmonic_padding": round(float(np.mean(ae_pad_shares)), 4),
        },
        "exp07_performance_benchmarks": {
            "random_forest_ms": percentile_stats(rf_latencies),
            "isolation_forest_ms": percentile_stats(if_latencies),
            "autoencoder_ms": percentile_stats(ae_latencies),
            "unified_total_ms": percentile_stats(unified_latencies),
            "batch_20_flows_total_ms": round(batch_20_ms, 2),
            "batch_20_flows_per_flow_ms": round(batch_20_ms / 20.0, 2),
            "peak_traced_memory_mb": round(peak_mem_bytes / (1024.0 * 1024.0), 3),
        },
        "exp08_384_held_out_invariance": {
            "evaluated_flows": len(test_set),
            "decision_and_score_mismatches": decision_mismatches,
        },
        "total_evaluation_runtime_sec": round(time.perf_counter() - t_start, 2),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
