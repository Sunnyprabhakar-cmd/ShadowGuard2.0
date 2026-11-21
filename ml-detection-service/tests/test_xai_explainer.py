"""
Shadow Guard 2.0 — XAI Stage 1 Unit & Mathematical Verification Suite
======================================================================
Tests the model-specific explainability engines in `shared/ml/xai_explainer.py`:
  1. `RandomForestSHAPExplainer` (official `shap.TreeExplainer`, `shap == 0.54.1`)
  2. `IsolationForestAnomalyExplainer` (reference-population perturbation + quantile deviation)
  3. `AutoencoderReconstructionExplainer` (PyTorch 69-feature MSE decomposition vs frozen P97 = 0.503670)
  4. `ThreeScalarMeasurementGrouper` (69-feature technical + 3-scalar grouped explanations & collinearity audit)
"""

import json
import os
import sys
import unittest
from pathlib import Path
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.ml.feature_schema import (
    EXPECTED_FEATURE_COUNT,
    FEATURE_NAMES_69,
    FEATURE_SCHEMA_VERSION,
    extract_69_features,
)
from shared.ml.tri_model_fusion import TriModelDetectionEngine
from shared.ml.xai_explainer import (
    AutoencoderReconstructionExplainer,
    CORRELATED_ATTRIBUTION_LIMITATION_NOTE,
    EVEN_POLY_DUPLICATE_INDICES,
    FEATURE_CATALOG_69,
    HARMONIC_PADDING_INDICES,
    IsolationForestAnomalyExplainer,
    ODD_POLY_DUPLICATE_INDICES,
    RandomForestSHAPExplainer,
    SHAP_AVAILABLE,
    SHAP_VERSION,
    ThreeScalarMeasurementGrouper,
    load_normal_reference_population,
)


class TestXAIStage1ExplainabilityCore(unittest.TestCase):
    """Comprehensive mathematical and functional tests for XAI Stage 1."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.models_dir = REPO_ROOT / "models"
        cls.dataset_json = REPO_ROOT / "data" / "autoencoder_flow_dataset_v2.json"

        cls.tri_engine = TriModelDetectionEngine(models_dir=cls.models_dir)
        cls.normal_matrix, cls.normal_stats = load_normal_reference_population(cls.dataset_json)

        cls.rf_explainer = RandomForestSHAPExplainer(
            rf_bundle=cls.tri_engine.rf_bundle,
            normal_matrix=cls.normal_matrix,
            normal_stats=cls.normal_stats,
        )
        cls.if_explainer = IsolationForestAnomalyExplainer(
            if_bundle=cls.tri_engine.if_bundle,
            normal_matrix=cls.normal_matrix,
            normal_stats=cls.normal_stats,
        )
        cls.ae_explainer = AutoencoderReconstructionExplainer(
            ae_engine=cls.tri_engine.ae_engine,
            normal_stats=cls.normal_stats,
        )

        # Load representative flows from test_set across normal ('none') and all 8 attack categories
        raw_data = json.loads(cls.dataset_json.read_text(encoding="utf-8"))
        test_set_records = raw_data["splits"]["test_set"]
        cls.sample_flows_by_category = {}
        for row in test_set_records:
            cat = row.get("attack_category", "none")
            if cat == "none":
                cat = "normal"
            if cat not in cls.sample_flows_by_category:
                feats = row.get("features_69") or extract_69_features(
                    {
                        "packets": float(row["packets"]),
                        "bytes": float(row["bytes"]),
                        "duration": float(row["duration"]),
                    }
                )
                cls.sample_flows_by_category[cat] = {
                    "flow_id": row["flow_id"],
                    "label": 1 if row.get("label") == "attack" else 0,
                    "attack_category": cat,
                    "packets": float(row["packets"]),
                    "bytes": float(row["bytes"]),
                    "duration": float(row["duration"]),
                    "features": [float(v) for v in feats],
                }

    # =========================================================================
    # 1. RANDOM FOREST SHAP EXPLAINER TESTS
    # =========================================================================

    def test_01_official_shap_tree_explainer_installed_and_active(self) -> None:
        """Verifies official `shap.TreeExplainer` is installed, compatible, and active."""
        self.assertTrue(SHAP_AVAILABLE, "Official shap library must be installed and importable")
        self.assertEqual(SHAP_VERSION, "0.54.1")
        self.assertEqual(self.rf_explainer.status, "healthy")
        self.assertTrue(self.rf_explainer.is_exact_shap)
        self.assertIn("official_shap_tree_explainer", self.rf_explainer.explainer_backend)
        self.assertEqual(self.rf_explainer.classes, [0, 1])
        self.assertEqual(self.rf_explainer.benign_class_index, 0)
        self.assertEqual(self.rf_explainer.attack_class_index, 1)

    def test_02_rf_shap_additivity_and_inference_parity_across_all_categories(self) -> None:
        """
        Verifies across normal and all 8 attack categories that:
          1. `RandomForestSHAPExplainer` matches `TriModelDetectionEngine.score_random_forest`
             probabilities and predictions to 6 decimal places.
          2. Exact SHAP additivity holds: `base_expected_value_attack + sum(shap_values) == P(attack|x)`
             within `< 1e-6`.
        """
        self.assertGreaterEqual(len(self.sample_flows_by_category), 9)
        for cat, item in self.sample_flows_by_category.items():
            feats = item["features"]
            engine_rf = self.tri_engine.score_random_forest(feats)
            xai_rf = self.rf_explainer.explain_flow(feats, top_k=5)

            self.assertEqual(xai_rf["status"], "healthy", f"Failed on category {cat}")
            self.assertTrue(xai_rf["is_exact_shap"])
            self.assertEqual(xai_rf["prediction"], engine_rf["prediction"])
            self.assertAlmostEqual(
                xai_rf["attack_probability"], engine_rf["attack_probability"], places=6
            )
            self.assertAlmostEqual(
                xai_rf["benign_probability"], engine_rf["benign_probability"], places=6
            )

            # Verify exact TreeSHAP additivity identity
            self.assertTrue(xai_rf["additivity_verified"], f"Additivity failed for {cat}")
            self.assertLess(xai_rf["additivity_error"], 1e-6)

            raw_shap_sum = sum(
                f["shap_value_attack"] for f in xai_rf["all_feature_shap_values"]
            )
            reconstructed = xai_rf["base_expected_value_attack"] + raw_shap_sum
            self.assertAlmostEqual(reconstructed, xai_rf["attack_probability"], places=4)

    def test_03_rf_shap_feature_schema_and_top_contributors_ordering(self) -> None:
        """Verifies all 69 canonical features and top-5 positive/negative contributor rankings."""
        syn_flow = self.sample_flows_by_category["ddos_flood"]["features"]
        res = self.rf_explainer.explain_flow(syn_flow, top_k=5)

        self.assertEqual(len(res["all_feature_shap_values"]), EXPECTED_FEATURE_COUNT)
        names = [f["feature_name"] for f in res["all_feature_shap_values"]]
        self.assertEqual(names, FEATURE_NAMES_69)

        top_pos = res["top_positive_attack_contributors"]
        self.assertGreater(len(top_pos), 0)
        self.assertLessEqual(len(top_pos), 5)
        for i in range(len(top_pos) - 1):
            self.assertGreaterEqual(
                top_pos[i]["shap_value_attack"], top_pos[i + 1]["shap_value_attack"]
            )
            self.assertGreater(top_pos[i]["shap_value_attack"], 0.0)

        top_neg = res["top_negative_benign_contributors"]
        for i in range(len(top_neg) - 1):
            self.assertLessEqual(
                top_neg[i]["shap_value_attack"], top_neg[i + 1]["shap_value_attack"]
            )
            self.assertLess(top_neg[i]["shap_value_attack"], 0.0)

    def test_04_rf_shap_array_shape_handling_binary_and_multiclass(self) -> None:
        """Verifies `_extract_class_shap_vector` handles 3D ndarray, list of 2D ndarrays, 2D ndarray, and multiclass."""
        vec = np.arange(69, dtype=np.float64) * 0.001
        # 1. 3D ndarray (1, 69, 2)
        arr_3d = np.stack([-vec, vec], axis=-1).reshape(1, 69, 2)
        phi_1, base_1 = RandomForestSHAPExplainer._extract_class_shap_vector(
            arr_3d, np.array([0.5, 0.5]), target_class_idx=1, n_classes=2
        )
        np.testing.assert_allclose(phi_1, vec)
        self.assertAlmostEqual(base_1, 0.5)

        # 2. Legacy list of 2D arrays [(1, 69), (1, 69)]
        list_2d = [-vec.reshape(1, 69), vec.reshape(1, 69)]
        phi_list, base_list = RandomForestSHAPExplainer._extract_class_shap_vector(
            list_2d, [0.4, 0.6], target_class_idx=1, n_classes=2
        )
        np.testing.assert_allclose(phi_list, vec)
        self.assertAlmostEqual(base_list, 0.6)

        # 3. Single 2D ndarray (1, 69)
        arr_2d = vec.reshape(1, 69)
        phi_0, base_0 = RandomForestSHAPExplainer._extract_class_shap_vector(
            arr_2d, [0.5], target_class_idx=0, n_classes=2
        )
        np.testing.assert_allclose(phi_0, -vec)
        self.assertAlmostEqual(base_0, 0.5)

        # 4. Multiclass 3D ndarray (1, 69, 4)
        arr_mc = np.zeros((1, 69, 4), dtype=np.float64)
        arr_mc[0, :, 2] = vec * 2.0
        phi_mc, base_mc = RandomForestSHAPExplainer._extract_class_shap_vector(
            arr_mc, [0.25, 0.25, 0.30, 0.20], target_class_idx=2, n_classes=4
        )
        np.testing.assert_allclose(phi_mc, vec * 2.0)
        self.assertAlmostEqual(base_mc, 0.30)

    def test_05_rf_fallback_never_claims_exact_shap(self) -> None:
        """
        Verifies that when fallback mode is triggered (`force_fallback_mode=True`),
        `is_exact_shap` is strictly `False` and `additivity_verified` is `False`.
        """
        fallback_explainer = RandomForestSHAPExplainer(
            rf_bundle=self.tri_engine.rf_bundle,
            normal_matrix=self.normal_matrix,
            normal_stats=self.normal_stats,
            force_fallback_mode=True,
        )
        self.assertFalse(fallback_explainer.is_exact_shap)
        self.assertIn("not_exact_shap", fallback_explainer.explainer_backend)

        syn_flow = self.sample_flows_by_category["ddos_flood"]["features"]
        res = fallback_explainer.explain_flow(syn_flow, top_k=5)
        self.assertEqual(res["status"], "healthy")
        self.assertFalse(res["is_exact_shap"])
        self.assertFalse(res["additivity_verified"])

    def test_06_rf_global_feature_importance(self) -> None:
        """Verifies global SHAP feature importance ranking across reference samples."""
        global_imp = self.rf_explainer.compute_global_feature_importance(
            self.normal_matrix, max_samples=50, top_k=10
        )
        self.assertEqual(global_imp["status"], "healthy")
        self.assertTrue(global_imp["is_exact_shap"])
        self.assertEqual(global_imp["evaluated_samples"], 50)
        self.assertEqual(len(global_imp["top_features"]), 10)
        self.assertEqual(len(global_imp["all_features_ranked"]), EXPECTED_FEATURE_COUNT)

        shares_sum = sum(f["shap_importance_share"] for f in global_imp["all_features_ranked"])
        self.assertAlmostEqual(shares_sum, 1.0, places=2)

    # =========================================================================
    # 2. ISOLATION FOREST ANOMALY EXPLAINER TESTS
    # =========================================================================

    def test_07_isolation_forest_score_parity_and_non_probabilistic_semantics(self) -> None:
        """
        Verifies `IsolationForestAnomalyExplainer` produces the exact `raw_decision_score`,
        `anomaly_score`, and `is_anomaly` decision as `TriModelDetectionEngine.score_isolation_forest`,
        and strictly labels its output as an unsupervised anomaly score (never a probability).
        """
        for cat, item in self.sample_flows_by_category.items():
            feats = item["features"]
            engine_if = self.tri_engine.score_isolation_forest(feats)
            xai_if = self.if_explainer.explain_flow(feats, top_k=5)

            self.assertEqual(xai_if["status"], "healthy")
            self.assertEqual(
                xai_if["score_semantics"], "UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY"
            )
            self.assertIn("NOT a probability", xai_if["explanation_narrative"])
            self.assertEqual(xai_if["reference_population_size"], 840)
            self.assertEqual(xai_if["is_anomaly"], engine_if["is_anomaly"])
            self.assertAlmostEqual(
                xai_if["raw_decision_score"], engine_if["raw_decision_score"], places=6
            )
            self.assertAlmostEqual(
                xai_if["anomaly_score"], engine_if["anomaly_score"], places=6
            )
            self.assertAlmostEqual(
                xai_if["decision_threshold"], engine_if["threshold"], places=6
            )

    def test_08_isolation_forest_perturbation_and_reference_comparison(self) -> None:
        """
        Verifies perturbation shifts on an anomalous flow (`syn_flood` / `data_exfiltration`)
        identify unusually high/low measurements relative to the 840-flow normal reference
        and align with `shap.TreeExplainer(if_model)` on raw measurement families.
        """
        exfil_flow = self.sample_flows_by_category["data_exfiltration"]["features"]
        res = self.if_explainer.explain_flow(exfil_flow, top_k=5)

        self.assertTrue(res["is_anomaly"])
        self.assertGreater(res["unusually_high_count"] + res["unusually_low_count"], 10)
        self.assertEqual(len(res["top_influential_features"]), 5)
        self.assertEqual(len(res["all_feature_comparisons"]), EXPECTED_FEATURE_COUNT)

        # Verify whole-measurement counterfactual replacement rescues raw score toward normal
        cf = res["counterfactual_raw_measurement_perturbations"]
        max_rescue = max(
            cf["replace_packets_with_normal_median"]["raw_score_shift_toward_normal"],
            cf["replace_bytes_with_normal_median"]["raw_score_shift_toward_normal"],
            cf["replace_duration_with_normal_median"]["raw_score_shift_toward_normal"],
        )
        self.assertGreater(
            max_rescue,
            0.0,
            "Replacing the anomalous raw measurement with normal median must increase raw decision score toward normal",
        )

        # Compare against trusted reference explainer (shap.TreeExplainer on Isolation Forest)
        ref_cmp = self.if_explainer.compare_with_tree_explainer_reference(exfil_flow)
        self.assertEqual(ref_cmp["status"], "verified")
        self.assertGreater(ref_cmp["tree_shap_l1_norm"], 0.0)
        self.assertAlmostEqual(
            sum(ref_cmp["perturbation_raw_shares"].values()), 1.0, places=3
        )
        self.assertAlmostEqual(
            sum(ref_cmp["tree_shap_raw_shares"].values()), 1.0, places=3
        )

    # =========================================================================
    # 3. AUTOENCODER RECONSTRUCTION EXPLAINER TESTS
    # =========================================================================

    def test_09_autoencoder_mse_parity_and_frozen_p97_threshold(self) -> None:
        """
        Verifies `AutoencoderReconstructionExplainer` uses the exact `FeaturePreprocessor`
        and PyTorch `FlowAutoencoder`, matches `ae_engine.score_features` MSE to 6 decimal
        places, and preserves the frozen validation-derived `P97 = 0.503670` threshold.
        """
        for cat, item in self.sample_flows_by_category.items():
            feats = item["features"]
            engine_ae = self.tri_engine.score_autoencoder(feats)
            xai_ae = self.ae_explainer.explain_flow(feats, top_k=5)

            self.assertEqual(xai_ae["status"], "healthy")
            self.assertEqual(
                xai_ae["score_semantics"], "RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY"
            )
            self.assertAlmostEqual(xai_ae["threshold"], 0.503670, places=6)
            self.assertEqual(xai_ae["threshold_percentile"], "P97")
            self.assertAlmostEqual(
                xai_ae["threshold_comparison"]["frozen_primary_threshold_p97"],
                0.503670,
                places=6,
            )
            self.assertAlmostEqual(
                xai_ae["threshold_comparison"]["warning_threshold_p95"],
                0.409105,
                places=6,
            )
            self.assertAlmostEqual(
                xai_ae["threshold_comparison"]["critical_threshold_p99"],
                0.645935,
                places=6,
            )

            self.assertEqual(xai_ae["decision"], engine_ae["decision"])
            self.assertEqual(xai_ae["is_anomaly"], engine_ae["is_anomaly"])
            self.assertAlmostEqual(
                xai_ae["reconstruction_error"], engine_ae["reconstruction_error"], places=6
            )
            self.assertAlmostEqual(
                xai_ae["anomaly_score"], engine_ae["anomaly_score"], places=6
            )

            # Mathematical identity: mean of all 69 per-feature squared errors == reconstruction_error
            mean_sq = float(
                np.mean([f["squared_error"] for f in xai_ae["all_features_by_index"]])
            )
            self.assertAlmostEqual(mean_sq, xai_ae["reconstruction_error"], places=5)

            # Sum of error shares == 1.0
            share_sum = sum(f["error_share"] for f in xai_ae["all_features_by_index"])
            self.assertAlmostEqual(share_sum, 1.0, places=2)

            # Verify strict descending rank order (rank 1..69)
            ranked = xai_ae["ranked_features"]
            self.assertEqual(len(ranked), EXPECTED_FEATURE_COUNT)
            for idx in range(len(ranked) - 1):
                self.assertEqual(ranked[idx]["rank"], idx + 1)
                self.assertGreaterEqual(
                    ranked[idx]["squared_error"], ranked[idx + 1]["squared_error"]
                )

            # Top 5 anomalous features match top 5 of ranked_features
            self.assertEqual(xai_ae["top_anomalous_features"], ranked[:5])
            self.assertEqual(len(xai_ae["bottleneck_latent_8d"]), 8)

    # =========================================================================
    # 4. 3-SCALAR GROUPING, COLLINEARITY, DETERMINISM & EDGE CASES
    # =========================================================================

    def test_10_three_scalar_grouping_and_collinearity_audit(self) -> None:
        """
        Verifies that the 69-feature catalog and `ThreeScalarMeasurementGrouper`
        accurately document the 13 exact duplicate columns (`f_25..f_39`) and
        14 collinear harmonic padding columns (`f_55..f_68`), and produce valid
        grouped attributions over `(packets, bytes, duration)`.
        """
        dup_cols = [m for m in FEATURE_CATALOG_69 if m["is_duplicate_column"]]
        pad_cols = [m for m in FEATURE_CATALOG_69 if m["is_collinear_padding"]]
        self.assertEqual(len(dup_cols), 13)
        self.assertEqual(len(pad_cols), 14)
        self.assertEqual(len(EVEN_POLY_DUPLICATE_INDICES), 8)
        self.assertEqual(len(ODD_POLY_DUPLICATE_INDICES), 7)
        self.assertEqual(len(HARMONIC_PADDING_INDICES), 14)

        syn_flow = self.sample_flows_by_category["ddos_flood"]["features"]
        rf_res = self.rf_explainer.explain_flow(syn_flow)
        grp = rf_res["grouped_measurement_explanation"]

        self.assertEqual(grp["intrinsic_raw_measurements"], ["packets", "bytes", "duration"])
        self.assertIn("f_25..f_39", grp["correlated_feature_limitation"])
        self.assertIn("f_55..f_68", grp["correlated_feature_limitation"])

        raw_shares = grp["raw_measurement_attribution"]
        total_raw_share = (
            raw_shares["packets"]["share_of_total"]
            + raw_shares["bytes"]["share_of_total"]
            + raw_shares["duration"]["share_of_total"]
        )
        self.assertAlmostEqual(total_raw_share, 1.0, places=3)

        struct_shares = grp["structural_group_attribution"]
        total_struct_share = sum(v["share_of_total"] for v in struct_shares.values())
        self.assertAlmostEqual(total_struct_share, 1.0, places=3)

    def test_11_deterministic_stability_and_cross_label_collision_invariance(self) -> None:
        """
        Verifies that identical `(packets=65, bytes=5070, duration=7.8)` inputs
        (the documented cross-label collision pair `flow-collision-norm-00` vs
        `flow-collision-atk-00`) produce bit-for-bit identical attributions across
        all three explainers (`RF`, `IF`, `AE`).
        """
        collision_feats_a = extract_69_features({"packets": 65.0, "bytes": 5070.0, "duration": 7.8})
        collision_feats_b = extract_69_features({"packets": 65.0, "bytes": 5070.0, "duration": 7.8})

        rf_a = self.rf_explainer.explain_flow(collision_feats_a)
        rf_b = self.rf_explainer.explain_flow(collision_feats_b)
        self.assertEqual(rf_a["all_feature_shap_values"], rf_b["all_feature_shap_values"])

        if_a = self.if_explainer.explain_flow(collision_feats_a)
        if_b = self.if_explainer.explain_flow(collision_feats_b)
        self.assertEqual(if_a["all_feature_comparisons"], if_b["all_feature_comparisons"])

        ae_a = self.ae_explainer.explain_flow(collision_feats_a)
        ae_b = self.ae_explainer.explain_flow(collision_feats_b)
        self.assertEqual(ae_a["all_features_by_index"], ae_b["all_features_by_index"])

    def test_12_graceful_degraded_handling_on_invalid_inputs(self) -> None:
        """Verifies all three explainers return graceful degraded status on malformed inputs."""
        bad_short = [1.0, 2.0, 3.0]
        bad_nan = [float("nan")] * 69

        for bad in (bad_short, bad_nan):
            rf_deg = self.rf_explainer.explain_flow(bad)
            self.assertEqual(rf_deg["status"], "degraded")

            if_deg = self.if_explainer.explain_flow(bad)
            self.assertEqual(if_deg["status"], "degraded")

            ae_deg = self.ae_explainer.explain_flow(bad)
            self.assertEqual(ae_deg["status"], "degraded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
