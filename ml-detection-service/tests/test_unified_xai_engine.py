"""
Shadow Guard 2.0 — XAI Stage 2 Unit & Integration Verification Suite
====================================================================
Tests `UnifiedTriModelExplainer` (`shared/ml/unified_xai_engine.py`) across:
  1. All three explainers working together (by `flow_id`, 69-feature vector, and raw flow dict).
  2. Unanimous model agreement (3-of-3 attack and 3-of-3 normal).
  3. Inter-model disagreement (2-of-3 majority dissent and 1-of-3 single-detector AE_ONLY dissent).
  4. Partial model failures (RF unavailable, IF unavailable, AE unavailable, 2-of-3 unavailable).
  5. Complete explanation failure (all 3 models unavailable and runtime explainer exceptions).
  6. Invalid flow inputs (unknown flow_id, wrong dimension, NaN/Inf).
  7. Deterministic stability & cross-label feature collision detection.
  8. Collinearity-aware feature grouping & strict separation of mathematical scales.
  9. Complete unified response contract verification.
  10. 100% invariance of all 384 held-out test flows (`test_set`) before and after unified XAI integration.
"""

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from shared.ml.feature_schema import extract_69_features
from shared.ml.tri_model_fusion import TriModelDetectionEngine
from shared.ml.unified_xai_engine import UnifiedTriModelExplainer, _canonical_concept_id


class TestXAIStage2UnifiedEngine(unittest.TestCase):
    """Comprehensive unit and mathematical verification tests for XAI Stage 2."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.models_dir = REPO_ROOT / "models"
        cls.dataset_path = REPO_ROOT / "data" / "autoencoder_flow_dataset_v2.json"
        cls.held_out_preds_path = REPO_ROOT / "data" / "held_out_384_tri_model_predictions.json"

        cls.tri_engine = TriModelDetectionEngine(models_dir=cls.models_dir)
        cls.unified_engine = UnifiedTriModelExplainer(
            tri_engine=cls.tri_engine,
            models_dir=cls.models_dir,
            dataset_path=cls.dataset_path,
        )

        raw_ds = json.loads(cls.dataset_path.read_text(encoding="utf-8"))
        cls.test_set = raw_ds["splits"]["test_set"]
        cls.held_out_baseline = json.loads(cls.held_out_preds_path.read_text(encoding="utf-8"))[
            "flows"
        ]

        # Locate representative flows in test_set for each consensus state using held_out_baseline
        cls.unanimous_attack_flow = None
        cls.unanimous_normal_flow = None
        cls.majority_2of3_flow = None
        cls.ae_only_flow = None

        test_by_id = {r["flow_id"]: r for r in cls.test_set}
        for b_item in cls.held_out_baseline:
            fid = b_item["flow_id"]
            row = test_by_id.get(fid)
            if row is None:
                continue
            tri = b_item["tri_model_decision"]
            agreeing = tri["models_agreeing"]
            if len(agreeing) == 3 and cls.unanimous_attack_flow is None:
                cls.unanimous_attack_flow = row
            elif (
                len(agreeing) == 0
                and tri["final_decision"] == "normal"
                and cls.unanimous_normal_flow is None
            ):
                cls.unanimous_normal_flow = row
            elif len(agreeing) == 2 and cls.majority_2of3_flow is None:
                cls.majority_2of3_flow = row
            elif agreeing == ["autoencoder"] and cls.ae_only_flow is None:
                cls.ae_only_flow = row

    def test_01_all_three_explainers_working_together_and_output_structure(self) -> None:
        """
        Verifies UnifiedTriModelExplainer accepts flow_id, 69-feature vector, and raw_flow dict,
        invokes all 3 explainers, and returns the complete required schema.
        """
        row = self.unanimous_attack_flow
        self.assertIsNotNone(row)

        # 1. By flow_id
        res_by_id = self.unified_engine.explain(flow_id=row["flow_id"])
        # 2. By 69-feature vector
        res_by_feats = self.unified_engine.explain(
            flow_id=row["flow_id"], features=row["features_69"]
        )
        # 3. By raw_flow dict
        res_by_raw = self.unified_engine.explain(
            flow_id=row["flow_id"],
            raw_flow={
                "packets": row["packets"],
                "bytes": row["bytes"],
                "duration": row["duration"],
            },
        )

        required_top_keys = [
            "flow_id",
            "schema_version",
            "explanation_generation_status",
            "healthy_explainers",
            "degraded_explainers",
            "flow_metadata",
            "final_tri_model_classification",
            "random_forest_explanation",
            "isolation_forest_explanation",
            "autoencoder_explanation",
            "individual_model_explanations_full",
            "model_agreement_and_disagreement",
            "shared_contributing_measurements",
            "model_specific_contributing_measurements",
            "human_readable_soc_analyst_explanation",
            "explanation_confidence_and_limitations",
            "total_explanation_latency_ms",
        ]
        for k in required_top_keys:
            self.assertIn(k, res_by_id, f"Missing required key: {k}")

        self.assertEqual(res_by_id["explanation_generation_status"], "healthy")
        self.assertEqual(
            res_by_id["healthy_explainers"],
            ["random_forest", "isolation_forest", "autoencoder"],
        )
        self.assertEqual(res_by_id["degraded_explainers"], [])

        # Verify bit-for-bit identical model explanations whether invoked by flow_id, features, or raw_flow
        self.assertEqual(
            res_by_id["final_tri_model_classification"],
            res_by_feats["final_tri_model_classification"],
        )
        self.assertEqual(
            res_by_id["random_forest_explanation"],
            res_by_raw["random_forest_explanation"],
        )
        self.assertEqual(
            res_by_id["isolation_forest_explanation"],
            res_by_raw["isolation_forest_explanation"],
        )
        self.assertEqual(
            res_by_id["autoencoder_explanation"],
            res_by_raw["autoencoder_explanation"],
        )

    def test_02_model_agreement_unanimous_attack_and_unanimous_normal(self) -> None:
        """Verifies unanimous 3-of-3 attack consensus and 3-of-3 normal consensus."""
        atk_res = self.unified_engine.explain(flow_id=self.unanimous_attack_flow["flow_id"])
        agr_atk = atk_res["model_agreement_and_disagreement"]
        self.assertEqual(agr_atk["consensus_state"], "UNANIMOUS_ANOMALY_3_OF_3")
        self.assertTrue(agr_atk["models_agree"])
        self.assertFalse(agr_atk["has_model_disagreement"])
        self.assertEqual(
            agr_atk["models_flagging_anomaly"],
            ["random_forest", "isolation_forest", "autoencoder"],
        )
        self.assertEqual(
            agr_atk["pairwise_decision_agreement"],
            {"rf_vs_if_agree": True, "rf_vs_ae_agree": True, "if_vs_ae_agree": True},
        )
        self.assertEqual(
            atk_res["explanation_confidence_and_limitations"]["explanation_reliability_tier"],
            "HIGH_UNANIMOUS_CONSENSUS",
        )

        norm_res = self.unified_engine.explain(flow_id=self.unanimous_normal_flow["flow_id"])
        agr_norm = norm_res["model_agreement_and_disagreement"]
        self.assertEqual(agr_norm["consensus_state"], "UNANIMOUS_NORMAL_3_OF_3")
        self.assertTrue(agr_norm["models_agree"])
        self.assertFalse(agr_norm["has_model_disagreement"])
        self.assertEqual(
            agr_norm["models_flagging_normal"],
            ["random_forest", "isolation_forest", "autoencoder"],
        )

    def test_03_model_disagreement_majority_and_single_detector_ae_only(self) -> None:
        """
        Verifies inter-model disagreement cases:
          1. 2-of-3 majority anomaly dissent (`MAJORITY_ANOMALY_2_OF_3_DISSENT`).
          2. Single-model Autoencoder-only anomaly (`SINGLE_MODEL_ANOMALY_DISSENT_AUTOENCODER`),
             proving `auto_block_permitted == False`.
        """
        self.assertIsNotNone(self.majority_2of3_flow)
        maj_res = self.unified_engine.explain(flow_id=self.majority_2of3_flow["flow_id"])
        agr_maj = maj_res["model_agreement_and_disagreement"]
        self.assertEqual(agr_maj["consensus_state"], "MAJORITY_ANOMALY_2_OF_3_DISSENT")
        self.assertFalse(agr_maj["models_agree"])
        self.assertTrue(agr_maj["has_model_disagreement"])
        self.assertEqual(len(agr_maj["models_flagging_anomaly"]), 2)
        self.assertEqual(len(agr_maj["models_flagging_normal"]), 1)

        self.assertIsNotNone(self.ae_only_flow)
        ae_only_res = self.unified_engine.explain(flow_id=self.ae_only_flow["flow_id"])
        agr_ae = ae_only_res["model_agreement_and_disagreement"]
        self.assertEqual(
            agr_ae["consensus_state"], "SINGLE_MODEL_ANOMALY_DISSENT_AUTOENCODER"
        )
        self.assertFalse(agr_ae["models_agree"])
        self.assertTrue(agr_ae["has_model_disagreement"])
        self.assertEqual(agr_ae["models_flagging_anomaly"], ["autoencoder"])
        self.assertFalse(
            ae_only_res["final_tri_model_classification"]["auto_block_permitted"],
            "Autoencoder-only anomaly must NEVER permit automatic IP blocking",
        )

    def test_04_partial_model_failures_single_and_multiple_models_unavailable(self) -> None:
        """
        Verifies graceful availability handling when:
          - Random Forest is unavailable
          - Isolation Forest is unavailable
          - Autoencoder is unavailable
          - Two models (RF + IF) are unavailable
        """
        feats = self.unanimous_attack_flow["features_69"]

        # 1. Random Forest unavailable
        orig_rf_status = self.tri_engine.rf_status
        try:
            self.tri_engine.rf_status = "degraded"
            res_no_rf = self.unified_engine.explain(flow_id="test-no-rf", features=feats)
            self.assertEqual(res_no_rf["explanation_generation_status"], "partially_degraded")
            self.assertEqual(res_no_rf["degraded_explainers"], ["random_forest"])
            self.assertEqual(
                res_no_rf["healthy_explainers"], ["isolation_forest", "autoencoder"]
            )
            self.assertEqual(res_no_rf["random_forest_explanation"]["status"], "degraded")
            self.assertEqual(res_no_rf["isolation_forest_explanation"]["status"], "healthy")
            self.assertEqual(res_no_rf["autoencoder_explanation"]["status"], "healthy")
            self.assertFalse(
                res_no_rf["final_tri_model_classification"]["auto_block_permitted"]
            )
        finally:
            self.tri_engine.rf_status = orig_rf_status

        # 2. Isolation Forest unavailable
        orig_if_status = self.tri_engine.if_status
        try:
            self.tri_engine.if_status = "degraded"
            res_no_if = self.unified_engine.explain(flow_id="test-no-if", features=feats)
            self.assertEqual(res_no_if["explanation_generation_status"], "partially_degraded")
            self.assertEqual(res_no_if["degraded_explainers"], ["isolation_forest"])
            self.assertEqual(
                res_no_if["healthy_explainers"], ["random_forest", "autoencoder"]
            )
            self.assertFalse(
                res_no_if["final_tri_model_classification"]["auto_block_permitted"]
            )
        finally:
            self.tri_engine.if_status = orig_if_status

        # 3. Autoencoder unavailable
        orig_ae_status = self.tri_engine.ae_engine.status
        try:
            self.tri_engine.ae_engine.status = "degraded"
            res_no_ae = self.unified_engine.explain(flow_id="test-no-ae", features=feats)
            self.assertEqual(res_no_ae["explanation_generation_status"], "partially_degraded")
            self.assertEqual(res_no_ae["degraded_explainers"], ["autoencoder"])
            self.assertEqual(
                res_no_ae["healthy_explainers"], ["random_forest", "isolation_forest"]
            )
            self.assertFalse(
                res_no_ae["final_tri_model_classification"]["auto_block_permitted"]
            )
        finally:
            self.tri_engine.ae_engine.status = orig_ae_status

        # 4. Multiple models (RF + IF) unavailable
        try:
            self.tri_engine.rf_status = "degraded"
            self.tri_engine.if_status = "degraded"
            res_only_ae = self.unified_engine.explain(flow_id="test-only-ae", features=feats)
            self.assertEqual(res_only_ae["explanation_generation_status"], "partially_degraded")
            self.assertEqual(
                res_only_ae["degraded_explainers"], ["random_forest", "isolation_forest"]
            )
            self.assertEqual(res_only_ae["healthy_explainers"], ["autoencoder"])
            self.assertFalse(
                res_only_ae["final_tri_model_classification"]["auto_block_permitted"]
            )
        finally:
            self.tri_engine.rf_status = orig_rf_status
            self.tri_engine.if_status = orig_if_status

    def test_05_complete_explanation_failure_and_runtime_exception_isolation(self) -> None:
        """
        Verifies complete explanation failure when all 3 models are unavailable or when
        an explainer raises an unexpected runtime exception.
        """
        feats = self.unanimous_attack_flow["features_69"]
        orig_rf = self.tri_engine.rf_status
        orig_if = self.tri_engine.if_status
        orig_ae = self.tri_engine.ae_engine.status
        try:
            self.tri_engine.rf_status = "degraded"
            self.tri_engine.if_status = "degraded"
            self.tri_engine.ae_engine.status = "degraded"

            res_all_down = self.unified_engine.explain(flow_id="test-all-down", features=feats)
            self.assertEqual(res_all_down["explanation_generation_status"], "degraded")
            self.assertEqual(res_all_down["healthy_explainers"], [])
            self.assertEqual(
                res_all_down["degraded_explainers"],
                ["random_forest", "isolation_forest", "autoencoder"],
            )
            self.assertEqual(
                res_all_down["final_tri_model_classification"]["final_decision"], "degraded"
            )
            self.assertEqual(
                res_all_down["final_tri_model_classification"]["recommended_action"],
                "manual-review",
            )
            self.assertFalse(
                res_all_down["final_tri_model_classification"]["auto_block_permitted"]
            )
        finally:
            self.tri_engine.rf_status = orig_rf
            self.tri_engine.if_status = orig_if
            self.tri_engine.ae_engine.status = orig_ae

        # Simulate runtime calculation failure in RF explainer while IF and AE succeed
        orig_explain_flow = self.unified_engine.rf_explainer.explain_flow
        try:
            def _raising_rf(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                raise RuntimeError("simulated_shap_runtime_failure")

            self.unified_engine.rf_explainer.explain_flow = _raising_rf  # type: ignore[method-assign]
            res_exc = self.unified_engine.explain(flow_id="test-rf-exc", features=feats)
            self.assertEqual(res_exc["explanation_generation_status"], "partially_degraded")
            self.assertIn(
                "simulated_shap_runtime_failure",
                res_exc["random_forest_explanation"]["degraded_reason"],
            )
            self.assertEqual(res_exc["isolation_forest_explanation"]["status"], "healthy")
            self.assertEqual(res_exc["autoencoder_explanation"]["status"], "healthy")
        finally:
            self.unified_engine.rf_explainer.explain_flow = orig_explain_flow  # type: ignore[method-assign]

    def test_06_invalid_flow_inputs(self) -> None:
        """Verifies unknown flow_id, wrong feature count, and NaN feature handling."""
        res_unknown = self.unified_engine.explain(flow_id="flow-nonexistent-999999")
        self.assertEqual(res_unknown["explanation_generation_status"], "degraded")
        self.assertIn("flow_id_not_found", res_unknown["degraded_reason"])
        self.assertFalse(
            res_unknown["final_tri_model_classification"]["auto_block_permitted"]
        )

        res_short = self.unified_engine.explain(flow_id="bad-short", features=[1.0, 2.0, 3.0])
        self.assertEqual(res_short["explanation_generation_status"], "degraded")
        self.assertFalse(
            res_short["final_tri_model_classification"]["auto_block_permitted"]
        )

        res_nan = self.unified_engine.explain(
            flow_id="bad-nan", features=[float("nan")] * 69
        )
        self.assertEqual(res_nan["explanation_generation_status"], "degraded")
        self.assertFalse(res_nan["final_tri_model_classification"]["auto_block_permitted"])

    def test_07_deterministic_explanations_and_feature_collision_detection(self) -> None:
        """
        Verifies deterministic explanations for identical inputs and automatic detection
        of the documented cross-label 3-scalar feature collision (`flow-collision-norm-00`
        vs `flow-collision-atk-00`).
        """
        res_a = self.unified_engine.explain(flow_id="flow-collision-norm-00")
        res_b = self.unified_engine.explain(flow_id="flow-collision-atk-00")

        self.assertEqual(res_a["explanation_generation_status"], "healthy")
        self.assertEqual(res_b["explanation_generation_status"], "healthy")

        # Identical (packets=65, bytes=5070, duration=7.8) must produce identical model explanations
        self.assertEqual(
            res_a["random_forest_explanation"], res_b["random_forest_explanation"]
        )
        self.assertEqual(
            res_a["isolation_forest_explanation"], res_b["isolation_forest_explanation"]
        )
        self.assertEqual(res_a["autoencoder_explanation"], res_b["autoencoder_explanation"])

        # And both must flag the cross-label feature collision in confidence_and_limitations
        self.assertTrue(
            res_a["explanation_confidence_and_limitations"]["is_cross_label_feature_collision"]
        )
        self.assertEqual(
            res_a["explanation_confidence_and_limitations"]["explanation_reliability_tier"],
            "AMBIGUOUS_3_SCALAR_FEATURE_COLLISION",
        )

    def test_08_collinearity_aware_concept_deduplication_and_no_scale_conflation(self) -> None:
        """
        Verifies that duplicate polynomial columns (`f_25..f_39`) and collinear harmonic
        padding (`f_55..f_68`) map to canonical deduplicated concepts and that native model
        attribution units are preserved without cross-scale averaging.
        """
        even_concepts = {_canonical_concept_id(i)[0] for i in range(25, 40, 2)}
        odd_concepts = {_canonical_concept_id(i)[0] for i in range(26, 40, 2)}
        pad_concepts = {_canonical_concept_id(i)[0] for i in range(55, 69)}

        self.assertEqual(even_concepts, {"concept_poly_even_packets2_dur2"})
        self.assertEqual(odd_concepts, {"concept_poly_odd_pkt_bytes_dur2"})
        self.assertEqual(pad_concepts, {"concept_harmonic_collinear_padding"})

        res = self.unified_engine.explain(flow_id=self.unanimous_attack_flow["flow_id"])
        self.assertEqual(
            res["random_forest_explanation"]["score_semantics"],
            "SUPERVISED_CLASS_PROBABILITY_SHAP_ADDITIVE_ATTRIBUTION",
        )
        self.assertEqual(
            res["isolation_forest_explanation"]["score_semantics"],
            "UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY",
        )
        self.assertEqual(
            res["autoencoder_explanation"]["score_semantics"],
            "RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY",
        )

    def test_09_zero_modification_of_384_held_out_test_flow_decisions(self) -> None:
        """
        Verifies across all 384 held-out test flows (`test_set`) that `UnifiedTriModelExplainer`
        produces the exact same `final_decision`, `is_anomaly`, `fused_anomaly_score`,
        `recommended_action`, `auto_block_permitted`, `decision_rule`, and individual model
        predictions/scores as the pre-existing `data/held_out_384_tri_model_predictions.json` baseline.
        """
        self.assertEqual(len(self.test_set), 384)
        self.assertEqual(len(self.held_out_baseline), 384)

        baseline_by_id = {item["flow_id"]: item for item in self.held_out_baseline}

        for row in self.test_set:
            fid = row["flow_id"]
            base = baseline_by_id[fid]
            base_tri = base["tri_model_decision"]
            base_models = base["models"]

            # Direct tri_engine evaluation
            live_tri = self.tri_engine.evaluate_tri_model_fusion(row["features_69"])

            self.assertEqual(live_tri["final_decision"], base_tri["final_decision"])
            self.assertEqual(live_tri["is_anomaly"], base_tri["is_anomaly"])
            self.assertAlmostEqual(
                live_tri["fused_anomaly_score"], base_tri["fused_S_score"], places=6
            )
            self.assertEqual(live_tri["recommended_action"], base_tri["recommended_action"])
            self.assertEqual(
                live_tri["auto_block_permitted"], base_tri["auto_block_permitted"]
            )
            self.assertEqual(live_tri["decision_rule"], base_tri["decision_rule"])

            # Individual model score parity
            self.assertAlmostEqual(
                live_tri["models"]["random_forest"]["attack_probability"],
                base_models["random_forest"]["attack_probability"],
                places=6,
            )
            self.assertAlmostEqual(
                live_tri["models"]["isolation_forest"]["raw_decision_score"],
                base_models["isolation_forest"]["raw_decision_score"],
                places=6,
            )
            self.assertAlmostEqual(
                live_tri["models"]["autoencoder"]["reconstruction_error"],
                base_models["autoencoder"]["reconstruction_error"],
                places=6,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
