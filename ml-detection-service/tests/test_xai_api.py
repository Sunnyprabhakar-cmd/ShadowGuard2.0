"""
Shadow Guard 2.0 — XAI Stage 3 Python ML Service API Test Suite
================================================================
Tests `/xai/health`, `/xai/explain`, `/xai/explain/batch`, input validation,
partial model degradation, and 100% backward compatibility with `/detect` and
`/detect/tri-model` via `dispatch_raw_http_request` (no model reloading per request).
"""

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ML_SVC_DIR = REPO_ROOT / "ml-detection-service"
for p in (str(ML_SVC_DIR), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from main import core_service, dispatch_raw_http_request  # noqa: E402


class TestXAIStage3PythonAPI(unittest.TestCase):
    """Tests Python XAI REST endpoints and detection backward compatibility."""

    @classmethod
    def setUpClass(cls) -> None:
        raw_ds = json.loads(
            (REPO_ROOT / "data" / "autoencoder_flow_dataset_v2.json").read_text(encoding="utf-8")
        )
        cls.test_set = raw_ds["splits"]["test_set"]
        cls.sample_atk = next(r for r in cls.test_set if r["flow_id"] == "flow-atk-01404")
        cls.sample_norm = next(r for r in cls.test_set if r["flow_id"] == "flow-norm-00293")

    def test_01_get_xai_health(self) -> None:
        res = dispatch_raw_http_request("GET", "/xai/health")
        self.assertEqual(res["statusCode"], 200)
        body = res["body"]
        self.assertEqual(body["status"], "healthy")
        self.assertEqual(body["schema_version"], "v2.0-69dim")
        self.assertEqual(body["expected_feature_count"], 69)
        self.assertGreaterEqual(body["catalog_flows_count"], 1524)
        self.assertTrue(body["explainers"]["random_forest"]["is_exact_shap"])

    def test_02_post_xai_explain_by_flow_id_and_features(self) -> None:
        res_id = dispatch_raw_http_request(
            "POST", "/xai/explain", {"flow_id": "flow-atk-01404", "top_k": 5}
        )
        self.assertEqual(res_id["statusCode"], 200)
        b1 = res_id["body"]
        self.assertEqual(b1["flow_id"], "flow-atk-01404")
        self.assertEqual(b1["explanation_generation_status"], "healthy")
        self.assertEqual(b1["final_tri_model_classification"]["final_decision"], "anomalous")
        self.assertTrue(b1["random_forest_explanation"]["is_exact_shap"])

        res_vec = dispatch_raw_http_request(
            "POST",
            "/xai/explain",
            {"flow_id": "flow-norm-00293", "features": self.sample_norm["features_69"]},
        )
        self.assertEqual(res_vec["statusCode"], 200)
        b2 = res_vec["body"]
        self.assertEqual(b2["final_tri_model_classification"]["final_decision"], "normal")

    def test_03_post_xai_explain_validation_errors(self) -> None:
        # 1. Invalid flow_id characters (path traversal attempt)
        res_bad_id = dispatch_raw_http_request(
            "POST", "/xai/explain", {"flow_id": "../etc/passwd"}
        )
        self.assertEqual(res_bad_id["statusCode"], 400)

        # 2. Unknown flow_id -> 404
        res_missing = dispatch_raw_http_request(
            "POST", "/xai/explain", {"flow_id": "flow-does-not-exist-999"}
        )
        self.assertEqual(res_missing["statusCode"], 404)

        # 3. Wrong feature dimension -> 400
        res_dim = dispatch_raw_http_request(
            "POST", "/xai/explain", {"flow_id": "bad-dim", "features": [1.0, 2.0, 3.0]}
        )
        self.assertEqual(res_dim["statusCode"], 400)

        # 4. Unsupported fusion policy -> 400
        res_pol = dispatch_raw_http_request(
            "POST", "/xai/explain", {"flow_id": "flow-norm-00293", "policy": "invalid_policy"}
        )
        self.assertEqual(res_pol["statusCode"], 400)

    def test_04_post_xai_explain_batch(self) -> None:
        res = dispatch_raw_http_request(
            "POST",
            "/xai/explain/batch",
            {
                "items": [
                    {"flow_id": "flow-atk-01404"},
                    {"flow_id": "flow-norm-00293"},
                ],
                "policy": "weighted_consensus",
            },
        )
        self.assertEqual(res["statusCode"], 200)
        body = res["body"]
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["total_requested"], 2)
        self.assertEqual(body["succeeded_count"], 2)
        self.assertEqual(body["degraded_count"], 0)
        self.assertEqual(len(body["results"]), 2)

    def test_05_partial_model_degradation_via_api(self) -> None:
        orig_rf = core_service.engine.rf_status
        try:
            core_service.engine.rf_status = "degraded"
            res = dispatch_raw_http_request(
                "POST", "/xai/explain", {"flow_id": "flow-atk-01404"}
            )
            self.assertEqual(res["statusCode"], 200)
            body = res["body"]
            self.assertEqual(body["explanation_generation_status"], "partially_degraded")
            self.assertEqual(body["degraded_explainers"], ["random_forest"])
            self.assertFalse(body["final_tri_model_classification"]["auto_block_permitted"])
        finally:
            core_service.engine.rf_status = orig_rf

    def test_06_detect_endpoints_unchanged_after_xai_calls(self) -> None:
        before = dispatch_raw_http_request(
            "POST", "/detect/tri-model", {"features": self.sample_atk["features_69"]}
        )
        _ = dispatch_raw_http_request("POST", "/xai/explain", {"flow_id": "flow-atk-01404"})
        after = dispatch_raw_http_request(
            "POST", "/detect/tri-model", {"features": self.sample_atk["features_69"]}
        )
        self.assertEqual(before["statusCode"], 200)
        self.assertEqual(after["statusCode"], 200)
        self.assertEqual(before["body"]["final_decision"], after["body"]["final_decision"])
        self.assertEqual(
            before["body"]["fused_anomaly_score"], after["body"]["fused_anomaly_score"]
        )
        self.assertEqual(
            before["body"]["auto_block_permitted"], after["body"]["auto_block_permitted"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
