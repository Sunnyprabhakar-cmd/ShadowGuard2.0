"""
Shadow Guard 2.0 — Dedicated Python Unit-Test Suite for Authoritative PyTorch Autoencoder & Tri-Model Fusion
============================================================================================================

Covers:
1. Canonical 69-feature schema & mathematical redundancy audit (`shared/ml/feature_schema.py`).
2. Full-record-identity deduplication & cross-label feature-collision preservation.
3. `FeaturePreprocessor` fitting, round-trip state serialization, clipping, and invalid-input rejection.
4. Authoritative PyTorch `FlowAutoencoder` architecture (`69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69`)
   and mini-batch training convergence (`train_pytorch_autoencoder`).
5. Validation-only threshold calibration (`P95 < P97 < P99`) and P97 validation FPR constraint (<= 3.5%).
6. Checkpoint persistence, SHA-256 verification, and tamper detection -> `degraded` state.
7. `AutoencoderInferenceEngine` normal / suspicious / anomalous classification and failure handling.
8. `TriModelDetectionEngine` & `MLDetectionServiceCore` tri-model fusion policies, RF confidence-rule
   fix, degraded-mode handling, and non-auto-block guardrails on Autoencoder-only detections.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import importlib.util
from scripts.train_autoencoder_v2 import train_pytorch_autoencoder
from shared.ml.autoencoder_model import (
    AutoencoderInferenceEngine,
    FeaturePreprocessor,
    FlowAutoencoder,
)
from shared.ml.feature_schema import (
    EXPECTED_FEATURE_COUNT,
    FEATURE_NAMES_69,
    FEATURE_SCHEMA_VERSION,
    audit_69_feature_mathematics,
    deduplicate_and_audit_records,
    extract_69_features,
    validate_event_for_69_features,
)
from shared.ml.tri_model_fusion import TriModelDetectionEngine


def load_ml_detection_core(models_dir: Path):
    spec = importlib.util.spec_from_file_location(
        "ml_detection_service_main", ROOT_DIR / "ml-detection-service" / "main.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.MLDetectionServiceCore(models_dir)


class TestAutoencoderAndTriModelFusion(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.models_dir = ROOT_DIR / "models"
        cls.dataset_path = ROOT_DIR / "data" / "autoencoder_flow_dataset_v2.json"
        with cls.dataset_path.open("r", encoding="utf-8") as f:
            cls.dataset = json.load(f)

    def test_01_feature_schema_and_mathematical_audit(self) -> None:
        vec = extract_69_features({"packets": 40, "bytes": 28000, "duration": 1.25})
        self.assertEqual(len(vec), EXPECTED_FEATURE_COUNT)
        self.assertEqual(len(FEATURE_NAMES_69), 69)

        samples = [
            extract_69_features({"packets": 10 + i * 5, "bytes": 4000 + i * 1200, "duration": 0.2 + i * 0.1})
            for i in range(30)
        ]
        audit = audit_69_feature_mathematics(samples)
        self.assertEqual(audit["schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertEqual(audit["duplicate_columns_count"], 13)
        self.assertTrue(audit["padding_f55_to_f68_rank1_collinear"])

        # Non-fabricating flow validator
        ineligible = validate_event_for_69_features({"event_id": "e1", "telemetry": {"packet_count": 0, "byte_count": 0}})
        self.assertFalse(ineligible["eligible"])
        eligible = validate_event_for_69_features({"packets": 15, "bytes": 9000, "duration": 0.4})
        self.assertTrue(eligible["eligible"])

    def test_02_deduplication_and_feature_collision_preservation(self) -> None:
        r1 = {
            "flow_id": "f-1",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 50001,
            "dst_port": 443,
            "protocol": "TCP",
            "timestamp": "2026-11-13T00:00:01Z",
            "packets": 20,
            "bytes": 10000,
            "duration": 0.5,
            "label": "normal",
        }
        # Exact duplicate of r1
        r1_dup = dict(r1)
        # Distinct flow with identical (packets, bytes, duration) and opposite label -> feature collision!
        r2_collision = {
            "flow_id": "f-2-atk",
            "src_ip": "198.51.100.99",
            "dst_ip": "10.0.0.2",
            "src_port": 60002,
            "dst_port": 443,
            "protocol": "TCP",
            "timestamp": "2026-11-13T00:05:00Z",
            "packets": 20,
            "bytes": 10000,
            "duration": 0.5,
            "label": "attack",
        }
        # Contradictory source record with the SAME flow_id as r3
        r3_a = {
            "flow_id": "f-corrupt-same",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.8",
            "src_port": 51111,
            "dst_port": 80,
            "protocol": "TCP",
            "timestamp": "2026-11-13T00:10:00Z",
            "packets": 12,
            "bytes": 6000,
            "duration": 0.3,
            "label": "normal",
        }
        r3_b = dict(r3_a, label="attack")

        res = deduplicate_and_audit_records([r1, r1_dup, r2_collision, r3_a, r3_b])
        self.assertEqual(res["exact_duplicates_removed"], 1)
        self.assertEqual(res["corrupted_or_contradictory_source_records_quarantined"], 2)
        self.assertEqual(res["feature_collision_ambiguity_flows_preserved"], 2)
        self.assertEqual(res["clean_records_count"], 2)

    def test_03_preprocessor_fitting_and_serialization(self) -> None:
        train_normal = self.dataset["splits"]["train_normal"][:120]
        X_norm = np.asarray([r["features_69"] for r in train_normal], dtype=np.float64)

        pre = FeaturePreprocessor(clip_bound=10.0)
        X_scaled = pre.fit_transform(X_norm)
        self.assertEqual(X_scaled.shape, (120, 69))
        self.assertTrue(np.all(np.isfinite(X_scaled)))
        self.assertLessEqual(float(np.max(np.abs(X_scaled))), 10.0)

        # Round-trip state_dict
        restored = FeaturePreprocessor.from_state_dict(pre.to_state_dict())
        X_restored = restored.transform(X_norm)
        np.testing.assert_allclose(X_scaled, X_restored, rtol=1e-6, atol=1e-6)

        # Reject wrong dimensions and NaNs
        with self.assertRaises(ValueError):
            pre.transform([1.0, 2.0, 3.0])
        bad_vec = list(X_norm[0])
        bad_vec[0] = float("nan")
        with self.assertRaises(ValueError):
            pre.transform(bad_vec)

    def test_04_pytorch_autoencoder_architecture_and_training(self) -> None:
        model = FlowAutoencoder(input_dim=69, enc1_dim=32, enc2_dim=16, bottleneck_dim=8)
        x = torch.randn(10, 69)
        z = model.encode(x)
        out = model(x)
        self.assertEqual(tuple(z.shape), (10, 8))
        self.assertEqual(tuple(out.shape), (10, 69))

        # Mini-training convergence test on subset of normal flows
        train_normal = self.dataset["splits"]["train_normal"][:160]
        val_normal = self.dataset["splits"]["val_normal"][:40]
        pre = FeaturePreprocessor()
        X_tr = pre.fit_transform([r["features_69"] for r in train_normal])
        X_va = pre.transform([r["features_69"] for r in val_normal])

        trained_model, summary = train_pytorch_autoencoder(
            X_train_scaled=X_tr,
            X_val_scaled=X_va,
            batch_size=32,
            max_epochs=15,
            learning_rate=0.003,
            patience=10,
            seed=42,
        )
        self.assertIsInstance(trained_model, FlowAutoencoder)
        self.assertLess(summary["best_val_mse"], summary["initial_val_mse"])

    def test_05_threshold_calibration_and_p97_justification(self) -> None:
        meta_path = self.models_dir / "autoencoder_metadata.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        cal = meta["validation_threshold_calibration"]

        p95 = cal["candidates"]["P95"]
        p97 = cal["candidates"]["P97"]
        p99 = cal["candidates"]["P99"]

        self.assertLess(p95["threshold"], p97["threshold"])
        self.assertLess(p97["threshold"], p99["threshold"])
        # Verify validation FPR operating requirement: P95 exceeds 3.5% (5.0%), P97 satisfies <= 3.5% (3.33%)
        self.assertGreater(p95["val_normal_false_positive_rate"], 0.035)
        self.assertLessEqual(p97["val_normal_false_positive_rate"], 0.035)
        self.assertEqual(meta["selected_threshold_percentile"], "P97")
        self.assertIn("val_normal", cal["selection_justification"])
        self.assertEqual(meta["benchmark_classification"], "SYNTHETIC_BENCHMARK_ONLY")

    def test_06_checkpoint_tamper_and_failure_handling(self) -> None:
        engine = AutoencoderInferenceEngine(self.models_dir)
        self.assertEqual(engine.status, "healthy")

        norm_vec = extract_69_features({"packets": 30, "bytes": 21000, "duration": 1.5})
        res_ok = engine.score_features(norm_vec)
        self.assertEqual(res_ok["status"], "healthy")
        self.assertFalse(res_ok["is_anomaly"])

        # Dimension mismatch -> degraded
        res_dim = engine.score_features([0.5] * 10)
        self.assertEqual(res_dim["status"], "degraded")
        self.assertIsNone(res_dim["is_anomaly"])

        # Checksum tamper detection in temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for fname in [
                "autoencoder_model.pt",
                "autoencoder_preprocessor.pkl",
                "autoencoder_metadata.json",
            ]:
                shutil.copy2(self.models_dir / fname, tmp_path / fname)

            # Tamper with expected SHA-256 in metadata
            meta_file = tmp_path / "autoencoder_metadata.json"
            meta_obj = json.loads(meta_file.read_text(encoding="utf-8"))
            meta_obj["artifact_checksums"]["autoencoder_model_pt_sha256"] = "0" * 64
            meta_file.write_text(json.dumps(meta_obj), encoding="utf-8")

            tampered_engine = AutoencoderInferenceEngine(tmp_path)
            self.assertEqual(tampered_engine.status, "degraded")
            self.assertEqual(tampered_engine.degraded_reason, "model_checkpoint_sha256_mismatch")
            res_tampered = tampered_engine.score_features(norm_vec)
            self.assertEqual(res_tampered["status"], "degraded")
            self.assertIsNone(res_tampered["is_anomaly"])

    def test_07_tri_model_fusion_and_guardrails(self) -> None:
        tri = TriModelDetectionEngine(self.models_dir)
        health = tri.get_health_summary()
        self.assertEqual(health["status"], "healthy")

        # 1. Normal flow -> all models normal, monitor, auto_block_permitted=False
        norm_vec = extract_69_features({"packets": 35, "bytes": 24500, "duration": 1.8})
        f_norm = tri.evaluate_tri_model_fusion(norm_vec)
        self.assertEqual(f_norm["fusion_status"], "healthy")
        self.assertEqual(f_norm["final_decision"], "normal")
        self.assertFalse(f_norm["is_anomaly"])
        self.assertFalse(f_norm["auto_block_permitted"])
        self.assertEqual(f_norm["recommended_action"], "monitor")
        # RF confidence rule fix: benign_probability > 0.80, attack_probability < 0.20
        self.assertLess(f_norm["models"]["random_forest"]["attack_probability"], 0.20)
        self.assertGreater(f_norm["models"]["random_forest"]["benign_probability"], 0.80)

        # 2. Extreme DDoS flow -> multi-model confirmed threat
        ddos_vec = extract_69_features({"packets": 3000, "bytes": 4200000, "duration": 0.06})
        f_ddos = tri.evaluate_tri_model_fusion(ddos_vec)
        self.assertEqual(f_ddos["final_decision"], "anomalous")
        self.assertTrue(f_ddos["is_anomaly"])
        self.assertIn("autoencoder", f_ddos["models_agreeing_on_anomaly"])

        # 3. Degraded input -> explicit degraded status, never silent normal or auto-block
        f_bad = tri.evaluate_tri_model_fusion([1.0, 2.0])
        self.assertEqual(f_bad["fusion_status"], "degraded")
        self.assertEqual(f_bad["final_decision"], "degraded")
        self.assertIsNone(f_bad["is_anomaly"])
        self.assertFalse(f_bad["auto_block_permitted"])
        self.assertEqual(f_bad["recommended_action"], "manual-review")

        # 4. MLDetectionServiceCore integration
        core = load_ml_detection_core(self.models_dir)
        det_res = core.handle_detect({"features": ddos_vec}, forward_downstream=False)
        self.assertIn("anomaly_score", det_res)
        self.assertIn("is_anomaly", det_res)
        self.assertIn("autoencoder", det_res)
        self.assertIn("tri_model_fusion", det_res)
        self.assertTrue(det_res["is_anomaly"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAutoencoderAndTriModelFusion)
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
