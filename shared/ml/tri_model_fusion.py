"""
Shadow Guard 2.0 — Stage 3: Tri-Model Detection Fusion Engine (RF + IF + PyTorch Autoencoder)
=============================================================================================

Combines:
1. Supervised Random Forest (`random_forest_69_v2.pkl`)
   - Resolves the legacy confidence-rule bug where `max(probabilities)` treated a 0.95 benign
     probability as high-confidence threat. Explicitly extracts `attack_probability = P(class=1)`.
2. Unsupervised Isolation Forest (`isolation_forest_69_v2.pkl`)
   - Normalizes raw decision function scores relative to the validation-calibrated threshold.
3. Unsupervised PyTorch FlowAutoencoder (`AutoencoderInferenceEngine`)
   - Evaluates 69-dimensional reconstruction error (MSE) against validation-calibrated
     thresholds (`P95 = 0.409105` suspicious tier, `P97 = 0.503670` frozen anomaly threshold,
     `P99 = 0.645935` high-confidence anomaly tier).

Enforces Mandatory Safety Guardrails:
- Preserves individual model outputs (`random_forest`, `isolation_forest`, `autoencoder`).
- Model or input failures produce explicit `degraded` status (`fusion_status = "degraded"` or
  `"partially_degraded"`), NEVER silent normal classification (`monitor`) or automatic IP blocking.
- Autoencoder-only detections (`AE_ONLY`) NEVER permit automatic IP blocking (`auto_block_permitted = False`);
  they route to `alert` or `manual-review` for correlation with NIDS/Honeypot telemetry.
"""

from __future__ import annotations

import math
import pickle
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from shared.ml.autoencoder_model import AutoencoderInferenceEngine
from shared.ml.feature_schema import (
    EXPECTED_FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
)


def _sigmoid(x: float) -> float:
    x_clipped = max(-20.0, min(20.0, float(x)))
    return 1.0 / (1.0 + math.exp(-x_clipped))


class TriModelDetectionEngine:
    """
    Unified inference and Tri-Model Detection Fusion engine for Shadow Guard 2.0.
    """

    def __init__(self, models_dir: Optional[Path] = None) -> None:
        root_default = Path(__file__).resolve().parent.parent.parent / "models"
        self.models_dir: Path = Path(models_dir) if models_dir is not None else root_default

        self.ae_engine: AutoencoderInferenceEngine = AutoencoderInferenceEngine()
        self.rf_bundle: Optional[Dict[str, Any]] = None
        self.rf_status: str = "degraded"
        self.rf_degraded_reason: Optional[str] = "uninitialized"

        self.if_bundle: Optional[Dict[str, Any]] = None
        self.if_status: str = "degraded"
        self.if_degraded_reason: Optional[str] = "uninitialized"

        self.load_all_models(self.models_dir)

    def load_all_models(self, models_dir: Optional[Path] = None) -> Dict[str, Any]:
        if models_dir is not None:
            self.models_dir = Path(models_dir)

        # 1. Load Authoritative PyTorch Autoencoder (with SHA-256 and schema verification)
        self.ae_engine.load_artifacts(self.models_dir, verify_checksums=True)

        # 2. Load 69-feature Isolation Forest
        self._load_isolation_forest(self.models_dir)

        # 3. Load 69-feature Random Forest
        self._load_random_forest(self.models_dir)

        return self.get_health_summary()

    def _load_isolation_forest(self, models_dir: Path) -> None:
        candidates = [
            models_dir / "isolation_forest_69_v2.pkl",
            models_dir / "isolation_forest_model.pkl",
            models_dir / "isolation_forest.pkl",
        ]
        for path in candidates:
            if path.exists():
                try:
                    with path.open("rb") as f:
                        data = pickle.load(f)
                    if isinstance(data, dict) and "isolation_forest" in data and "scaler" in data:
                        self.if_bundle = {
                            "model": data["isolation_forest"],
                            "scaler": data["scaler"],
                            "threshold": float(data.get("best_threshold", 0.0)),
                            "schema_version": str(data.get("schema_version", FEATURE_SCHEMA_VERSION)),
                            "artifact_path": str(path.name),
                        }
                        self.if_status = "healthy"
                        self.if_degraded_reason = None
                        return
                except Exception as exc:
                    self.if_status = "degraded"
                    self.if_degraded_reason = f"if_load_error:{type(exc).__name__}:{exc}"
                    self.if_bundle = None
                    return

        self.if_status = "degraded"
        self.if_degraded_reason = "missing_isolation_forest_artifact"
        self.if_bundle = None

    def _load_random_forest(self, models_dir: Path) -> None:
        candidates = [
            models_dir / "random_forest_69_v2.pkl",
            models_dir / "random_forest_model.pkl",
            models_dir / "random_forest.pkl",
        ]
        for path in candidates:
            if path.exists():
                try:
                    with path.open("rb") as f:
                        data = pickle.load(f)
                    if isinstance(data, dict) and "model" in data:
                        self.rf_bundle = {
                            "model": data["model"],
                            "scaler": data.get("scaler"),
                            "threshold": float(data.get("calibrated_prob_threshold", 0.50)),
                            "schema_version": str(data.get("schema_version", FEATURE_SCHEMA_VERSION)),
                            "artifact_path": str(path.name),
                        }
                    else:
                        self.rf_bundle = {
                            "model": data,
                            "scaler": None,
                            "threshold": 0.50,
                            "schema_version": FEATURE_SCHEMA_VERSION,
                            "artifact_path": str(path.name),
                        }
                    self.rf_status = "healthy"
                    self.rf_degraded_reason = None
                    return
                except Exception as exc:
                    self.rf_status = "degraded"
                    self.rf_degraded_reason = f"rf_load_error:{type(exc).__name__}:{exc}"
                    self.rf_bundle = None
                    return

        self.rf_status = "degraded"
        self.rf_degraded_reason = "missing_random_forest_artifact"
        self.rf_bundle = None

    @staticmethod
    def _validate_69_features(features: Any) -> Optional[np.ndarray]:
        if not isinstance(features, (list, tuple, np.ndarray)):
            return None
        try:
            arr = np.asarray(features, dtype=np.float64)
        except (ValueError, TypeError):
            return None
        if arr.ndim != 1 or arr.shape[0] != EXPECTED_FEATURE_COUNT:
            return None
        if not np.all(np.isfinite(arr)):
            return None
        return arr

    def score_isolation_forest(self, features: List[float]) -> Dict[str, Any]:
        t0 = time.perf_counter()
        if self.if_status != "healthy" or self.if_bundle is None:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "anomaly_score": None,
                "raw_decision_score": None,
                "threshold": None,
                "degraded_reason": self.if_degraded_reason or "isolation_forest_not_loaded",
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        arr = self._validate_69_features(features)
        if arr is None:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "anomaly_score": None,
                "raw_decision_score": None,
                "threshold": self.if_bundle["threshold"],
                "degraded_reason": f"invalid_input_features_expected_{EXPECTED_FEATURE_COUNT}_finite_floats",
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        try:
            X_2d = arr.reshape(1, -1)
            scaler = self.if_bundle.get("scaler")
            X_scaled = scaler.transform(X_2d) if scaler is not None else X_2d
            raw_score = float(self.if_bundle["model"].decision_function(X_scaled)[0])
            thresh = float(self.if_bundle["threshold"])
            is_anom = bool(raw_score < thresh)
            # In IsolationForest, lower raw_score = more anomalous.
            # Map (thresh - raw_score) via sigmoid with scale=0.08 so raw_score == thresh -> 0.50
            norm_score = _sigmoid((thresh - raw_score) / 0.08)
            return {
                "status": "healthy",
                "decision": "anomalous" if is_anom else "normal",
                "is_anomaly": is_anom,
                "anomaly_score": round(float(norm_score), 6),
                "raw_decision_score": round(raw_score, 6),
                "threshold": round(thresh, 6),
                "degraded_reason": None,
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }
        except Exception as exc:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "anomaly_score": None,
                "raw_decision_score": None,
                "threshold": self.if_bundle["threshold"],
                "degraded_reason": f"if_inference_error:{exc}",
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

    def score_random_forest(self, features: List[float]) -> Dict[str, Any]:
        """
        Scores a 69-feature vector using Random Forest and resolves the legacy confidence-rule
        inconsistency by explicitly separating `attack_probability` (probability of non-benign
        traffic) from `predicted_class_confidence` (`max(probabilities)`).
        """
        t0 = time.perf_counter()
        if self.rf_status != "healthy" or self.rf_bundle is None:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "prediction": None,
                "attack_probability": None,
                "benign_probability": None,
                "predicted_class_confidence": None,
                "probabilities": [],
                "threshold": None,
                "degraded_reason": self.rf_degraded_reason or "random_forest_not_loaded",
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        arr = self._validate_69_features(features)
        if arr is None:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "prediction": None,
                "attack_probability": None,
                "benign_probability": None,
                "predicted_class_confidence": None,
                "probabilities": [],
                "threshold": self.rf_bundle["threshold"],
                "degraded_reason": f"invalid_input_features_expected_{EXPECTED_FEATURE_COUNT}_finite_floats",
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        try:
            X_2d = arr.reshape(1, -1)
            scaler = self.rf_bundle.get("scaler")
            X_scaled = scaler.transform(X_2d) if scaler is not None else X_2d
            probs = self.rf_bundle["model"].predict_proba(X_scaled)[0].tolist()
            benign_prob = float(probs[0]) if len(probs) > 0 else 0.0
            attack_prob = float(1.0 - benign_prob) if len(probs) > 1 else float(probs[0])
            thresh = float(self.rf_bundle["threshold"])
            is_attack = bool(attack_prob >= thresh)
            pred_class = 1 if is_attack else 0

            return {
                "status": "healthy",
                "decision": "anomalous" if is_attack else "normal",
                "is_anomaly": is_attack,
                "prediction": int(pred_class),
                "attack_probability": round(attack_prob, 6),
                "benign_probability": round(benign_prob, 6),
                "predicted_class_confidence": round(float(max(probs)), 6),
                "probabilities": [round(float(p), 6) for p in probs],
                "threshold": round(thresh, 6),
                "degraded_reason": None,
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }
        except Exception as exc:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "prediction": None,
                "attack_probability": None,
                "benign_probability": None,
                "predicted_class_confidence": None,
                "probabilities": [],
                "threshold": self.rf_bundle["threshold"],
                "degraded_reason": f"rf_inference_error:{exc}",
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

    def score_autoencoder(self, features: List[float], top_k: int = 5) -> Dict[str, Any]:
        return self.ae_engine.score_features(features, top_k=top_k)

    def evaluate_tri_model_fusion(
        self,
        features: List[float],
        policy: str = "weighted_consensus",
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes all three models (Random Forest, Isolation Forest, PyTorch Autoencoder),
        preserves each model's full output, and applies the specified Tri-Model Detection Fusion
        policy with explicit degraded-mode and SOAR non-auto-block guardrails.
        """
        t0 = time.perf_counter()
        rf_out = self.score_random_forest(features)
        if_out = self.score_isolation_forest(features)
        ae_out = self.score_autoencoder(features)

        statuses = {
            "random_forest": rf_out["status"],
            "isolation_forest": if_out["status"],
            "autoencoder": ae_out["status"],
        }
        degraded_models = [name for name, st in statuses.items() if st != "healthy"]
        healthy_models = [name for name, st in statuses.items() if st == "healthy"]

        # Case 1: All models degraded or invalid input vector -> explicit degraded output
        if len(healthy_models) == 0:
            return {
                "fusion_status": "degraded",
                "fusion_policy": policy,
                "final_decision": "degraded",
                "is_anomaly": None,
                "fused_anomaly_score": None,
                "severity": "degraded",
                "recommended_action": "manual-review",
                "auto_block_permitted": False,
                "decision_rule": "ALL_MODELS_OR_INPUT_DEGRADED",
                "degraded_models": degraded_models,
                "models_agreeing_on_anomaly": [],
                "models": {
                    "random_forest": rf_out,
                    "isolation_forest": if_out,
                    "autoencoder": ae_out,
                },
                "total_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        fusion_status = "healthy" if len(degraded_models) == 0 else "partially_degraded"

        # Compute weighted anomaly score over healthy models
        base_weights = {
            "random_forest": 0.45,
            "isolation_forest": 0.25,
            "autoencoder": 0.30,
        }
        if policy == "unsupervised_ensemble":
            base_weights = {
                "random_forest": 0.0,
                "isolation_forest": 0.45,
                "autoencoder": 0.55,
            }

        model_scores = {
            "random_forest": rf_out["attack_probability"] if rf_out["status"] == "healthy" else None,
            "isolation_forest": if_out["anomaly_score"] if if_out["status"] == "healthy" else None,
            "autoencoder": ae_out["anomaly_score"] if ae_out["status"] == "healthy" else None,
        }

        active_weight_sum = sum(
            w for m, w in base_weights.items() if model_scores.get(m) is not None and w > 0
        )
        if active_weight_sum > 0:
            fused_score = sum(
                base_weights[m] * float(model_scores[m])
                for m in base_weights
                if model_scores.get(m) is not None and base_weights[m] > 0
            ) / active_weight_sum
        else:
            # Fallback average over any healthy model
            valid_vals = [float(v) for v in model_scores.values() if v is not None]
            fused_score = sum(valid_vals) / len(valid_vals)

        rf_anom = bool(rf_out["is_anomaly"]) if rf_out["status"] == "healthy" else False
        if_anom = bool(if_out["is_anomaly"]) if if_out["status"] == "healthy" else False
        ae_anom = bool(ae_out["is_anomaly"]) if ae_out["status"] == "healthy" else False
        ae_susp = (ae_out.get("decision") == "suspicious") if ae_out["status"] == "healthy" else False
        rf_prob = float(rf_out["attack_probability"] or 0.0) if rf_out["status"] == "healthy" else 0.0
        ae_err = float(ae_out["reconstruction_error"] or 0.0) if ae_out["status"] == "healthy" else 0.0
        ae_p99 = float(self.ae_engine.threshold_p99 or 0.645935)

        agreeing_models = []
        if rf_anom:
            agreeing_models.append("random_forest")
        if if_anom:
            agreeing_models.append("isolation_forest")
        if ae_anom:
            agreeing_models.append("autoencoder")

        # Policy 1: Unsupervised Ensemble (IF + AE only)
        if policy == "unsupervised_ensemble":
            if if_anom and ae_anom:
                final_decision = "anomalous"
                is_anomaly = True
                severity = "high"
                recommended_action = "alert"
                decision_rule = "UNSUPERVISED_DUAL_CONFIRMATION"
            elif ae_anom:
                final_decision = "anomalous"
                is_anomaly = True
                severity = "medium"
                recommended_action = "alert" if ae_err > ae_p99 else "manual-review"
                decision_rule = "UNSUPERVISED_AE_ANOMALY"
            elif if_anom:
                final_decision = "anomalous"
                is_anomaly = True
                severity = "medium"
                recommended_action = "manual-review"
                decision_rule = "UNSUPERVISED_IF_ANOMALY"
            elif ae_susp:
                final_decision = "suspicious"
                is_anomaly = False
                severity = "low"
                recommended_action = "monitor"
                decision_rule = "UNSUPERVISED_AE_SUSPICIOUS_WARNING"
            else:
                final_decision = "normal"
                is_anomaly = False
                severity = "low"
                recommended_action = "monitor"
                decision_rule = "UNSUPERVISED_NORMAL"
            auto_block_permitted = False

        # Policy 2: 2-of-3 Majority Vote
        elif policy == "majority_vote":
            if len(agreeing_models) >= 2:
                final_decision = "anomalous"
                is_anomaly = True
                severity = "critical" if len(agreeing_models) == 3 else "high"
                auto_block_permitted = bool(rf_anom and rf_prob >= 0.85 and len(degraded_models) == 0)
                recommended_action = "block" if auto_block_permitted else "alert"
                decision_rule = f"MAJORITY_VOTE_{len(agreeing_models)}_OF_3"
            elif len(agreeing_models) == 1:
                final_decision = "suspicious"
                is_anomaly = False
                severity = "medium"
                auto_block_permitted = False
                recommended_action = "manual-review"
                decision_rule = f"SINGLE_MODEL_DISSENT_{agreeing_models[0].upper()}"
            else:
                final_decision = "normal"
                is_anomaly = False
                severity = "low"
                auto_block_permitted = False
                recommended_action = "monitor"
                decision_rule = "MAJORITY_NORMAL"

        # Policy 3 (Default): Calibrated Weighted Consensus with Degraded & Non-Auto-Block Guardrails
        else:
            if rf_anom and (if_anom or ae_anom or ae_susp):
                final_decision = "anomalous"
                is_anomaly = True
                severity = "critical" if (rf_anom and if_anom and ae_anom) else "high"
                # Never auto-block if any model is degraded
                auto_block_permitted = bool(rf_prob >= 0.85 and len(degraded_models) == 0)
                recommended_action = "block" if auto_block_permitted else "alert"
                decision_rule = "MULTI_MODEL_CONFIRMED_THREAT"
            elif rf_anom and rf_prob >= 0.70:
                final_decision = "anomalous"
                is_anomaly = True
                auto_block_permitted = bool(rf_prob >= 0.85 and len(degraded_models) == 0)
                severity = "high" if auto_block_permitted else "medium"
                recommended_action = "block" if auto_block_permitted else "alert"
                decision_rule = "SUPERVISED_RF_CONFIRMED_SIGNATURE"
            elif if_anom and ae_anom:
                final_decision = "anomalous"
                is_anomaly = True
                severity = "high"
                auto_block_permitted = False
                recommended_action = "alert"
                decision_rule = "DUAL_UNSUPERVISED_ANOMALY_CONSENSUS"
            elif ae_anom and not rf_anom and not if_anom:
                # Mandatory guardrail: Autoencoder-only anomaly NEVER automatically blocks an IP.
                auto_block_permitted = False
                if ae_err > ae_p99:
                    final_decision = "anomalous"
                    is_anomaly = True
                    severity = "medium"
                    recommended_action = "alert"
                    decision_rule = "AUTOENCODER_HIGH_CONFIDENCE_ANOMALY_P99_NO_AUTOBLOCK"
                else:
                    final_decision = "suspicious"
                    is_anomaly = True
                    severity = "medium"
                    recommended_action = "manual-review"
                    decision_rule = "AUTOENCODER_ONLY_ANOMALY_P97_MANUAL_REVIEW"
            elif if_anom and not rf_anom and not ae_anom:
                final_decision = "suspicious"
                is_anomaly = True
                severity = "low"
                auto_block_permitted = False
                recommended_action = "manual-review"
                decision_rule = "ISOLATION_FOREST_ONLY_ANOMALY_MANUAL_REVIEW"
            elif rf_anom:
                final_decision = "suspicious"
                is_anomaly = True
                severity = "medium"
                auto_block_permitted = False
                recommended_action = "alert"
                decision_rule = "SUPERVISED_RF_MODERATE_CONFIDENCE"
            elif ae_susp and rf_prob >= 0.20:
                final_decision = "suspicious"
                is_anomaly = False
                severity = "low"
                auto_block_permitted = False
                recommended_action = "monitor"
                decision_rule = "AUTOENCODER_SUSPICIOUS_P95_ELEVATED_RF"
            elif ae_susp:
                final_decision = "suspicious"
                is_anomaly = False
                severity = "low"
                auto_block_permitted = False
                recommended_action = "monitor"
                decision_rule = "AUTOENCODER_SUSPICIOUS_P95_WARNING"
            else:
                final_decision = "normal"
                is_anomaly = False
                severity = "low"
                auto_block_permitted = False
                recommended_action = "monitor"
                decision_rule = "ALL_MODELS_NORMAL"

        return {
            "fusion_status": fusion_status,
            "fusion_policy": policy,
            "final_decision": final_decision,
            "is_anomaly": is_anomaly,
            "fused_anomaly_score": round(float(fused_score), 6),
            "severity": severity,
            "recommended_action": recommended_action,
            "auto_block_permitted": auto_block_permitted,
            "decision_rule": decision_rule,
            "degraded_models": degraded_models,
            "models_agreeing_on_anomaly": agreeing_models,
            "models": {
                "random_forest": rf_out,
                "isolation_forest": if_out,
                "autoencoder": ae_out,
            },
            "total_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
        }

    def get_health_summary(self) -> Dict[str, Any]:
        ae_healthy = self.ae_engine.status == "healthy"
        if_healthy = self.if_status == "healthy"
        rf_healthy = self.rf_status == "healthy"

        if ae_healthy and if_healthy and rf_healthy:
            overall = "healthy"
        elif not ae_healthy and not if_healthy and not rf_healthy:
            overall = "degraded"
        else:
            overall = "partially_degraded"

        return {
            "status": overall,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "expected_feature_count": EXPECTED_FEATURE_COUNT,
            "models": {
                "autoencoder": {
                    "status": self.ae_engine.status,
                    "model_version": self.ae_engine.model_version,
                    "selected_threshold": self.ae_engine.selected_threshold,
                    "selected_threshold_percentile": self.ae_engine.selected_threshold_name,
                    "warning_threshold_p95": self.ae_engine.threshold_p95,
                    "high_confidence_threshold_p99": self.ae_engine.threshold_p99,
                    "degraded_reason": self.ae_engine.degraded_reason,
                },
                "isolation_forest": {
                    "status": self.if_status,
                    "threshold": self.if_bundle["threshold"] if self.if_bundle else None,
                    "artifact": self.if_bundle["artifact_path"] if self.if_bundle else None,
                    "degraded_reason": self.if_degraded_reason,
                },
                "random_forest": {
                    "status": self.rf_status,
                    "threshold": self.rf_bundle["threshold"] if self.rf_bundle else None,
                    "artifact": self.rf_bundle["artifact_path"] if self.rf_bundle else None,
                    "degraded_reason": self.rf_degraded_reason,
                },
            },
        }
