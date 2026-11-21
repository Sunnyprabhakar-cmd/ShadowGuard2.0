"""
Shadow Guard 2.0 — Authoritative PyTorch Autoencoder Model, Preprocessor & Inference Engine
===========================================================================================

Provides:
1. `FlowAutoencoder(nn.Module)`:
   - Architecture: 69 -> 32 -> 16 -> 8 (bottleneck) -> 16 -> 32 -> 69
   - Hidden activations: ReLU
   - Output activation: Linear (unbounded real values matching centered RobustScaler space)
2. `FeaturePreprocessor`:
   - Identical transformation pipeline for training, validation, test, and live inference:
     a) Validates 69-feature dimensionality and finite float values (no NaN/Inf).
     b) Applies signed log1p compression (`sign(x) * log1p(|x|)`) to heavy-tailed volumetric,
        sinusoidal, polynomial, and harmonic-padding indices so multi-million polynomial terms
        do not dominate MSE loss.
     c) Applies `RobustScaler` (median & IQR fitted strictly on `train_normal`, with standard
        deviation fallback if IQR == 0).
     d) Clips transformed values to `[-10.0, 10.0]` for numerical stability on extreme floods.
3. `AutoencoderInferenceEngine`:
   - Loads `autoencoder_model.pt`, `autoencoder_preprocessor.pkl`, and `autoencoder_metadata.json`.
   - Verifies SHA-256 artifact integrity and `v2.0-69dim` feature schema compatibility.
   - Returns reconstruction error (MSE), normalized anomaly score, classification state
     (`normal`, `suspicious`, `anomalous`, or `degraded`), and top-k contributing features.
   - Never silently classifies traffic as normal when the model or input is degraded/invalid.
"""

from __future__ import annotations

import hashlib
import json
import math
import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import RobustScaler

from shared.ml.feature_schema import (
    EXPECTED_FEATURE_COUNT,
    FEATURE_NAMES_69,
    FEATURE_SCHEMA_VERSION,
)

# Indices that exhibit heavy-tailed or multi-order-of-magnitude skew:
# 0..9 (volume/rate/product), 10..24 (sinusoidal * bytes), 25..39 (quadratic/cubic polynomials),
# 55..68 (harmonic padding * (packets+bytes)/(duration+1)).
# Indices 40..54 are already bounded in [-1, 1] by cos(...) * exp(-duration).
LOG_COMPRESS_INDICES: List[int] = (
    list(range(0, 40)) + list(range(55, 69))
)


class FlowAutoencoder(nn.Module):
    """
    Fully-connected symmetrical Autoencoder for 69-dimensional network flow features:
      Encoder: 69 -> 32 -> 16 -> 8
      Decoder: 8 -> 16 -> 32 -> 69
    """

    def __init__(
        self,
        input_dim: int = EXPECTED_FEATURE_COUNT,
        enc1_dim: int = 32,
        enc2_dim: int = 16,
        bottleneck_dim: int = 8,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.enc1_dim = enc1_dim
        self.enc2_dim = enc2_dim
        self.bottleneck_dim = bottleneck_dim

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, enc1_dim),
            nn.ReLU(),
            nn.Linear(enc1_dim, enc2_dim),
            nn.ReLU(),
            nn.Linear(enc2_dim, bottleneck_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, enc2_dim),
            nn.ReLU(),
            nn.Linear(enc2_dim, enc1_dim),
            nn.ReLU(),
            nn.Linear(enc1_dim, input_dim),
        )

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed


class FeaturePreprocessor:
    """
    Deterministic preprocessing pipeline fitted strictly on `train_normal` 69-feature vectors
    and saved alongside the trained PyTorch Autoencoder.
    """

    def __init__(
        self,
        clip_bound: float = 10.0,
        log_compress_indices: Optional[List[int]] = None,
    ) -> None:
        self.schema_version: str = FEATURE_SCHEMA_VERSION
        self.expected_dim: int = EXPECTED_FEATURE_COUNT
        self.feature_names: List[str] = list(FEATURE_NAMES_69)
        self.clip_bound: float = float(clip_bound)
        self.log_compress_indices: List[int] = (
            list(log_compress_indices)
            if log_compress_indices is not None
            else list(LOG_COMPRESS_INDICES)
        )
        self.scaler: RobustScaler = RobustScaler(
            with_centering=True,
            with_scaling=True,
            quantile_range=(25.0, 75.0),
        )
        self.center_: Optional[np.ndarray] = None
        self.scale_: Optional[np.ndarray] = None
        self.is_fitted: bool = False

    def _validate_and_to_2d(self, X: Any) -> np.ndarray:
        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.ndim != 2:
            raise ValueError(f"Expected 1D or 2D feature array, got {arr.ndim}D")
        if arr.shape[1] != self.expected_dim:
            raise ValueError(
                f"Feature dimension mismatch: expected {self.expected_dim}, got {arr.shape[1]}"
            )
        if not np.all(np.isfinite(arr)):
            raise ValueError("Input features contain NaN or Infinite values")
        return arr

    def _apply_signed_log1p(self, arr: np.ndarray) -> np.ndarray:
        out = arr.copy()
        idx = self.log_compress_indices
        out[:, idx] = np.sign(out[:, idx]) * np.log1p(np.abs(out[:, idx]))
        return out

    def fit(self, X_normal: Any) -> "FeaturePreprocessor":
        arr = self._validate_and_to_2d(X_normal)
        compressed = self._apply_signed_log1p(arr)
        self.scaler.fit(compressed)

        center = np.asarray(self.scaler.center_, dtype=np.float64)
        scale = np.asarray(self.scaler.scale_, dtype=np.float64)

        # Guard against zero or near-zero IQR on any low-variance column
        std_fallback = np.std(compressed, axis=0)
        for j in range(self.expected_dim):
            if not np.isfinite(scale[j]) or abs(scale[j]) < 1e-6:
                scale[j] = float(std_fallback[j]) if std_fallback[j] >= 1e-6 else 1.0

        self.scaler.scale_ = scale
        self.center_ = center.copy()
        self.scale_ = scale.copy()
        self.is_fitted = True
        return self

    def transform(self, X: Any) -> np.ndarray:
        if not self.is_fitted or self.center_ is None or self.scale_ is None:
            raise RuntimeError("FeaturePreprocessor must be fitted before calling transform()")
        arr = self._validate_and_to_2d(X)
        compressed = self._apply_signed_log1p(arr)
        scaled = (compressed - self.center_) / self.scale_
        clipped = np.clip(scaled, -self.clip_bound, self.clip_bound)
        return clipped.astype(np.float32)

    def fit_transform(self, X_normal: Any) -> np.ndarray:
        return self.fit(X_normal).transform(X_normal)

    def to_state_dict(self) -> Dict[str, Any]:
        if not self.is_fitted or self.center_ is None or self.scale_ is None:
            raise RuntimeError("Cannot serialize unfitted FeaturePreprocessor")
        return {
            "schema_version": self.schema_version,
            "expected_dim": self.expected_dim,
            "feature_names": self.feature_names,
            "clip_bound": self.clip_bound,
            "log_compress_indices": self.log_compress_indices,
            "center": self.center_.tolist(),
            "scale": self.scale_.tolist(),
            "is_fitted": self.is_fitted,
        }

    @classmethod
    def from_state_dict(cls, state: Dict[str, Any]) -> "FeaturePreprocessor":
        obj = cls(
            clip_bound=float(state.get("clip_bound", 10.0)),
            log_compress_indices=list(state.get("log_compress_indices", LOG_COMPRESS_INDICES)),
        )
        obj.schema_version = str(state.get("schema_version", FEATURE_SCHEMA_VERSION))
        obj.expected_dim = int(state.get("expected_dim", EXPECTED_FEATURE_COUNT))
        obj.feature_names = list(state.get("feature_names", FEATURE_NAMES_69))
        obj.center_ = np.asarray(state["center"], dtype=np.float64)
        obj.scale_ = np.asarray(state["scale"], dtype=np.float64)
        obj.scaler.center_ = obj.center_.copy()
        obj.scaler.scale_ = obj.scale_.copy()
        obj.is_fitted = bool(state.get("is_fitted", True))
        return obj


def compute_sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class AutoencoderInferenceEngine:
    """
    Production-grade inference wrapper around `FlowAutoencoder` and `FeaturePreprocessor`.
    Enforces:
      - Artifact integrity and schema validation.
      - Explicit `degraded` status on missing model, corrupted weights, or invalid input.
      - Calibrated three-tier anomaly states (`normal`, `suspicious`, `anomalous`) using
        validation thresholds (`P95` warning threshold and selected `P97`/`P99` anomaly threshold).
    """

    def __init__(self, model_dir: Optional[Path] = None) -> None:
        self.model_dir: Optional[Path] = Path(model_dir) if model_dir else None
        self.model: Optional[FlowAutoencoder] = None
        self.preprocessor: Optional[FeaturePreprocessor] = None
        self.metadata: Dict[str, Any] = {}
        self.status: str = "degraded"
        self.degraded_reason: Optional[str] = "uninitialized"
        self.model_version: str = "unavailable"
        self.threshold_p95: float = 0.0
        self.threshold_p97: float = 0.0
        self.threshold_p99: float = 0.0
        self.selected_threshold: float = 0.0
        self.selected_threshold_name: str = "none"

        if self.model_dir is not None:
            self.load_artifacts(self.model_dir)

    def load_artifacts(self, model_dir: Path, verify_checksums: bool = True) -> bool:
        model_dir = Path(model_dir)
        self.model_dir = model_dir
        pt_path = model_dir / "autoencoder_model.pt"
        pkl_path = model_dir / "autoencoder_preprocessor.pkl"
        meta_path = model_dir / "autoencoder_metadata.json"

        if not pt_path.exists() or not pkl_path.exists() or not meta_path.exists():
            self.status = "degraded"
            self.degraded_reason = "missing_autoencoder_artifact_files"
            self.model = None
            self.preprocessor = None
            return False

        try:
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            if metadata.get("schema_version") != FEATURE_SCHEMA_VERSION:
                self.status = "degraded"
                self.degraded_reason = (
                    f"schema_version_mismatch:{metadata.get('schema_version')}!={FEATURE_SCHEMA_VERSION}"
                )
                return False

            if verify_checksums and "artifact_checksums" in metadata:
                expected_pt_hash = metadata["artifact_checksums"].get("autoencoder_model_pt_sha256")
                expected_pkl_hash = metadata["artifact_checksums"].get("autoencoder_preprocessor_pkl_sha256")
                if expected_pt_hash and compute_sha256_file(pt_path) != expected_pt_hash:
                    self.status = "degraded"
                    self.degraded_reason = "model_checkpoint_sha256_mismatch"
                    return False
                if expected_pkl_hash and compute_sha256_file(pkl_path) != expected_pkl_hash:
                    self.status = "degraded"
                    self.degraded_reason = "preprocessor_sha256_mismatch"
                    return False

            with pkl_path.open("rb") as f:
                preproc_obj = pickle.load(f)
            if isinstance(preproc_obj, FeaturePreprocessor):
                preprocessor = preproc_obj
            elif isinstance(preproc_obj, dict):
                preprocessor = FeaturePreprocessor.from_state_dict(preproc_obj)
            else:
                raise TypeError("Unsupported preprocessor artifact type")

            checkpoint = torch.load(pt_path, map_location="cpu", weights_only=False)
            arch = checkpoint.get("architecture", {})
            model = FlowAutoencoder(
                input_dim=int(arch.get("input_dim", EXPECTED_FEATURE_COUNT)),
                enc1_dim=int(arch.get("enc1_dim", 32)),
                enc2_dim=int(arch.get("enc2_dim", 16)),
                bottleneck_dim=int(arch.get("bottleneck_dim", 8)),
            )
            model.load_state_dict(checkpoint["model_state_dict"])
            model.eval()

            thresholds = metadata.get("calibration_thresholds", {})
            self.threshold_p95 = float(thresholds.get("P95", 0.0))
            self.threshold_p97 = float(thresholds.get("P97", 0.0))
            self.threshold_p99 = float(thresholds.get("P99", 0.0))
            self.selected_threshold = float(metadata.get("selected_threshold", self.threshold_p97))
            self.selected_threshold_name = str(metadata.get("selected_threshold_percentile", "P97"))

            if self.selected_threshold <= 0.0:
                self.status = "degraded"
                self.degraded_reason = "invalid_or_non_positive_calibrated_threshold"
                return False

            self.model = model
            self.preprocessor = preprocessor
            self.metadata = metadata
            self.model_version = str(metadata.get("model_version", "ae-v2.0.0"))
            self.status = "healthy"
            self.degraded_reason = None
            return True
        except Exception as exc:
            self.status = "degraded"
            self.degraded_reason = f"artifact_load_failure:{type(exc).__name__}:{exc}"
            self.model = None
            self.preprocessor = None
            return False

    def score_features(self, features: List[float], top_k: int = 5) -> Dict[str, Any]:
        """
        Runs a single 69-feature vector through the preprocessor and PyTorch Autoencoder.
        If the engine is degraded or the input vector is invalid, returns `status='degraded'`
        and `is_anomaly=None` rather than silently returning normal.
        """
        t0 = time.perf_counter()
        if self.status != "healthy" or self.model is None or self.preprocessor is None:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "anomaly_score": None,
                "reconstruction_error": None,
                "threshold": self.selected_threshold if self.selected_threshold > 0 else None,
                "threshold_percentile": self.selected_threshold_name,
                "warning_threshold_p95": self.threshold_p95 if self.threshold_p95 > 0 else None,
                "model_version": self.model_version,
                "degraded_reason": self.degraded_reason or "autoencoder_not_loaded",
                "top_contributing_features": [],
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        try:
            scaled_2d = self.preprocessor.transform(features)
        except Exception as exc:
            return {
                "status": "degraded",
                "decision": "degraded",
                "is_anomaly": None,
                "anomaly_score": None,
                "reconstruction_error": None,
                "threshold": self.selected_threshold,
                "threshold_percentile": self.selected_threshold_name,
                "warning_threshold_p95": self.threshold_p95,
                "model_version": self.model_version,
                "degraded_reason": f"invalid_input_features:{exc}",
                "top_contributing_features": [],
                "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        with torch.no_grad():
            tensor_in = torch.from_numpy(scaled_2d)
            tensor_out = self.model(tensor_in)
            diff_sq = (tensor_in - tensor_out).pow(2).squeeze(0).numpy()
            mse_error = float(np.mean(diff_sq))

        # Monotonic normalized anomaly score in [0.0, 1.0]:
        #   - error == 0             -> 0.0
        #   - error == threshold_p95 -> ~0.40
        #   - error == selected_thr  -> 0.50 (exact anomaly decision boundary)
        #   - error >> selected_thr  -> approaches 1.0
        ratio = mse_error / max(self.selected_threshold, 1e-9)
        normalized_score = float(ratio / (1.0 + ratio))

        if mse_error > self.selected_threshold:
            decision = "anomalous"
            is_anomaly = True
        elif self.threshold_p95 > 0.0 and mse_error > self.threshold_p95:
            decision = "suspicious"
            is_anomaly = False
        else:
            decision = "normal"
            is_anomaly = False

        top_indices = np.argsort(diff_sq)[::-1][:top_k]
        total_sq = float(np.sum(diff_sq)) or 1e-12
        top_features = [
            {
                "feature_index": int(idx),
                "feature_name": FEATURE_NAMES_69[int(idx)],
                "squared_error": round(float(diff_sq[int(idx)]), 6),
                "error_share": round(float(diff_sq[int(idx)] / total_sq), 4),
            }
            for idx in top_indices
        ]

        return {
            "status": "healthy",
            "decision": decision,
            "is_anomaly": is_anomaly,
            "anomaly_score": round(normalized_score, 6),
            "reconstruction_error": round(mse_error, 6),
            "threshold": round(self.selected_threshold, 6),
            "threshold_percentile": self.selected_threshold_name,
            "warning_threshold_p95": round(self.threshold_p95, 6),
            "model_version": self.model_version,
            "degraded_reason": None,
            "top_contributing_features": top_features,
            "inference_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
        }

    def score_batch(self, feature_matrix: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Vectorized batch inference returning `(mse_errors, normalized_scores)` for evaluation scripts.
        """
        if self.status != "healthy" or self.model is None or self.preprocessor is None:
            raise RuntimeError(f"AutoencoderInferenceEngine is degraded: {self.degraded_reason}")
        scaled = self.preprocessor.transform(feature_matrix)
        with torch.no_grad():
            tensor_in = torch.from_numpy(scaled)
            tensor_out = self.model(tensor_in)
            mse_errors = torch.mean((tensor_in - tensor_out) ** 2, dim=1).numpy()
        ratios = mse_errors / max(self.selected_threshold, 1e-9)
        norm_scores = ratios / (1.0 + ratios)
        return mse_errors, norm_scores
