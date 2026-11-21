"""
Shadow Guard 2.0 — Explainable AI (XAI) Core Module (Stage 1)
=============================================================

Provides model-faithful, read-only explainability for the three existing Shadow Guard 2.0
machine-learning detectors operating on the canonical 69-dimensional flow schema (`v2.0-69dim`):

1. `RandomForestSHAPExplainer`:
   - Uses the official `shap.TreeExplainer` (`shap == 0.54.1`) on the existing saved
     `models/random_forest_69_v2.pkl` artifact without retraining or modifying the model.
   - Applies the exact saved `StandardScaler` preprocessing pipeline and respects `model.classes_`
     ordering (`[0, 1]` for binary benign/attack, plus general multiclass support).
   - Verifies the exact Shapley additivity identity:
       base_value + sum_{j=0..68} shap_values[j] == P_RF(class | x)
   - Identifies the top-5 positive contributors (pushing toward attack) and top-5 negative
     contributors (pushing toward benign), computes global SHAP feature importance, and
     includes a clearly labeled model-agnostic perturbation fallback (`is_exact_shap=False`)
     only if `shap` cannot be imported in a restricted environment.

2. `IsolationForestAnomalyExplainer`:
   - Uses the existing saved `models/isolation_forest_69_v2.pkl` artifact (`StandardScaler` +
     `IsolationForest`, `best_threshold = -0.024499`) and the 840-flow `train_normal` reference
     population (`data/autoencoder_flow_dataset_v2.json`).
   - Implements a documented reference-population perturbation attribution method:
     a) Single-feature median replacement (`x_j <- median_normal_j`) measuring the shift in
        `raw_decision_score` and monotonic `anomaly_score`.
     b) Correlated-group replacement (`duplicate_polynomial_even`, `duplicate_polynomial_odd`,
        `collinear_harmonic_padding`, and raw `(packets, bytes, duration)` families) so tree
        splits distributed across identical/collinear columns are faithfully captured.
     c) Optional reference comparison against `shap.TreeExplainer(isolation_forest)` in
        decision-function space.
   - Compares each feature against the 840-flow `train_normal` distribution (`median`, `IQR`,
     `P05`, `P25`, `P75`, `P95`, `robust_z_score`, `empirical_percentile`) and flags unusually
     high or low measurements.
   - Strictly distinguishes `UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY` from probabilities.

3. `AutoencoderReconstructionExplainer`:
   - Uses the existing authoritative PyTorch `AutoencoderInferenceEngine` (`FlowAutoencoder`
     `69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69` and `FeaturePreprocessor` from
     `models/autoencoder_model.pt`, `models/autoencoder_preprocessor.pkl`, and
     `models/autoencoder_metadata.json`).
   - Preserves the frozen validation-calibrated thresholds (`P95 = 0.409105`, `P97 = 0.503670`,
     `P99 = 0.645935`).
   - Computes all 69 per-feature squared reconstruction errors `(z_j - z_hat_j)^2` and relative
     error shares, ranks all 69 features, extracts the top-5 anomalous features, and compares
     overall MSE and per-feature errors against the frozen `P97` threshold.
   - Strictly labels reconstruction error as `RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY`.

4. `ThreeScalarMeasurementGrouper`:
   - Explicitly documents that all 69 features in `v2.0-69dim` are deterministic mathematical
     transformations of only three raw flow measurements (`packets`, `bytes`, `duration`).
   - Annotates the 13 exact duplicate polynomial features (`f_25..f_39`) and 14 rank-1 collinear
     harmonic padding features (`f_55..f_68`).
   - Aggregates feature attributions at both the canonical 69-feature technical level and the
     human-readable `(packets, bytes, duration)` & rate (`bytes/sec`, `packets/sec`,
     `avg_bytes_per_packet`) level.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch

from shared.ml.autoencoder_model import AutoencoderInferenceEngine
from shared.ml.feature_schema import (
    EXPECTED_FEATURE_COUNT,
    FEATURE_NAMES_69,
    FEATURE_SCHEMA_VERSION,
    extract_69_features,
)
from shared.ml.tri_model_fusion import TriModelDetectionEngine, _sigmoid

try:
    import shap as _shap_lib

    SHAP_AVAILABLE = True
    SHAP_VERSION = getattr(_shap_lib, "__version__", "unknown")
    SHAP_IMPORT_ERROR: Optional[str] = None
except Exception as _shap_exc:  # pragma: no cover
    _shap_lib = None
    SHAP_AVAILABLE = False
    SHAP_VERSION = None
    SHAP_IMPORT_ERROR = f"{type(_shap_exc).__name__}: {_shap_exc}"


# =============================================================================
# 1. CANONICAL 69-FEATURE METADATA & 3-SCALAR MEASUREMENT GROUPER
# =============================================================================

EVEN_POLY_DUPLICATE_INDICES: List[int] = [25 + i for i in range(0, 15, 2)]  # 8 features: f_25, f_27, ..., f_39
ODD_POLY_DUPLICATE_INDICES: List[int] = [25 + i for i in range(1, 15, 2)]   # 7 features: f_26, f_28, ..., f_38
HARMONIC_PADDING_INDICES: List[int] = list(range(55, 69))                   # 14 features: f_55 .. f_68

CORRELATED_ATTRIBUTION_LIMITATION_NOTE: str = (
    "IMPORTANT FEATURE SCHEMA & ATTRIBUTION LIMITATION: All 69 features in canonical schema "
    "v2.0-69dim are deterministic mathematical functions of only three raw network flow "
    "measurements (packets, bytes, duration). Specifically, features f_25..f_39 contain 13 exact "
    "duplicate columns (8 identical even-index columns equal to packets^2/(duration^2+1) and 7 "
    "identical odd-index columns equal to (packets*bytes)/(duration^2+1)), and features f_55..f_68 "
    "are 14 rank-1 collinear scalar multiples of (packets+bytes)/(duration+1)*sin(idx). "
    "In tree-based models (Random Forest, Isolation Forest) and neural autoencoders, feature "
    "attributions (SHAP values, perturbation shifts, and squared reconstruction errors) are "
    "split across collinear/duplicate coordinates according to which coordinate each tree split "
    "or neural weight matrix used during training. Consequently: (1) individual rankings among "
    "duplicate/collinear columns should be interpreted as group-level signal rather than 69 "
    "independent measurements, and (2) SHAP and anomaly attributions explain internal model "
    "behavior, NOT the real-world causal root cause of an attack."
)


def build_feature_catalog_69() -> List[Dict[str, Any]]:
    """
    Returns complete technical and human-readable metadata for all 69 canonical features,
    including raw measurement dependencies (`packets`, `bytes`, `duration`), mathematical
    formula, structural group, and collinearity/duplicate status.
    """
    catalog: List[Dict[str, Any]] = []

    base_specs = [
        (0, "Packet Count", "packets", ["packets"], "packet_count", "Raw packet count p"),
        (1, "Byte Volume", "bytes", ["bytes"], "byte_volume", "Raw byte count b"),
        (2, "Flow Duration (s)", "duration", ["duration"], "flow_duration", "Flow duration d in seconds"),
        (3, "Throughput (Bytes/sec)", "bytes / duration", ["bytes", "duration"], "rate_and_interaction", "Byte throughput b / d"),
        (4, "Packet Rate (Packets/sec)", "packets / duration", ["packets", "duration"], "rate_and_interaction", "Packet rate p / d"),
        (5, "Average Packet Size (Bytes/pkt)", "bytes / packets", ["packets", "bytes"], "rate_and_interaction", "Mean payload size per packet b / p"),
        (6, "Volume-Packet Product", "packets * bytes", ["packets", "bytes"], "rate_and_interaction", "Volumetric product p * b"),
        (7, "Log Packet Count", "ln(packets + 1)", ["packets"], "packet_count", "Log-compressed packet count ln(p + 1)"),
        (8, "Log Byte Volume", "ln(bytes + 1)", ["bytes"], "byte_volume", "Log-compressed byte volume ln(b + 1)"),
        (9, "Log Flow Duration", "ln(duration + 1)", ["duration"], "flow_duration", "Log-compressed duration ln(d + 1)"),
    ]

    for idx, label, formula, raw_deps, primary_family, desc in base_specs:
        catalog.append(
            {
                "feature_index": idx,
                "feature_name": FEATURE_NAMES_69[idx],
                "human_label": label,
                "formula": formula,
                "raw_dependencies": raw_deps,
                "primary_measurement_family": primary_family,
                "structural_group": "G1_base_and_rate_f00_f09",
                "is_duplicate_column": False,
                "duplicate_group_leader": None,
                "is_collinear_padding": False,
                "description": desc,
            }
        )

    for i in range(15):
        idx = 10 + i
        catalog.append(
            {
                "feature_index": idx,
                "feature_name": FEATURE_NAMES_69[idx],
                "human_label": f"Sinusoidal Volume-Rate Projection #{i}",
                "formula": f"sin(packets * {i + 1}) * bytes / (duration + 1)",
                "raw_dependencies": ["packets", "bytes", "duration"],
                "primary_measurement_family": "rate_and_interaction",
                "structural_group": "G2_sinusoidal_projections_f10_f24",
                "is_duplicate_column": False,
                "duplicate_group_leader": None,
                "is_collinear_padding": False,
                "description": f"Harmonic packet-phase modulated byte rate (harmonic k={i + 1})",
            }
        )

    for i in range(15):
        idx = 25 + i
        is_even = (i % 2) == 0
        leader_idx = 25 if is_even else 26
        formula = (
            "packets^2 / (duration^2 + 1)"
            if is_even
            else "(packets * bytes) / (duration^2 + 1)"
        )
        raw_deps = ["packets", "duration"] if is_even else ["packets", "bytes", "duration"]
        primary_family = "packet_count" if is_even else "rate_and_interaction"
        catalog.append(
            {
                "feature_index": idx,
                "feature_name": FEATURE_NAMES_69[idx],
                "human_label": (
                    f"Quadratic Packet-Duration Ratio (dup of f_25)" if is_even and idx != 25
                    else "Quadratic Packet-Duration Ratio (Leader f_25)" if is_even
                    else f"Packet-Byte Duration Ratio (dup of f_26)" if idx != 26
                    else "Packet-Byte Duration Ratio (Leader f_26)"
                ),
                "formula": formula,
                "raw_dependencies": raw_deps,
                "primary_measurement_family": primary_family,
                "structural_group": "G3_polynomial_ratios_f25_f39_duplicates",
                "is_duplicate_column": idx not in (25, 26),
                "duplicate_group_leader": FEATURE_NAMES_69[leader_idx],
                "is_collinear_padding": False,
                "description": (
                    f"Polynomial ratio identical across {'even' if is_even else 'odd'} indices "
                    f"(leader: {FEATURE_NAMES_69[leader_idx]})"
                ),
            }
        )

    for i in range(15):
        idx = 40 + i
        catalog.append(
            {
                "feature_index": idx,
                "feature_name": FEATURE_NAMES_69[idx],
                "human_label": f"Damped Cosine Duration Decay #{i}",
                "formula": f"cos({i} * (packets + bytes + duration) / 3) * exp(-duration)",
                "raw_dependencies": ["packets", "bytes", "duration"] if i > 0 else ["duration"],
                "primary_measurement_family": "flow_duration" if i == 0 else "rate_and_interaction",
                "structural_group": "G4_damped_cosine_f40_f54",
                "is_duplicate_column": False,
                "duplicate_group_leader": None,
                "is_collinear_padding": False,
                "description": (
                    "Pure exponential duration decay exp(-duration)"
                    if i == 0
                    else f"Cosine-modulated exponential duration decay (frequency i={i})"
                ),
            }
        )

    for i in range(14):
        idx = 55 + i
        catalog.append(
            {
                "feature_index": idx,
                "feature_name": FEATURE_NAMES_69[idx],
                "human_label": f"Collinear Harmonic Rate Padding #{idx}",
                "formula": f"((packets + bytes) / (duration + 1)) * sin({idx})",
                "raw_dependencies": ["packets", "bytes", "duration"],
                "primary_measurement_family": "rate_and_interaction",
                "structural_group": "G5_harmonic_padding_f55_f68_collinear",
                "is_duplicate_column": False,
                "duplicate_group_leader": FEATURE_NAMES_69[55],
                "is_collinear_padding": True,
                "description": f"Rank-1 collinear scalar multiple sin({idx}) of (packets + bytes) / (duration + 1)",
            }
        )

    return catalog


FEATURE_CATALOG_69: List[Dict[str, Any]] = build_feature_catalog_69()


class ThreeScalarMeasurementGrouper:
    """
    Aggregates 69-feature technical attributions into:
      1. Raw 3-Scalar Measurement Drivers (`packets`, `bytes`, `duration`) using equal
         dependency-share weighting across each feature's `raw_dependencies`.
      2. 5 Structural Feature Groups (`G1`..`G5`) so duplicate polynomial features (`f_25..f_39`)
         and rank-1 collinear padding features (`f_55..f_68`) are summarized transparently.
      3. Human-readable physical flow measurement comparison (`packets`, `bytes`, `duration`,
         `bytes/sec`, `packets/sec`, `avg_bytes_per_packet`) against the `train_normal` reference
         population.
    """

    def __init__(self, normal_reference_stats: Optional[Dict[str, Any]] = None) -> None:
        self.catalog = FEATURE_CATALOG_69
        self.normal_reference_stats = normal_reference_stats or {}

    def summarize_attributions(
        self,
        signed_or_unsigned_values: np.ndarray,
        features_69: List[float],
        value_type: str = "shap",
    ) -> Dict[str, Any]:
        arr = np.asarray(signed_or_unsigned_values, dtype=np.float64).reshape(-1)
        abs_arr = np.abs(arr)
        total_abs = float(np.sum(abs_arr)) or 1e-12

        # 1. Apportion magnitude & net signed impact across the 3 raw measurements (packets, bytes, duration)
        raw_driver_abs = {"packets": 0.0, "bytes": 0.0, "duration": 0.0}
        raw_driver_signed = {"packets": 0.0, "bytes": 0.0, "duration": 0.0}

        for idx, meta in enumerate(self.catalog):
            deps = meta["raw_dependencies"]
            share_weight = 1.0 / float(len(deps))
            for dep in deps:
                raw_driver_abs[dep] += float(abs_arr[idx]) * share_weight
                raw_driver_signed[dep] += float(arr[idx]) * share_weight

        raw_driver_shares = {
            k: round(v / total_abs, 4) for k, v in raw_driver_abs.items()
        }
        dominant_raw_measurement = max(raw_driver_shares.items(), key=lambda kv: kv[1])[0]

        # 2. Aggregate across the 5 structural groups
        structural_groups: Dict[str, Dict[str, Any]] = {
            "G1_base_and_rate_f00_f09": {
                "label": "Base Volumetric, Rate & Logarithmic Features (f_00..f_09)",
                "feature_count": 10,
                "signed_sum": 0.0,
                "abs_sum": 0.0,
                "share_of_total": 0.0,
            },
            "G2_sinusoidal_projections_f10_f24": {
                "label": "Sinusoidal Volume-Rate Projections (f_10..f_24)",
                "feature_count": 15,
                "signed_sum": 0.0,
                "abs_sum": 0.0,
                "share_of_total": 0.0,
            },
            "G3_polynomial_ratios_f25_f39_duplicates": {
                "label": "Polynomial Interaction Ratios (f_25..f_39, 13 Exact Duplicates)",
                "feature_count": 15,
                "signed_sum": 0.0,
                "abs_sum": 0.0,
                "share_of_total": 0.0,
            },
            "G4_damped_cosine_f40_f54": {
                "label": "Damped Cosine Duration Harmonics (f_40..f_54)",
                "feature_count": 15,
                "signed_sum": 0.0,
                "abs_sum": 0.0,
                "share_of_total": 0.0,
            },
            "G5_harmonic_padding_f55_f68_collinear": {
                "label": "Rank-1 Collinear Harmonic Padding (f_55..f_68)",
                "feature_count": 14,
                "signed_sum": 0.0,
                "abs_sum": 0.0,
                "share_of_total": 0.0,
            },
        }

        for idx, meta in enumerate(self.catalog):
            grp_key = meta["structural_group"]
            structural_groups[grp_key]["signed_sum"] += float(arr[idx])
            structural_groups[grp_key]["abs_sum"] += float(abs_arr[idx])

        for grp_key, ginfo in structural_groups.items():
            ginfo["signed_sum"] = round(ginfo["signed_sum"], 6)
            ginfo["abs_sum"] = round(ginfo["abs_sum"], 6)
            ginfo["share_of_total"] = round(ginfo["abs_sum"] / total_abs, 4)

        # 3. Duplicate & Collinear Group Summary
        even_poly_abs = float(np.sum(abs_arr[EVEN_POLY_DUPLICATE_INDICES]))
        odd_poly_abs = float(np.sum(abs_arr[ODD_POLY_DUPLICATE_INDICES]))
        pad_abs = float(np.sum(abs_arr[HARMONIC_PADDING_INDICES]))

        # 4. Physical 6-measurement human-readable profile (f_00 .. f_05)
        physical_measurements = self.build_physical_measurement_profile(features_69)

        return {
            "attribution_value_type": value_type,
            "intrinsic_raw_measurements": ["packets", "bytes", "duration"],
            "dominant_raw_measurement": dominant_raw_measurement,
            "raw_measurement_attribution": {
                k: {
                    "abs_attribution": round(raw_driver_abs[k], 6),
                    "signed_attribution": round(raw_driver_signed[k], 6),
                    "share_of_total": raw_driver_shares[k],
                }
                for k in ("packets", "bytes", "duration")
            },
            "structural_group_attribution": structural_groups,
            "collinear_and_duplicate_group_totals": {
                "even_polynomial_duplicates_f25_f39": {
                    "leader_feature": "f_25_poly_ratio_0",
                    "formula": "packets^2 / (duration^2 + 1)",
                    "member_count": len(EVEN_POLY_DUPLICATE_INDICES),
                    "combined_abs_attribution": round(even_poly_abs, 6),
                    "combined_share_of_total": round(even_poly_abs / total_abs, 4),
                },
                "odd_polynomial_duplicates_f26_f38": {
                    "leader_feature": "f_26_poly_ratio_1",
                    "formula": "(packets * bytes) / (duration^2 + 1)",
                    "member_count": len(ODD_POLY_DUPLICATE_INDICES),
                    "combined_abs_attribution": round(odd_poly_abs, 6),
                    "combined_share_of_total": round(odd_poly_abs / total_abs, 4),
                },
                "harmonic_collinear_padding_f55_f68": {
                    "leader_feature": "f_55_harmonic_pad_55",
                    "formula": "((packets + bytes) / (duration + 1)) * sin(idx)",
                    "member_count": len(HARMONIC_PADDING_INDICES),
                    "combined_abs_attribution": round(pad_abs, 6),
                    "combined_share_of_total": round(pad_abs / total_abs, 4),
                },
            },
            "physical_flow_measurements": physical_measurements,
            "human_readable_summary": self._format_human_summary(
                physical_measurements, raw_driver_shares, dominant_raw_measurement
            ),
            "correlated_feature_limitation": CORRELATED_ATTRIBUTION_LIMITATION_NOTE,
        }

    def build_physical_measurement_profile(self, features_69: List[float]) -> Dict[str, Any]:
        key_indices = [
            (0, "packets", "Packet Count", "packets"),
            (1, "bytes", "Byte Volume", "bytes"),
            (2, "duration", "Flow Duration", "seconds"),
            (3, "bytes_per_sec", "Throughput (Bytes/sec)", "B/s"),
            (4, "packets_per_sec", "Packet Rate (Packets/sec)", "pkt/s"),
            (5, "avg_bytes_per_packet", "Avg Packet Size (Bytes/pkt)", "B/pkt"),
        ]
        out: Dict[str, Any] = {}
        for idx, key, label, unit in key_indices:
            val = float(features_69[idx])
            ref = self.normal_reference_stats.get(idx)
            if ref:
                iqr = max(float(ref["iqr"]), 1e-6)
                rob_z = (val - float(ref["median"])) / iqr
                if val > float(ref["p95"]) and rob_z > 2.0:
                    status = "UNUSUALLY_HIGH"
                elif val < float(ref["p05"]) and rob_z < -2.0:
                    status = "UNUSUALLY_LOW"
                elif val > float(ref["p75"]) and rob_z > 1.0:
                    status = "ELEVATED_ABOVE_NORMAL"
                elif val < float(ref["p25"]) and rob_z < -1.0:
                    status = "BELOW_NORMAL_MEDIAN"
                else:
                    status = "WITHIN_NORMAL_BASELINE"
                out[key] = {
                    "feature_index": idx,
                    "feature_name": FEATURE_NAMES_69[idx],
                    "label": label,
                    "unit": unit,
                    "value": round(val, 4),
                    "normal_median": round(float(ref["median"]), 4),
                    "normal_iqr": round(float(ref["iqr"]), 4),
                    "normal_p05_to_p95": [round(float(ref["p05"]), 4), round(float(ref["p95"]), 4)],
                    "robust_z_score": round(float(rob_z), 4),
                    "baseline_comparison": status,
                }
            else:
                out[key] = {
                    "feature_index": idx,
                    "feature_name": FEATURE_NAMES_69[idx],
                    "label": label,
                    "unit": unit,
                    "value": round(val, 4),
                }
        return out

    @staticmethod
    def _format_human_summary(
        physical: Dict[str, Any],
        raw_shares: Dict[str, float],
        dominant_raw: str,
    ) -> str:
        pkt = physical.get("packets", {})
        byt = physical.get("bytes", {})
        dur = physical.get("duration", {})
        bps = physical.get("bytes_per_sec", {})
        pps = physical.get("packets_per_sec", {})
        bpp = physical.get("avg_bytes_per_packet", {})

        abnormal_parts: List[str] = []
        for item in (pkt, byt, dur, bps, pps, bpp):
            comp = item.get("baseline_comparison")
            if comp in ("UNUSUALLY_HIGH", "UNUSUALLY_LOW"):
                abnormal_parts.append(
                    f"{item['label']}={item['value']} {item['unit']} ({comp} vs normal median {item['normal_median']}, robust Z={item['robust_z_score']:+.2f})"
                )

        share_str = (
            f"packets={raw_shares['packets'] * 100:.1f}%, "
            f"bytes={raw_shares['bytes'] * 100:.1f}%, "
            f"duration={raw_shares['duration'] * 100:.1f}%"
        )
        if abnormal_parts:
            return (
                f"Flow exhibits extreme physical measurements relative to normal baseline: "
                f"{'; '.join(abnormal_parts)}. Across the 69 derived features, attribution weight "
                f"is driven primarily by {dominant_raw} ({share_str})."
            )
        return (
            f"Flow physical measurements (packets={pkt.get('value')}, bytes={byt.get('value')}, "
            f"duration={dur.get('value')}s, throughput={bps.get('value')} B/s) lie near or within "
            f"marginal normal bounds; model attribution across the 69 derived features is distributed "
            f"as {share_str} (dominant driver: {dominant_raw})."
        )


# =============================================================================
# 2. REFERENCE NORMAL POPULATION LOADER (`train_normal`, 840 Flows)
# =============================================================================

def load_normal_reference_population(
    dataset_path: Optional[Path] = None,
) -> Tuple[np.ndarray, Dict[int, Dict[str, float]]]:
    """
    Loads the 840-flow `train_normal` split from `data/autoencoder_flow_dataset_v2.json`
    and computes per-feature reference distribution statistics (`median`, `iqr`, `p05`,
    `p25`, `p75`, `p95`, `mean`, `std`) across all 69 features.
    """
    if dataset_path is None:
        dataset_path = (
            Path(__file__).resolve().parent.parent.parent
            / "data"
            / "autoencoder_flow_dataset_v2.json"
        )
    dataset_path = Path(dataset_path)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Normal reference dataset not found at {dataset_path}")

    raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    train_normal_records = raw.get("splits", {}).get("train_normal", [])
    if not train_normal_records:
        raise ValueError("train_normal split in autoencoder_flow_dataset_v2.json is empty")

    matrix = np.asarray(
        [rec["features_69"] for rec in train_normal_records],
        dtype=np.float64,
    )
    if matrix.ndim != 2 or matrix.shape[1] != EXPECTED_FEATURE_COUNT:
        raise ValueError(f"Unexpected train_normal matrix shape: {matrix.shape}")

    medians = np.percentile(matrix, 50.0, axis=0)
    p05 = np.percentile(matrix, 5.0, axis=0)
    p25 = np.percentile(matrix, 25.0, axis=0)
    p75 = np.percentile(matrix, 75.0, axis=0)
    p95 = np.percentile(matrix, 95.0, axis=0)
    iqrs = p75 - p25
    means = np.mean(matrix, axis=0)
    stds = np.std(matrix, axis=0)

    stats: Dict[int, Dict[str, float]] = {}
    for j in range(EXPECTED_FEATURE_COUNT):
        stats[j] = {
            "median": float(medians[j]),
            "iqr": float(iqrs[j]) if float(iqrs[j]) > 1e-9 else float(max(stds[j], 1e-6)),
            "p05": float(p05[j]),
            "p25": float(p25[j]),
            "p75": float(p75[j]),
            "p95": float(p95[j]),
            "mean": float(means[j]),
            "std": float(stds[j]),
        }

    return matrix, stats


# =============================================================================
# 3. PART A — RANDOM FOREST SHAP EXPLAINER (`shap.TreeExplainer`)
# =============================================================================

class RandomForestSHAPExplainer:
    """
    Authoritative SHAP explainer for the existing trained Random Forest classifier
    (`models/random_forest_69_v2.pkl`).

    Uses the official `shap.TreeExplainer` (`shap == 0.54.1`) to explain the exact
    `StandardScaler` + `RandomForestClassifier.predict_proba` pipeline.
    Never retrains or modifies the production Random Forest artifact.
    """

    def __init__(
        self,
        rf_bundle: Optional[Dict[str, Any]],
        normal_matrix: Optional[np.ndarray] = None,
        normal_stats: Optional[Dict[int, Dict[str, float]]] = None,
        force_fallback_mode: bool = False,
    ) -> None:
        self.rf_bundle = rf_bundle
        self.normal_matrix = normal_matrix
        self.normal_stats = normal_stats or {}
        self.grouper = ThreeScalarMeasurementGrouper(self.normal_stats)
        self.force_fallback_mode = bool(force_fallback_mode)

        self.status: str = "degraded"
        self.degraded_reason: Optional[str] = "uninitialized"
        self.explainer_backend: str = "unavailable"
        self.is_exact_shap: bool = False
        self.tree_explainer: Any = None
        self.classes: List[Any] = []
        self.attack_class_index: int = 1
        self.benign_class_index: int = 0
        self._global_importance_cache: Optional[Dict[str, Any]] = None

        self._initialize_explainer()

    def _initialize_explainer(self) -> None:
        if not self.rf_bundle or self.rf_bundle.get("model") is None:
            self.status = "degraded"
            self.degraded_reason = "random_forest_model_not_loaded"
            return

        model = self.rf_bundle["model"]
        raw_classes = list(getattr(model, "classes_", [0, 1]))
        self.classes = raw_classes

        # Resolve benign (0 / 'normal' / 'benign') and attack class indices
        self.benign_class_index = 0
        for idx, c in enumerate(raw_classes):
            if str(c).lower() in ("0", "normal", "benign", "normal_traffic"):
                self.benign_class_index = idx
                break
        self.attack_class_index = 1 if len(raw_classes) > 1 and self.benign_class_index == 0 else 0

        if SHAP_AVAILABLE and not self.force_fallback_mode:
            try:
                self.tree_explainer = _shap_lib.TreeExplainer(model)
                self.status = "healthy"
                self.degraded_reason = None
                self.explainer_backend = f"official_shap_tree_explainer_v{SHAP_VERSION}"
                self.is_exact_shap = True
                return
            except Exception as exc:
                self.degraded_reason = f"shap_tree_explainer_init_error:{type(exc).__name__}:{exc}"

        # Validated model-agnostic perturbation fallback if `shap` is unavailable or forced off.
        # Explicitly marked `is_exact_shap = False` so an approximation is NEVER claimed as exact SHAP.
        if self.normal_matrix is not None and len(self.normal_matrix) > 0:
            self.status = "healthy"
            self.explainer_backend = "model_agnostic_reference_perturbation_fallback_not_exact_shap"
            self.is_exact_shap = False
            if not self.degraded_reason:
                self.degraded_reason = SHAP_IMPORT_ERROR or "shap_disabled_using_perturbation_fallback"
        else:
            self.status = "degraded"
            self.degraded_reason = self.degraded_reason or "shap_unavailable_and_no_reference_baseline"

    @staticmethod
    def _extract_class_shap_vector(
        raw_shap_values: Any,
        raw_expected_value: Any,
        target_class_idx: int,
        n_classes: int,
    ) -> Tuple[np.ndarray, float]:
        """
        Correctly handles all SHAP output shapes across binary and multiclass models:
          1. 3D ndarray `(n_samples, n_features, n_classes)` (standard in `shap >= 0.45 / 0.54.1`)
          2. List of `n_classes` 2D ndarrays `[(n_samples, n_features), ...]` (legacy `shap`)
          3. 2D ndarray `(n_samples, n_features)` (single-output binary/regression)
        """
        if isinstance(raw_shap_values, list):
            idx = min(target_class_idx, len(raw_shap_values) - 1)
            phi = np.asarray(raw_shap_values[idx], dtype=np.float64)[0]
        else:
            arr = np.asarray(raw_shap_values, dtype=np.float64)
            if arr.ndim == 3:
                idx = min(target_class_idx, arr.shape[2] - 1)
                phi = arr[0, :, idx]
            elif arr.ndim == 2:
                phi = arr[0, :]
                if target_class_idx == 0 and n_classes == 2:
                    phi = -phi
            else:
                raise ValueError(f"Unsupported SHAP output array shape: {arr.shape}")

        ev_arr = np.asarray(raw_expected_value, dtype=np.float64).reshape(-1)
        if ev_arr.size > target_class_idx:
            base_val = float(ev_arr[target_class_idx])
        elif ev_arr.size == 1:
            base_val = float(ev_arr[0]) if target_class_idx == 1 else float(1.0 - ev_arr[0])
        else:
            base_val = 0.5
        return phi, base_val

    def explain_flow(self, features: List[float], top_k: int = 5) -> Dict[str, Any]:
        """
        Computes an individual flow explanation for the existing Random Forest model.
        """
        t0 = time.perf_counter()
        if self.status != "healthy" or not self.rf_bundle or self.rf_bundle.get("model") is None:
            return {
                "status": "degraded",
                "model_name": "random_forest",
                "explanation_method": self.explainer_backend,
                "is_exact_shap": False,
                "degraded_reason": self.degraded_reason or "random_forest_unavailable",
                "prediction": None,
                "attack_probability": None,
                "benign_probability": None,
                "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        arr = TriModelDetectionEngine._validate_69_features(features)
        if arr is None:
            return {
                "status": "degraded",
                "model_name": "random_forest",
                "explanation_method": self.explainer_backend,
                "is_exact_shap": False,
                "degraded_reason": f"invalid_input_features_expected_{EXPECTED_FEATURE_COUNT}_finite_floats",
                "prediction": None,
                "attack_probability": None,
                "benign_probability": None,
                "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        model = self.rf_bundle["model"]
        scaler = self.rf_bundle.get("scaler")
        threshold = float(self.rf_bundle.get("threshold", 0.50))

        X_raw_2d = arr.reshape(1, -1)
        X_scaled = scaler.transform(X_raw_2d) if scaler is not None else X_raw_2d

        probs = model.predict_proba(X_scaled)[0].tolist()
        benign_prob = float(probs[self.benign_class_index])
        if len(probs) == 2:
            attack_prob = float(probs[self.attack_class_index])
            target_attack_idx = self.attack_class_index
        else:
            # Multiclass support: explain highest non-benign class probability
            non_benign = [
                (idx, float(p))
                for idx, p in enumerate(probs)
                if idx != self.benign_class_index
            ]
            target_attack_idx, attack_prob = max(non_benign, key=lambda kv: kv[1])

        is_attack = bool(attack_prob >= threshold)
        predicted_class_idx = target_attack_idx if is_attack else self.benign_class_index
        predicted_class_label = "attack" if is_attack else "normal"
        predicted_class_prob = float(probs[predicted_class_idx])

        if self.is_exact_shap and self.tree_explainer is not None:
            raw_sv = self.tree_explainer.shap_values(X_scaled, check_additivity=True)
            raw_ev = self.tree_explainer.expected_value

            attack_shap, attack_base = self._extract_class_shap_vector(
                raw_sv, raw_ev, target_attack_idx, len(probs)
            )
            pred_shap, pred_base = self._extract_class_shap_vector(
                raw_sv, raw_ev, predicted_class_idx, len(probs)
            )
            additivity_reconstructed = float(attack_base + np.sum(attack_shap))
            additivity_diff = abs(attack_prob - additivity_reconstructed)
            additivity_verified = bool(additivity_diff < 1e-6)
        else:
            # Validated model-agnostic reference perturbation fallback (explicitly labeled NOT exact SHAP)
            medians = np.array(
                [self.normal_stats[j]["median"] for j in range(EXPECTED_FEATURE_COUNT)],
                dtype=np.float64,
            ).reshape(1, -1)
            med_scaled = scaler.transform(medians) if scaler is not None else medians
            attack_base = float(model.predict_proba(med_scaled)[0][target_attack_idx])

            perturbed_batch = np.repeat(X_raw_2d, EXPECTED_FEATURE_COUNT, axis=0)
            for j in range(EXPECTED_FEATURE_COUNT):
                perturbed_batch[j, j] = medians[0, j]
            pert_scaled = scaler.transform(perturbed_batch) if scaler is not None else perturbed_batch
            pert_probs = model.predict_proba(pert_scaled)[:, target_attack_idx]
            attack_shap = attack_prob - pert_probs
            pred_shap = attack_shap if is_attack else -attack_shap
            pred_base = attack_base if is_attack else float(1.0 - attack_base)
            additivity_reconstructed = float(attack_base + np.sum(attack_shap))
            additivity_diff = abs(attack_prob - additivity_reconstructed)
            additivity_verified = False

        # Build full 69-feature attribution list for the attack-class probability P(attack|x)
        feature_attributions: List[Dict[str, Any]] = []
        for j in range(EXPECTED_FEATURE_COUNT):
            meta = FEATURE_CATALOG_69[j]
            s_attack = float(attack_shap[j])
            s_pred = float(pred_shap[j])
            ref = self.normal_stats.get(j, {})
            feature_attributions.append(
                {
                    "feature_index": j,
                    "feature_name": FEATURE_NAMES_69[j],
                    "human_label": meta["human_label"],
                    "raw_value": round(float(arr[j]), 6),
                    "scaled_value": round(float(X_scaled[0, j]), 6),
                    "normal_median": round(float(ref.get("median", 0.0)), 6),
                    "shap_value_attack": round(s_attack, 6),
                    "shap_value_predicted_class": round(s_pred, 6),
                    "abs_shap_value": round(abs(s_attack), 6),
                    "direction": (
                        "pushes_toward_attack"
                        if s_attack > 1e-9
                        else "pushes_toward_benign"
                        if s_attack < -1e-9
                        else "neutral"
                    ),
                    "primary_measurement_family": meta["primary_measurement_family"],
                    "structural_group": meta["structural_group"],
                    "is_duplicate_column": meta["is_duplicate_column"],
                    "duplicate_group_leader": meta["duplicate_group_leader"],
                    "is_collinear_padding": meta["is_collinear_padding"],
                }
            )

        # Top 5 positive contributors (pushing prediction toward attack, s_attack > 0)
        positive_sorted = sorted(
            [f for f in feature_attributions if f["shap_value_attack"] > 0],
            key=lambda item: item["shap_value_attack"],
            reverse=True,
        )[:top_k]

        # Top 5 negative contributors (pushing prediction toward benign/normal, s_attack < 0)
        negative_sorted = sorted(
            [f for f in feature_attributions if f["shap_value_attack"] < 0],
            key=lambda item: item["shap_value_attack"],
        )[:top_k]

        # Top-k by absolute magnitude
        top_abs_sorted = sorted(
            feature_attributions,
            key=lambda item: item["abs_shap_value"],
            reverse=True,
        )[:top_k]

        grouped_summary = self.grouper.summarize_attributions(
            attack_shap, arr.tolist(), value_type="shap_attack_probability_delta"
        )

        return {
            "status": "healthy",
            "model_name": "random_forest",
            "schema_version": FEATURE_SCHEMA_VERSION,
            "explanation_method": self.explainer_backend,
            "is_exact_shap": self.is_exact_shap,
            "score_semantics": "SUPERVISED_CLASS_PROBABILITY_SHAP_ADDITIVE_ATTRIBUTION",
            "prediction": int(1 if is_attack else 0),
            "predicted_class_label": predicted_class_label,
            "predicted_class_index": int(predicted_class_idx),
            "predicted_class_confidence": round(predicted_class_prob, 6),
            "attack_class_index": int(target_attack_idx),
            "attack_probability": round(attack_prob, 6),
            "benign_probability": round(benign_prob, 6),
            "probabilities": [round(float(p), 6) for p in probs],
            "decision_threshold": round(threshold, 6),
            "base_expected_value_attack": round(attack_base, 6),
            "base_expected_value_predicted_class": round(pred_base, 6),
            "shap_sum_attack": round(float(np.sum(attack_shap)), 6),
            "reconstructed_attack_probability": round(additivity_reconstructed, 6),
            "additivity_error": float(additivity_diff),
            "additivity_verified": additivity_verified,
            "top_positive_attack_contributors": positive_sorted,
            "top_negative_benign_contributors": negative_sorted,
            "top_absolute_contributors": top_abs_sorted,
            "all_feature_shap_values": feature_attributions,
            "grouped_measurement_explanation": grouped_summary,
            "explanation_narrative": self._build_rf_narrative(
                is_attack=is_attack,
                attack_prob=attack_prob,
                attack_base=attack_base,
                threshold=threshold,
                top_pos=positive_sorted,
                top_neg=negative_sorted,
                grouped=grouped_summary,
            ),
            "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
        }

    def compute_global_feature_importance(
        self,
        sample_matrix: np.ndarray,
        max_samples: int = 200,
        top_k: int = 15,
    ) -> Dict[str, Any]:
        """
        Computes global SHAP feature importance (`mean(|SHAP|)` for the attack class)
        alongside the trained Random Forest's impurity-based `feature_importances_`.
        """
        if self._global_importance_cache is not None and len(sample_matrix) == self._global_importance_cache.get("evaluated_samples"):
            return self._global_importance_cache

        t0 = time.perf_counter()
        if self.status != "healthy" or not self.rf_bundle or self.rf_bundle.get("model") is None:
            return {
                "status": "degraded",
                "degraded_reason": self.degraded_reason or "random_forest_unavailable",
            }

        model = self.rf_bundle["model"]
        scaler = self.rf_bundle.get("scaler")
        mat = np.asarray(sample_matrix, dtype=np.float64)
        if mat.shape[0] > max_samples:
            mat = mat[:max_samples]

        X_scaled = scaler.transform(mat) if scaler is not None else mat
        gini_imp = np.asarray(
            getattr(model, "feature_importances_", np.zeros(EXPECTED_FEATURE_COUNT)),
            dtype=np.float64,
        )

        if self.is_exact_shap and self.tree_explainer is not None:
            raw_sv = self.tree_explainer.shap_values(X_scaled)
            if isinstance(raw_sv, list):
                sv_attack = np.asarray(raw_sv[self.attack_class_index], dtype=np.float64)
            else:
                arr = np.asarray(raw_sv, dtype=np.float64)
                sv_attack = arr[:, :, self.attack_class_index] if arr.ndim == 3 else arr
            mean_abs_shap = np.mean(np.abs(sv_attack), axis=0)
        else:
            mean_abs_shap = gini_imp.copy()

        total_mean_abs = float(np.sum(mean_abs_shap)) or 1e-12
        ranked_indices = np.argsort(mean_abs_shap)[::-1]

        features_ranked: List[Dict[str, Any]] = []
        for rank_idx, f_idx in enumerate(ranked_indices, start=1):
            idx = int(f_idx)
            meta = FEATURE_CATALOG_69[idx]
            features_ranked.append(
                {
                    "rank": rank_idx,
                    "feature_index": idx,
                    "feature_name": FEATURE_NAMES_69[idx],
                    "human_label": meta["human_label"],
                    "mean_abs_shap": round(float(mean_abs_shap[idx]), 6),
                    "shap_importance_share": round(float(mean_abs_shap[idx] / total_mean_abs), 4),
                    "gini_importance": round(float(gini_imp[idx]), 6),
                    "primary_measurement_family": meta["primary_measurement_family"],
                    "structural_group": meta["structural_group"],
                    "is_duplicate_column": meta["is_duplicate_column"],
                    "duplicate_group_leader": meta["duplicate_group_leader"],
                    "is_collinear_padding": meta["is_collinear_padding"],
                }
            )

        grouped_global = self.grouper.summarize_attributions(
            mean_abs_shap,
            mat[0].tolist(),
            value_type="global_mean_abs_shap",
        )

        result = {
            "status": "healthy",
            "schema_version": FEATURE_SCHEMA_VERSION,
            "explanation_method": self.explainer_backend,
            "is_exact_shap": self.is_exact_shap,
            "evaluated_samples": int(mat.shape[0]),
            "top_features": features_ranked[:top_k],
            "all_features_ranked": features_ranked,
            "grouped_global_importance": {
                "raw_measurement_attribution": grouped_global["raw_measurement_attribution"],
                "structural_group_attribution": grouped_global["structural_group_attribution"],
                "collinear_and_duplicate_group_totals": grouped_global["collinear_and_duplicate_group_totals"],
                "correlated_feature_limitation": CORRELATED_ATTRIBUTION_LIMITATION_NOTE,
            },
            "computation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
        }
        self._global_importance_cache = result
        return result

    @staticmethod
    def _build_rf_narrative(
        is_attack: bool,
        attack_prob: float,
        attack_base: float,
        threshold: float,
        top_pos: List[Dict[str, Any]],
        top_neg: List[Dict[str, Any]],
        grouped: Dict[str, Any],
    ) -> str:
        verdict = "MALICIOUS (attack)" if is_attack else "BENIGN (normal)"
        pos_str = ", ".join(
            f"{f['feature_name']} ({f['shap_value_attack']:+.4f}, raw={f['raw_value']})"
            for f in top_pos[:3]
        ) or "none"
        neg_str = ", ".join(
            f"{f['feature_name']} ({f['shap_value_attack']:+.4f}, raw={f['raw_value']})"
            for f in top_neg[:3]
        ) or "none"
        raw_shares = grouped["raw_measurement_attribution"]
        return (
            f"Random Forest classified this flow as {verdict} with attack probability "
            f"P(attack|x)={attack_prob:.4f} (threshold={threshold:.2f}, base expected value={attack_base:.4f}). "
            f"Top features increasing attack probability: [{pos_str}]. "
            f"Top features decreasing attack probability toward normal: [{neg_str}]. "
            f"Aggregated across the 3 underlying raw measurements, attribution weight is "
            f"packets={raw_shares['packets']['share_of_total'] * 100:.1f}%, "
            f"bytes={raw_shares['bytes']['share_of_total'] * 100:.1f}%, "
            f"duration={raw_shares['duration']['share_of_total'] * 100:.1f}%."
        )


# =============================================================================
# 4. PART B — ISOLATION FOREST ANOMALY EXPLAINER (PERTURBATION + BASELINE)
# =============================================================================

class IsolationForestAnomalyExplainer:
    """
    Model-agnostic, reference-population perturbation and baseline quantile explainer
    for the existing trained Isolation Forest (`models/isolation_forest_69_v2.pkl`).

    Methodology:
      1. Evaluates the exact saved `StandardScaler` + `IsolationForest.decision_function`
         pipeline (`best_threshold = -0.024499`, where `raw_decision_score < threshold`
         indicates an anomaly).
      2. Computes vectorized single-feature counterfactual perturbations by replacing
         each feature `x_j` with the 840-flow `train_normal` median `Q50(X_j)`, measuring:
           - `raw_score_rescue_delta = raw_score(x with x_j <- median_j) - raw_score(x)`
             (Positive delta means replacing `x_j` with normal median moves the flow
             toward normal interior space, proving `x_j` contributed to isolation).
           - `anomaly_score_delta = anomaly_score(x) - anomaly_score(x with x_j <- median_j)`
      3. Computes correlated-group counterfactual perturbations by simultaneously
         replacing correlated duplicate/collinear groups (`f_25..f_39` even/odd duplicates,
         `f_55..f_68` harmonic padding) and physical `(packets, bytes, duration)` families
         with `train_normal` medians so tree splits distributed across identical/collinear
         features are captured faithfully.
      4. Compares every feature against the `train_normal` reference distribution (`median`,
         `IQR`, `P05`, `P25`, `P75`, `P95`, `robust_z_score`, `empirical_percentile`).
      5. Never presents Isolation Forest anomaly scores or attributions as probabilities.
    """

    def __init__(
        self,
        if_bundle: Optional[Dict[str, Any]],
        normal_matrix: Optional[np.ndarray],
        normal_stats: Optional[Dict[int, Dict[str, float]]],
    ) -> None:
        self.if_bundle = if_bundle
        self.normal_matrix = normal_matrix
        self.normal_stats = normal_stats or {}
        self.grouper = ThreeScalarMeasurementGrouper(self.normal_stats)

        self.status: str = "degraded"
        self.degraded_reason: Optional[str] = "uninitialized"
        self._sorted_normal_cols: Optional[np.ndarray] = None
        self._normal_medians_vec: Optional[np.ndarray] = None

        self._initialize()

    def _get_if_model(self) -> Any:
        if not self.if_bundle:
            return None
        return self.if_bundle.get("model") or self.if_bundle.get("isolation_forest")

    def _get_if_threshold(self) -> float:
        if not self.if_bundle:
            return -0.024499
        return float(
            self.if_bundle.get("threshold", self.if_bundle.get("best_threshold", -0.024499))
        )

    def _initialize(self) -> None:
        if not self.if_bundle or self._get_if_model() is None:
            self.status = "degraded"
            self.degraded_reason = "isolation_forest_model_not_loaded"
            return
        if (
            self.normal_matrix is None
            or len(self.normal_matrix) == 0
            or len(self.normal_stats) != EXPECTED_FEATURE_COUNT
        ):
            self.status = "degraded"
            self.degraded_reason = "normal_reference_population_not_loaded"
            return

        self._sorted_normal_cols = np.sort(self.normal_matrix, axis=0)
        self._normal_medians_vec = np.array(
            [self.normal_stats[j]["median"] for j in range(EXPECTED_FEATURE_COUNT)],
            dtype=np.float64,
        )
        self.status = "healthy"
        self.degraded_reason = None

    def _empirical_percentile(self, feature_idx: int, value: float) -> float:
        if self._sorted_normal_cols is None:
            return 50.0
        col = self._sorted_normal_cols[:, feature_idx]
        pos = int(np.searchsorted(col, value, side="right"))
        return round((pos / float(len(col))) * 100.0, 2)

    def explain_flow(self, features: List[float], top_k: int = 5) -> Dict[str, Any]:
        """
        Generates a perturbation-based and reference-population anomaly explanation for
        an individual flow under the existing Isolation Forest model.
        """
        t0 = time.perf_counter()
        if self.status != "healthy" or not self.if_bundle or self._normal_medians_vec is None:
            return {
                "status": "degraded",
                "model_name": "isolation_forest",
                "explanation_method": "reference_population_perturbation_and_quantile_deviation",
                "score_semantics": "UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY",
                "degraded_reason": self.degraded_reason or "isolation_forest_unavailable",
                "is_anomaly": None,
                "anomaly_score": None,
                "raw_decision_score": None,
                "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        arr = TriModelDetectionEngine._validate_69_features(features)
        if arr is None:
            return {
                "status": "degraded",
                "model_name": "isolation_forest",
                "explanation_method": "reference_population_perturbation_and_quantile_deviation",
                "score_semantics": "UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY",
                "degraded_reason": f"invalid_input_features_expected_{EXPECTED_FEATURE_COUNT}_finite_floats",
                "is_anomaly": None,
                "anomaly_score": None,
                "raw_decision_score": None,
                "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        model = self._get_if_model()
        scaler = self.if_bundle.get("scaler")
        threshold = self._get_if_threshold()

        X_raw_2d = arr.reshape(1, -1)
        X_scaled = scaler.transform(X_raw_2d) if scaler is not None else X_raw_2d
        raw_score = float(model.decision_function(X_scaled)[0])
        is_anomaly = bool(raw_score < threshold)
        norm_anomaly_score = float(_sigmoid((threshold - raw_score) / 0.08))

        # 1. Single-feature counterfactual perturbation batch (69 rows: row j replaces x_j with normal median_j)
        perturbed_single = np.repeat(X_raw_2d, EXPECTED_FEATURE_COUNT, axis=0)
        for j in range(EXPECTED_FEATURE_COUNT):
            perturbed_single[j, j] = self._normal_medians_vec[j]

        # 2. Correlated-group counterfactual perturbations for duplicate/collinear blocks
        #    Row 0: replace all 8 even polynomial duplicates (f_25..f_39 even)
        #    Row 1: replace all 7 odd polynomial duplicates (f_26..f_38 odd)
        #    Row 2: replace all 14 harmonic padding columns (f_55..f_68)
        #    Row 3: replace all packet-only derived features with normal median packet flow
        #    Row 4: replace all byte-only derived features with normal median byte flow
        #    Row 5: replace all duration-only derived features with normal median duration flow
        group_perturb_rows = np.repeat(X_raw_2d, 6, axis=0)
        group_perturb_rows[0, EVEN_POLY_DUPLICATE_INDICES] = self._normal_medians_vec[EVEN_POLY_DUPLICATE_INDICES]
        group_perturb_rows[1, ODD_POLY_DUPLICATE_INDICES] = self._normal_medians_vec[ODD_POLY_DUPLICATE_INDICES]
        group_perturb_rows[2, HARMONIC_PADDING_INDICES] = self._normal_medians_vec[HARMONIC_PADDING_INDICES]

        # Re-extract 69 features when replacing raw packets, bytes, or duration with normal median
        p_med = self.normal_stats[0]["median"]
        b_med = self.normal_stats[1]["median"]
        d_med = self.normal_stats[2]["median"]
        group_perturb_rows[3, :] = extract_69_features({"packets": p_med, "bytes": float(arr[1]), "duration": float(arr[2])})
        group_perturb_rows[4, :] = extract_69_features({"packets": float(arr[0]), "bytes": b_med, "duration": float(arr[2])})
        group_perturb_rows[5, :] = extract_69_features({"packets": float(arr[0]), "bytes": float(arr[1]), "duration": d_med})

        combined_batch = np.vstack([perturbed_single, group_perturb_rows])
        combined_scaled = scaler.transform(combined_batch) if scaler is not None else combined_batch
        combined_raw_scores = model.decision_function(combined_scaled)

        single_pert_raw = combined_raw_scores[:EXPECTED_FEATURE_COUNT]
        group_pert_raw = combined_raw_scores[EXPECTED_FEATURE_COUNT:]

        # raw_score_rescue_delta > 0 means replacing feature j with normal median increased
        # decision_function toward normal (i.e., feature j pushed the flow toward anomaly).
        raw_rescue_deltas = single_pert_raw - raw_score
        single_pert_anom_scores = np.array(
            [_sigmoid((threshold - float(s)) / 0.08) for s in single_pert_raw],
            dtype=np.float64,
        )
        anomaly_score_deltas = norm_anomaly_score - single_pert_anom_scores

        # Distribute correlated duplicate-block rescue delta across duplicate members when
        # single-column perturbation was masked by identical twin columns in tree splits
        even_block_rescue = max(0.0, float(group_pert_raw[0] - raw_score))
        odd_block_rescue = max(0.0, float(group_pert_raw[1] - raw_score))
        pad_block_rescue = max(0.0, float(group_pert_raw[2] - raw_score))

        effective_influence = np.zeros(EXPECTED_FEATURE_COUNT, dtype=np.float64)
        feature_explanations: List[Dict[str, Any]] = []
        unusually_high_features: List[Dict[str, Any]] = []
        unusually_low_features: List[Dict[str, Any]] = []

        for j in range(EXPECTED_FEATURE_COUNT):
            meta = FEATURE_CATALOG_69[j]
            ref = self.normal_stats[j]
            val = float(arr[j])
            iqr = max(float(ref["iqr"]), 1e-6)
            rob_z = (val - float(ref["median"])) / iqr
            pct = self._empirical_percentile(j, val)

            if val > float(ref["p95"]) and rob_z > 2.0:
                dev_status = "UNUSUALLY_HIGH"
            elif val < float(ref["p05"]) and rob_z < -2.0:
                dev_status = "UNUSUALLY_LOW"
            elif val > float(ref["p75"]) and rob_z > 1.0:
                dev_status = "MODERATELY_HIGH"
            elif val < float(ref["p25"]) and rob_z < -1.0:
                dev_status = "MODERATELY_LOW"
            else:
                dev_status = "WITHIN_NORMAL_RANGE"

            single_delta = float(raw_rescue_deltas[j])
            anom_delta = float(anomaly_score_deltas[j])

            # Combine direct perturbation shift with group-aware duplicate rescue if applicable
            if j in EVEN_POLY_DUPLICATE_INDICES:
                group_share = even_block_rescue / len(EVEN_POLY_DUPLICATE_INDICES)
                eff_score = max(abs(single_delta), group_share) * (1.0 if single_delta >= 0 else -1.0)
            elif j in ODD_POLY_DUPLICATE_INDICES:
                group_share = odd_block_rescue / len(ODD_POLY_DUPLICATE_INDICES)
                eff_score = max(abs(single_delta), group_share) * (1.0 if single_delta >= 0 else -1.0)
            elif j in HARMONIC_PADDING_INDICES:
                group_share = pad_block_rescue / len(HARMONIC_PADDING_INDICES)
                eff_score = max(abs(single_delta), group_share) * (1.0 if single_delta >= 0 else -1.0)
            else:
                eff_score = single_delta

            effective_influence[j] = eff_score

            entry = {
                "feature_index": j,
                "feature_name": FEATURE_NAMES_69[j],
                "human_label": meta["human_label"],
                "flow_value": round(val, 6),
                "normal_median": round(float(ref["median"]), 6),
                "normal_iqr": round(float(ref["iqr"]), 6),
                "normal_p05": round(float(ref["p05"]), 6),
                "normal_p95": round(float(ref["p95"]), 6),
                "robust_z_score": round(float(rob_z), 4),
                "normal_empirical_percentile": pct,
                "population_deviation_status": dev_status,
                "perturbation_raw_score_shift": round(single_delta, 6),
                "perturbation_anomaly_score_shift": round(anom_delta, 6),
                "effective_isolation_influence": round(float(eff_score), 6),
                "influence_direction": (
                    "increases_anomaly_isolation"
                    if eff_score > 1e-6 or abs(rob_z) > 2.5
                    else "stabilizes_within_normal"
                ),
                "primary_measurement_family": meta["primary_measurement_family"],
                "structural_group": meta["structural_group"],
                "is_duplicate_column": meta["is_duplicate_column"],
                "duplicate_group_leader": meta["duplicate_group_leader"],
                "is_collinear_padding": meta["is_collinear_padding"],
            }
            feature_explanations.append(entry)
            if dev_status == "UNUSUALLY_HIGH":
                unusually_high_features.append(entry)
            elif dev_status == "UNUSUALLY_LOW":
                unusually_low_features.append(entry)

        # Rank influential features by combined perturbation shift and population extremity
        ranked_influential = sorted(
            feature_explanations,
            key=lambda f: (abs(f["effective_isolation_influence"]), abs(f["robust_z_score"])),
            reverse=True,
        )[:top_k]

        unusually_high_sorted = sorted(
            unusually_high_features, key=lambda f: f["robust_z_score"], reverse=True
        )[:top_k]
        unusually_low_sorted = sorted(
            unusually_low_features, key=lambda f: f["robust_z_score"]
        )[:top_k]

        # Counterfactual 3-scalar raw measurement replacement summary
        counterfactual_raw_replacement = {
            "replace_packets_with_normal_median": {
                "normal_median_packets": round(p_med, 4),
                "perturbed_raw_decision_score": round(float(group_pert_raw[3]), 6),
                "raw_score_shift_toward_normal": round(float(group_pert_raw[3] - raw_score), 6),
            },
            "replace_bytes_with_normal_median": {
                "normal_median_bytes": round(b_med, 4),
                "perturbed_raw_decision_score": round(float(group_pert_raw[4]), 6),
                "raw_score_shift_toward_normal": round(float(group_pert_raw[4] - raw_score), 6),
            },
            "replace_duration_with_normal_median": {
                "normal_median_duration": round(d_med, 4),
                "perturbed_raw_decision_score": round(float(group_pert_raw[5]), 6),
                "raw_score_shift_toward_normal": round(float(group_pert_raw[5] - raw_score), 6),
            },
        }

        grouped_summary = self.grouper.summarize_attributions(
            effective_influence,
            arr.tolist(),
            value_type="isolation_forest_perturbation_influence",
        )

        return {
            "status": "healthy",
            "model_name": "isolation_forest",
            "schema_version": FEATURE_SCHEMA_VERSION,
            "explanation_method": "reference_population_perturbation_and_quantile_deviation",
            "score_semantics": "UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY",
            "scientific_disclaimer": (
                "Isolation Forest outputs an unsupervised tree-isolation depth score "
                "(raw_decision_score < threshold indicates shorter average path length in random "
                "partition trees) and a monotonic severity index in [0, 1]. Neither the anomaly "
                "score nor perturbation feature influence is a calibrated probability or causal "
                "explanation of malicious intent."
            ),
            "reference_population_size": int(len(self.normal_matrix)),
            "decision": "anomalous" if is_anomaly else "normal",
            "is_anomaly": is_anomaly,
            "raw_decision_score": round(raw_score, 6),
            "decision_threshold": round(threshold, 6),
            "margin_from_threshold": round(raw_score - threshold, 6),
            "anomaly_score": round(norm_anomaly_score, 6),
            "top_influential_features": ranked_influential,
            "unusually_high_measurements": unusually_high_sorted,
            "unusually_low_measurements": unusually_low_sorted,
            "unusually_high_count": len(unusually_high_features),
            "unusually_low_count": len(unusually_low_features),
            "counterfactual_raw_measurement_perturbations": counterfactual_raw_replacement,
            "all_feature_comparisons": feature_explanations,
            "grouped_measurement_explanation": grouped_summary,
            "explanation_narrative": self._build_if_narrative(
                is_anomaly=is_anomaly,
                raw_score=raw_score,
                threshold=threshold,
                norm_score=norm_anomaly_score,
                top_features=ranked_influential,
                high_count=len(unusually_high_features),
                low_count=len(unusually_low_features),
                counterfactual=counterfactual_raw_replacement,
            ),
            "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
        }

    @staticmethod
    def _build_if_narrative(
        is_anomaly: bool,
        raw_score: float,
        threshold: float,
        norm_score: float,
        top_features: List[Dict[str, Any]],
        high_count: int,
        low_count: int,
        counterfactual: Dict[str, Any],
    ) -> str:
        verdict = "ANOMALOUS (isolated outlier)" if is_anomaly else "NORMAL (interior point)"
        feat_str = ", ".join(
            f"{f['feature_name']} (shift={f['effective_isolation_influence']:+.4f}, Z={f['robust_z_score']:+.2f}, {f['population_deviation_status']})"
            for f in top_features[:3]
        ) or "none"
        cf_p = counterfactual["replace_packets_with_normal_median"]["raw_score_shift_toward_normal"]
        cf_b = counterfactual["replace_bytes_with_normal_median"]["raw_score_shift_toward_normal"]
        cf_d = counterfactual["replace_duration_with_normal_median"]["raw_score_shift_toward_normal"]
        return (
            f"Isolation Forest evaluated this flow as {verdict} with raw decision score "
            f"{raw_score:.4f} vs threshold {threshold:.4f} (monotonic anomaly score={norm_score:.4f}; "
            f"note: this is an unsupervised isolation metric, NOT a probability). "
            f"Compared against the 840-flow normal reference baseline, {high_count} features are "
            f"unusually high (>P95) and {low_count} features are unusually low (<P05). "
            f"Top isolation drivers by median-replacement perturbation: [{feat_str}]. "
            f"Whole-measurement counterfactual replacement shifts raw score toward normal by: "
            f"packets={cf_p:+.4f}, bytes={cf_b:+.4f}, duration={cf_d:+.4f}."
        )

    def compare_with_tree_explainer_reference(self, features: List[float]) -> Dict[str, Any]:
        """
        Compares our reference-population perturbation attribution against the official
        `shap.TreeExplainer` decomposition of `IsolationForest` tree path lengths,
        serving as a trusted mathematical reference check for Stage 1 verification.
        """
        if not SHAP_AVAILABLE or self.status != "healthy":
            return {"status": "unavailable", "reason": SHAP_IMPORT_ERROR or self.degraded_reason}

        arr = TriModelDetectionEngine._validate_69_features(features)
        if arr is None:
            return {"status": "invalid_input"}

        model = self._get_if_model()
        scaler = self.if_bundle.get("scaler")
        X_scaled = scaler.transform(arr.reshape(1, -1)) if scaler is not None else arr.reshape(1, -1)

        if_tree_exp = _shap_lib.TreeExplainer(model)
        # In shap.TreeExplainer for IsolationForest, negative SHAP values pull average path
        # length / decision score down toward anomaly; negating gives anomaly-pushing magnitude.
        if_shap_vals = -np.asarray(if_tree_exp.shap_values(X_scaled), dtype=np.float64).reshape(-1)
        shap_grouped = self.grouper.summarize_attributions(
            if_shap_vals, arr.tolist(), value_type="reference_tree_shap_if"
        )

        pert_result = self.explain_flow(features)
        pert_grouped = pert_result["grouped_measurement_explanation"]

        shap_raw = shap_grouped["raw_measurement_attribution"]
        pert_raw = pert_grouped["raw_measurement_attribution"]

        shap_dominant_family = max(shap_raw.items(), key=lambda kv: kv[1]["share_of_total"])[0]
        pert_dominant_family = max(pert_raw.items(), key=lambda kv: kv[1]["share_of_total"])[0]

        return {
            "status": "verified",
            "reference_explainer": f"shap.TreeExplainer_v{SHAP_VERSION}",
            "perturbation_dominant_raw_family": pert_dominant_family,
            "tree_shap_dominant_raw_family": shap_dominant_family,
            "perturbation_raw_shares": {
                k: v["share_of_total"] for k, v in pert_raw.items()
            },
            "tree_shap_raw_shares": {
                k: v["share_of_total"] for k, v in shap_raw.items()
            },
            "tree_shap_l1_norm": round(float(np.sum(np.abs(if_shap_vals))), 6),
        }


# =============================================================================
# 5. PART C — AUTOENCODER RECONSTRUCTION EXPLAINER (FROZEN P97 = 0.503670)
# =============================================================================

class AutoencoderReconstructionExplainer:
    """
    Reconstruction error explainer for the authoritative PyTorch `FlowAutoencoder`
    (`69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69`, `ae-pytorch-v2.0.0`).

    Uses the exact existing `FeaturePreprocessor` (`signed_log1p` + `RobustScaler(25, 75)`
    + `clip[-10, 10]`) and preserves the frozen validation-derived `P97 = 0.503670`
    threshold (`P95 = 0.409105`, `P99 = 0.645935`).
    """

    def __init__(
        self,
        ae_engine: AutoencoderInferenceEngine,
        normal_stats: Optional[Dict[int, Dict[str, float]]] = None,
    ) -> None:
        self.ae_engine = ae_engine
        self.normal_stats = normal_stats or {}
        self.grouper = ThreeScalarMeasurementGrouper(self.normal_stats)

    def explain_flow(self, features: List[float], top_k: int = 5) -> Dict[str, Any]:
        """
        Runs the 69-dimensional vector through the exact `FeaturePreprocessor` and PyTorch
        `FlowAutoencoder`, computing all 69 per-feature reconstruction errors, ranking them,
        identifying the top-5 anomalous features, and comparing against the frozen `P97`
        threshold.
        """
        t0 = time.perf_counter()
        if (
            self.ae_engine is None
            or self.ae_engine.status != "healthy"
            or self.ae_engine.model is None
            or self.ae_engine.preprocessor is None
        ):
            return {
                "status": "degraded",
                "model_name": "autoencoder",
                "explanation_method": "pytorch_bottleneck_reconstruction_error_decomposition",
                "score_semantics": "RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY",
                "degraded_reason": (
                    self.ae_engine.degraded_reason
                    if self.ae_engine is not None
                    else "autoencoder_engine_unavailable"
                ),
                "is_anomaly": None,
                "reconstruction_error": None,
                "anomaly_score": None,
                "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        try:
            scaled_2d = self.ae_engine.preprocessor.transform(features)
        except Exception as exc:
            return {
                "status": "degraded",
                "model_name": "autoencoder",
                "explanation_method": "pytorch_bottleneck_reconstruction_error_decomposition",
                "score_semantics": "RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY",
                "degraded_reason": f"invalid_input_features:{exc}",
                "is_anomaly": None,
                "reconstruction_error": None,
                "anomaly_score": None,
                "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
            }

        raw_arr = np.asarray(features, dtype=np.float64).reshape(-1)
        with torch.no_grad():
            tensor_in = torch.from_numpy(scaled_2d)
            latent_8d = self.ae_engine.model.encode(tensor_in).squeeze(0).numpy()
            tensor_out = self.ae_engine.model(tensor_in)
            scaled_in = tensor_in.squeeze(0).numpy()
            scaled_out = tensor_out.squeeze(0).numpy()
            residuals = scaled_in - scaled_out
            diff_sq = (residuals ** 2).astype(np.float64)
            mse_error = float(np.mean(diff_sq))
            total_sq = float(np.sum(diff_sq)) or 1e-12

        p95 = float(self.ae_engine.threshold_p95)
        p97 = float(self.ae_engine.selected_threshold)
        p99 = float(self.ae_engine.threshold_p99)
        percentile_name = str(self.ae_engine.selected_threshold_name or "P97")

        ratio_to_p97 = mse_error / max(p97, 1e-9)
        normalized_score = float(ratio_to_p97 / (1.0 + ratio_to_p97))

        if mse_error > p97:
            decision = "anomalous"
            is_anomaly = True
            threshold_tier = "CRITICAL_ABOVE_P99" if (p99 > 0 and mse_error > p99) else "ANOMALOUS_ABOVE_P97"
        elif p95 > 0.0 and mse_error > p95:
            decision = "suspicious"
            is_anomaly = False
            threshold_tier = "SUSPICIOUS_BETWEEN_P95_AND_P97"
        else:
            decision = "normal"
            is_anomaly = False
            threshold_tier = "NORMAL_BELOW_P95"

        # Build all 69 per-feature reconstruction error records and rank them descending
        ranked_indices = np.argsort(diff_sq)[::-1]
        rank_of_index = {int(f_idx): int(r + 1) for r, f_idx in enumerate(ranked_indices)}

        all_features_breakdown: List[Dict[str, Any]] = []
        features_exceeding_p97_count = 0
        for j in range(EXPECTED_FEATURE_COUNT):
            meta = FEATURE_CATALOG_69[j]
            sq_err = float(diff_sq[j])
            exceeds_p97 = bool(sq_err > p97)
            if exceeds_p97:
                features_exceeding_p97_count += 1
            all_features_breakdown.append(
                {
                    "rank": rank_of_index[j],
                    "feature_index": j,
                    "feature_name": FEATURE_NAMES_69[j],
                    "human_label": meta["human_label"],
                    "raw_value": round(float(raw_arr[j]), 6),
                    "preprocessed_input_z": round(float(scaled_in[j]), 6),
                    "reconstructed_output_z": round(float(scaled_out[j]), 6),
                    "signed_residual": round(float(residuals[j]), 6),
                    "squared_error": round(sq_err, 6),
                    "error_share": round(float(sq_err / total_sq), 4),
                    "ratio_to_p97_threshold": round(float(sq_err / max(p97, 1e-9)), 4),
                    "exceeds_p97_reference": exceeds_p97,
                    "primary_measurement_family": meta["primary_measurement_family"],
                    "structural_group": meta["structural_group"],
                    "is_duplicate_column": meta["is_duplicate_column"],
                    "duplicate_group_leader": meta["duplicate_group_leader"],
                    "is_collinear_padding": meta["is_collinear_padding"],
                }
            )

        ranked_features = sorted(all_features_breakdown, key=lambda x: x["rank"])
        top_anomalous_features = ranked_features[:top_k]

        grouped_summary = self.grouper.summarize_attributions(
            diff_sq,
            raw_arr.tolist(),
            value_type="autoencoder_squared_reconstruction_error",
        )

        return {
            "status": "healthy",
            "model_name": "autoencoder",
            "model_version": self.ae_engine.model_version,
            "architecture": "69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69",
            "schema_version": FEATURE_SCHEMA_VERSION,
            "explanation_method": "pytorch_bottleneck_reconstruction_error_decomposition",
            "score_semantics": "RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY",
            "scientific_disclaimer": (
                "Autoencoder reconstruction error (MSE) measures how poorly the 8-neuron bottleneck "
                "manifold trained on 840 normal flows reconstructs the preprocessed 69-feature vector. "
                "Reconstruction error is an anomaly measurement, NOT a calibrated probability or "
                "proof of malicious activity; Autoencoder-only anomalies must never independently "
                "authorize automatic IP blocking."
            ),
            "decision": decision,
            "is_anomaly": is_anomaly,
            "reconstruction_error": round(mse_error, 6),
            "anomaly_score": round(normalized_score, 6),
            "threshold": round(p97, 6),
            "threshold_percentile": percentile_name,
            "threshold_comparison": {
                "frozen_primary_threshold_p97": round(p97, 6),
                "warning_threshold_p95": round(p95, 6),
                "critical_threshold_p99": round(p99, 6),
                "overall_mse_to_p97_ratio": round(ratio_to_p97, 4),
                "overall_mse_minus_p97": round(mse_error - p97, 6),
                "exceeds_p95": bool(p95 > 0 and mse_error > p95),
                "exceeds_p97": is_anomaly,
                "exceeds_p99": bool(p99 > 0 and mse_error > p99),
                "threshold_tier": threshold_tier,
                "individual_features_exceeding_p97_count": features_exceeding_p97_count,
            },
            "bottleneck_latent_8d": [round(float(v), 6) for v in latent_8d],
            "top_anomalous_features": top_anomalous_features,
            "ranked_features": ranked_features,
            "all_features_by_index": all_features_breakdown,
            "grouped_measurement_explanation": grouped_summary,
            "explanation_narrative": self._build_ae_narrative(
                decision=decision,
                mse_error=mse_error,
                p97=p97,
                ratio=ratio_to_p97,
                top_features=top_anomalous_features,
                grouped=grouped_summary,
            ),
            "explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
        }

    @staticmethod
    def _build_ae_narrative(
        decision: str,
        mse_error: float,
        p97: float,
        ratio: float,
        top_features: List[Dict[str, Any]],
        grouped: Dict[str, Any],
    ) -> str:
        top_str = ", ".join(
            f"{f['feature_name']} (sq_err={f['squared_error']:.4f}, share={f['error_share'] * 100:.1f}%, z_in={f['preprocessed_input_z']:+.2f} vs z_out={f['reconstructed_output_z']:+.2f})"
            for f in top_features[:3]
        ) or "none"
        raw_shares = grouped["raw_measurement_attribution"]
        return (
            f"PyTorch Autoencoder (69->32->16->8->16->32->69) produced overall Mean Squared "
            f"Reconstruction Error MSE={mse_error:.6f} vs frozen validation threshold "
            f"P97={p97:.6f} ({ratio:.2f}x P97, decision={decision.upper()}; note: MSE is an "
            f"unsupervised reconstruction residual, NOT a probability). "
            f"Top anomalous features contributing to reconstruction error: [{top_str}]. "
            f"Grouped across the 3 raw flow scalars, reconstruction error is concentrated in "
            f"packets={raw_shares['packets']['share_of_total'] * 100:.1f}%, "
            f"bytes={raw_shares['bytes']['share_of_total'] * 100:.1f}%, "
            f"duration={raw_shares['duration']['share_of_total'] * 100:.1f}%."
        )
