"""
Shadow Guard 2.0 — XAI Stage 2: Unified Tri-Model Explanation Engine
====================================================================

Integrates the three validated Stage 1 model-specific explainers (`shared/ml/xai_explainer.py`)
into a single read-only explanation orchestrator (`UnifiedTriModelExplainer`) without modifying
Stage 1 code, model weights, preprocessing artifacts, thresholds, fusion policies, or SOAR rules.

Key Architectural & Scientific Guarantees:
1. Read-Only Orchestration:
   - Calls `TriModelDetectionEngine.evaluate_tri_model_fusion(features, policy="weighted_consensus")`
     without altering any prediction, threshold (`RF=0.50`, `IF=-0.024499`, `AE P97=0.503670`),
     decision rule, or `auto_block_permitted` guardrail.
2. Strict Separation of Mathematical Scales (No Cross-Model Averaging):
   - Never sums, averages, or directly equates:
     * Random Forest TreeSHAP values (additive class-1 probability deltas in `[-1.0, +1.0]`),
     * Isolation Forest perturbation shifts (unsupervised tree-isolation depth shifts), and
     * Autoencoder per-feature squared errors (bottleneck reconstruction MSE residuals in `[0, 100]`).
3. Collinearity-Aware Shared vs Model-Specific Attribution Analysis:
   - Because all 69 features in `v2.0-69dim` are deterministic functions of only 3 raw scalars
     (`packets`, `bytes`, `duration`)—including 13 exact polynomial duplicates (`f_25..f_39`) and
     14 rank-1 collinear harmonic padding features (`f_55..f_68`)—shared and model-specific
     drivers are evaluated at:
     a) The intrinsic raw measurement level (`packets`, `bytes`, `duration` within-model share), and
     b) The canonical deduplicated feature-concept level (collapsing duplicate/collinear blocks to
        their mathematical group leader so correlated columns are never misreported as independent
        confirmations).
4. Complete Availability & Fault Handling:
   - Gracefully handles all 3 models available (`healthy`), any single model unavailable
     (`RF` down, `IF` down, or `AE` down -> `partially_degraded`), multiple models unavailable
     (`partially_degraded` / `degraded`), invalid feature vectors (`degraded`), unknown `flow_id`
     (`degraded`), and runtime explanation calculation exceptions (`partially_degraded` / `degraded`).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
import torch

torch.set_num_threads(1)

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
    ThreeScalarMeasurementGrouper,
    load_normal_reference_population,
)


def _canonical_concept_id(feature_index: int) -> Tuple[str, str]:
    """
    Maps a 69-feature index to a deduplicated mathematical concept identifier and label
    so exact duplicate columns (`f_25..f_39`) and rank-1 collinear harmonic padding
    columns (`f_55..f_68`) are never counted as independent feature agreements.
    """
    meta = FEATURE_CATALOG_69[feature_index]
    if feature_index in EVEN_POLY_DUPLICATE_INDICES:
        return (
            "concept_poly_even_packets2_dur2",
            "Even Polynomial Ratio Group f_25..f_39 (packets^2 / (duration^2 + 1))",
        )
    if feature_index in ODD_POLY_DUPLICATE_INDICES:
        return (
            "concept_poly_odd_pkt_bytes_dur2",
            "Odd Polynomial Ratio Group f_26..f_38 ((packets * bytes) / (duration^2 + 1))",
        )
    if feature_index in HARMONIC_PADDING_INDICES:
        return (
            "concept_harmonic_collinear_padding",
            "Harmonic Collinear Padding Group f_55..f_68 (((packets + bytes) / (duration + 1)) * sin(idx))",
        )
    return (
        meta["feature_name"],
        f"{meta['feature_name']} ({meta['human_label']})",
    )


class UnifiedTriModelExplainer:
    """
    Unified Tri-Model Explanation Engine for Shadow Guard 2.0 (XAI Stage 2).
    """

    def __init__(
        self,
        tri_engine: Optional[TriModelDetectionEngine] = None,
        models_dir: Optional[Path] = None,
        dataset_path: Optional[Path] = None,
        rf_explainer: Optional[RandomForestSHAPExplainer] = None,
        if_explainer: Optional[IsolationForestAnomalyExplainer] = None,
        ae_explainer: Optional[AutoencoderReconstructionExplainer] = None,
    ) -> None:
        self.repo_root = Path(__file__).resolve().parent.parent.parent
        self.models_dir = Path(models_dir) if models_dir is not None else (self.repo_root / "models")
        self.dataset_path = (
            Path(dataset_path)
            if dataset_path is not None
            else (self.repo_root / "data" / "autoencoder_flow_dataset_v2.json")
        )

        self.tri_engine = tri_engine or TriModelDetectionEngine(models_dir=self.models_dir)
        self.normal_matrix, self.normal_stats = load_normal_reference_population(self.dataset_path)
        self.grouper = ThreeScalarMeasurementGrouper(self.normal_stats)

        self.rf_explainer = rf_explainer or RandomForestSHAPExplainer(
            rf_bundle=self.tri_engine.rf_bundle,
            normal_matrix=self.normal_matrix,
            normal_stats=self.normal_stats,
        )
        self.if_explainer = if_explainer or IsolationForestAnomalyExplainer(
            if_bundle=self.tri_engine.if_bundle,
            normal_matrix=self.normal_matrix,
            normal_stats=self.normal_stats,
        )
        self.ae_explainer = ae_explainer or AutoencoderReconstructionExplainer(
            ae_engine=self.tri_engine.ae_engine,
            normal_stats=self.normal_stats,
        )

        # Flow catalog indexed by flow_id and (packets, bytes, duration) collision signature
        self.flow_catalog: Dict[str, Dict[str, Any]] = {}
        self.pbd_collision_index: Dict[Tuple[float, float, float], List[Dict[str, Any]]] = {}
        self._load_flow_catalog()

    def _load_flow_catalog(self) -> None:
        if not self.dataset_path.exists():
            return
        try:
            raw = json.loads(self.dataset_path.read_text(encoding="utf-8"))
            splits = raw.get("splits", {})
            for split_name, records in splits.items():
                if not isinstance(records, list):
                    continue
                for rec in records:
                    fid = str(rec.get("flow_id", "")).strip()
                    if not fid:
                        continue
                    entry = dict(rec)
                    entry["split_origin"] = split_name
                    self.flow_catalog[fid] = entry

                    pbd_key = (
                        round(float(rec.get("packets", 0.0)), 4),
                        round(float(rec.get("bytes", 0.0)), 4),
                        round(float(rec.get("duration", 0.0)), 4),
                    )
                    self.pbd_collision_index.setdefault(pbd_key, []).append(
                        {
                            "flow_id": fid,
                            "label": str(rec.get("label", "unknown")),
                            "attack_category": str(rec.get("attack_category", "none")),
                            "traffic_profile": str(rec.get("traffic_profile", "unknown")),
                            "split_origin": split_name,
                        }
                    )
        except Exception:
            pass

    def resolve_flow_input(
        self,
        flow_id: Optional[str] = None,
        features: Optional[List[float]] = None,
        raw_flow: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[List[float]], Dict[str, Any], Optional[str]]:
        """
        Resolves either a `flow_id`, a 69-dimensional `features` vector, or a `raw_flow`
        dict containing `{packets, bytes, duration}` into `(resolved_flow_id, features_69, metadata, error)`.
        """
        meta: Dict[str, Any] = {}

        if flow_id is not None and features is None and raw_flow is None:
            fid = str(flow_id).strip()
            rec = self.flow_catalog.get(fid)
            if rec is None:
                return fid, None, {}, f"flow_id_not_found:{fid}"
            feats = rec.get("features_69")
            if not isinstance(feats, list) or len(feats) != EXPECTED_FEATURE_COUNT:
                feats = extract_69_features(
                    {
                        "packets": float(rec["packets"]),
                        "bytes": float(rec["bytes"]),
                        "duration": float(rec["duration"]),
                    }
                )
            meta = {
                "flow_id": fid,
                "src_ip": rec.get("src_ip"),
                "dst_ip": rec.get("dst_ip"),
                "src_port": rec.get("src_port"),
                "dst_port": rec.get("dst_port"),
                "protocol": rec.get("protocol"),
                "timestamp": rec.get("timestamp"),
                "packets": float(rec.get("packets", feats[0])),
                "bytes": float(rec.get("bytes", feats[1])),
                "duration": float(rec.get("duration", feats[2])),
                "split_origin": rec.get("split_origin"),
                "traffic_profile": rec.get("traffic_profile"),
            }
            return fid, [float(v) for v in feats], meta, None

        if raw_flow is not None and features is None:
            try:
                feats = extract_69_features(raw_flow)
                fid = str(flow_id or raw_flow.get("flow_id") or "adhoc-raw-flow")
                meta = {
                    "flow_id": fid,
                    "src_ip": raw_flow.get("src_ip"),
                    "dst_ip": raw_flow.get("dst_ip"),
                    "src_port": raw_flow.get("src_port"),
                    "dst_port": raw_flow.get("dst_port"),
                    "protocol": raw_flow.get("protocol"),
                    "packets": float(feats[0]),
                    "bytes": float(feats[1]),
                    "duration": float(feats[2]),
                }
                return fid, feats, meta, None
            except Exception as exc:
                return str(flow_id or "adhoc-raw-flow"), None, {}, f"invalid_raw_flow:{exc}"

        fid = str(flow_id or "adhoc-feature-vector")
        if features is None:
            return fid, None, {}, "missing_flow_id_and_features"

        validated = TriModelDetectionEngine._validate_69_features(features)
        if validated is None:
            return (
                fid,
                None,
                {},
                f"invalid_input_features_expected_{EXPECTED_FEATURE_COUNT}_finite_floats",
            )

        feats_list = [float(v) for v in validated.tolist()]
        cat_rec = self.flow_catalog.get(fid, {})
        meta = {
            "flow_id": fid,
            "src_ip": cat_rec.get("src_ip"),
            "dst_ip": cat_rec.get("dst_ip"),
            "src_port": cat_rec.get("src_port"),
            "dst_port": cat_rec.get("dst_port"),
            "protocol": cat_rec.get("protocol"),
            "timestamp": cat_rec.get("timestamp"),
            "packets": float(feats_list[0]),
            "bytes": float(feats_list[1]),
            "duration": float(feats_list[2]),
            "split_origin": cat_rec.get("split_origin"),
            "traffic_profile": cat_rec.get("traffic_profile"),
        }
        return fid, feats_list, meta, None

    def explain(
        self,
        flow_id: Optional[str] = None,
        features: Optional[List[float]] = None,
        raw_flow: Optional[Dict[str, Any]] = None,
        policy: str = "weighted_consensus",
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Generates a complete, unified Tri-Model explanation for a flow ID or 69-feature vector.
        Never modifies the underlying detection decision or model state.
        """
        t0 = time.perf_counter()
        resolved_id, feats_69, flow_meta, resolve_err = self.resolve_flow_input(
            flow_id=flow_id, features=features, raw_flow=raw_flow
        )

        if resolve_err is not None or feats_69 is None:
            # Evaluate tri-model on the raw features (if provided) so degraded contract matches
            tri_deg = self.tri_engine.evaluate_tri_model_fusion(
                features if isinstance(features, list) else [], policy=policy
            )
            return self._build_invalid_or_failed_response(
                flow_id=resolved_id or "unknown-flow",
                reason=resolve_err or "invalid_input_features",
                tri_decision=tri_deg,
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # 1. Obtain authoritative, unmodified Tri-Model Detection Fusion output
        tri_decision = self.tri_engine.evaluate_tri_model_fusion(feats_69, policy=policy)

        # 2. Retrieve individual model explanations with exception isolation
        rf_exp = self._safe_run_explainer(
            "random_forest",
            lambda: self.rf_explainer.explain_flow(feats_69, top_k=top_k),
            tri_decision["models"]["random_forest"],
        )
        if_exp = self._safe_run_explainer(
            "isolation_forest",
            lambda: self.if_explainer.explain_flow(feats_69, top_k=top_k),
            tri_decision["models"]["isolation_forest"],
        )
        ae_exp = self._safe_run_explainer(
            "autoencoder",
            lambda: self.ae_explainer.explain_flow(feats_69, top_k=top_k),
            tri_decision["models"]["autoencoder"],
        )

        # 3. Determine overall explanation generation status
        exp_statuses = {
            "random_forest": rf_exp.get("status", "degraded"),
            "isolation_forest": if_exp.get("status", "degraded"),
            "autoencoder": ae_exp.get("status", "degraded"),
        }
        healthy_explainers = [m for m, st in exp_statuses.items() if st == "healthy"]
        degraded_explainers = [m for m, st in exp_statuses.items() if st != "healthy"]

        if len(healthy_explainers) == 3:
            generation_status = "healthy"
        elif len(healthy_explainers) > 0:
            generation_status = "partially_degraded"
        else:
            generation_status = "degraded"

        # 4. Physical measurement profile (packets, bytes, duration, rates)
        physical_profile = self.grouper.build_physical_measurement_profile(feats_69)
        flow_meta["physical_measurements"] = physical_profile

        # 5. Analyze model agreement and disagreement
        agreement_block = self._analyze_agreement_and_disagreement(
            tri_decision=tri_decision,
            rf_exp=rf_exp,
            if_exp=if_exp,
            ae_exp=ae_exp,
            healthy_explainers=healthy_explainers,
            degraded_explainers=degraded_explainers,
        )

        # 6. Identify shared vs model-specific contributing measurements (without cross-scale averaging)
        shared_measurements, model_specific_measurements = self._analyze_shared_and_specific_measurements(
            rf_exp=rf_exp,
            if_exp=if_exp,
            ae_exp=ae_exp,
            feats_69=feats_69,
            physical_profile=physical_profile,
        )

        # 7. Check for cross-label feature collisions in the reference dataset
        collision_info = self._check_feature_collision(feats_69)

        # 8. Build scientifically justified confidence & limitations assessment
        confidence_and_limitations = self._build_confidence_and_limitations(
            generation_status=generation_status,
            healthy_explainers=healthy_explainers,
            degraded_explainers=degraded_explainers,
            rf_exp=rf_exp,
            if_exp=if_exp,
            ae_exp=ae_exp,
            agreement_block=agreement_block,
            collision_info=collision_info,
        )

        # 9. Generate evidence-grounded human-readable SOC analyst explanation
        soc_explanation = self._build_soc_analyst_explanation(
            flow_id=resolved_id or "adhoc-feature-vector",
            tri_decision=tri_decision,
            rf_exp=rf_exp,
            if_exp=if_exp,
            ae_exp=ae_exp,
            agreement_block=agreement_block,
            shared_measurements=shared_measurements,
            model_specific_measurements=model_specific_measurements,
            physical_profile=physical_profile,
            confidence_and_limitations=confidence_and_limitations,
        )

        return {
            "flow_id": resolved_id,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "explanation_generation_status": generation_status,
            "healthy_explainers": healthy_explainers,
            "degraded_explainers": degraded_explainers,
            "flow_metadata": flow_meta,
            "final_tri_model_classification": {
                "fusion_status": tri_decision["fusion_status"],
                "fusion_policy": tri_decision["fusion_policy"],
                "final_decision": tri_decision["final_decision"],
                "is_anomaly": tri_decision["is_anomaly"],
                "fused_anomaly_score": tri_decision["fused_anomaly_score"],
                "severity": tri_decision["severity"],
                "recommended_action": tri_decision["recommended_action"],
                "auto_block_permitted": tri_decision["auto_block_permitted"],
                "decision_rule": tri_decision["decision_rule"],
                "degraded_models": tri_decision["degraded_models"],
                "models_agreeing_on_anomaly": tri_decision["models_agreeing_on_anomaly"],
            },
            "random_forest_explanation": self._summarize_rf_for_unified(rf_exp),
            "isolation_forest_explanation": self._summarize_if_for_unified(if_exp),
            "autoencoder_explanation": self._summarize_ae_for_unified(ae_exp),
            "individual_model_explanations_full": {
                "random_forest": rf_exp,
                "isolation_forest": if_exp,
                "autoencoder": ae_exp,
            },
            "model_agreement_and_disagreement": agreement_block,
            "shared_contributing_measurements": shared_measurements,
            "model_specific_contributing_measurements": model_specific_measurements,
            "human_readable_soc_analyst_explanation": soc_explanation,
            "explanation_confidence_and_limitations": confidence_and_limitations,
            "total_explanation_latency_ms": round((time.perf_counter() - t0) * 1000.0, 4),
        }

    @staticmethod
    def _safe_run_explainer(
        model_name: str,
        fn: Callable[[], Dict[str, Any]],
        tri_model_sub_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Executes a model-specific explainer while isolating runtime exceptions and honoring
        model availability status from `TriModelDetectionEngine`.
        """
        if tri_model_sub_result.get("status") != "healthy":
            return {
                "status": "degraded",
                "model_name": model_name,
                "degraded_reason": tri_model_sub_result.get("degraded_reason")
                or f"{model_name}_unavailable_in_tri_model_engine",
            }
        try:
            res = fn()
            if not isinstance(res, dict):
                return {
                    "status": "degraded",
                    "model_name": model_name,
                    "degraded_reason": f"{model_name}_explainer_returned_non_dict",
                }
            return res
        except Exception as exc:
            return {
                "status": "degraded",
                "model_name": model_name,
                "degraded_reason": f"{model_name}_explanation_exception:{type(exc).__name__}:{exc}",
            }

    @staticmethod
    def _summarize_rf_for_unified(rf_exp: Dict[str, Any]) -> Dict[str, Any]:
        if rf_exp.get("status") != "healthy":
            return {
                "status": "degraded",
                "model_name": "random_forest",
                "degraded_reason": rf_exp.get("degraded_reason", "random_forest_unavailable"),
                "prediction": None,
                "attack_probability": None,
                "benign_probability": None,
                "top_positive_attack_contributors": [],
                "top_negative_benign_contributors": [],
            }
        return {
            "status": "healthy",
            "model_name": "random_forest",
            "explanation_method": rf_exp["explanation_method"],
            "is_exact_shap": rf_exp["is_exact_shap"],
            "score_semantics": rf_exp["score_semantics"],
            "prediction": rf_exp["prediction"],
            "predicted_class_label": rf_exp["predicted_class_label"],
            "attack_probability": rf_exp["attack_probability"],
            "benign_probability": rf_exp["benign_probability"],
            "decision_threshold": rf_exp["decision_threshold"],
            "base_expected_value_attack": rf_exp["base_expected_value_attack"],
            "shap_sum_attack": rf_exp["shap_sum_attack"],
            "additivity_error": rf_exp["additivity_error"],
            "additivity_verified": rf_exp["additivity_verified"],
            "top_positive_attack_contributors": rf_exp["top_positive_attack_contributors"],
            "top_negative_benign_contributors": rf_exp["top_negative_benign_contributors"],
            "raw_measurement_attribution": rf_exp["grouped_measurement_explanation"][
                "raw_measurement_attribution"
            ],
            "explanation_narrative": rf_exp["explanation_narrative"],
        }

    @staticmethod
    def _summarize_if_for_unified(if_exp: Dict[str, Any]) -> Dict[str, Any]:
        if if_exp.get("status") != "healthy":
            return {
                "status": "degraded",
                "model_name": "isolation_forest",
                "score_semantics": "UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY",
                "degraded_reason": if_exp.get("degraded_reason", "isolation_forest_unavailable"),
                "is_anomaly": None,
                "anomaly_score": None,
                "raw_decision_score": None,
                "top_influential_features": [],
            }
        return {
            "status": "healthy",
            "model_name": "isolation_forest",
            "explanation_method": if_exp["explanation_method"],
            "score_semantics": if_exp["score_semantics"],
            "decision": if_exp["decision"],
            "is_anomaly": if_exp["is_anomaly"],
            "anomaly_score": if_exp["anomaly_score"],
            "raw_decision_score": if_exp["raw_decision_score"],
            "decision_threshold": if_exp["decision_threshold"],
            "margin_from_threshold": if_exp["margin_from_threshold"],
            "reference_population_size": if_exp["reference_population_size"],
            "top_influential_features": if_exp["top_influential_features"],
            "unusually_high_measurements": if_exp["unusually_high_measurements"],
            "unusually_low_measurements": if_exp["unusually_low_measurements"],
            "unusually_high_count": if_exp["unusually_high_count"],
            "unusually_low_count": if_exp["unusually_low_count"],
            "counterfactual_raw_measurement_perturbations": if_exp[
                "counterfactual_raw_measurement_perturbations"
            ],
            "raw_measurement_attribution": if_exp["grouped_measurement_explanation"][
                "raw_measurement_attribution"
            ],
            "explanation_narrative": if_exp["explanation_narrative"],
        }

    @staticmethod
    def _summarize_ae_for_unified(ae_exp: Dict[str, Any]) -> Dict[str, Any]:
        if ae_exp.get("status") != "healthy":
            return {
                "status": "degraded",
                "model_name": "autoencoder",
                "score_semantics": "RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY",
                "degraded_reason": ae_exp.get("degraded_reason", "autoencoder_unavailable"),
                "is_anomaly": None,
                "reconstruction_error": None,
                "anomaly_score": None,
                "top_anomalous_features": [],
            }
        return {
            "status": "healthy",
            "model_name": "autoencoder",
            "model_version": ae_exp["model_version"],
            "architecture": ae_exp["architecture"],
            "explanation_method": ae_exp["explanation_method"],
            "score_semantics": ae_exp["score_semantics"],
            "decision": ae_exp["decision"],
            "is_anomaly": ae_exp["is_anomaly"],
            "reconstruction_error": ae_exp["reconstruction_error"],
            "anomaly_score": ae_exp["anomaly_score"],
            "threshold": ae_exp["threshold"],
            "threshold_percentile": ae_exp["threshold_percentile"],
            "threshold_comparison": ae_exp["threshold_comparison"],
            "top_anomalous_features": ae_exp["top_anomalous_features"],
            "bottleneck_latent_8d": ae_exp["bottleneck_latent_8d"],
            "raw_measurement_attribution": ae_exp["grouped_measurement_explanation"][
                "raw_measurement_attribution"
            ],
            "explanation_narrative": ae_exp["explanation_narrative"],
        }

    @staticmethod
    def _analyze_agreement_and_disagreement(
        tri_decision: Dict[str, Any],
        rf_exp: Dict[str, Any],
        if_exp: Dict[str, Any],
        ae_exp: Dict[str, Any],
        healthy_explainers: List[str],
        degraded_explainers: List[str],
    ) -> Dict[str, Any]:
        """
        Determines cross-model decision agreement and disagreement without conflating
        supervised probabilities, isolation scores, and reconstruction errors.
        """
        per_model_verdict: Dict[str, str] = {}
        flagging_anomaly: List[str] = []
        flagging_normal: List[str] = []
        flagging_suspicious: List[str] = []

        if rf_exp.get("status") == "healthy":
            rf_anom = bool(rf_exp["prediction"] == 1)
            per_model_verdict["random_forest"] = "anomalous" if rf_anom else "normal"
            if rf_anom:
                flagging_anomaly.append("random_forest")
            else:
                flagging_normal.append("random_forest")
        else:
            per_model_verdict["random_forest"] = "unavailable"

        if if_exp.get("status") == "healthy":
            if_anom = bool(if_exp["is_anomaly"])
            per_model_verdict["isolation_forest"] = "anomalous" if if_anom else "normal"
            if if_anom:
                flagging_anomaly.append("isolation_forest")
            else:
                flagging_normal.append("isolation_forest")
        else:
            per_model_verdict["isolation_forest"] = "unavailable"

        if ae_exp.get("status") == "healthy":
            ae_dec = str(ae_exp["decision"])
            per_model_verdict["autoencoder"] = ae_dec
            if bool(ae_exp["is_anomaly"]):
                flagging_anomaly.append("autoencoder")
            elif ae_dec == "suspicious":
                flagging_suspicious.append("autoencoder")
            else:
                flagging_normal.append("autoencoder")
        else:
            per_model_verdict["autoencoder"] = "unavailable"

        if len(healthy_explainers) == 0:
            consensus_state = "DEGRADED_NO_MODELS_AVAILABLE"
            has_disagreement = False
        elif len(degraded_explainers) > 0:
            if len(flagging_anomaly) == len(healthy_explainers):
                consensus_state = f"PARTIAL_AVAILABILITY_ALL_{len(healthy_explainers)}_HEALTHY_ANOMALOUS"
                has_disagreement = False
            elif len(flagging_normal) == len(healthy_explainers):
                consensus_state = f"PARTIAL_AVAILABILITY_ALL_{len(healthy_explainers)}_HEALTHY_NORMAL"
                has_disagreement = False
            else:
                consensus_state = "PARTIAL_AVAILABILITY_DISSENT"
                has_disagreement = True
        else:
            if len(flagging_anomaly) == 3:
                consensus_state = "UNANIMOUS_ANOMALY_3_OF_3"
                has_disagreement = False
            elif len(flagging_normal) == 3:
                consensus_state = "UNANIMOUS_NORMAL_3_OF_3"
                has_disagreement = False
            elif len(flagging_anomaly) == 2:
                consensus_state = "MAJORITY_ANOMALY_2_OF_3_DISSENT"
                has_disagreement = True
            elif len(flagging_anomaly) == 1:
                consensus_state = f"SINGLE_MODEL_ANOMALY_DISSENT_{flagging_anomaly[0].upper()}"
                has_disagreement = True
            else:
                consensus_state = "NORMAL_WITH_AUTOENCODER_P95_SUSPICIOUS_WARNING"
                has_disagreement = True

        # Pairwise agreement booleans (None when either model is unavailable)
        def _pair_agrees(m1: str, m2: str) -> Optional[bool]:
            v1 = per_model_verdict.get(m1, "unavailable")
            v2 = per_model_verdict.get(m2, "unavailable")
            if v1 == "unavailable" or v2 == "unavailable":
                return None
            b1 = v1 == "anomalous"
            b2 = v2 == "anomalous"
            return b1 == b2

        pairwise = {
            "rf_vs_if_agree": _pair_agrees("random_forest", "isolation_forest"),
            "rf_vs_ae_agree": _pair_agrees("random_forest", "autoencoder"),
            "if_vs_ae_agree": _pair_agrees("isolation_forest", "autoencoder"),
        }

        # Build explicit evidence-grounded explanation of agreement or disagreement
        disagreement_explanation = UnifiedTriModelExplainer._build_disagreement_explanation(
            consensus_state=consensus_state,
            tri_decision=tri_decision,
            rf_exp=rf_exp,
            if_exp=if_exp,
            ae_exp=ae_exp,
            flagging_anomaly=flagging_anomaly,
            flagging_normal=flagging_normal,
            degraded_explainers=degraded_explainers,
        )

        return {
            "consensus_state": consensus_state,
            "models_agree": not has_disagreement and len(healthy_explainers) > 0,
            "has_model_disagreement": has_disagreement,
            "available_models": healthy_explainers,
            "unavailable_models": degraded_explainers,
            "per_model_verdict": per_model_verdict,
            "models_flagging_anomaly": flagging_anomaly,
            "models_flagging_normal": flagging_normal,
            "models_flagging_suspicious": flagging_suspicious,
            "pairwise_decision_agreement": pairwise,
            "disagreement_explanation": disagreement_explanation,
        }

    @staticmethod
    def _build_disagreement_explanation(
        consensus_state: str,
        tri_decision: Dict[str, Any],
        rf_exp: Dict[str, Any],
        if_exp: Dict[str, Any],
        ae_exp: Dict[str, Any],
        flagging_anomaly: List[str],
        flagging_normal: List[str],
        degraded_explainers: List[str],
    ) -> str:
        rf_str = (
            f"RF P(attack)={rf_exp['attack_probability']:.4f} (thr={rf_exp['decision_threshold']:.2f})"
            if rf_exp.get("status") == "healthy"
            else f"RF unavailable ({rf_exp.get('degraded_reason')})"
        )
        if_str = (
            f"IF raw_score={if_exp['raw_decision_score']:.4f} vs thr={if_exp['decision_threshold']:.4f} (anom_score={if_exp['anomaly_score']:.4f})"
            if if_exp.get("status") == "healthy"
            else f"IF unavailable ({if_exp.get('degraded_reason')})"
        )
        ae_str = (
            f"AE MSE={ae_exp['reconstruction_error']:.6f} vs P97={ae_exp['threshold']:.6f}"
            if ae_exp.get("status") == "healthy"
            else f"AE unavailable ({ae_exp.get('degraded_reason')})"
        )

        if consensus_state == "UNANIMOUS_ANOMALY_3_OF_3":
            return (
                f"All three detectors unanimously classify this flow as anomalous across distinct "
                f"mathematical paradigms: supervised Random Forest ({rf_str}), unsupervised "
                f"Isolation Forest ({if_str}), and PyTorch Autoencoder ({ae_str})."
            )
        if consensus_state == "UNANIMOUS_NORMAL_3_OF_3":
            return (
                f"All three detectors unanimously classify this flow as normal: supervised Random "
                f"Forest ({rf_str}), Isolation Forest interior depth ({if_str}), and PyTorch "
                f"Autoencoder reconstruction ({ae_str})."
            )
        if degraded_explainers:
            return (
                f"Partial or degraded model availability: unavailable models={degraded_explainers}. "
                f"Remaining model evidence: {rf_str}; {if_str}; {ae_str}. Under safety guardrails, "
                f"auto_block_permitted={tri_decision['auto_block_permitted']}."
            )
        return (
            f"Inter-model disagreement detected ({consensus_state}): models flagging anomaly="
            f"{flagging_anomaly}, models flagging normal={flagging_normal}. "
            f"Supervised vs unsupervised evidence: {rf_str}; {if_str}; {ae_str}. "
            f"Under policy '{tri_decision['fusion_policy']}', rule '{tri_decision['decision_rule']}' "
            f"resolved final_decision='{tri_decision['final_decision']}' with "
            f"recommended_action='{tri_decision['recommended_action']}' and "
            f"auto_block_permitted={tri_decision['auto_block_permitted']}."
        )

    @staticmethod
    def _analyze_shared_and_specific_measurements(
        rf_exp: Dict[str, Any],
        if_exp: Dict[str, Any],
        ae_exp: Dict[str, Any],
        feats_69: List[float],
        physical_profile: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Identifies shared contributing measurements and model-specific contributing measurements
        without comparing or averaging raw SHAP values, Isolation Forest scores, and AE MSE.

        Instead, each model's internal attribution distribution is normalized within its own
        mathematical space first (share of total `|attribution|` in `[0, 1]`), and top-k features
        are mapped to deduplicated mathematical concepts (`_canonical_concept_id`) so exact
        duplicate columns (`f_25..f_39`) and collinear harmonic padding (`f_55..f_68`) are
        never falsely reported as independent cross-model feature agreements.
        """
        # 1. Raw Measurement Family Level (`packets`, `bytes`, `duration`)
        #    A raw measurement is considered a "substantial driver" for a model if it accounts for
        #    >= 25% of that model's internal attribution weight (or is the #1 dominant measurement).
        raw_drivers_by_model: Dict[str, List[str]] = {}
        raw_shares_by_model: Dict[str, Dict[str, float]] = {}

        for m_name, exp in (
            ("random_forest", rf_exp),
            ("isolation_forest", if_exp),
            ("autoencoder", ae_exp),
        ):
            if exp.get("status") != "healthy":
                continue
            grp = exp.get("grouped_measurement_explanation", {})
            raw_attr = grp.get("raw_measurement_attribution", {})
            dom = grp.get("dominant_raw_measurement")
            shares = {
                k: float(raw_attr.get(k, {}).get("share_of_total", 0.0))
                for k in ("packets", "bytes", "duration")
            }
            raw_shares_by_model[m_name] = shares
            substantial = [
                k for k, sh in shares.items() if sh >= 0.25 or k == dom
            ]
            raw_drivers_by_model[m_name] = substantial

        raw_measurement_consensus: List[Dict[str, Any]] = []
        raw_measurement_specific: Dict[str, List[str]] = {
            "random_forest": [],
            "isolation_forest": [],
            "autoencoder": [],
        }

        for raw_key in ("packets", "bytes", "duration"):
            supporting_models = [
                m for m, drv in raw_drivers_by_model.items() if raw_key in drv
            ]
            phys_entry = physical_profile.get(raw_key, {})
            if len(supporting_models) >= 2:
                raw_measurement_consensus.append(
                    {
                        "raw_measurement": raw_key,
                        "label": phys_entry.get("label", raw_key),
                        "flow_value": phys_entry.get("value"),
                        "normal_median": phys_entry.get("normal_median"),
                        "robust_z_score": phys_entry.get("robust_z_score"),
                        "baseline_comparison": phys_entry.get("baseline_comparison"),
                        "supporting_models": supporting_models,
                        "within_model_attribution_shares": {
                            m: round(raw_shares_by_model[m][raw_key], 4)
                            for m in supporting_models
                        },
                    }
                )
            elif len(supporting_models) == 1:
                raw_measurement_specific[supporting_models[0]].append(raw_key)

        # 2. Deduplicated Top-K Feature Concept Level
        #    Extract top-5 features per healthy model and map to canonical deduplicated concepts
        concepts_by_model: Dict[str, Dict[str, Dict[str, Any]]] = {}

        if rf_exp.get("status") == "healthy":
            rf_concepts: Dict[str, Dict[str, Any]] = {}
            for item in rf_exp.get("top_absolute_contributors", [])[:5]:
                cid, clabel = _canonical_concept_id(int(item["feature_index"]))
                if cid not in rf_concepts:
                    rf_concepts[cid] = {
                        "concept_id": cid,
                        "concept_label": clabel,
                        "representative_feature": item["feature_name"],
                        "primary_measurement_family": item["primary_measurement_family"],
                        "is_collinear_or_duplicate_group": bool(cid.startswith("concept_")),
                        "model_metric": f"shap_value_attack={item['shap_value_attack']:+.4f}",
                    }
            concepts_by_model["random_forest"] = rf_concepts

        if if_exp.get("status") == "healthy":
            if_concepts: Dict[str, Dict[str, Any]] = {}
            for item in if_exp.get("top_influential_features", [])[:5]:
                cid, clabel = _canonical_concept_id(int(item["feature_index"]))
                if cid not in if_concepts:
                    if_concepts[cid] = {
                        "concept_id": cid,
                        "concept_label": clabel,
                        "representative_feature": item["feature_name"],
                        "primary_measurement_family": item["primary_measurement_family"],
                        "is_collinear_or_duplicate_group": bool(cid.startswith("concept_")),
                        "model_metric": (
                            f"perturbation_influence={item['effective_isolation_influence']:+.4f}, "
                            f"robust_z={item['robust_z_score']:+.2f}"
                        ),
                    }
            concepts_by_model["isolation_forest"] = if_concepts

        if ae_exp.get("status") == "healthy":
            ae_concepts: Dict[str, Dict[str, Any]] = {}
            for item in ae_exp.get("top_anomalous_features", [])[:5]:
                cid, clabel = _canonical_concept_id(int(item["feature_index"]))
                if cid not in ae_concepts:
                    ae_concepts[cid] = {
                        "concept_id": cid,
                        "concept_label": clabel,
                        "representative_feature": item["feature_name"],
                        "primary_measurement_family": item["primary_measurement_family"],
                        "is_collinear_or_duplicate_group": bool(cid.startswith("concept_")),
                        "model_metric": (
                            f"squared_error={item['squared_error']:.4f} "
                            f"(share={item['error_share'] * 100:.1f}%)"
                        ),
                    }
            concepts_by_model["autoencoder"] = ae_concepts

        all_concept_ids = set()
        for m_concepts in concepts_by_model.values():
            all_concept_ids.update(m_concepts.keys())

        shared_feature_concepts: List[Dict[str, Any]] = []
        specific_feature_concepts: Dict[str, List[Dict[str, Any]]] = {
            "random_forest": [],
            "isolation_forest": [],
            "autoencoder": [],
        }

        for cid in sorted(all_concept_ids):
            present_in = [m for m, mc in concepts_by_model.items() if cid in mc]
            if len(present_in) >= 2:
                sample_info = concepts_by_model[present_in[0]][cid]
                shared_feature_concepts.append(
                    {
                        "concept_id": cid,
                        "concept_label": sample_info["concept_label"],
                        "primary_measurement_family": sample_info["primary_measurement_family"],
                        "is_collinear_or_duplicate_group": sample_info[
                            "is_collinear_or_duplicate_group"
                        ],
                        "models_sharing_concept": present_in,
                        "per_model_native_evidence": {
                            m: concepts_by_model[m][cid]["model_metric"] for m in present_in
                        },
                    }
                )
            elif len(present_in) == 1:
                m_only = present_in[0]
                specific_feature_concepts[m_only].append(concepts_by_model[m_only][cid])

        shared_block = {
            "methodology_note": (
                "Shared drivers are identified without averaging or equating SHAP probabilities, "
                "Isolation Forest path-depth shifts, and Autoencoder MSE residuals. Duplicate "
                "polynomial columns (f_25..f_39) and collinear harmonic padding (f_55..f_68) are "
                "collapsed into canonical mathematical concepts prior to overlap analysis."
            ),
            "shared_raw_measurements": raw_measurement_consensus,
            "shared_deduplicated_feature_concepts": shared_feature_concepts,
        }

        specific_block = {
            "random_forest_unique_drivers": {
                "raw_measurements": raw_measurement_specific["random_forest"],
                "deduplicated_feature_concepts": specific_feature_concepts["random_forest"],
            },
            "isolation_forest_unique_drivers": {
                "raw_measurements": raw_measurement_specific["isolation_forest"],
                "deduplicated_feature_concepts": specific_feature_concepts["isolation_forest"],
            },
            "autoencoder_unique_drivers": {
                "raw_measurements": raw_measurement_specific["autoencoder"],
                "deduplicated_feature_concepts": specific_feature_concepts["autoencoder"],
            },
        }
        return shared_block, specific_block

    def _check_feature_collision(self, feats_69: List[float]) -> Dict[str, Any]:
        pbd_key = (
            round(float(feats_69[0]), 4),
            round(float(feats_69[1]), 4),
            round(float(feats_69[2]), 4),
        )
        matching_records = self.pbd_collision_index.get(pbd_key, [])
        distinct_labels = sorted({r["label"] for r in matching_records})
        is_cross_label_collision = len(distinct_labels) > 1
        return {
            "pbd_signature": {"packets": pbd_key[0], "bytes": pbd_key[1], "duration": pbd_key[2]},
            "matching_catalog_flows_count": len(matching_records),
            "is_cross_label_feature_collision": is_cross_label_collision,
            "distinct_labels_in_catalog": distinct_labels,
            "colliding_flows": matching_records if is_cross_label_collision else [],
        }

    @staticmethod
    def _build_confidence_and_limitations(
        generation_status: str,
        healthy_explainers: List[str],
        degraded_explainers: List[str],
        rf_exp: Dict[str, Any],
        if_exp: Dict[str, Any],
        ae_exp: Dict[str, Any],
        agreement_block: Dict[str, Any],
        collision_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        if generation_status == "degraded":
            reliability = "DEGRADED_UNAVAILABLE"
        elif generation_status == "partially_degraded":
            reliability = "REDUCED_PARTIAL_MODEL_AVAILABILITY"
        elif collision_info["is_cross_label_feature_collision"]:
            reliability = "AMBIGUOUS_3_SCALAR_FEATURE_COLLISION"
        elif agreement_block["has_model_disagreement"]:
            reliability = "MODERATE_INTER_MODEL_DISSENT"
        else:
            reliability = "HIGH_UNANIMOUS_CONSENSUS"

        method_distinctions = {
            "random_forest": (
                "Exact TreeSHAP (official shap.TreeExplainer v0.54.1) explaining supervised "
                "attack-class probability P(attack|x) with verified additivity."
                if rf_exp.get("is_exact_shap")
                else "Model-agnostic reference perturbation fallback (NOT exact SHAP)."
                if rf_exp.get("status") == "healthy"
                else "Unavailable / Degraded."
            ),
            "isolation_forest": (
                "Reference-population median-replacement perturbation and quantile comparison "
                "(840 normal flows) explaining unsupervised tree-isolation decision score "
                "(NOT a probability)."
                if if_exp.get("status") == "healthy"
                else "Unavailable / Degraded."
            ),
            "autoencoder": (
                "Per-feature squared reconstruction error decomposition (z_j - z_hat_j)^2 across "
                "the 8-neuron bottleneck manifold vs frozen validation threshold P97=0.503670 "
                "(NOT a probability)."
                if ae_exp.get("status") == "healthy"
                else "Unavailable / Degraded."
            ),
        }

        limitations: List[str] = [
            CORRELATED_ATTRIBUTION_LIMITATION_NOTE,
            (
                "Cross-model scale incommensurability: Random Forest SHAP values (probability deltas), "
                "Isolation Forest perturbation shifts (isolation tree depth scores), and Autoencoder "
                "squared reconstruction errors (MSE residuals) have distinct mathematical units and "
                "must never be directly summed or averaged."
            ),
            (
                "Flow-level non-causality: Explanations reflect mathematical relationships over "
                "(packets, bytes, duration) and cannot inspect L7 payload contents; definitive "
                "incident attribution requires correlation with Suricata NIDS alerts, honeypot "
                "telemetry, and threat intelligence."
            ),
        ]
        if collision_info["is_cross_label_feature_collision"]:
            coll_ids = [c["flow_id"] for c in collision_info["colliding_flows"]]
            limitations.append(
                f"Cross-label 3-scalar feature collision detected: measurements "
                f"(packets={collision_info['pbd_signature']['packets']}, "
                f"bytes={collision_info['pbd_signature']['bytes']}, "
                f"duration={collision_info['pbd_signature']['duration']}s) occur in both normal and "
                f"attack records ({coll_ids}), producing identical 69-feature vectors."
            )
        if degraded_explainers:
            limitations.append(
                f"Degraded explainer availability: {degraded_explainers} could not be evaluated; "
                f"automatic IP blocking is strictly disabled."
            )

        return {
            "explanation_reliability_tier": reliability,
            "attribution_method_distinctions": method_distinctions,
            "is_cross_label_feature_collision": collision_info["is_cross_label_feature_collision"],
            "feature_collision_details": collision_info,
            "scientific_limitations": limitations,
        }

    @staticmethod
    def _build_soc_analyst_explanation(
        flow_id: str,
        tri_decision: Dict[str, Any],
        rf_exp: Dict[str, Any],
        if_exp: Dict[str, Any],
        ae_exp: Dict[str, Any],
        agreement_block: Dict[str, Any],
        shared_measurements: Dict[str, Any],
        model_specific_measurements: Dict[str, Any],
        physical_profile: Dict[str, Any],
        confidence_and_limitations: Dict[str, Any],
    ) -> Dict[str, Any]:
        pkt = physical_profile.get("packets", {})
        byt = physical_profile.get("bytes", {})
        dur = physical_profile.get("duration", {})
        bps = physical_profile.get("bytes_per_sec", {})
        pps = physical_profile.get("packets_per_sec", {})

        exec_verdict = (
            f"Flow '{flow_id}' (packets={pkt.get('value')}, bytes={byt.get('value')}, "
            f"duration={dur.get('value')}s, rate={bps.get('value')} B/s, {pps.get('value')} pkt/s) "
            f"was classified by the '{tri_decision['fusion_policy']}' policy as "
            f"'{tri_decision['final_decision'].upper()}' (rule='{tri_decision['decision_rule']}', "
            f"severity='{tri_decision['severity']}', recommended_action='{tri_decision['recommended_action']}', "
            f"auto_block_permitted={tri_decision['auto_block_permitted']})."
        )

        # Model evidence sentences
        evidence_parts: List[str] = []
        if rf_exp.get("status") == "healthy":
            top_pos = rf_exp.get("top_positive_attack_contributors", [])[:3]
            pos_txt = ", ".join(
                f"{f['feature_name']} ({f['shap_value_attack']:+.4f})" for f in top_pos
            ) or "none"
            evidence_parts.append(
                f"Random Forest (Exact TreeSHAP={rf_exp['is_exact_shap']}) predicted "
                f"'{rf_exp['predicted_class_label']}' with P(attack)={rf_exp['attack_probability']:.4f} "
                f"(base={rf_exp['base_expected_value_attack']:.4f}, top attack-pushing features: [{pos_txt}])."
            )
        else:
            evidence_parts.append(
                f"Random Forest explanation unavailable ({rf_exp.get('degraded_reason')})."
            )

        if if_exp.get("status") == "healthy":
            top_if = if_exp.get("top_influential_features", [])[:3]
            if_txt = ", ".join(
                f"{f['feature_name']} (shift={f['effective_isolation_influence']:+.4f}, Z={f['robust_z_score']:+.2f})"
                for f in top_if
            ) or "none"
            evidence_parts.append(
                f"Isolation Forest (Perturbation + 840-flow normal baseline) scored raw_decision_score="
                f"{if_exp['raw_decision_score']:.4f} vs threshold={if_exp['decision_threshold']:.4f} "
                f"(unsupervised anomaly_score={if_exp['anomaly_score']:.4f}, decision='{if_exp['decision']}', "
                f"top isolation drivers: [{if_txt}])."
            )
        else:
            evidence_parts.append(
                f"Isolation Forest explanation unavailable ({if_exp.get('degraded_reason')})."
            )

        if ae_exp.get("status") == "healthy":
            top_ae = ae_exp.get("top_anomalous_features", [])[:3]
            ae_txt = ", ".join(
                f"{f['feature_name']} (sq_err={f['squared_error']:.4f}, {f['error_share'] * 100:.1f}%)"
                for f in top_ae
            ) or "none"
            evidence_parts.append(
                f"PyTorch Autoencoder (Bottleneck MSE decomposition) produced MSE="
                f"{ae_exp['reconstruction_error']:.6f} vs frozen P97={ae_exp['threshold']:.6f} "
                f"(decision='{ae_exp['decision']}', top reconstruction residuals: [{ae_txt}])."
            )
        else:
            evidence_parts.append(
                f"Autoencoder explanation unavailable ({ae_exp.get('degraded_reason')})."
            )

        shared_raw_names = [
            item["raw_measurement"] for item in shared_measurements["shared_raw_measurements"]
        ]
        shared_txt = (
            f"Shared dominant raw flow measurements across models: {shared_raw_names}."
            if shared_raw_names
            else "No single raw measurement dominated across multiple models."
        )

        checklist: List[str] = [
            f"Verify physical flow telemetry: packets={pkt.get('value')} ({pkt.get('baseline_comparison')}), bytes={byt.get('value')} ({byt.get('baseline_comparison')}), duration={dur.get('value')}s ({dur.get('baseline_comparison')}).",
        ]
        if tri_decision["decision_rule"] in (
            "AUTOENCODER_ONLY_ANOMALY_P97_MANUAL_REVIEW",
            "AUTOENCODER_HIGH_CONFIDENCE_ANOMALY_P99_NO_AUTOBLOCK",
            "ISOLATION_FOREST_ONLY_ANOMALY_MANUAL_REVIEW",
        ):
            checklist.append(
                "Single-detector unsupervised anomaly: Automatic IP blocking is prohibited by SOAR guardrails. Correlate source IP with Suricata EVE alerts and honeypot interactions before manual containment."
            )
        elif tri_decision["auto_block_permitted"]:
            checklist.append(
                "High-confidence multi-model confirmed threat: SOAR automatic containment is permitted subject to critical infrastructure allowlist and active lease checks."
            )
        if confidence_and_limitations["is_cross_label_feature_collision"]:
            checklist.append(
                "WARNING — Cross-label 3-scalar feature collision: This (packets, bytes, duration) tuple appears in both benign and malicious reference records. Inspect L7 protocol/NIDS logs to disambiguate."
            )

        full_text = " ".join(
            [
                exec_verdict,
                *evidence_parts,
                agreement_block["disagreement_explanation"],
                shared_txt,
            ]
        )

        return {
            "executive_verdict": exec_verdict,
            "tri_model_evidence_synthesis": evidence_parts,
            "agreement_and_disagreement_reasoning": agreement_block["disagreement_explanation"],
            "shared_driver_summary": shared_txt,
            "analyst_investigation_checklist": checklist,
            "full_narrative": full_text,
        }

    @staticmethod
    def _build_invalid_or_failed_response(
        flow_id: str,
        reason: str,
        tri_decision: Dict[str, Any],
        elapsed_ms: float,
    ) -> Dict[str, Any]:
        return {
            "flow_id": flow_id,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "explanation_generation_status": "degraded",
            "degraded_reason": reason,
            "healthy_explainers": [],
            "degraded_explainers": ["random_forest", "isolation_forest", "autoencoder"],
            "flow_metadata": {"flow_id": flow_id},
            "final_tri_model_classification": {
                "fusion_status": tri_decision.get("fusion_status", "degraded"),
                "fusion_policy": tri_decision.get("fusion_policy", "weighted_consensus"),
                "final_decision": tri_decision.get("final_decision", "degraded"),
                "is_anomaly": None,
                "fused_anomaly_score": None,
                "severity": "degraded",
                "recommended_action": "manual-review",
                "auto_block_permitted": False,
                "decision_rule": tri_decision.get("decision_rule", "ALL_MODELS_OR_INPUT_DEGRADED"),
                "degraded_models": ["random_forest", "isolation_forest", "autoencoder"],
                "models_agreeing_on_anomaly": [],
            },
            "random_forest_explanation": {
                "status": "degraded",
                "model_name": "random_forest",
                "degraded_reason": reason,
            },
            "isolation_forest_explanation": {
                "status": "degraded",
                "model_name": "isolation_forest",
                "score_semantics": "UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY",
                "degraded_reason": reason,
            },
            "autoencoder_explanation": {
                "status": "degraded",
                "model_name": "autoencoder",
                "score_semantics": "RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY",
                "degraded_reason": reason,
            },
            "individual_model_explanations_full": {},
            "model_agreement_and_disagreement": {
                "consensus_state": "DEGRADED_NO_MODELS_AVAILABLE",
                "models_agree": False,
                "has_model_disagreement": False,
                "available_models": [],
                "unavailable_models": ["random_forest", "isolation_forest", "autoencoder"],
                "per_model_verdict": {
                    "random_forest": "unavailable",
                    "isolation_forest": "unavailable",
                    "autoencoder": "unavailable",
                },
                "models_flagging_anomaly": [],
                "models_flagging_normal": [],
                "models_flagging_suspicious": [],
                "pairwise_decision_agreement": {
                    "rf_vs_if_agree": None,
                    "rf_vs_ae_agree": None,
                    "if_vs_ae_agree": None,
                },
                "disagreement_explanation": f"Explanation generation failed ({reason}); routed to manual-review with auto_block_permitted=False.",
            },
            "shared_contributing_measurements": {
                "shared_raw_measurements": [],
                "shared_deduplicated_feature_concepts": [],
            },
            "model_specific_contributing_measurements": {},
            "human_readable_soc_analyst_explanation": {
                "executive_verdict": f"Explanation could not be generated for flow '{flow_id}' due to '{reason}'.",
                "tri_model_evidence_synthesis": [],
                "agreement_and_disagreement_reasoning": f"Degraded state ({reason}).",
                "shared_driver_summary": "Unavailable.",
                "analyst_investigation_checklist": [
                    "Verify input flow telemetry contains 69 finite numeric features or a valid catalog flow_id."
                ],
                "full_narrative": f"Degraded explanation for '{flow_id}': {reason}. Automatic IP blocking is disabled.",
            },
            "explanation_confidence_and_limitations": {
                "explanation_reliability_tier": "DEGRADED_UNAVAILABLE",
                "attribution_method_distinctions": {},
                "is_cross_label_feature_collision": False,
                "scientific_limitations": [f"Explanation failed: {reason}"],
            },
            "total_explanation_latency_ms": round(elapsed_ms, 4),
        }
