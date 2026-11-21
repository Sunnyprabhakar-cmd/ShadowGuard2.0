"""
Shadow Guard 2.0 — ML Detection Service (Isolation Forest + PyTorch Autoencoder + Tri-Model Fusion)
===================================================================================================

Preserves 100% backward compatibility with Shadow Guard 1.0 (`POST /detect`, `GET /health`)
while integrating:
1. Authoritative PyTorch `FlowAutoencoder` startup loading, SHA-256 verification, and `v2.0-69dim`
   feature schema validation.
2. Dedicated Autoencoder inference endpoint (`POST /detect/autoencoder`) and model metadata endpoint
   (`GET /model/autoencoder/info`).
3. Tri-Model Detection Fusion endpoint (`POST /detect/tri-model`) combining Random Forest,
   Isolation Forest, and PyTorch Autoencoder with validation-calibrated thresholds (`P95`, `P97`, `P99`).
4. Explicit `degraded` status handling when any model or input vector fails validation (never
   silently classifying traffic as normal or permitting automatic IP blocking on degraded/AE-only signals).
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib import request as urllib_request

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
for _p in (str(CURRENT_DIR), str(ROOT_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from shared.ml.feature_schema import (
    EXPECTED_FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
    extract_69_features,
    validate_event_for_69_features,
)
from shared.ml.tri_model_fusion import TriModelDetectionEngine
from shared.ml.unified_xai_engine import UnifiedTriModelExplainer

_FLOW_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_ALLOWED_POLICIES = {"weighted_consensus", "unsupervised_ensemble", "majority_vote"}
_MAX_BATCH_EXPLAIN_ITEMS = 50


def _resolve_models_dir() -> Path:
    env_path = os.getenv("MODEL_PATH")
    if env_path:
        p = Path(env_path)
        if (p / "autoencoder_model.pt").exists():
            return p
    local_models = Path(__file__).resolve().parent / "models"
    if (local_models / "autoencoder_model.pt").exists():
        return local_models
    root_models = ROOT_DIR / "models"
    return root_models


def _post_json_safe(url: str, payload: Dict[str, Any], timeout: float = 3.0) -> None:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=timeout):
            pass
    except Exception:
        pass


class MLDetectionServiceCore:
    """
    Core service logic shared by the FastAPI application and standalone HTTP/test harnesses.
    """

    def __init__(self, models_dir: Optional[Path] = None) -> None:
        self.models_dir: Path = Path(models_dir) if models_dir is not None else _resolve_models_dir()
        self.engine: TriModelDetectionEngine = TriModelDetectionEngine(self.models_dir)
        dataset_candidate = ROOT_DIR / "data" / "autoencoder_flow_dataset_v2.json"
        if not dataset_candidate.exists():
            dataset_candidate = CURRENT_DIR / "data" / "autoencoder_flow_dataset_v2.json"
        self.xai_engine: UnifiedTriModelExplainer = UnifiedTriModelExplainer(
            tri_engine=self.engine,
            models_dir=self.models_dir,
            dataset_path=dataset_candidate,
        )

    def resolve_features_from_payload(self, payload: Dict[str, Any]) -> Optional[List[float]]:
        features = payload.get("features")
        if isinstance(features, list) and len(features) > 0:
            return features
        context = payload.get("context") or {}
        eligibility = validate_event_for_69_features(context)
        if eligibility.get("eligible"):
            return extract_69_features(
                {
                    "packets": eligibility["packets"],
                    "bytes": eligibility["bytes"],
                    "duration": eligibility["duration"],
                }
            )
        return features if isinstance(features, list) else None

    def handle_detect(self, payload: Dict[str, Any], forward_downstream: bool = True) -> Dict[str, Any]:
        """
        Backward-compatible `POST /detect` handler enriched with PyTorch Autoencoder
        and Tri-Model Detection Fusion outputs.
        """
        features = self.resolve_features_from_payload(payload)
        context = dict(payload.get("context") or {})
        context.pop("ground_truth", None)
        policy = str(payload.get("policy") or "weighted_consensus")

        fusion = self.engine.evaluate_tri_model_fusion(
            features=features if features is not None else [],
            policy=policy,
            context=context,
        )
        if_out = fusion["models"]["isolation_forest"]
        ae_out = fusion["models"]["autoencoder"]
        rf_out = fusion["models"]["random_forest"]

        # If all models or input features are degraded, return explicit degraded status
        # (never silently classify as normal!).
        if fusion["fusion_status"] == "degraded":
            return {
                "status": "degraded",
                "anomaly_score": None,
                "is_anomaly": None,
                "threshold": if_out.get("threshold"),
                "degraded_reason": (
                    ae_out.get("degraded_reason")
                    or if_out.get("degraded_reason")
                    or rf_out.get("degraded_reason")
                ),
                "autoencoder": ae_out,
                "isolation_forest": if_out,
                "random_forest": rf_out,
                "tri_model_fusion": fusion,
            }

        # Preserve legacy top-level fields (`anomaly_score`, `is_anomaly`, `threshold`)
        # while reflecting the Tri-Model Fusion verdict so Autoencoder + Isolation Forest + RF
        # work together seamlessly.
        primary_score = (
            if_out["raw_decision_score"]
            if if_out["status"] == "healthy" and if_out["raw_decision_score"] is not None
            else fusion["fused_anomaly_score"]
        )
        primary_thresh = (
            if_out["threshold"]
            if if_out["status"] == "healthy" and if_out["threshold"] is not None
            else ae_out.get("threshold")
        )
        combined_is_anomaly = bool(fusion["is_anomaly"])

        enriched_context = {
            **context,
            "tri_model_fusion": {
                "fusion_status": fusion["fusion_status"],
                "final_decision": fusion["final_decision"],
                "fused_anomaly_score": fusion["fused_anomaly_score"],
                "recommended_action": fusion["recommended_action"],
                "auto_block_permitted": fusion["auto_block_permitted"],
                "decision_rule": fusion["decision_rule"],
                "models_agreeing_on_anomaly": fusion["models_agreeing_on_anomaly"],
                "degraded_models": fusion["degraded_models"],
            },
            "autoencoder": {
                "status": ae_out["status"],
                "decision": ae_out["decision"],
                "is_anomaly": ae_out["is_anomaly"],
                "reconstruction_error": ae_out["reconstruction_error"],
                "anomaly_score": ae_out["anomaly_score"],
                "threshold": ae_out["threshold"],
                "threshold_percentile": ae_out["threshold_percentile"],
                "warning_threshold_p95": ae_out["warning_threshold_p95"],
                "model_version": ae_out["model_version"],
                "top_contributing_features": ae_out["top_contributing_features"],
            },
        }

        if forward_downstream and features is not None:
            attack_type = str(context.get("attack_type") or context.get("attackType") or "").lower()
            flow_type = str(context.get("flow_type") or "").lower()
            force_classification = (
                flow_type == "anomaly"
                or (attack_type not in {"", "normal_traffic", "benign"} and attack_type != "unknown")
            )
            if combined_is_anomaly or force_classification:
                _post_json_safe(
                    "http://threat-classification-service:8000/classify",
                    {"features": features, "context": enriched_context},
                )
            else:
                _post_json_safe(
                    "http://playbook-decision-engine:3000/decide",
                    {
                        "prediction": 0,
                        "probabilities": [1.0, 0.0],
                        "context": {
                            **enriched_context,
                            "attack_type": context.get("attack_type") or "normal_traffic",
                            "flow_type": context.get("flow_type") or "normal",
                        },
                        "sourceIp": context.get("src_ip"),
                    },
                )

        return {
            "status": fusion["fusion_status"],
            "anomaly_score": float(primary_score) if primary_score is not None else None,
            "is_anomaly": combined_is_anomaly,
            "threshold": float(primary_thresh) if primary_thresh is not None else None,
            "autoencoder": ae_out,
            "isolation_forest": if_out,
            "random_forest": rf_out,
            "tri_model_fusion": fusion,
        }

    def handle_detect_autoencoder(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        features = self.resolve_features_from_payload(payload)
        top_k = int(payload.get("top_k", 5))
        return self.engine.score_autoencoder(features if features is not None else [], top_k=top_k)

    def handle_detect_tri_model(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        features = self.resolve_features_from_payload(payload)
        policy = str(payload.get("policy") or "weighted_consensus")
        context = payload.get("context") or {}
        return self.engine.evaluate_tri_model_fusion(
            features=features if features is not None else [],
            policy=policy,
            context=context,
        )

    def handle_autoencoder_info(self) -> Dict[str, Any]:
        ae = self.engine.ae_engine
        return {
            "status": ae.status,
            "degraded_reason": ae.degraded_reason,
            "model_version": ae.model_version,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "expected_feature_count": EXPECTED_FEATURE_COUNT,
            "selected_threshold": ae.selected_threshold,
            "selected_threshold_percentile": ae.selected_threshold_name,
            "calibration_thresholds": {
                "P95": ae.threshold_p95,
                "P97": ae.threshold_p97,
                "P99": ae.threshold_p99,
            },
            "metadata": ae.metadata,
        }

    def handle_health(self) -> Dict[str, Any]:
        summary = self.engine.get_health_summary()
        return {
            "status": summary["status"],
            "model_loaded": summary["status"] in ("healthy", "partially_degraded"),
            "autoencoder_loaded": summary["models"]["autoencoder"]["status"] == "healthy",
            "isolation_forest_loaded": summary["models"]["isolation_forest"]["status"] == "healthy",
            "random_forest_loaded": summary["models"]["random_forest"]["status"] == "healthy",
            "tri_model_health": summary,
        }

    def handle_reload(self, models_dir: Optional[Path] = None) -> Dict[str, Any]:
        health = self.engine.load_all_models(models_dir or self.models_dir)
        self.xai_engine.rf_explainer._initialize_explainer()
        self.xai_engine.if_explainer._initialize()
        return health

    def handle_xai_health(self) -> Dict[str, Any]:
        tri_health = self.engine.get_health_summary()
        rf_exp = self.xai_engine.rf_explainer
        if_exp = self.xai_engine.if_explainer
        ae_healthy = self.engine.ae_engine.status == "healthy"
        explainers = {
            "random_forest": {
                "status": rf_exp.status,
                "is_exact_shap": rf_exp.is_exact_shap,
                "method": rf_exp.explainer_backend,
                "degraded_reason": rf_exp.degraded_reason,
            },
            "isolation_forest": {
                "status": if_exp.status,
                "method": "reference_population_perturbation_and_quantile_deviation",
                "reference_population_size": int(len(if_exp.normal_matrix)) if if_exp.normal_matrix is not None else 0,
                "degraded_reason": if_exp.degraded_reason,
            },
            "autoencoder": {
                "status": "healthy" if ae_healthy else "degraded",
                "method": "pytorch_bottleneck_reconstruction_error_decomposition",
                "threshold_p97": self.engine.ae_engine.selected_threshold,
                "degraded_reason": self.engine.ae_engine.degraded_reason,
            },
        }
        healthy_cnt = sum(1 for v in explainers.values() if v["status"] == "healthy")
        overall = "healthy" if healthy_cnt == 3 else ("partially_degraded" if healthy_cnt > 0 else "degraded")
        global_rf_imp = None
        if rf_exp.status == "healthy" and self.xai_engine.normal_matrix is not None:
            try:
                global_rf_imp = rf_exp.compute_global_feature_importance(
                    self.xai_engine.normal_matrix, max_samples=50, top_k=10
                )
            except Exception:
                global_rf_imp = None
        return {
            "status": overall,
            "schema_version": FEATURE_SCHEMA_VERSION,
            "expected_feature_count": EXPECTED_FEATURE_COUNT,
            "catalog_flows_count": len(self.xai_engine.flow_catalog),
            "tri_model_status": tri_health["status"],
            "explainers": explainers,
            "global_rf_shap_importance": global_rf_imp,
        }

    @staticmethod
    def _validate_xai_request_item(payload: Dict[str, Any]) -> Optional[str]:
        if not isinstance(payload, dict):
            return "Request item must be a JSON object"
        flow_id = payload.get("flow_id")
        features = payload.get("features")
        raw_flow = payload.get("raw_flow")
        policy = str(payload.get("policy") or "weighted_consensus")
        if policy not in _ALLOWED_POLICIES:
            return f"Unsupported fusion policy '{policy}'. Allowed: {sorted(_ALLOWED_POLICIES)}"
        if flow_id is not None:
            if not isinstance(flow_id, str) or not _FLOW_ID_PATTERN.match(flow_id.strip()):
                return "Invalid flow_id format (expected 1-128 alphanumeric/._:- characters)"
        if flow_id is None and features is None and raw_flow is None:
            return "Must provide at least one of 'flow_id', 'features' (69 floats), or 'raw_flow'"
        if features is not None:
            if not isinstance(features, list) or len(features) != EXPECTED_FEATURE_COUNT:
                return f"Invalid 'features': expected list of {EXPECTED_FEATURE_COUNT} finite floats"
            for val in features:
                try:
                    fval = float(val)
                except (TypeError, ValueError):
                    return "Invalid 'features': non-numeric value encountered"
                if not math.isfinite(fval):
                    return "Invalid 'features': NaN or Infinity is not permitted"
        top_k = payload.get("top_k", 5)
        try:
            tk = int(top_k)
            if tk < 1 or tk > 20:
                return "Invalid 'top_k': must be between 1 and 20"
        except (TypeError, ValueError):
            return "Invalid 'top_k': must be an integer between 1 and 20"
        return None

    def handle_xai_explain(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        err = self._validate_xai_request_item(payload)
        if err is not None:
            return 400, {"status": "error", "error": err, "schema_version": FEATURE_SCHEMA_VERSION}

        flow_id = payload.get("flow_id")
        features = payload.get("features")
        raw_flow = payload.get("raw_flow")
        policy = str(payload.get("policy") or "weighted_consensus")
        top_k = int(payload.get("top_k", 5))
        include_full = bool(payload.get("include_full_features", False))

        res = self.xai_engine.explain(
            flow_id=flow_id,
            features=features,
            raw_flow=raw_flow,
            policy=policy,
            top_k=top_k,
        )
        if not include_full and isinstance(res, dict):
            res = {k: v for k, v in res.items() if k != "individual_model_explanations_full"}

        if res.get("explanation_generation_status") == "degraded" and str(res.get("degraded_reason", "")).startswith("flow_id_not_found:"):
            return 404, res
        return 200, res

    def handle_xai_explain_batch(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            return 400, {"status": "error", "error": "Request must contain an 'items' array"}
        items = payload["items"]
        if len(items) == 0:
            return 400, {"status": "error", "error": "'items' array must not be empty"}
        if len(items) > _MAX_BATCH_EXPLAIN_ITEMS:
            return 400, {
                "status": "error",
                "error": f"Batch size {len(items)} exceeds maximum limit of {_MAX_BATCH_EXPLAIN_ITEMS}",
            }

        default_policy = str(payload.get("policy") or "weighted_consensus")
        default_top_k = payload.get("top_k", 5)
        include_full = bool(payload.get("include_full_features", False))

        results: List[Dict[str, Any]] = []
        succeeded_count = 0
        degraded_count = 0

        for idx, raw_item in enumerate(items):
            item_obj = dict(raw_item) if isinstance(raw_item, dict) else {}
            if "policy" not in item_obj:
                item_obj["policy"] = default_policy
            if "top_k" not in item_obj:
                item_obj["top_k"] = default_top_k
            if "include_full_features" not in item_obj:
                item_obj["include_full_features"] = include_full

            code, out = self.handle_xai_explain(item_obj)
            if code == 200 and out.get("explanation_generation_status") in ("healthy", "partially_degraded"):
                succeeded_count += 1
            else:
                degraded_count += 1
            results.append({"index": idx, "http_status": code, "explanation": out})

        return 200, {
            "status": "success" if succeeded_count > 0 else "degraded",
            "schema_version": FEATURE_SCHEMA_VERSION,
            "total_requested": len(items),
            "succeeded_count": succeeded_count,
            "degraded_count": degraded_count,
            "results": results,
        }


core_service = MLDetectionServiceCore()

# Attempt FastAPI bindings if installed in environment
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel

    app = FastAPI(
        title="Shadow Guard 2.0 ML Detection Service",
        description="Tri-Model Anomaly Detection (Isolation Forest + Random Forest + PyTorch Autoencoder) + XAI Engine",
        version="2.0.0",
    )

    class FeatureData(BaseModel):
        features: Optional[List[float]] = None
        context: Optional[Dict[str, Any]] = None
        policy: Optional[str] = "weighted_consensus"
        top_k: Optional[int] = 5

    class XAIExplainRequest(BaseModel):
        flow_id: Optional[str] = None
        features: Optional[List[float]] = None
        raw_flow: Optional[Dict[str, Any]] = None
        policy: Optional[str] = "weighted_consensus"
        top_k: Optional[int] = 5
        include_full_features: Optional[bool] = False

    class XAIBatchRequest(BaseModel):
        items: List[Dict[str, Any]]
        policy: Optional[str] = "weighted_consensus"
        top_k: Optional[int] = 5
        include_full_features: Optional[bool] = False

    @app.post("/detect")
    async def detect_anomaly(data: FeatureData):
        return core_service.handle_detect(data.model_dump() if hasattr(data, "model_dump") else data.dict())

    @app.post("/detect/autoencoder")
    async def detect_autoencoder(data: FeatureData):
        return core_service.handle_detect_autoencoder(
            data.model_dump() if hasattr(data, "model_dump") else data.dict()
        )

    @app.post("/detect/tri-model")
    async def detect_tri_model(data: FeatureData):
        return core_service.handle_detect_tri_model(
            data.model_dump() if hasattr(data, "model_dump") else data.dict()
        )

    @app.get("/model/autoencoder/info")
    async def autoencoder_info():
        return core_service.handle_autoencoder_info()

    @app.post("/model/reload")
    async def reload_models():
        return core_service.handle_reload()

    @app.get("/health")
    async def health():
        return core_service.handle_health()

    @app.get("/xai/health")
    async def xai_health():
        return core_service.handle_xai_health()

    @app.post("/xai/explain")
    async def xai_explain(data: XAIExplainRequest):
        payload = data.model_dump() if hasattr(data, "model_dump") else data.dict()
        code, body = core_service.handle_xai_explain(payload)
        return JSONResponse(status_code=code, content=body)

    @app.post("/xai/explain/batch")
    async def xai_explain_batch(data: XAIBatchRequest):
        payload = data.model_dump() if hasattr(data, "model_dump") else data.dict()
        code, body = core_service.handle_xai_explain_batch(payload)
        return JSONResponse(status_code=code, content=body)

except ImportError:
    app = None


class _StandaloneHTTPHandler(BaseHTTPRequestHandler):
    """
    Lightweight standard-library HTTP server handler used when FastAPI/Uvicorn is not installed
    on the host Python environment. Exposes the exact same REST endpoints and JSON schemas.
    """

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, core_service.handle_health())
        elif self.path == "/model/autoencoder/info":
            self._send_json(200, core_service.handle_autoencoder_info())
        elif self.path == "/xai/health":
            self._send_json(200, core_service.handle_xai_health())
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(raw)
        except Exception:
            self._send_json(400, {"status": "degraded", "error": "Invalid JSON payload"})
            return

        if self.path == "/detect":
            res = core_service.handle_detect(payload, forward_downstream=False)
            self._send_json(200, res)
        elif self.path == "/detect/autoencoder":
            res = core_service.handle_detect_autoencoder(payload)
            self._send_json(200, res)
        elif self.path == "/detect/tri-model":
            res = core_service.handle_detect_tri_model(payload)
            self._send_json(200, res)
        elif self.path == "/model/reload":
            res = core_service.handle_reload()
            self._send_json(200, res)
        elif self.path == "/xai/explain":
            code, res = core_service.handle_xai_explain(payload)
            self._send_json(code, res)
        elif self.path == "/xai/explain/batch":
            code, res = core_service.handle_xai_explain_batch(payload)
            self._send_json(code, res)
        else:
            self._send_json(404, {"error": "Not found"})


def dispatch_raw_http_request(
    method: str,
    path: str,
    body_obj: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Executes a raw HTTP/1.1 request through `_StandaloneHTTPHandler` using in-memory streams,
    returning `{"statusCode": int, "body": dict}`. Used when OS sandbox blocks TCP connect().
    """
    import io

    body_bytes = json.dumps(body_obj).encode("utf-8") if body_obj is not None else b""
    raw_req = (
        f"{method.upper()} {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:8001\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"\r\n"
    ).encode("utf-8") + body_bytes

    rfile = io.BytesIO(raw_req)
    wfile = io.BytesIO()

    class _MockSocket:
        def makefile(self, mode: str, *args: Any, **kwargs: Any) -> io.BytesIO:
            return rfile if "r" in mode else wfile

        def sendall(self, data: bytes) -> None:
            wfile.write(data)

    _StandaloneHTTPHandler(_MockSocket(), ("127.0.0.1", 50000), None)
    resp_text = wfile.getvalue().decode("utf-8", errors="replace")
    header_part, _, body_part = resp_text.partition("\r\n\r\n")
    status_line = header_part.splitlines()[0] if header_part else "HTTP/1.1 500 Error"
    parts = status_line.split(" ")
    status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 500
    return {
        "statusCode": status_code,
        "body": json.loads(body_part) if body_part.strip() else {},
    }


def run_standalone_server(host: str = "127.0.0.1", port: int = 8001) -> None:
    server = HTTPServer((host, port), _StandaloneHTTPHandler)
    print(f"Shadow Guard 2.0 ML Detection Service listening on http://{host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    port_num = int(os.getenv("PORT", "8001"))
    run_standalone_server("127.0.0.1", port_num)
