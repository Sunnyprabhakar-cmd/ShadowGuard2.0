# Shadow Guard 2.0 — XAI API Reference (Stage 3)

## 1. Python ML Detection Service XAI Endpoints (`ml-detection-service`, Port `8001` / `8000` in Docker)

### `GET /xai/health`
Returns readiness of `UnifiedTriModelExplainer` and each Stage 1 explainer (`RandomForestSHAPExplainer`, `IsolationForestAnomalyExplainer`, `AutoencoderReconstructionExplainer`) without exposing internal file paths or secrets.
- **200 OK Example**:
```json
{
  "status": "healthy",
  "schema_version": "v2.0-69dim",
  "expected_feature_count": 69,
  "catalog_flows_count": 1524,
  "tri_model_status": "healthy",
  "explainers": {
    "random_forest": {
      "status": "healthy",
      "is_exact_shap": true,
      "method": "official_shap_tree_explainer_v0.54.1",
      "degraded_reason": null
    },
    "isolation_forest": {
      "status": "healthy",
      "method": "reference_population_perturbation_and_quantile_deviation",
      "reference_population_size": 840,
      "degraded_reason": null
    },
    "autoencoder": {
      "status": "healthy",
      "method": "pytorch_bottleneck_reconstruction_error_decomposition",
      "threshold_p97": 0.50367,
      "degraded_reason": null
    }
  }
}
```

### `POST /xai/explain`
Generates a unified read-only Tri-Model explanation for a `flow_id`, 69-dimensional `features` array, or `raw_flow` (`{packets, bytes, duration}`).
- **Request Body**:
```json
{
  "flow_id": "flow-atk-01404",
  "policy": "weighted_consensus",
  "top_k": 5,
  "include_full_features": false
}
```
- **Error Codes**: `400` (invalid `flow_id`, wrong feature dimension, NaN/Inf, unsupported policy, invalid `top_k`), `404` (`flow_id_not_found`), `200` (returns `healthy`, `partially_degraded`, or `degraded` unified explanation).

### `POST /xai/explain/batch`
Processes up to `50` explanation items in one request, isolating per-item errors.
- **Request Body**:
```json
{
  "items": [{ "flow_id": "flow-atk-01404" }, { "flow_id": "flow-norm-00293" }],
  "policy": "weighted_consensus",
  "top_k": 5
}
```
- **Response**: `{ "status": "success", "total_requested": 2, "succeeded_count": 2, "degraded_count": 0, "results": [...] }`.

---

## 2. Node.js SOC Dashboard Authenticated API Gateway (`threat-dashboard-service`, Port `7000`)

All `/api/v2/xai/*` endpoints enforce JWT / API-Key authentication via `securityManager.requireRole(...)`, sanitize outputs via `sanitizeXaiForRole`, and record events in `securityAuditLog`.

| Method & Path | Minimum Role | Description & Error Handling |
| :--- | :---: | :--- |
| `GET /api/v2/xai/overview` | `VIEWER` | Returns ML XAI health, PostgreSQL/LRU persistence stats, supported methods, and safety policy (`read_only_on_predictions: true`, `ae_only_auto_block_permitted: false`). |
| `GET /api/v2/xai/explanation/:flowId` | `VIEWER` | Validates `flowId` (`^[A-Za-z0-9_.:-]{1,128}$`), checks LRU/PostgreSQL cache or calls `/xai/explain`, persists result, and redacts `src_ip`/`dst_ip`/`src_port` for `VIEWER`. Returns `400`, `401`, `404`, `503` (`ML_UNAVAILABLE`), `504` (`ML_TIMEOUT`). |
| `POST /api/v2/xai/explanation` | `SOC_ANALYST` | Generates & persists an explanation for `flow_id`, 69-dim `features`, or `raw_flow`. Returns `403` for `VIEWER`. |
| `POST /api/v2/xai/explanation/batch` | `SOC_ANALYST` | Batch-generates and persists up to `50` explanations. Returns `403` for `VIEWER`. |
| `GET /api/v2/xai/diagnostics` | `ADMIN` | Administrative XAI diagnostics (ML health, store stats, timeout config, strict auth status). Returns `403` for `VIEWER` and `SOC_ANALYST`. |
