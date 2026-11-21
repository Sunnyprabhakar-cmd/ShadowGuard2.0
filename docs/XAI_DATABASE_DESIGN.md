# Shadow Guard 2.0 — XAI Database Design (`004_xai_explanations.sql`)

## 1. Overview & Migration Strategy
Migration [004_xai_explanations.sql](file:///d:/ShadowGuard-main/ShadowGuard-main/database/migrations/004_xai_explanations.sql) extends PostgreSQL 15 without modifying any existing Shadow Guard 1.0 or 2.0 tables (`threat_logs`, `incidents`, `attacker_profiles`, `response_actions`, etc.). It records `'004_xai_explanations'` idempotently in `schema_migrations`.

## 2. Table: `xai_explanations`

| Column | Type | Purpose |
| :--- | :--- | :--- |
| `id` | `UUID PRIMARY KEY DEFAULT gen_random_uuid()` | Internal surrogate primary key |
| `explanation_id` | `VARCHAR(128) NOT NULL UNIQUE` | Deterministic identifier (`xai-<sha256[:24]>`) |
| `flow_id` | `VARCHAR(128) NOT NULL` | Investigated network flow identifier |
| `input_signature_sha256` | `CHAR(64) NOT NULL` | SHA-256 over `(flow_id, policy, features)` for duplicate prevention |
| `fusion_policy` | `VARCHAR(64) NOT NULL` | Preserved fusion policy (`weighted_consensus`, etc.) |
| `feature_schema_version` | `VARCHAR(32) NOT NULL` | Canonical schema (`v2.0-69dim`) |
| `model_versions` | `JSONB` | Versions of RF, IF, and PyTorch Autoencoder |
| `explanation_methods` | `JSONB` | Method labels (`official_shap_tree_explainer_v0.54.1`, `is_exact_shap`, perturbation, MSE) |
| `final_tri_model_classification` | `JSONB` | Read-only snapshot of final decision, rule, and `auto_block_permitted` |
| `rf_shap_contributions` | `JSONB` | Random Forest TreeSHAP top positive/negative contributors & additivity error |
| `if_attribution` | `JSONB` | Isolation Forest perturbation shifts & 840-flow quantile comparisons |
| `ae_reconstruction_errors` | `JSONB` | Autoencoder MSE, frozen $P_{97}=0.503670$ comparison, top-5 anomalous features |
| `unified_model_agreement` | `JSONB` | Consensus state, pairwise agreement, and disagreement reasoning |
| `shared_and_specific_drivers` | `JSONB` | Shared raw measurements and deduplicated feature concepts |
| `analyst_explanation` | `JSONB` | Executive verdict, evidence synthesis, and investigation checklist |
| `explanation_confidence_limitations` | `JSONB` | Reliability tier, method distinctions, collision flag, scientific limitations |
| `explanation_status` | `VARCHAR(32) CHECK (...)` | `healthy`, `partially_degraded`, or `degraded` |
| `total_latency_ms` | `NUMERIC(10, 4)` | End-to-end explanation latency |
| `created_at`, `updated_at` | `TIMESTAMPTZ` | Audit timestamps |

## 3. Duplicate Prevention, Transactions & Indexing
- **Unique Constraint**: `CONSTRAINT uq_xai_flow_policy_signature UNIQUE (flow_id, fusion_policy, input_signature_sha256)`.
- **Transactional Upsert**: `XaiExplanationStore.saveExplanation()` executes parameterized `BEGIN` -> `INSERT ... ON CONFLICT (flow_id, fusion_policy, input_signature_sha256) DO UPDATE` -> `COMMIT` (with `ROLLBACK` on error), preventing duplicate rows while remaining safe under concurrent requests.
- **Indexes**:
  - B-Tree: `idx_xai_explanations_flow_id`, `idx_xai_explanations_status`, `idx_xai_explanations_created_at DESC`
  - GIN (JSONB): `idx_xai_explanations_agreement_gin`, `idx_xai_explanations_classification_gin`
- **Graceful Degradation**: If PostgreSQL is unreachable, `XaiExplanationStore` falls back seamlessly to its LRU cache (`memory_fallback`) and reports `database_available: false` without interrupting SOC operations.
