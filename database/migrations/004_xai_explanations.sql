-- ============================================================================
-- Shadow Guard 2.0 — XAI Stage 3 Migration: Explainable AI Persistence
-- Migration: 004_xai_explanations.sql
--
-- Creates the `xai_explanations` table to persist read-only unified and
-- model-specific XAI outputs (Random Forest SHAP, Isolation Forest perturbation,
-- PyTorch Autoencoder MSE decomposition, and Tri-Model agreement/narrative).
-- Does not modify any existing Shadow Guard 1.0 or 2.0 tables.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS xai_explanations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    explanation_id VARCHAR(128) NOT NULL UNIQUE,
    flow_id VARCHAR(128) NOT NULL,
    input_signature_sha256 CHAR(64) NOT NULL,
    fusion_policy VARCHAR(64) NOT NULL DEFAULT 'weighted_consensus',
    feature_schema_version VARCHAR(32) NOT NULL DEFAULT 'v2.0-69dim',
    model_versions JSONB NOT NULL DEFAULT '{}'::jsonb,
    explanation_methods JSONB NOT NULL DEFAULT '{}'::jsonb,
    final_tri_model_classification JSONB NOT NULL DEFAULT '{}'::jsonb,
    rf_shap_contributions JSONB NOT NULL DEFAULT '{}'::jsonb,
    if_attribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    ae_reconstruction_errors JSONB NOT NULL DEFAULT '{}'::jsonb,
    unified_model_agreement JSONB NOT NULL DEFAULT '{}'::jsonb,
    shared_and_specific_drivers JSONB NOT NULL DEFAULT '{}'::jsonb,
    analyst_explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
    explanation_confidence_limitations JSONB NOT NULL DEFAULT '{}'::jsonb,
    explanation_status VARCHAR(32) NOT NULL CHECK (explanation_status IN ('healthy', 'partially_degraded', 'degraded')),
    total_latency_ms NUMERIC(10, 4),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_xai_flow_policy_signature UNIQUE (flow_id, fusion_policy, input_signature_sha256)
);

-- B-Tree indexes for fast flow lookup, status filtering, and chronological SOC queries
CREATE INDEX IF NOT EXISTS idx_xai_explanations_flow_id
    ON xai_explanations (flow_id);

CREATE INDEX IF NOT EXISTS idx_xai_explanations_status
    ON xai_explanations (explanation_status);

CREATE INDEX IF NOT EXISTS idx_xai_explanations_created_at
    ON xai_explanations (created_at DESC);

-- GIN indexes for structured JSONB queries over model agreement and final classification
CREATE INDEX IF NOT EXISTS idx_xai_explanations_agreement_gin
    ON xai_explanations USING GIN (unified_model_agreement);

CREATE INDEX IF NOT EXISTS idx_xai_explanations_classification_gin
    ON xai_explanations USING GIN (final_tri_model_classification);

-- Record migration idempotently
INSERT INTO schema_migrations (migration_name)
VALUES ('004_xai_explanations')
ON CONFLICT (migration_name) DO NOTHING;
