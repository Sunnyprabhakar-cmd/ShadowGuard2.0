/**
 * Shadow Guard 2.0 — XAI Stage 3 Persistence & Cache Store
 *
 * Provides parameterized PostgreSQL persistence (`xai_explanations` table in
 * `004_xai_explanations.sql`) using explicit database transactions (`BEGIN` /
 * `COMMIT` / `ROLLBACK`), duplicate prevention via `input_signature_sha256`,
 * and an in-memory LRU cache with automatic fallback when PostgreSQL is
 * unavailable in standalone host execution.
 */

'use strict';

const crypto = require('crypto');

let PgPool = null;
try {
  ({ Pool: PgPool } = require('pg'));
} catch (_) {
  PgPool = null;
}

class XaiExplanationStore {
  constructor(options = {}) {
    this.maxCacheEntries = Number(options.maxCacheEntries || 256);
    this.cache = new Map(); // `${flow_id}::${policy}` -> stored record
    this.memoryRecords = new Map(); // explanation_id -> stored record
    this.pool = options.pool || null;
    this.databaseAvailable = false;
    this.lastDbError = null;

    if (!this.pool && PgPool && process.env.DISABLE_XAI_PG !== 'true') {
      try {
        this.pool = new PgPool({
          user: process.env.DB_USER || 'user',
          host: process.env.DB_HOST || 'localhost',
          database: process.env.DB_NAME || 'threat_logs',
          password: process.env.DB_PASS || 'password',
          port: Number(process.env.DB_PORT || 5433),
          max: 5,
          idleTimeoutMillis: 15000,
          connectionTimeoutMillis: Number(options.dbTimeoutMs || 1500),
        });
      } catch (err) {
        this.lastDbError = err.message;
        this.pool = null;
      }
    }
  }

  static computeInputSignature(flowId, policy, features = null) {
    const payload = JSON.stringify({
      flow_id: String(flowId || ''),
      policy: String(policy || 'weighted_consensus'),
      features: Array.isArray(features) ? features.map((v) => Number(v)) : null,
    });
    return crypto.createHash('sha256').update(payload).digest('hex');
  }

  static computeExplanationId(flowId, policy, inputSignatureSha256) {
    const raw = `${flowId}|${policy}|${inputSignatureSha256}`;
    return `xai-${crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24)}`;
  }

  _setCache(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxCacheEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(key, value);
  }

  _extractDbRecord(explanationPayload, features = null) {
    const flowId = String(explanationPayload.flow_id || 'unknown-flow');
    const policy = String(
      explanationPayload.final_tri_model_classification?.fusion_policy || 'weighted_consensus'
    );
    const sig = XaiExplanationStore.computeInputSignature(flowId, policy, features);
    const explanationId = XaiExplanationStore.computeExplanationId(flowId, policy, sig);

    const rf = explanationPayload.random_forest_explanation || {};
    const iso = explanationPayload.isolation_forest_explanation || {};
    const ae = explanationPayload.autoencoder_explanation || {};

    return {
      explanation_id: explanationId,
      flow_id: flowId,
      input_signature_sha256: sig,
      fusion_policy: policy,
      feature_schema_version: String(explanationPayload.schema_version || 'v2.0-69dim'),
      model_versions: {
        random_forest: 'random_forest_69_v2',
        isolation_forest: 'isolation_forest_69_v2',
        autoencoder: ae.model_version || 'ae-pytorch-v2.0.0',
      },
      explanation_methods: {
        random_forest: rf.explanation_method || 'degraded',
        is_exact_shap: Boolean(rf.is_exact_shap),
        isolation_forest: iso.explanation_method || 'degraded',
        autoencoder: ae.explanation_method || 'degraded',
      },
      final_tri_model_classification: explanationPayload.final_tri_model_classification || {},
      rf_shap_contributions: rf,
      if_attribution: iso,
      ae_reconstruction_errors: ae,
      unified_model_agreement: explanationPayload.model_agreement_and_disagreement || {},
      shared_and_specific_drivers: {
        shared_contributing_measurements: explanationPayload.shared_contributing_measurements || {},
        model_specific_contributing_measurements:
          explanationPayload.model_specific_contributing_measurements || {},
      },
      analyst_explanation: explanationPayload.human_readable_soc_analyst_explanation || {},
      explanation_confidence_limitations:
        explanationPayload.explanation_confidence_and_limitations || {},
      explanation_status: String(explanationPayload.explanation_generation_status || 'degraded'),
      total_latency_ms: Number(explanationPayload.total_explanation_latency_ms || 0),
      full_payload: explanationPayload,
    };
  }

  /**
   * Persist an explanation record idempotently using a PostgreSQL transaction
   * (with duplicate prevention via `ON CONFLICT (flow_id, fusion_policy, input_signature_sha256)`),
   * falling back safely to in-memory storage if PostgreSQL is offline.
   */
  async saveExplanation(explanationPayload, features = null) {
    const rec = this._extractDbRecord(explanationPayload, features);
    const cacheKey = `${rec.flow_id}::${rec.fusion_policy}`;

    // Store in memory cache & fallback map
    const nowIso = new Date().toISOString();
    const storedMem = {
      ...rec,
      created_at: this.memoryRecords.get(rec.explanation_id)?.created_at || nowIso,
      updated_at: nowIso,
    };
    this.memoryRecords.set(rec.explanation_id, storedMem);
    this._setCache(cacheKey, storedMem);

    if (!this.pool) {
      return {
        persisted: true,
        storage_backend: 'memory_fallback',
        database_available: false,
        explanation_id: rec.explanation_id,
        duplicate_prevented: false,
      };
    }

    let client = null;
    try {
      client = await this.pool.connect();
      await client.query('BEGIN');
      const sql = `
        INSERT INTO xai_explanations (
          explanation_id, flow_id, input_signature_sha256, fusion_policy,
          feature_schema_version, model_versions, explanation_methods,
          final_tri_model_classification, rf_shap_contributions, if_attribution,
          ae_reconstruction_errors, unified_model_agreement, shared_and_specific_drivers,
          analyst_explanation, explanation_confidence_limitations,
          explanation_status, total_latency_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb, $15::jsonb, $16, $17)
        ON CONFLICT (flow_id, fusion_policy, input_signature_sha256) DO UPDATE SET
          explanation_status = EXCLUDED.explanation_status,
          total_latency_ms = EXCLUDED.total_latency_ms,
          updated_at = CURRENT_TIMESTAMP
        RETURNING explanation_id, (xmax <> 0) AS was_duplicate_update, created_at, updated_at
      `;
      const params = [
        rec.explanation_id,
        rec.flow_id,
        rec.input_signature_sha256,
        rec.fusion_policy,
        rec.feature_schema_version,
        JSON.stringify(rec.model_versions),
        JSON.stringify(rec.explanation_methods),
        JSON.stringify(rec.final_tri_model_classification),
        JSON.stringify(rec.rf_shap_contributions),
        JSON.stringify(rec.if_attribution),
        JSON.stringify(rec.ae_reconstruction_errors),
        JSON.stringify(rec.unified_model_agreement),
        JSON.stringify(rec.shared_and_specific_drivers),
        JSON.stringify(rec.analyst_explanation),
        JSON.stringify(rec.explanation_confidence_limitations),
        rec.explanation_status,
        rec.total_latency_ms,
      ];
      const result = await client.query(sql, params);
      await client.query('COMMIT');
      this.databaseAvailable = true;
      this.lastDbError = null;
      const row = result.rows[0] || {};
      return {
        persisted: true,
        storage_backend: 'postgresql',
        database_available: true,
        explanation_id: row.explanation_id || rec.explanation_id,
        duplicate_prevented: Boolean(row.was_duplicate_update),
        created_at: row.created_at || nowIso,
      };
    } catch (err) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch (_) {}
      }
      this.databaseAvailable = false;
      this.lastDbError = err.message;
      return {
        persisted: true,
        storage_backend: 'memory_fallback',
        database_available: false,
        database_error: err.message,
        explanation_id: rec.explanation_id,
        duplicate_prevented: false,
      };
    } finally {
      if (client) {
        client.release();
      }
    }
  }

  /**
   * Retrieve cached or persisted explanation by `flow_id` + `policy`.
   */
  async getExplanationByFlowId(flowId, policy = 'weighted_consensus') {
    const cacheKey = `${String(flowId)}::${String(policy)}`;
    if (this.cache.has(cacheKey)) {
      return {
        found: true,
        source: 'lru_cache',
        record: this.cache.get(cacheKey),
      };
    }

    if (this.pool) {
      try {
        const sql = `
          SELECT explanation_id, flow_id, fusion_policy, feature_schema_version,
                 model_versions, explanation_methods, final_tri_model_classification,
                 rf_shap_contributions, if_attribution, ae_reconstruction_errors,
                 unified_model_agreement, shared_and_specific_drivers,
                 analyst_explanation, explanation_confidence_limitations,
                 explanation_status, total_latency_ms, created_at, updated_at
          FROM xai_explanations
          WHERE flow_id = $1 AND fusion_policy = $2
          ORDER BY updated_at DESC
          LIMIT 1
        `;
        const res = await this.pool.query(sql, [String(flowId), String(policy)]);
        this.databaseAvailable = true;
        if (res.rows && res.rows.length > 0) {
          const row = res.rows[0];
          this._setCache(cacheKey, row);
          return { found: true, source: 'postgresql', record: row };
        }
      } catch (err) {
        this.databaseAvailable = false;
        this.lastDbError = err.message;
      }
    }

    for (const rec of this.memoryRecords.values()) {
      if (rec.flow_id === String(flowId) && rec.fusion_policy === String(policy)) {
        this._setCache(cacheKey, rec);
        return { found: true, source: 'memory_fallback', record: rec };
      }
    }

    return { found: false, source: null, record: null };
  }

  async getOverviewStats() {
    let pgCount = null;
    let rows = [];
    if (this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT explanation_id, flow_id, fusion_policy, explanation_status,
                  final_tri_model_classification, unified_model_agreement,
                  total_latency_ms, created_at, updated_at
           FROM xai_explanations
           ORDER BY updated_at DESC
           LIMIT 200`
        );
        this.databaseAvailable = true;
        rows = res.rows || [];
        pgCount = rows.length;
      } catch (err) {
        this.databaseAvailable = false;
        this.lastDbError = err.message;
      }
    }

    const sourceRecords =
      pgCount !== null
        ? rows
        : Array.from(this.memoryRecords.values()).sort(
            (a, b) => new Date(b.updated_at || b.created_at || 0) - new Date(a.updated_at || a.created_at || 0)
          );

    let maliciousCount = 0;
    let benignCount = 0;
    let suspiciousCount = 0;
    let partialCount = 0;
    let degradedCount = 0;
    const agreementCounts = {
      unanimous_anomaly: 0,
      unanimous_normal: 0,
      disagreement: 0,
      degraded_or_partial: 0,
    };

    const recentExplanations = [];
    for (const rec of sourceRecords) {
      const status = String(rec.explanation_status || 'degraded');
      if (status === 'partially_degraded') partialCount += 1;
      else if (status === 'degraded') degradedCount += 1;

      const cls = rec.final_tri_model_classification || {};
      const dec = String(cls.final_decision || 'degraded');
      if (dec === 'anomalous') maliciousCount += 1;
      else if (dec === 'normal') benignCount += 1;
      else if (dec === 'suspicious') suspiciousCount += 1;

      const agr = rec.unified_model_agreement || {};
      const cState = String(agr.consensus_state || '');
      if (cState === 'UNANIMOUS_ANOMALY_3_OF_3') agreementCounts.unanimous_anomaly += 1;
      else if (cState === 'UNANIMOUS_NORMAL_3_OF_3') agreementCounts.unanimous_normal += 1;
      else if (agr.has_model_disagreement) agreementCounts.disagreement += 1;
      else agreementCounts.degraded_or_partial += 1;

      if (recentExplanations.length < 30) {
        recentExplanations.push({
          explanation_id: rec.explanation_id,
          flow_id: rec.flow_id,
          fusion_policy: rec.fusion_policy || cls.fusion_policy || 'weighted_consensus',
          final_decision: dec,
          recommended_action: cls.recommended_action || 'manual-review',
          auto_block_permitted: Boolean(cls.auto_block_permitted),
          explanation_status: status,
          consensus_state: cState || 'UNKNOWN',
          has_model_disagreement: Boolean(agr.has_model_disagreement),
          total_latency_ms: Number(rec.total_latency_ms || 0),
          created_at: rec.created_at || rec.updated_at || new Date().toISOString(),
        });
      }
    }

    return {
      storage_backend: this.databaseAvailable ? 'postgresql' : 'memory_fallback',
      database_available: this.databaseAvailable,
      persisted_explanations_count: pgCount !== null ? pgCount : this.memoryRecords.size,
      total_explanations: sourceRecords.length,
      malicious_flows_explained: maliciousCount,
      benign_flows_explained: benignCount,
      suspicious_flows_explained: suspiciousCount,
      partially_degraded_explanations: partialCount,
      explanation_generation_failures: degradedCount,
      agreement_statistics: agreementCounts,
      recent_explanations: recentExplanations,
      lru_cache_entries: this.cache.size,
      lru_cache_capacity: this.maxCacheEntries,
      last_db_error: this.lastDbError,
    };
  }
}

module.exports = { XaiExplanationStore };
