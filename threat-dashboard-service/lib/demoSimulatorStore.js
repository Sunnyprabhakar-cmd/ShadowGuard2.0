/**
 * Shadow Guard 2.0 — Demo Traffic Simulator Session Store & Aggregator
 * ====================================================================
 * Strictly isolated from live production `socAggregator` and `xaiStore`.
 * Tracks per-session demo flows, tri-model detection results, correlated
 * demo incidents, MITRE ATT&CK mappings, simulated SOAR actions, and
 * XAI explanation triggers for real-time WebSocket streaming and
 * post-session evaluation.
 */

'use strict';

const crypto = require('crypto');

const MITRE_BY_CATEGORY = {
  port_scan: ['T1046 - Network Service Discovery'],
  ssh_brute_force: ['T1110 - Brute Force', 'T1021.004 - Remote Services: SSH'],
  brute_force: ['T1110 - Brute Force'],
  service_enumeration: ['T1046 - Network Service Discovery', 'T1018 - Remote System Discovery'],
  ddos: ['T1498 - Network Denial of Service'],
  data_exfiltration: ['T1041 - Exfiltration Over C2 Channel', 'T1048 - Exfiltration Over Alternative Protocol'],
  c2_beaconing: ['T1071 - Application Layer Protocol', 'T1573 - Encrypted Channel'],
  malware_command_control: ['T1071 - Application Layer Protocol', 'T1573 - Encrypted Channel'],
  multi_vector: ['T1190 - Exploit Public-Facing Application', 'T1046 - Network Service Discovery', 'T1041 - Exfiltration Over C2 Channel'],
  stealth_anomaly: ['T1027 - Obfuscated Files or Information', 'T1203 - Exploitation for Client Execution'],
  zero_day: ['T1203 - Exploitation for Client Execution'],
  normal_traffic: []
};

function computeExtendedFeatures(ev) {
  const packets = Number(ev.packets || ev.packet_count || 0);
  const bytes = Number(ev.bytes || ev.bytes_sent || 0);
  const duration = Number(ev.duration || 0.001) || 0.001;
  const features = [
    packets,
    bytes,
    duration,
    bytes / duration,
    packets / duration,
    packets > 0 ? bytes / packets : 0,
    packets * bytes,
    Math.log(packets + 1),
    Math.log(bytes + 1),
    Math.log(duration + 1)
  ];
  for (let i = 0; i < 15; i++) {
    features.push((Math.sin(packets * (i + 1)) * bytes) / (duration + 1));
  }
  for (let i = 0; i < 15; i++) {
    features.push((Math.pow(packets, 2 - (i % 2)) * Math.pow(bytes, i % 2)) / (Math.pow(duration, 2) + 1));
  }
  for (let i = 0; i < 15; i++) {
    const val = (packets + bytes + duration) / 3;
    features.push(Math.cos(i * val) * Math.exp(-duration));
  }
  while (features.length < 69) {
    const idx = features.length;
    features.push(((packets + bytes) / (duration + 1)) * Math.sin(idx));
  }
  return features.slice(0, 69);
}

class DemoSimulatorStore {
  constructor(options = {}) {
    this.maxEventsPerSession = options.maxEventsPerSession || 500;
    this.sessions = new Map();
    this.activeSessionId = null;
    this.seenFlowIds = new Set();
  }

  _ensureSession(sessionId, meta = {}) {
    if (!sessionId) return null;
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        session_id: sessionId,
        event_source: 'demo_simulator',
        state: meta.state || 'Running',
        scenario: meta.scenario || 'mixed',
        mode: meta.mode || 'mixed',
        speed: meta.speed || 'medium',
        started_at: meta.started_at || new Date().toISOString(),
        ended_at: meta.ended_at || null,
        events: [],
        incidents: new Map(),
        soar_actions: [],
        demo_leases: [],
        xai_triggers: [],
        category_counts: {},
        protocol_counts: {},
        authoritative_total_generated: 0,
        duplicate_events: 0,
        counters: {
          events_generated: 0,
          benign_events: 0,
          malicious_events: 0,
          detected_threats: 0,
          incidents_generated: 0,
          soar_actions_simulated: 0,
          xai_explanations_triggered: 0
        }
      });
    }
    const sess = this.sessions.get(sessionId);
    if (meta.state) sess.state = meta.state;
    if (meta.ended_at) sess.ended_at = meta.ended_at;
    if (meta.counters && typeof meta.counters.events_generated === 'number') {
      sess.authoritative_total_generated = Math.max(sess.authoritative_total_generated, meta.counters.events_generated);
    }
    this.activeSessionId = sessionId;
    return sess;
  }

  updateSessionMeta(statusData = {}) {
    if (!statusData || !statusData.session_id) return null;
    return this._ensureSession(statusData.session_id, {
      state: statusData.state,
      scenario: statusData.scenario,
      mode: statusData.mode,
      speed: statusData.speed,
      started_at: statusData.started_at,
      ended_at: statusData.ended_at,
      counters: statusData.counters
    });
  }

  async ingestSimulatorEvents(rawEvents = [], { detectFn = null, xaiFn = null, sessionMeta = {} } = {}) {
    const newlyIngested = [];
    for (const raw of rawEvents) {
      if (!raw || !raw.flow_id) continue;
      const dedupKey = `${raw.session_id || sessionMeta.session_id || 'default'}:${raw.flow_id}`;
      if (this.seenFlowIds.has(dedupKey) || this.seenFlowIds.has(raw.flow_id)) {
        const existingSess = this.getSession(raw.session_id || sessionMeta.session_id);
        if (existingSess && raw._countDuplicateOnReingest) {
          existingSess.duplicate_events += 1;
        }
        continue;
      }
      this.seenFlowIds.add(dedupKey);
      this.seenFlowIds.add(raw.flow_id);

      const sessionId = raw.session_id || sessionMeta.session_id || this.activeSessionId || 'demo-sess-default';
      const sess = this._ensureSession(sessionId, sessionMeta);
      const features = computeExtendedFeatures(raw);

      let mlResult = null;
      if (typeof detectFn === 'function') {
        try {
          mlResult = await detectFn({
            features,
            context: {
              flow_id: raw.flow_id,
              src_ip: raw.src_ip,
              dst_ip: raw.dst_ip,
              src_port: raw.src_port,
              dst_port: raw.dst_port,
              protocol: raw.protocol,
              attack_type: raw.attack_type,
              packets: raw.packets,
              bytes_sent: raw.bytes,
              duration: raw.duration,
              flow_type: raw.attack_type === 'normal_traffic' ? 'normal' : 'anomaly',
              event_source: 'demo_simulator',
              session_id: sessionId
            }
          });
        } catch (_) {
          mlResult = null;
        }
      }

      const rf = mlResult?.random_forest || {};
      const isof = mlResult?.isolation_forest || {};
      const ae = mlResult?.autoencoder || {};
      const fusion = mlResult?.tri_model_fusion || {};

      const mlEvaluated = Boolean(mlResult && mlResult.status !== 'degraded' && fusion.fusion_status !== 'degraded');
      const isAnomaly = mlEvaluated
        ? (typeof fusion.is_anomaly === 'boolean' ? fusion.is_anomaly : Boolean(mlResult?.is_anomaly))
        : false;
      const recommendedAction = fusion.recommended_action || (isAnomaly ? 'alert' : 'monitor');
      const finalDecision = mlEvaluated
        ? (fusion.final_decision || (isAnomaly ? 'ANOMALY' : 'NORMAL'))
        : 'UNPROCESSED';
      const modelDisagreement = Boolean(
        fusion.model_disagreement
        || (fusion.models_agreeing_on_anomaly !== undefined && fusion.models_agreeing_on_anomaly > 0 && fusion.models_agreeing_on_anomaly < 3)
      );

      let xaiTrigger = null;
      if (isAnomaly && typeof xaiFn === 'function') {
        try {
          const xaiRes = await xaiFn({
            flow_id: raw.flow_id,
            features,
            context: {
              flow_id: raw.flow_id,
              src_ip: raw.src_ip,
              dst_ip: raw.dst_ip,
              protocol: raw.protocol,
              attack_type: raw.attack_type,
              event_source: 'demo_simulator',
              session_id: sessionId
            }
          });
          if (xaiRes) {
            xaiTrigger = {
              flow_id: raw.flow_id,
              session_id: sessionId,
              event_source: 'demo_simulator',
              triggered_at: new Date().toISOString(),
              explanation_status: xaiRes.explanation_generation_status || 'healthy',
              top_features: (xaiRes.unified_top_features || []).slice(0, 5)
            };
            sess.xai_triggers.unshift(xaiTrigger);
            if (sess.xai_triggers.length > 100) sess.xai_triggers.length = 100;
            sess.counters.xai_explanations_triggered += 1;
          }
        } catch (_) {
          xaiTrigger = null;
        }
      }

      const canonicalCat = raw.ground_truth?.canonical_category || raw.attack_type || 'unknown';
      const mitre = MITRE_BY_CATEGORY[canonicalCat] || MITRE_BY_CATEGORY[raw.attack_type] || [];

      let soarRecord = null;
      let incidentId = null;
      if (isAnomaly) {
        sess.counters.detected_threats += 1;
        const incKey = `${raw.src_ip}:${canonicalCat}`;
        if (!sess.incidents.has(incKey)) {
          incidentId = `demo-inc-${crypto.randomUUID().slice(0, 8)}`;
          sess.incidents.set(incKey, {
            incident_id: incidentId,
            session_id: sessionId,
            event_source: 'demo_simulator',
            demo_simulated: true,
            title: `[DEMO] ${canonicalCat} from ${raw.src_ip}`,
            attack_categories: [canonicalCat],
            source_ips: [raw.src_ip],
            mitre_techniques: mitre,
            severity: recommendedAction === 'block' ? 'high' : 'medium',
            status: 'open_demo',
            correlated_events: 1,
            created_at: raw.timestamp || new Date().toISOString(),
            updated_at: raw.timestamp || new Date().toISOString()
          });
          sess.counters.incidents_generated += 1;
        } else {
          const inc = sess.incidents.get(incKey);
          inc.correlated_events += 1;
          inc.updated_at = raw.timestamp || new Date().toISOString();
          incidentId = inc.incident_id;
        }

        soarRecord = {
          action_id: `demo-soar-${crypto.randomUUID().slice(0, 8)}`,
          flow_id: raw.flow_id,
          session_id: sessionId,
          event_source: 'demo_simulator',
          demo_simulated: true,
          playbook_triggered: recommendedAction === 'block' ? 'PB-DEMO-CONTAINMENT' : 'PB-DEMO-TRIAGE',
          response_decision: recommendedAction === 'block' ? 'DEMO_SIMULATED_BLOCK' : `DEMO_${String(recommendedAction).toUpperCase()}`,
          manual_review_required: Boolean(fusion.auto_block_permitted === false || modelDisagreement),
          simulated_block_lease: recommendedAction === 'block'
            ? { ip: raw.src_ip, lease_minutes: 30, status: 'DEMO_SIMULATED_LEASE' }
            : null,
          execution_status: 'DEMO_SIMULATED',
          audit_event: 'DEMO_ACTION_SIMULATED',
          target_ip: raw.src_ip,
          timestamp: new Date().toISOString()
        };
        sess.soar_actions.unshift(soarRecord);
        if (sess.soar_actions.length > 200) sess.soar_actions.length = 200;
        if (soarRecord.simulated_block_lease) {
          sess.demo_leases.unshift({
            ...soarRecord.simulated_block_lease,
            session_id: sessionId,
            flow_id: raw.flow_id,
            created_at: soarRecord.timestamp
          });
          if (sess.demo_leases.length > 100) sess.demo_leases.length = 100;
        }
        sess.counters.soar_actions_simulated += 1;
      }

      const enriched = {
        flow_id: raw.flow_id,
        session_id: sessionId,
        event_source: 'demo_simulator',
        demo_simulated: true,
        timestamp: raw.timestamp || new Date().toISOString(),
        src_ip: raw.src_ip,
        dst_ip: raw.dst_ip,
        src_port: raw.src_port,
        dst_port: raw.dst_port,
        protocol: raw.protocol,
        packets: raw.packets,
        bytes: raw.bytes,
        duration: raw.duration,
        attack_type: raw.attack_type,
        canonical_category: canonicalCat,
        ground_truth: raw.ground_truth || null,
        ml_evaluated: mlEvaluated,
        detection: {
          rf_prediction: rf.prediction ?? null,
          rf_probability: typeof rf.attack_probability === 'number' ? rf.attack_probability : null,
          if_anomaly_score: typeof isof.raw_decision_score === 'number' ? isof.raw_decision_score : null,
          ae_reconstruction_error: typeof ae.reconstruction_error === 'number' ? ae.reconstruction_error : null,
          tri_model_decision: finalDecision,
          is_anomaly: isAnomaly,
          confidence: typeof fusion.fused_anomaly_score === 'number' ? fusion.fused_anomaly_score : null,
          model_disagreement: modelDisagreement,
          final_alert_status: isAnomaly ? (recommendedAction === 'block' ? 'DEMO_BLOCK_ALERT' : 'DEMO_ALERT') : 'NORMAL'
        },
        incident_id: incidentId,
        mitre_techniques: mitre,
        soar: soarRecord,
        xai: xaiTrigger
      };

      sess.events.unshift(enriched);
      if (sess.events.length > this.maxEventsPerSession) sess.events.length = this.maxEventsPerSession;

      sess.counters.events_generated += 1;
      if (raw.ground_truth?.is_malicious) sess.counters.malicious_events += 1;
      else sess.counters.benign_events += 1;

      sess.category_counts[canonicalCat] = (sess.category_counts[canonicalCat] || 0) + 1;
      const proto = String(raw.protocol || 'TCP').toUpperCase();
      sess.protocol_counts[proto] = (sess.protocol_counts[proto] || 0) + 1;

      newlyIngested.push(enriched);
    }
    return newlyIngested;
  }

  getSession(sessionId) {
    const id = sessionId || this.activeSessionId;
    return id ? this.sessions.get(id) || null : null;
  }

  getSessionEvents(sessionId = null, limit = 100) {
    const sess = this.getSession(sessionId);
    if (!sess) return [];
    return sess.events.slice(0, Math.max(1, Math.min(Number(limit) || 100, this.maxEventsPerSession)));
  }

  getSessionSnapshot(sessionId = null) {
    const sess = this.getSession(sessionId);
    if (!sess) {
      return {
        session_id: null,
        event_source: 'demo_simulator',
        state: 'Idle',
        counters: {
          events_generated: 0,
          benign_events: 0,
          malicious_events: 0,
          detected_threats: 0,
          incidents_generated: 0,
          soar_actions_simulated: 0,
          xai_explanations_triggered: 0
        },
        category_counts: {},
        protocol_counts: {},
        incidents: [],
        soar_actions: [],
        demo_leases: [],
        xai_triggers: [],
        recent_events: []
      };
    }
    return {
      session_id: sess.session_id,
      event_source: 'demo_simulator',
      state: sess.state,
      scenario: sess.scenario,
      mode: sess.mode,
      speed: sess.speed,
      started_at: sess.started_at,
      ended_at: sess.ended_at,
      counters: { ...sess.counters },
      category_counts: { ...sess.category_counts },
      protocol_counts: { ...sess.protocol_counts },
      incidents: Array.from(sess.incidents.values()),
      soar_actions: sess.soar_actions.slice(0, 50),
      demo_leases: sess.demo_leases.slice(0, 50),
      xai_triggers: sess.xai_triggers.slice(0, 50),
      recent_events: sess.events.slice(0, 50)
    };
  }

  getSessionSummary(sessionId = null, simSummary = null) {
    const sess = this.getSession(sessionId);
    if (!sess && !simSummary) return null;
    const events = sess ? sess.events : [];
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    let totalEvaluated = 0;
    const categoryBreakdown = {};

    for (const ev of events) {
      const cat = ev.canonical_category || 'unknown';
      if (!categoryBreakdown[cat]) {
        categoryBreakdown[cat] = { total: 0, evaluated: 0, unprocessed: 0, detected: 0, benign_pred: 0 };
      }
      categoryBreakdown[cat].total += 1;

      const isEvaluated = ev.ml_evaluated === true;
      if (!isEvaluated) {
        categoryBreakdown[cat].unprocessed += 1;
        continue;
      }

      totalEvaluated += 1;
      categoryBreakdown[cat].evaluated += 1;
      if (ev.detection?.is_anomaly) categoryBreakdown[cat].detected += 1;
      else categoryBreakdown[cat].benign_pred += 1;

      if (ev.ground_truth && typeof ev.ground_truth.is_malicious === 'boolean') {
        const gtMal = ev.ground_truth.is_malicious;
        const predMal = Boolean(ev.detection?.is_anomaly);
        if (gtMal && predMal) tp++;
        else if (!gtMal && predMal) fp++;
        else if (!gtMal && !predMal) tn++;
        else if (gtMal && !predMal) fn++;
      }
    }

    const totalReceived = events.length;
    const totalGenerated = Math.max(
      simSummary?.total_events_generated ?? 0,
      sess?.authoritative_total_generated ?? 0,
      totalReceived
    );
    const totalUnprocessed = Math.max(0, totalGenerated - totalEvaluated);
    const duplicateEvents = sess?.duplicate_events ?? 0;
    const evaluationComplete = totalUnprocessed === 0;
    const evaluationStatus = evaluationComplete ? 'complete' : 'provisional';

    const precision = (tp + fp) > 0 ? Number((tp / (tp + fp)).toFixed(4)) : null;
    const recall = (tp + fn) > 0 ? Number((tp / (tp + fn)).toFixed(4)) : null;
    const f1Score = (precision !== null && recall !== null && (precision + recall) > 0)
      ? Number(((2 * precision * recall) / (precision + recall)).toFixed(4))
      : null;

    return {
      synthetic_demo_evaluation: true,
      note: evaluationComplete
        ? 'Synthetic demo-session evaluation only; not a real-world security performance result.'
        : 'PROVISIONAL / INCOMPLETE evaluation: some generated events were not evaluated by ML.',
      evaluation_status: evaluationStatus,
      evaluation_complete: evaluationComplete,
      session_id: sess?.session_id || simSummary?.session_id || null,
      event_source: 'demo_simulator',
      state: simSummary?.state || sess?.state || 'Idle',
      scenario: simSummary?.scenario || sess?.scenario || 'mixed',
      mode: simSummary?.mode || sess?.mode || 'mixed',
      started_at: simSummary?.started_at || sess?.started_at || null,
      ended_at: simSummary?.ended_at || sess?.ended_at || null,
      total_generated: totalGenerated,
      total_received: totalReceived,
      total_evaluated: totalEvaluated,
      total_unprocessed: totalUnprocessed,
      duplicate_events: duplicateEvents,
      total_events_generated: totalGenerated,
      normal_events: simSummary?.benign_events ?? sess?.counters.benign_events ?? 0,
      malicious_events: simSummary?.malicious_events ?? sess?.counters.malicious_events ?? 0,
      events_detected: sess?.counters.detected_threats ?? (tp + fp),
      true_positives: tp,
      false_positives: fp,
      true_negatives: tn,
      false_negatives: fn,
      precision,
      recall,
      f1_score: f1Score,
      incidents_created: sess ? sess.incidents.size : 0,
      alerts_correlated: sess ? Array.from(sess.incidents.values()).reduce((s, i) => s + i.correlated_events, 0) : 0,
      soar_actions_simulated: sess?.counters.soar_actions_simulated ?? 0,
      xai_explanations_triggered: sess?.counters.xai_explanations_triggered ?? 0,
      category_breakdown: Object.keys(categoryBreakdown).length > 0 ? categoryBreakdown : (simSummary?.category_breakdown || {})
    };
  }

  clearSession(sessionId = null) {
    if (sessionId) {
      const sess = this.sessions.get(sessionId);
      if (sess) {
        for (const ev of sess.events) this.seenFlowIds.delete(ev.flow_id);
        this.sessions.delete(sessionId);
      }
      if (this.activeSessionId === sessionId) this.activeSessionId = null;
      return;
    }
    this.sessions.clear();
    this.seenFlowIds.clear();
    this.activeSessionId = null;
  }

  static filterRecordsBySource(records = [], sourceMode = 'live') {
    const mode = String(sourceMode || 'live').toLowerCase();
    if (mode === 'all') return records;
    if (mode === 'demo') return records.filter((r) => r && r.event_source === 'demo_simulator');
    return records.filter((r) => !r || r.event_source !== 'demo_simulator');
  }
}

module.exports = {
  DemoSimulatorStore,
  computeExtendedFeatures
};
