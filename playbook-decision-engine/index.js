/**
 * Shadow Guard 2.0 - Playbook Decision Engine (:3003)
 *
 * Preserves 100% backward compatibility with Shadow Guard 1.0 (`POST /decide`, `POST /reload-rules`)
 * while adding the Shadow Guard 2.0 Multi-Condition SOAR Playbook Engine (`POST /api/soar/evaluate`,
 * `GET /api/soar/playbooks`, `PATCH /api/soar/playbooks/:id`, `GET /api/soar/decisions`)
 * and RabbitMQ event bus integration.
 */

'use strict';

let express = null;
try {
    express = require('express');
} catch (_) {
    express = function createFallbackApp() {
        const routes = { GET: {}, POST: {}, PATCH: {} };
        return {
            use() {},
            get(p, fn) { routes.GET[p] = fn; },
            post(p, fn) { routes.POST[p] = fn; },
            patch(p, fn) { routes.PATCH[p] = fn; },
            listen() {},
            handle(req, res, next) {
                const fn = (routes[req.method] || {})[req.path || req.url];
                if (fn) {
                    Promise.resolve(fn(req, res)).catch(next);
                } else if (next) {
                    next(new Error(`No route for ${req.method} ${req.url}`));
                }
            }
        };
    };
    express.json = () => (req, res, next) => next && next();
}
const fs = require('fs');
const path = require('path');
const { SoarPlaybookEngine } = require('./engine/soarPlaybookEngine');
const rmqModule = require('./lib/rabbitmq');
const createRabbitMQClient = typeof rmqModule === 'function'
    ? (opts) => new rmqModule(opts)
    : rmqModule.createRabbitMQClient;

let axios = null;
try {
    axios = require('axios');
} catch (_) {
    // Fallback to native fetch when running on host without node_modules
}

const app = express();
const port = Number(process.env.PORT || 3000);
const SERVICE_NAME = 'playbook-decision-engine';

app.use(express.json({ limit: '2mb' }));

const soarEngine = new SoarPlaybookEngine();
const mqClient = createRabbitMQClient({ serviceName: SERVICE_NAME });

const rulesPath = process.env.PLAYBOOK_RULES_PATH || path.join(__dirname, 'rules', 'playbook-rules.json');
let playbookRules = {
    benignPrediction: 0,
    confidenceThresholds: {
        low: 0.6,
        high: 0.85
    },
    actions: {
        benign: 'monitor',
        lowConfidenceThreat: 'alert',
        highConfidenceThreat: 'block'
    }
};

const highRiskAttackTypes = new Set([
    'ddos',
    'data_exfiltration',
    'malware_command_control',
    'malware_c2',
    'multi_vector',
    'zero_day',
    'zero_day_attack'
]);

const mediumRiskAttackTypes = new Set([
    'port_scan',
    'brute_force'
]);

function normalizeAttackType(value) {
    return String(value || 'unknown').trim().toLowerCase().replace(/\s+/g, '_');
}

function loadRules() {
    try {
        const raw = fs.readFileSync(rulesPath, 'utf8');
        const parsed = JSON.parse(raw);
        playbookRules = {
            ...playbookRules,
            ...parsed,
            confidenceThresholds: {
                ...playbookRules.confidenceThresholds,
                ...(parsed.confidenceThresholds || {})
            },
            actions: {
                ...playbookRules.actions,
                ...(parsed.actions || {})
            }
        };
        console.log('Playbook rules loaded from file');
    } catch (error) {
        console.warn('Using default playbook rules. Reason:', error.message);
    }
}

function computeThreatProbability(prediction, probabilities) {
    if (!Array.isArray(probabilities) || probabilities.length === 0) {
        return 0;
    }
    const benignIdx = Number(playbookRules.benignPrediction || 0);
    if (prediction === benignIdx && probabilities.length >= 2 && benignIdx >= 0 && benignIdx < probabilities.length) {
        return Math.max(0, Math.min(1, 1.0 - Number(probabilities[benignIdx] || 0)));
    }
    return Math.max(...probabilities.map(Number));
}

function decideAction(prediction, probabilities) {
    const benignPrediction = playbookRules.benignPrediction;
    const isBenign = prediction === benignPrediction;
    const threatProbability = computeThreatProbability(prediction, probabilities);

    if (isBenign) {
        return {
            action: playbookRules.actions.benign,
            reason: 'Benign class predicted'
        };
    }

    if (threatProbability >= playbookRules.confidenceThresholds.high) {
        return {
            action: playbookRules.actions.highConfidenceThreat,
            reason: `Threat confidence high (${threatProbability.toFixed(3)})`
        };
    }

    if (threatProbability >= playbookRules.confidenceThresholds.low) {
        return {
            action: playbookRules.actions.lowConfidenceThreat,
            reason: `Threat confidence medium (${threatProbability.toFixed(3)})`
        };
    }

    return {
        action: 'manual-review',
        reason: `Threat confidence below low threshold (${threatProbability.toFixed(3)})`
    };
}

function deriveRiskMetadata(context = {}, probabilities = [], prediction = null) {
    const attackType = normalizeAttackType(
        context.attack_type || context.attackType || context.type || 'unknown'
    );
    const maxProbability = computeThreatProbability(prediction, probabilities);
    const packets = Number(context.packets || 0);
    const bytesSent = Number(context.bytes_sent || context.bytesSent || 0);
    const flowType = String(context.flow_type || '').toLowerCase();
    const anomalyBoost = flowType === 'anomaly' ? 0.15 : 0;
    const volumetricBoost = packets >= 5000 || bytesSent >= 5000000 ? 0.1 : 0;

    let severity = 'low';
    let recommendedAction = playbookRules.actions.benign;
    let riskScore = Math.max(maxProbability, 0);
    let reason = `Model confidence ${maxProbability.toFixed(3)}`;

    if (attackType === 'normal_traffic' || attackType === 'benign') {
        severity = 'low';
        recommendedAction = playbookRules.actions.benign;
        riskScore = 0.1;
        reason = 'Benign traffic pattern';
    } else if (attackType === 'zero_day' || attackType === 'zero_day_attack') {
        severity = 'critical';
        recommendedAction = playbookRules.actions.highConfidenceThreat;
        riskScore = Math.max(riskScore, 0.99);
        reason = 'Zero-day scenario detected';
    } else if (highRiskAttackTypes.has(attackType)) {
        severity = 'high';
        recommendedAction = playbookRules.actions.highConfidenceThreat;
        riskScore = Math.max(riskScore, 0.9 + anomalyBoost + volumetricBoost);
        reason = `High-risk attack pattern detected (${attackType})`;
    } else if (mediumRiskAttackTypes.has(attackType)) {
        severity = 'medium';
        recommendedAction = playbookRules.actions.lowConfidenceThreat;
        riskScore = Math.max(riskScore, 0.7 + anomalyBoost);
        reason = `Medium-risk attack pattern detected (${attackType})`;
    } else if (flowType === 'anomaly' && maxProbability >= playbookRules.confidenceThresholds.high) {
        severity = 'high';
        recommendedAction = playbookRules.actions.highConfidenceThreat;
        riskScore = Math.max(riskScore, 0.9);
        reason = `Anomalous flow with high confidence (${maxProbability.toFixed(3)})`;
    } else if (flowType === 'anomaly' && maxProbability >= playbookRules.confidenceThresholds.low) {
        severity = 'medium';
        recommendedAction = playbookRules.actions.lowConfidenceThreat;
        riskScore = Math.max(riskScore, 0.7);
        reason = `Anomalous flow with medium confidence (${maxProbability.toFixed(3)})`;
    } else if (maxProbability >= playbookRules.confidenceThresholds.high) {
        severity = 'high';
        recommendedAction = playbookRules.actions.highConfidenceThreat;
        riskScore = Math.max(riskScore, 0.86);
        reason = `Threat confidence high (${maxProbability.toFixed(3)})`;
    } else if (maxProbability >= playbookRules.confidenceThresholds.low) {
        severity = 'medium';
        recommendedAction = playbookRules.actions.lowConfidenceThreat;
        riskScore = Math.max(riskScore, 0.65);
        reason = `Threat confidence medium (${maxProbability.toFixed(3)})`;
    }

    return {
        attackType,
        severity,
        riskScore: Math.min(riskScore, 0.99),
        recommendedAction,
        reason
    };
}

async function postJsonSafe(url, payload) {
    if (axios) {
        return axios.post(url, payload, { timeout: 3000 });
    }
    if (typeof fetch === 'function') {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        try {
            await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: controller.signal
            });
        } finally {
            clearTimeout(timer);
        }
    }
}

loadRules();

// ============================================================================
// LEGACY SHADOW GUARD 1.0 ENDPOINTS (100% Backward Compatible)
// ============================================================================
app.post('/decide', async (req, res) => {
    const { prediction, probabilities, sourceIp, context = {} } = req.body || {};

    try {
        const trafficContext = context || {};
        const isDemoEvent = trafficContext.event_source === 'demo_simulator';
        const normalizedSourceIp = sourceIp || trafficContext.src_ip || trafficContext.sourceIp || null;
        const attackType = trafficContext.attack_type || trafficContext.attackType || trafficContext.type || `class_${prediction}`;
        const triFusion = trafficContext.tri_model_fusion || null;

        // Guardrail 1: If Tri-Model Fusion reports degraded status, never silently classify as normal
        // and never automatically block an IP.
        if (triFusion && triFusion.fusion_status === 'degraded') {
            const degradedDecision = {
                status: 'degraded',
                action: 'manual-review',
                demo_simulated: isDemoEvent,
                soar_plan: {
                    playbook_id: 'PB-DEGRADED-FALLBACK',
                    actions: ['REQUIRE_ANALYST_APPROVAL'],
                    auto_block_permitted: false,
                    demo_simulated: isDemoEvent
                },
                details: {
                    status: 'degraded',
                    prediction: null,
                    probabilities: probabilities || [],
                    confidence: null,
                    severity: 'degraded',
                    flow_id: trafficContext.flow_id || null,
                    event_source: trafficContext.event_source || null,
                    session_id: trafficContext.session_id || null,
                    demo_simulated: isDemoEvent,
                    sourceIp: normalizedSourceIp,
                    ip: normalizedSourceIp,
                    src_ip: normalizedSourceIp,
                    dst_ip: trafficContext.dst_ip || trafficContext.destinationIp || null,
                    src_port: trafficContext.src_port || null,
                    dst_port: trafficContext.dst_port || null,
                    protocol: trafficContext.protocol || null,
                    attack_type: attackType,
                    reason: 'Model or feature input degraded; routed to manual review',
                    tri_model_fusion: triFusion,
                    autoencoder: trafficContext.autoencoder || null,
                    decidedAt: new Date().toISOString()
                }
            };
            return res.json(degradedDecision);
        }

        const risk = deriveRiskMetadata(trafficContext, probabilities, prediction);
        const modelDecision = decideAction(prediction, probabilities);
        const shouldTrustBenignPrediction = prediction === playbookRules.benignPrediction
            && (risk.attackType === 'normal_traffic' || risk.attackType === 'unknown')
            && String(trafficContext.flow_type || '').toLowerCase() !== 'anomaly'
            && !(triFusion && triFusion.is_anomaly === true);

        let selectedAction = shouldTrustBenignPrediction
            ? modelDecision.action
            : risk.recommendedAction;
        let selectedReason = shouldTrustBenignPrediction
            ? modelDecision.reason
            : risk.reason;
        let selectedSeverity = shouldTrustBenignPrediction ? 'low' : risk.severity;
        let selectedConfidence = shouldTrustBenignPrediction ? 0.1 : risk.riskScore;

        // Guardrail 2: Honor Tri-Model Fusion decision & enforce non-auto-block on Autoencoder-only anomalies
        if (triFusion) {
            if (triFusion.is_anomaly === true && selectedAction === 'monitor') {
                selectedAction = triFusion.recommended_action || 'alert';
                selectedSeverity = triFusion.severity || 'medium';
                selectedConfidence = Math.max(selectedConfidence, Number(triFusion.fused_anomaly_score || 0.65));
                selectedReason = `Tri-model fusion (${triFusion.decision_rule})`;
            }
            if (triFusion.auto_block_permitted === false && selectedAction === 'block') {
                selectedAction = triFusion.recommended_action && triFusion.recommended_action !== 'block'
                    ? triFusion.recommended_action
                    : 'alert';
                selectedReason = `${selectedReason} [Auto-block prevented by guardrail: ${triFusion.decision_rule}]`;
            }
        }

        // Also evaluate through SOAR 2.0 Playbook Engine for enriched plan
        const soarPlan = soarEngine.evaluateContext({
            source_ip: normalizedSourceIp,
            classification_confidence: selectedConfidence,
            incident_severity: selectedSeverity,
            attacker_risk_score: Math.round(selectedConfidence * 100)
        });

        if (triFusion && triFusion.auto_block_permitted === false && Array.isArray(soarPlan.actions)) {
            soarPlan.actions = soarPlan.actions.filter(a => {
                if (typeof a === 'string') return !a.startsWith('BLOCK_IP');
                if (a && typeof a === 'object' && String(a.type || '').startsWith('BLOCK_IP')) return false;
                return true;
            });
            soarPlan.auto_block_permitted = false;
            if (soarPlan.actions.length === 0) {
                soarPlan.actions.push({ type: 'REQUIRE_ANALYST_APPROVAL', reason: triFusion.decision_rule });
            }
        }

        if (isDemoEvent) {
            soarPlan.demo_simulated = true;
            soarPlan.auto_block_permitted = false;
        }

        const decision = {
            action: selectedAction,
            demo_simulated: isDemoEvent,
            action_label: isDemoEvent ? `DEMO_SIMULATED_${String(selectedAction).toUpperCase()}` : selectedAction,
            soar_plan: soarPlan,
            details: {
                prediction,
                probabilities,
                confidence: selectedConfidence,
                severity: selectedSeverity,
                flow_id: trafficContext.flow_id || null,
                event_source: trafficContext.event_source || null,
                session_id: trafficContext.session_id || null,
                demo_simulated: isDemoEvent,
                sourceIp: normalizedSourceIp,
                ip: normalizedSourceIp,
                src_ip: normalizedSourceIp,
                dst_ip: trafficContext.dst_ip || trafficContext.destinationIp || null,
                src_port: trafficContext.src_port || null,
                dst_port: trafficContext.dst_port || null,
                protocol: trafficContext.protocol || null,
                attack_type: attackType,
                packets: trafficContext.packets || 0,
                bytes_sent: trafficContext.bytes_sent || trafficContext.bytesSent || 0,
                duration: trafficContext.duration || 0,
                flow_type: trafficContext.flow_type || null,
                reason: isDemoEvent ? `[DEMO] ${selectedReason}` : selectedReason,
                playbook_id: soarPlan.playbook_id,
                tri_model_fusion: triFusion,
                autoencoder: trafficContext.autoencoder || null,
                decidedAt: new Date().toISOString()
            }
        };

        try {
            await postJsonSafe('http://alert-notification-service:3000/alert', decision);
        } catch (err) {
            console.warn('Alert notification unreachable in standalone mode:', err.message);
        }

        await mqClient.publish('soar.decision.created', decision);
        res.json(decision);
    } catch (error) {
        console.error('Error in decision engine:', error);
        res.status(500).json({ error: 'Failed to make decision' });
    }
});

app.post('/reload-rules', (req, res) => {
    loadRules();
    res.json({ message: 'Playbook rules reloaded' });
});

// ============================================================================
// SHADOW GUARD 2.0 SOAR PLAYBOOK ENDPOINTS
// ============================================================================
app.post('/api/soar/evaluate', async (req, res) => {
    try {
        const plan = soarEngine.evaluateContext(req.body || {});
        await mqClient.publish('soar.decision.created', plan);
        res.json({ status: 'success', data: plan });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

app.get('/api/soar/playbooks', (req, res) => {
    res.json({
        status: 'success',
        count: soarEngine.playbooks.size,
        data: soarEngine.listPlaybooks()
    });
});

app.patch('/api/soar/playbooks/:id', (req, res) => {
    try {
        const updated = soarEngine.updatePlaybook(req.params.id, req.body || {});
        res.json({ status: 'success', data: updated });
    } catch (err) {
        res.status(404).json({ status: 'error', message: err.message });
    }
});

app.get('/api/soar/decisions', (req, res) => {
    res.json({
        status: 'success',
        count: soarEngine.decisionHistory.length,
        data: soarEngine.decisionHistory.slice(0, 100)
    });
});

// Health endpoints
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: SERVICE_NAME,
        version: '2.0.0',
        playbooks_loaded: soarEngine.playbooks.size
    });
});

app.get('/health/live', (req, res) => {
    res.status(200).json({ status: 'alive', service: SERVICE_NAME });
});

app.get('/health/ready', (req, res) => {
    res.status(200).json({
        status: 'ready',
        service: SERVICE_NAME,
        playbooks_loaded: soarEngine.playbooks.size
    });
});

async function startService() {
    try {
        await mqClient.connect();
        await mqClient.consume('q.soar.incidents', async (incident) => {
            if (incident && incident.source_ip) {
                const plan = soarEngine.evaluateContext({
                    source_ip: incident.source_ip,
                    incident_severity: incident.severity,
                    classification_confidence: incident.confidence,
                    attacker_risk_score: incident.severity === 'CRITICAL' ? 92 : 75,
                    honeypot_interaction_count: (incident.sources_involved || []).some(s => /honeypot|deception/i.test(s)) ? 1 : 0
                });
                await mqClient.publish('soar.decision.created', plan);
            }
        });
    } catch (err) {
        console.warn(`[${SERVICE_NAME}] Running in HTTP-first mode (RabbitMQ unavailable: ${err.message})`);
    }

    app.listen(port, () => {
        console.log(`Playbook Decision Engine listening on port ${port}`);
    });
}

if (require.main === module) {
    startService();
}

module.exports = { app, soarEngine };
