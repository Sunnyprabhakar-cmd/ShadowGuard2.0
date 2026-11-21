/**
 * Shadow Guard 2.0 - Dynamic Deception Manager Service (:3013)
 *
 * Subscribes to security incidents and attacker profile updates via RabbitMQ,
 * executes policy-driven adaptive deception directives (DEC-01 .. DEC-04),
 * synchronizes configuration updates with `honeypot-manager-service` (:3010),
 * and exposes operator override, rollback, and audit endpoints.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const { AdaptiveDeceptionEngine } = require('./engine/adaptiveDeceptionEngine');
const { createRabbitMQClient } = require('./lib/rabbitmq');

const PORT = Number(process.env.PORT || 3013);
const SERVICE_NAME = 'deception-manager-service';
const HONEYPOT_MANAGER_URL = process.env.HONEYPOT_MANAGER_URL || 'http://honeypot-manager-service:3010';

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

async function syncWithHoneypotManager(directive) {
    if (typeof fetch !== 'function') return;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
        await fetch(`${HONEYPOT_MANAGER_URL}/api/honeypots/${encodeURIComponent(directive.target_honeypot_id)}/config`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                adaptive_directive_id: directive.directive_id,
                action_type: directive.action_type,
                parameters: directive.parameters
            }),
            signal: controller.signal
        });
    } catch (_) {
        // Non-fatal in standalone mode
    } finally {
        clearTimeout(timer);
    }
}

const deceptionEngine = new AdaptiveDeceptionEngine({
    honeypotManagerCallback: syncWithHoneypotManager
});
const mqClient = createRabbitMQClient({ serviceName: SERVICE_NAME });

// Health probes
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: SERVICE_NAME,
        version: '2.0.0',
        auto_adapt_enabled: deceptionEngine.autoAdaptEnabled,
        active_directives: Array.from(deceptionEngine.activeDirectives.values()).filter(d => d.status === 'ACTIVE').length,
        rabbitmq: mqClient.getStatus(),
        timestamp: new Date().toISOString()
    });
});

app.get('/health/live', (req, res) => {
    res.status(200).json({ status: 'alive', service: SERVICE_NAME });
});

app.get('/health/ready', (req, res) => {
    res.status(200).json({
        status: 'ready',
        service: SERVICE_NAME,
        policies_loaded: deceptionEngine.policies.size
    });
});

// Get full adaptive deception status, policies, states & audit log
app.get('/api/deception/status', (req, res) => {
    res.json({
        status: 'success',
        data: deceptionEngine.getStatusSummary()
    });
});

// Evaluate telemetry and trigger matching adaptive deception policies
app.post('/api/deception/evaluate', async (req, res) => {
    try {
        const result = await deceptionEngine.evaluateAndAdapt(req.body || {});
        if (result.adapted) {
            for (const dir of result.directives) {
                await mqClient.publish('deception.directive.applied', dir);
            }
        }
        res.json({ status: 'success', data: result });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// Manual operator directive application
app.post('/api/deception/directives', async (req, res) => {
    try {
        const directive = await deceptionEngine.applyDirective(req.body || {});
        await mqClient.publish('deception.directive.applied', directive);
        res.status(201).json({ status: 'success', data: directive });
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

// Roll back a deception directive
app.post('/api/deception/directives/:id/rollback', async (req, res) => {
    try {
        const { operator, reason } = req.body || {};
        const rolledBack = deceptionEngine.rollbackDirective(req.params.id, operator, reason);
        await mqClient.publish('deception.directive.rolledback', rolledBack);
        res.json({ status: 'success', data: rolledBack });
    } catch (err) {
        res.status(404).json({ status: 'error', message: err.message });
    }
});

// Operator override: pause or resume automatic adaptation
app.post('/api/deception/override', (req, res) => {
    const { auto_adapt_enabled, operator } = req.body || {};
    const state = deceptionEngine.setAutoAdaptMode(auto_adapt_enabled, operator);
    res.json({ status: 'success', data: state });
});

// Audit log endpoint
app.get('/api/deception/audit', (req, res) => {
    res.json({
        status: 'success',
        count: deceptionEngine.auditLog.length,
        data: deceptionEngine.auditLog
    });
});

async function startService() {
    try {
        await mqClient.connect();
        await mqClient.consume('q.deception.adapt', async (payload) => {
            if (payload) {
                const res = await deceptionEngine.evaluateAndAdapt(payload);
                if (res.adapted) {
                    for (const dir of res.directives) {
                        await mqClient.publish('deception.directive.applied', dir);
                    }
                }
            }
        });
    } catch (err) {
        console.warn(`[${SERVICE_NAME}] Running in HTTP-first mode (RabbitMQ unavailable: ${err.message})`);
    }

    app.listen(PORT, () => {
        console.log(`[${SERVICE_NAME}] Listening on port ${PORT}`);
    });
}

if (require.main === module) {
    startService();
}

module.exports = { app, deceptionEngine };
