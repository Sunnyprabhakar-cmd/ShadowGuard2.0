/**
 * Shadow Guard 2.0 - Event Correlation Service (:8005)
 *
 * Subscribes to `q.correlation.events` on RabbitMQ (`sg.events` topic exchange),
 * correlates multi-source security telemetry using an in-memory sliding time-window index,
 * groups related alerts into structured Security Incidents, and publishes `incident.created`
 * and `incident.updated` events for Attack Chain Reconstruction and SOAR response.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const { EventCorrelationEngine } = require('./engine/correlationEngine');
const { createRabbitMQClient } = require('./lib/rabbitmq');

const PORT = Number(process.env.PORT || 8005);
const SERVICE_NAME = 'event-correlation-service';
const DB_SERVICE_URL = process.env.DATABASE_SERVICE_URL || 'http://threat-log-database-service:3006';
const ATTACK_CHAIN_URL = process.env.ATTACK_CHAIN_URL || 'http://attack-chain-service:8006';

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

const correlationEngine = new EventCorrelationEngine();
const mqClient = createRabbitMQClient({ serviceName: SERVICE_NAME });

async function notifyDownstreamIncident(incident, action) {
    // 1. Publish to RabbitMQ
    const routingKey = action === 'CREATED' ? 'incident.created' : 'incident.updated';
    await mqClient.publish(routingKey, incident);

    // 2. Best-effort HTTP sync to DB service & Attack Chain service
    if (typeof fetch === 'function') {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2500);
        try {
            await Promise.allSettled([
                fetch(`${DB_SERVICE_URL}/api/v2/incidents`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(incident),
                    signal: controller.signal
                }),
                fetch(`${ATTACK_CHAIN_URL}/api/chains/reconstruct`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ incident }),
                    signal: controller.signal
                })
            ]);
        } catch (_) {
            // Non-fatal in standalone test mode
        } finally {
            clearTimeout(timer);
        }
    }
}

// Health probes
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: SERVICE_NAME,
        version: '2.0.0',
        correlation_stats: correlationEngine.getStats(),
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
        active_windows: correlationEngine.windowIndex.size
    });
});

// List all correlated incidents
app.get('/api/incidents', (req, res) => {
    const severity = req.query.severity;
    const status = req.query.status;
    let list = correlationEngine.getAllIncidents();
    if (severity) {
        list = list.filter(i => i.severity === String(severity).toUpperCase());
    }
    if (status) {
        list = list.filter(i => i.status === String(status).toUpperCase());
    }
    res.json({
        status: 'success',
        count: list.length,
        stats: correlationEngine.getStats(),
        data: list
    });
});

// Get single incident by ID
app.get('/api/incidents/:id', (req, res) => {
    const inc = correlationEngine.getIncident(req.params.id);
    if (!inc) {
        return res.status(404).json({ status: 'error', message: `Incident ${req.params.id} not found` });
    }
    res.json({ status: 'success', data: inc });
});

// Update incident status (e.g. OPEN -> INVESTIGATING -> CONTAINED -> CLOSED)
app.patch('/api/incidents/:id/status', (req, res) => {
    const inc = correlationEngine.getIncident(req.params.id);
    if (!inc) {
        return res.status(404).json({ status: 'error', message: `Incident ${req.params.id} not found` });
    }
    const { status } = req.body || {};
    if (!status) {
        return res.status(400).json({ status: 'error', message: 'status is required' });
    }
    inc.status = String(status).toUpperCase();
    inc.updated_at = new Date().toISOString();
    res.json({ status: 'success', data: inc });
});

// Correlate single or batch events via HTTP
app.post('/api/correlate', async (req, res) => {
    try {
        const { event, events, context } = req.body || {};
        if (Array.isArray(events)) {
            const results = [];
            for (const ev of events) {
                const r = correlationEngine.correlateEvent(ev, context || {});
                if (r.correlated && r.incident) {
                    await notifyDownstreamIncident(r.incident, r.incident_action);
                }
                results.push(r);
            }
            return res.json({ status: 'success', count: results.length, results });
        }

        const targetEvent = event || req.body;
        const result = correlationEngine.correlateEvent(targetEvent, context || {});
        if (result.correlated && result.incident) {
            await notifyDownstreamIncident(result.incident, result.incident_action);
        }
        res.json({ status: 'success', data: result });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

async function startService() {
    try {
        await mqClient.connect();
        await mqClient.consume('q.correlation.events', async (event) => {
            const result = correlationEngine.correlateEvent(event);
            if (result.correlated && result.incident) {
                await notifyDownstreamIncident(result.incident, result.incident_action);
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

module.exports = { app, correlationEngine };
