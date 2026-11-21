/**
 * Shadow Guard 2.0 - Threat Intelligence Service (:3012)
 *
 * Enriches security indicators (IP addresses, domains, SHA-256 hashes)
 * with multi-provider reputation scores, ASN/Geo metadata, and confidence levels.
 * Also subscribes to RabbitMQ security events to perform asynchronous indicator enrichment.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const { ThreatIntelEngine } = require('./providers/intelProviders');
const { createRabbitMQClient } = require('./lib/rabbitmq');

const PORT = Number(process.env.PORT || 3012);
const SERVICE_NAME = 'threat-intelligence-service';

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

const intelEngine = new ThreatIntelEngine();
const mqClient = createRabbitMQClient({ serviceName: SERVICE_NAME });

// Health probes
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: SERVICE_NAME,
        version: '2.0.0',
        rabbitmq: mqClient.getStatus(),
        intel_stats: intelEngine.getStats(),
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
        cache_entries: intelEngine.cache.size
    });
});

// Lookup IP reputation
app.get('/api/intel/ip/:ip', async (req, res) => {
    try {
        const result = await intelEngine.lookupIp(req.params.ip, {
            honeypot_hit: req.query.honeypot === 'true'
        });
        res.json({ status: 'success', data: result });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// Lookup Domain reputation
app.get('/api/intel/domain/:domain', async (req, res) => {
    try {
        const result = await intelEngine.lookupDomain(req.params.domain);
        res.json({ status: 'success', data: result });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// Lookup SHA-256 Hash reputation
app.get('/api/intel/hash/:sha256', async (req, res) => {
    try {
        const result = await intelEngine.lookupHash(req.params.sha256);
        res.json({ status: 'success', data: result });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// Unified batch/single indicator lookup
app.post('/api/intel/lookup', async (req, res) => {
    try {
        const { indicator_type, indicator_value, context } = req.body || {};
        if (!indicator_type || !indicator_value) {
            return res.status(400).json({
                status: 'error',
                message: 'indicator_type (ip|domain|sha256) and indicator_value are required'
            });
        }
        let result;
        if (indicator_type === 'ip') {
            result = await intelEngine.lookupIp(indicator_value, context || {});
        } else if (indicator_type === 'domain') {
            result = await intelEngine.lookupDomain(indicator_value);
        } else if (indicator_type === 'sha256' || indicator_type === 'hash') {
            result = await intelEngine.lookupHash(indicator_value);
        } else {
            return res.status(400).json({ status: 'error', message: `Unsupported indicator_type: ${indicator_type}` });
        }
        res.json({ status: 'success', data: result });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// Service statistics & lookup history
app.get('/api/intel/stats', (req, res) => {
    res.json({
        status: 'success',
        data: intelEngine.getStats()
    });
});

async function startService() {
    try {
        await mqClient.connect();
        await mqClient.consume('q.intel.enrichment', async (event) => {
            if (event && event.source_ip) {
                const isHoneypot = event.source_category === 'deception';
                const intel = await intelEngine.lookupIp(event.source_ip, { honeypot_hit: isHoneypot });
                if (intel.is_malicious) {
                    await mqClient.publish('intel.enriched.ip', {
                        event_id: event.event_id,
                        source_ip: event.source_ip,
                        intel
                    });
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

module.exports = { app, intelEngine };
