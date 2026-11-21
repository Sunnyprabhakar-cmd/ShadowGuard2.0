/**
 * Shadow Guard 2.0 - Attacker Behaviour Profiling Service (:8004)
 *
 * Subscribes to normalized network, NIDS, and honeypot security events via RabbitMQ,
 * maintains longitudinal Attacker Profiles, computes explainable risk scores (0-100),
 * and exposes REST endpoints for the SOC Dashboard and SOAR Playbook Engine.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const { AttackerProfilingEngine } = require('./engine/profilingEngine');
const { createRabbitMQClient } = require('./lib/rabbitmq');

const PORT = Number(process.env.PORT || 8004);
const SERVICE_NAME = 'attacker-profiling-service';
const INTEL_SERVICE_URL = process.env.THREAT_INTEL_URL || 'http://threat-intelligence-service:3012';
const DB_SERVICE_URL = process.env.DATABASE_SERVICE_URL || 'http://threat-log-database-service:3006';

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

async function fetchThreatIntel(ip, context = {}) {
    if (typeof fetch !== 'function') return null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
        const qs = context.honeypot_hit ? '?honeypot=true' : '';
        const res = await fetch(`${INTEL_SERVICE_URL}/api/intel/ip/${encodeURIComponent(ip)}${qs}`, {
            signal: controller.signal
        });
        if (!res.ok) return null;
        const body = await res.json();
        return body.data || null;
    } catch (_) {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

async function persistProfileToDb(profile) {
    if (typeof fetch !== 'function') return;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
        await fetch(`${DB_SERVICE_URL}/api/v2/attacker-profiles`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(profile),
            signal: controller.signal
        });
    } catch (_) {
        // Non-fatal in standalone mode
    } finally {
        clearTimeout(timer);
    }
}

const profilingEngine = new AttackerProfilingEngine({
    intelLookupFn: fetchThreatIntel
});
const mqClient = createRabbitMQClient({ serviceName: SERVICE_NAME });

// Health probes
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: SERVICE_NAME,
        version: '2.0.0',
        tracked_profiles: profilingEngine.profiles.size,
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
        tracked_profiles: profilingEngine.profiles.size
    });
});

// List all attacker profiles sorted by risk score descending
app.get('/api/profiles', (req, res) => {
    const minRisk = Number(req.query.min_risk || 0);
    const threatLevel = req.query.threat_level;
    let list = profilingEngine.getAllProfiles();
    if (minRisk > 0) {
        list = list.filter(p => p.risk_assessment.final_score >= minRisk);
    }
    if (threatLevel) {
        list = list.filter(p => p.risk_assessment.threat_level === String(threatLevel).toUpperCase());
    }
    res.json({
        status: 'success',
        count: list.length,
        data: list
    });
});

// Get specific attacker profile by source IP
app.get('/api/profiles/:ip', (req, res) => {
    const profile = profilingEngine.getProfile(req.params.ip);
    if (!profile) {
        return res.status(404).json({
            status: 'error',
            message: `No attacker profile found for indicator ${req.params.ip}`
        });
    }
    res.json({ status: 'success', data: profile });
});

// Observe / ingest a security event via HTTP (supports both synchronous and async testing)
app.post('/api/profiles/observe', async (req, res) => {
    try {
        const { event, intel } = req.body || {};
        const targetEvent = event || req.body;
        if (!targetEvent || !targetEvent.source_ip) {
            return res.status(400).json({ status: 'error', message: 'Valid security event with source_ip is required' });
        }
        const updatedProfile = await profilingEngine.ingestEvent(targetEvent, intel || null);
        await persistProfileToDb(updatedProfile);
        await mqClient.publish('profile.updated', {
            source_ip: updatedProfile.source_ip,
            risk_assessment: updatedProfile.risk_assessment,
            behavioural_patterns: updatedProfile.behavioural_patterns,
            honeypot_sessions: updatedProfile.honeypot_sessions
        });
        res.json({ status: 'success', data: updatedProfile });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

async function startService() {
    try {
        await mqClient.connect();
        await mqClient.consume('q.profiling.events', async (event) => {
            if (event && event.source_ip) {
                const updated = await profilingEngine.ingestEvent(event);
                if (updated) {
                    await persistProfileToDb(updated);
                    await mqClient.publish('profile.updated', {
                        source_ip: updated.source_ip,
                        risk_assessment: updated.risk_assessment,
                        behavioural_patterns: updated.behavioural_patterns
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

module.exports = { app, profilingEngine };
