/**
 * Shadow Guard 2.0 - Automated Response Service (:3005)
 *
 * Preserves 100% backward compatibility with Shadow Guard 1.0 (`POST /respond`, `GET /health`)
 * while integrating the Shadow Guard 2.0 SOAR Response Execution & Safety Engine:
 *   - Immutable Critical Infrastructure Allowlist protection
 *   - Timed IP Block Leases with automatic expiration sweeper
 *   - Manual Operator Approval Queue (`approve` / `reject`)
 *   - One-Click Rollback (`rollback`) and Audit Logging
 */

'use strict';

const express = require('express');
const { spawn } = require('child_process');
const { ResponseExecutionEngine } = require('./engine/responseExecutionEngine');
const { createRabbitMQClient } = require('./lib/rabbitmq');

let axios = null;
try {
    axios = require('axios');
} catch (_) {
    // Fallback to native fetch when running on host without node_modules
}

const app = express();
const port = Number(process.env.PORT || 3000);
const SERVICE_NAME = 'automated-response-service';
const enableLocalIptables = process.env.ENABLE_LOCAL_IPTABLES === 'true';
const DECEPTION_MANAGER_URL = process.env.DECEPTION_MANAGER_URL || 'http://deception-manager-service:3013';

app.use(express.json({ limit: '2mb' }));

function runIptablesCommand(mode, ip) {
    return new Promise((resolve, reject) => {
        if (mode === 'UNBLOCK') {
            const delInput = spawn('iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
            delInput.on('exit', () => {
                const delOutput = spawn('iptables', ['-D', 'OUTPUT', '-d', ip, '-j', 'DROP']);
                delOutput.on('exit', () => resolve('IP unblocked from INPUT and OUTPUT chains'));
            });
            return;
        }

        const blockInput = spawn('iptables', ['-C', 'INPUT', '-s', ip, '-j', 'DROP']);
        blockInput.on('exit', (code) => {
            if (code === 0) {
                resolve('IP already blocked in INPUT chain');
                return;
            }
            const addInput = spawn('iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
            addInput.on('exit', (addCode) => {
                if (addCode !== 0) {
                    reject(new Error('Failed to add INPUT block rule'));
                    return;
                }
                const addOutput = spawn('iptables', ['-A', 'OUTPUT', '-d', ip, '-j', 'DROP']);
                addOutput.on('exit', (outCode) => {
                    if (outCode !== 0) {
                        reject(new Error('Failed to add OUTPUT block rule'));
                        return;
                    }
                    resolve('IP blocked in INPUT and OUTPUT chains');
                });
            });
        });
    });
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

const responseEngine = new ResponseExecutionEngine({
    enableLocalIptables,
    iptablesExecutor: runIptablesCommand,
    deceptionCallback: async (directiveReq) => {
        await postJsonSafe(`${DECEPTION_MANAGER_URL}/api/deception/evaluate`, directiveReq);
    }
});

const mqClient = createRabbitMQClient({ serviceName: SERVICE_NAME });

// Automatic lease expiration sweeper (every 15 seconds)
const leaseSweepTimer = setInterval(() => {
    const expired = responseEngine.expireLeases();
    if (expired.length > 0) {
        console.log(`[${SERVICE_NAME}] Automatically expired ${expired.length} IP block lease(s)`);
    }
}, 15000);
if (typeof leaseSweepTimer.unref === 'function') {
    leaseSweepTimer.unref();
}

// ============================================================================
// LEGACY SHADOW GUARD 1.0 ENDPOINT (`POST /respond`)
// ============================================================================
app.post('/respond', async (req, res) => {
    const { action, details } = req.body || {};
    const responseDetails = details || {};
    console.log('Executing response for action:', action);

    try {
        let executionRecord = null;
        if (action === 'block' && responseDetails.ip) {
            const ip = responseDetails.ip;
            if (!responseEngine.isValidIp(ip)) {
                return res.status(400).json({ error: 'Invalid IP for block action' });
            }

            executionRecord = await responseEngine.executeAction({
                action_type: 'BLOCK_IP_TEMPORARY',
                target_ip: ip,
                lease_minutes: Number(responseDetails.lease_minutes || 30),
                playbook_id: responseDetails.playbook_id || 'LEGACY_PLAYBOOK',
                event_source: responseDetails.event_source || null,
                session_id: responseDetails.session_id || null,
                flow_id: responseDetails.flow_id || null,
                details: responseDetails
            });
        } else {
            executionRecord = await responseEngine.executeAction({
                action_type: action || 'MONITOR_ONLY',
                target_ip: responseDetails.ip || null,
                event_source: responseDetails.event_source || null,
                session_id: responseDetails.session_id || null,
                flow_id: responseDetails.flow_id || null,
                details: responseDetails
            });
        }

        try {
            await postJsonSafe('http://threat-log-database-service:3000/log', {
                type: responseDetails.attack_type || responseDetails.attackType || 'response',
                action,
                details: {
                    ...responseDetails,
                    soar_execution: executionRecord
                },
                timestamp: new Date().toISOString()
            });
        } catch (err) {
            console.warn('Database service unreachable in standalone mode:', err.message);
        }

        await mqClient.publish('soar.response.executed', executionRecord);
        res.json({
            message: 'Response executed and logged',
            execution: executionRecord
        });
    } catch (error) {
        console.error('Error in response service:', error);
        res.status(500).json({ error: 'Failed to execute response' });
    }
});

// ============================================================================
// SHADOW GUARD 2.0 SOAR RESPONSE & GOVERNANCE ENDPOINTS
// ============================================================================
app.get('/api/responses/status', (req, res) => {
    res.json({
        status: 'success',
        data: responseEngine.getStatusSummary()
    });
});

app.post('/api/responses/execute', async (req, res) => {
    try {
        const record = await responseEngine.executeAction(req.body || {});
        await mqClient.publish('soar.response.executed', record);
        res.json({ status: 'success', data: record });
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

app.post('/api/responses/:id/approve', async (req, res) => {
    try {
        const { operator } = req.body || {};
        const executed = await responseEngine.approveExecution(req.params.id, operator);
        await mqClient.publish('soar.response.approved', executed);
        res.json({ status: 'success', data: executed });
    } catch (err) {
        res.status(404).json({ status: 'error', message: err.message });
    }
});

app.post('/api/responses/:id/reject', (req, res) => {
    try {
        const { operator, reason } = req.body || {};
        const rejected = responseEngine.rejectExecution(req.params.id, operator, reason);
        res.json({ status: 'success', data: rejected });
    } catch (err) {
        res.status(404).json({ status: 'error', message: err.message });
    }
});

app.post('/api/responses/:id/rollback', async (req, res) => {
    try {
        const { operator, reason } = req.body || {};
        const rolledBack = await responseEngine.rollbackExecution(req.params.id, operator, reason);
        await mqClient.publish('soar.response.rolledback', rolledBack);
        res.json({ status: 'success', data: rolledBack });
    } catch (err) {
        res.status(404).json({ status: 'error', message: err.message });
    }
});

app.post('/api/responses/expire-leases', (req, res) => {
    const expired = responseEngine.expireLeases();
    res.json({
        status: 'success',
        expired_count: expired.length,
        data: expired
    });
});

app.get('/api/responses/allowlist', (req, res) => {
    res.json({
        status: 'success',
        count: responseEngine.allowlist.size,
        data: Array.from(responseEngine.allowlist.values())
    });
});

app.post('/api/responses/allowlist', (req, res) => {
    try {
        const { ip, label, operator } = req.body || {};
        const entry = responseEngine.addAllowlistIp(ip, label, operator);
        res.status(201).json({ status: 'success', data: entry });
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

app.delete('/api/responses/allowlist/:ip', (req, res) => {
    try {
        const result = responseEngine.removeAllowlistIp(req.params.ip, req.query.operator);
        res.json({ status: 'success', data: result });
    } catch (err) {
        res.status(400).json({ status: 'error', message: err.message });
    }
});

// Health probes
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: SERVICE_NAME,
        version: '2.0.0',
        active_blocks: responseEngine.activeBlocks.size,
        pending_approvals: responseEngine.pendingApprovals.size
    });
});

app.get('/health/live', (req, res) => {
    res.status(200).json({ status: 'alive', service: SERVICE_NAME });
});

app.get('/health/ready', (req, res) => {
    res.status(200).json({
        status: 'ready',
        service: SERVICE_NAME,
        allowlist_entries: responseEngine.allowlist.size
    });
});

async function startService() {
    try {
        await mqClient.connect();
        await mqClient.consume('q.soar.execute', async (plan) => {
            if (plan && Array.isArray(plan.actions)) {
                for (const act of plan.actions) {
                    await responseEngine.executeAction({
                        action_type: act.type,
                        target_ip: plan.source_ip,
                        lease_minutes: act.lease_minutes,
                        require_approval: act.require_approval,
                        playbook_id: plan.playbook_id,
                        target_policy: act.target_policy
                    });
                }
            }
        });
    } catch (err) {
        console.warn(`[${SERVICE_NAME}] Running in HTTP-first mode (RabbitMQ unavailable: ${err.message})`);
    }

    app.listen(port, () => {
        console.log(`Automated Response Service listening on port ${port}`);
    });
}

if (require.main === module) {
    startService();
}

module.exports = { app, responseEngine };
