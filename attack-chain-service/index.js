/**
 * Shadow Guard 2.0 - Attack Chain Reconstruction Service (:8006)
 *
 * Subscribes to `q.attackchain.incidents` (`incident.#` on `sg.events`),
 * reconstructs chronological MITRE ATT&CK kill chains with explicit
 * OBSERVED, INFERRED, and SUSPECTED certainty tiers, and exposes REST endpoints
 * for the SOC Dashboard and Incident Forensics UI.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const { AttackChainBuilder, KILL_CHAIN_ORDER } = require('./engine/attackChainBuilder');
const { createRabbitMQClient } = require('./lib/rabbitmq');

const PORT = Number(process.env.PORT || 8006);
const SERVICE_NAME = 'attack-chain-service';

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

const chainBuilder = new AttackChainBuilder();
const mqClient = createRabbitMQClient({ serviceName: SERVICE_NAME });

// Health probes
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: SERVICE_NAME,
        version: '2.0.0',
        reconstructed_chains: chainBuilder.chainsByIncident.size,
        supported_tactics: KILL_CHAIN_ORDER.length,
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
        reconstructed_chains: chainBuilder.chainsByIncident.size
    });
});

// List all reconstructed attack chains
app.get('/api/chains', (req, res) => {
    const sourceIp = req.query.source_ip;
    let list = chainBuilder.getAllChains();
    if (sourceIp) {
        list = list.filter(c => c.source_ip === String(sourceIp).trim());
    }
    res.json({
        status: 'success',
        count: list.length,
        data: list
    });
});

// Get attack chain for a specific incident_id
app.get('/api/chains/:incidentId', (req, res) => {
    const chain = chainBuilder.getChainByIncident(req.params.incidentId);
    if (!chain) {
        return res.status(404).json({
            status: 'error',
            message: `No attack chain found for incident ${req.params.incidentId}`
        });
    }
    res.json({ status: 'success', data: chain });
});

// Reconstruct or update an attack chain from an incident payload
app.post('/api/chains/reconstruct', async (req, res) => {
    try {
        const incident = (req.body && req.body.incident) || req.body;
        if (!incident || !incident.incident_id) {
            return res.status(400).json({
                status: 'error',
                message: 'Valid incident object with incident_id and events_snapshot is required'
            });
        }
        const chain = chainBuilder.reconstructChain(incident);
        await mqClient.publish('attackchain.reconstructed', {
            chain_id: chain.chain_id,
            incident_id: chain.incident_id,
            source_ip: chain.source_ip,
            kill_chain_depth: chain.kill_chain_depth,
            certainty_breakdown: chain.certainty_breakdown
        });
        res.json({ status: 'success', data: chain });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

async function startService() {
    try {
        await mqClient.connect();
        await mqClient.consume('q.attackchain.incidents', async (incident) => {
            if (incident && incident.incident_id) {
                const chain = chainBuilder.reconstructChain(incident);
                await mqClient.publish('attackchain.reconstructed', {
                    chain_id: chain.chain_id,
                    incident_id: chain.incident_id,
                    source_ip: chain.source_ip,
                    kill_chain_depth: chain.kill_chain_depth,
                    certainty_breakdown: chain.certainty_breakdown
                });
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

module.exports = { app, chainBuilder };
