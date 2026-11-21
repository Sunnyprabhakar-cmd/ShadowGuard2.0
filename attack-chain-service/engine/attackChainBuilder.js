/**
 * Shadow Guard 2.0 - Evidence-Based MITRE ATT&CK Chain Reconstruction Engine
 *
 * Reconstructs chronological multi-stage attack chains from correlated security incidents
 * and enforces strict ontological separation (User Modification #5):
 *   - OBSERVED  : Direct deterministic evidence (Honeypot session/command/file or Suricata SID match)
 *   - INFERRED  : Statistical / Machine Learning flow classification or heuristic anomaly
 *   - SUSPECTED : Hypothesized missing intermediate kill-chain bridge connecting two confirmed stages
 *                 with decayed confidence and explicit bounding evidence references.
 */

'use strict';

const crypto = require('crypto');

// Ordered Kill-Chain Tactics (1 -> 8)
const KILL_CHAIN_ORDER = [
    { order: 1, tactic_id: 'TA0043', tactic_name: 'Reconnaissance' },
    { order: 2, tactic_id: 'TA0001', tactic_name: 'Initial Access' },
    { order: 3, tactic_id: 'TA0006', tactic_name: 'Credential Access' },
    { order: 4, tactic_id: 'TA0007', tactic_name: 'Discovery' },
    { order: 5, tactic_id: 'TA0002', tactic_name: 'Execution' },
    { order: 6, tactic_id: 'TA0011', tactic_name: 'Command and Control' },
    { order: 7, tactic_id: 'TA0010', tactic_name: 'Exfiltration' },
    { order: 8, tactic_id: 'TA0040', tactic_name: 'Impact' }
];

class AttackChainBuilder {
    constructor() {
        // Map incident_id -> ReconstructedChain
        this.chainsByIncident = new Map();
    }

    /**
     * Reconstruct or update a chronological MITRE ATT&CK kill chain from a correlated incident
     */
    reconstructChain(incident) {
        if (!incident || !incident.incident_id) {
            throw new Error('Valid incident with incident_id is required for attack chain reconstruction');
        }

        const events = Array.isArray(incident.events_snapshot) ? [...incident.events_snapshot] : [];
        // Sort events chronologically
        events.sort((a, b) => new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime());

        const stageMap = new Map(); // key: `${tactic_id}:${technique_id}:${certainty}` -> StageNode

        for (const ev of events) {
            const mappedNodes = this._mapEventToMitreNodes(ev);
            for (const node of mappedNodes) {
                const key = `${node.tactic_id}:${node.technique_id}:${node.certainty_tier}`;
                if (!stageMap.has(key)) {
                    stageMap.set(key, {
                        node_id: crypto.randomUUID(),
                        stage_order: node.stage_order,
                        tactic_id: node.tactic_id,
                        tactic_name: node.tactic_name,
                        technique_id: node.technique_id,
                        technique_name: node.technique_name,
                        certainty_tier: node.certainty_tier, // OBSERVED | INFERRED | SUSPECTED
                        confidence: node.confidence,
                        first_observed_at: ev.timestamp || incident.first_seen,
                        last_observed_at: ev.timestamp || incident.last_seen,
                        evidence_event_ids: ev.event_id ? [ev.event_id] : [],
                        telemetry_sources: [ev.source_service || ev.source_category || 'unknown'],
                        affected_services: node.affected_service ? [node.affected_service] : [],
                        rationale: node.rationale
                    });
                } else {
                    const existing = stageMap.get(key);
                    existing.last_observed_at = ev.timestamp || existing.last_observed_at;
                    existing.confidence = Number(Math.min(0.99, Math.max(existing.confidence, node.confidence) + 0.02).toFixed(2));
                    if (ev.event_id && !existing.evidence_event_ids.includes(ev.event_id)) {
                        existing.evidence_event_ids.push(ev.event_id);
                    }
                    const src = ev.source_service || ev.source_category || 'unknown';
                    if (!existing.telemetry_sources.includes(src)) {
                        existing.telemetry_sources.push(src);
                    }
                    if (node.affected_service && !existing.affected_services.includes(node.affected_service)) {
                        existing.affected_services.push(node.affected_service);
                    }
                }
            }
        }

        let stages = Array.from(stageMap.values());

        // Evaluate gap-bridging for SUSPECTED intermediate stages
        const suspectedBridges = this._inferSuspectedBridgeStages(stages);
        stages = [...stages, ...suspectedBridges];

        // Sort stages by kill-chain order first, then timestamp
        stages.sort((a, b) => {
            if (a.stage_order !== b.stage_order) return a.stage_order - b.stage_order;
            return new Date(a.first_observed_at).getTime() - new Date(b.first_observed_at).getTime();
        });

        // Build directed edges between consecutive stages
        const edges = [];
        for (let i = 0; i < stages.length - 1; i++) {
            edges.push({
                from_node_id: stages[i].node_id,
                to_node_id: stages[i + 1].node_id,
                from_technique: stages[i].technique_id,
                to_technique: stages[i + 1].technique_id,
                transition_type: stages[i + 1].certainty_tier === 'SUSPECTED' || stages[i].certainty_tier === 'SUSPECTED'
                    ? 'HYPOTHESIZED_BRIDGE'
                    : 'CHRONOLOGICAL_PROGRESSION'
            });
        }

        const countsByTier = {
            OBSERVED: stages.filter(s => s.certainty_tier === 'OBSERVED').length,
            INFERRED: stages.filter(s => s.certainty_tier === 'INFERRED').length,
            SUSPECTED: stages.filter(s => s.certainty_tier === 'SUSPECTED').length
        };

        const chain = {
            chain_id: this.chainsByIncident.has(incident.incident_id)
                ? this.chainsByIncident.get(incident.incident_id).chain_id
                : crypto.randomUUID(),
            incident_id: incident.incident_id,
            source_ip: incident.source_ip,
            severity: incident.severity,
            overall_confidence: incident.confidence,
            reconstructed_at: new Date().toISOString(),
            kill_chain_depth: new Set(stages.map(s => s.tactic_id)).size,
            total_stages: stages.length,
            certainty_breakdown: countsByTier,
            stages,
            edges,
            mermaid_diagram: this._generateMermaidGraph(stages),
            analyst_summary: this._buildAnalystSummary(incident, stages, countsByTier),
            recommended_mitigations: this._buildMitigationRecommendations(stages)
        };

        this.chainsByIncident.set(incident.incident_id, chain);
        return chain;
    }

    /**
     * Map a single normalized security event to 1 or more MITRE ATT&CK stage nodes
     * with explicit OBSERVED vs INFERRED ontological classification.
     */
    _mapEventToMitreNodes(ev) {
        const nodes = [];
        const isDeception = ev.source_category === 'deception' || Boolean(ev.honeypot_metadata);
        const isNids = ev.source_category === 'nids' || Boolean(ev.nids_metadata);
        const hp = ev.honeypot_metadata || {};
        const nids = ev.nids_metadata || {};
        const evType = String(ev.event_type || '').toUpperCase();
        const serviceLabel = hp.targeted_service || (ev.destination_port ? `PORT_${ev.destination_port}` : 'NETWORK');

        // 1. Reconnaissance (TA0043 - T1595 Active Scanning / T1046 Network Service Discovery)
        if (/PORT_SCAN|SYN_SCAN|RECON|SURICATA_SCAN/i.test(evType) || /scan/i.test(nids.signature || '')) {
            nodes.push({
                stage_order: 1,
                tactic_id: 'TA0043',
                tactic_name: 'Reconnaissance',
                technique_id: 'T1595',
                technique_name: 'Active Scanning: Vulnerability & Port Probing',
                certainty_tier: isNids || isDeception ? 'OBSERVED' : 'INFERRED',
                confidence: isNids || isDeception ? 0.94 : 0.78,
                affected_service: serviceLabel,
                rationale: isNids
                    ? `Observed Suricata NIDS signature [${nids.signature || 'Scan Alert'}] from ${ev.source_ip}.`
                    : `Inferred active scanning behaviour from network flow feature distribution on ${serviceLabel}.`
            });
        }

        // 2. Initial Access (TA0001 - T1190 Exploit Public-Facing Application / T1078 Valid Accounts)
        if (isDeception && (hp.auth_outcome === 'SUCCESS' || /SESSION_CONNECT|CONNECTION_OPEN|CANARY_TRIGGER/i.test(evType))) {
            nodes.push({
                stage_order: 2,
                tactic_id: 'TA0001',
                tactic_name: 'Initial Access',
                technique_id: 'T1190',
                technique_name: 'Exploit Public-Facing Application / Decoy Service Touch',
                certainty_tier: 'OBSERVED',
                confidence: 0.98,
                affected_service: serviceLabel,
                rationale: `Direct connection established with deception sensor (${hp.honeypot_id || ev.source_service}) on ${serviceLabel}.`
            });
        }

        // 3. Credential Access (TA0006 - T1110 Brute Force)
        if (
            (hp && (hp.auth_outcome === 'FAILED' || hp.auth_outcome === 'SUCCESS') && hp.username_attempted) ||
            /BRUTE_FORCE|AUTH_FAILURE|SSH_BRUTE/i.test(evType)
        ) {
            nodes.push({
                stage_order: 3,
                tactic_id: 'TA0006',
                tactic_name: 'Credential Access',
                technique_id: 'T1110',
                technique_name: 'Brute Force: Password Guessing & Credential Stuffing',
                certainty_tier: isDeception || isNids ? 'OBSERVED' : 'INFERRED',
                confidence: isDeception ? 0.99 : (isNids ? 0.92 : 0.76),
                affected_service: serviceLabel,
                rationale: isDeception
                    ? `Observed ${hp.auth_outcome} authentication attempt for username '${hp.username_attempted}' on honeypot ${hp.honeypot_id || 'Cowrie'}.`
                    : `Detected repeated authentication brute-force pattern targeting ${serviceLabel}.`
            });
        }

        // 4. Discovery (TA0007 - T1082 System Information Discovery / T1046 Service Enumeration)
        if (
            (hp.command_executed && /\b(uname|whoami|id|cat\s+\/proc|ifconfig|ip\s+a|ps\s+|ls\b)/i.test(hp.command_executed)) ||
            /OPEN_CANARY|SERVICE_ENUM|SMB_PROBE|MYSQL_PROBE|FTP_PROBE/i.test(evType)
        ) {
            nodes.push({
                stage_order: 4,
                tactic_id: 'TA0007',
                tactic_name: 'Discovery',
                technique_id: hp.command_executed ? 'T1082' : 'T1046',
                technique_name: hp.command_executed ? 'System Information Discovery' : 'Network Service Discovery',
                certainty_tier: 'OBSERVED',
                confidence: 0.97,
                affected_service: serviceLabel,
                rationale: hp.command_executed
                    ? `Observed attacker shell discovery command '${hp.command_executed}' inside Cowrie session.`
                    : `Observed decoy service enumeration against ${serviceLabel}.`
            });
        }

        // 5. Execution (TA0002 - T1059 Command and Scripting Interpreter)
        if (hp.command_executed || hp.file_sha256 || /COMMAND_EXEC|MALWARE_CAPTURE|PAYLOAD_DROP/i.test(evType)) {
            nodes.push({
                stage_order: 5,
                tactic_id: 'TA0002',
                tactic_name: 'Execution',
                technique_id: 'T1059.004',
                technique_name: 'Command and Scripting Interpreter: Unix Shell / Payload Drop',
                certainty_tier: 'OBSERVED',
                confidence: 1.00,
                affected_service: serviceLabel,
                rationale: hp.command_executed
                    ? `Directly captured shell execution '${hp.command_executed}' in honeypot session ${hp.session_id || 'n/a'}.`
                    : `Captured quarantined payload SHA-256 (${String(hp.file_sha256).slice(0, 16)}...) in deception sandbox.`
            });
        }

        // 6. Command and Control (TA0011 - T1071 Application Layer Protocol / T1105 Ingress Tool Transfer)
        if (
            (hp.command_executed && /\b(wget|curl|tftp|nc|bash\s+-i)/i.test(hp.command_executed)) ||
            hp.download_url ||
            /C2|COMMAND_AND_CONTROL|BOTNET|BEACON/i.test(evType)
        ) {
            nodes.push({
                stage_order: 6,
                tactic_id: 'TA0011',
                tactic_name: 'Command and Control',
                technique_id: hp.download_url || (hp.command_executed && /wget|curl/i.test(hp.command_executed)) ? 'T1105' : 'T1071',
                technique_name: hp.download_url ? 'Ingress Tool Transfer' : 'Application Layer C2 Protocol',
                certainty_tier: isDeception || isNids ? 'OBSERVED' : 'INFERRED',
                confidence: isDeception ? 0.98 : 0.81,
                affected_service: serviceLabel,
                rationale: isDeception
                    ? `Observed tool transfer / C2 staging command (${hp.download_url || hp.command_executed}).`
                    : `Inferred C2 beaconing pattern from network flow periodicity and ML classifier.`
            });
        }

        // 7. Exfiltration (TA0010 - T1041 Exfiltration Over C2 Channel)
        if (/EXFILTRATION|DATA_THEFT|DNS_TUNNEL/i.test(evType)) {
            nodes.push({
                stage_order: 7,
                tactic_id: 'TA0010',
                tactic_name: 'Exfiltration',
                technique_id: 'T1041',
                technique_name: 'Exfiltration Over Command-and-Control Channel',
                certainty_tier: isNids ? 'OBSERVED' : 'INFERRED',
                confidence: isNids ? 0.92 : 0.79,
                affected_service: serviceLabel,
                rationale: isNids
                    ? `Suricata NIDS alert confirmed outbound data transfer signature on ${serviceLabel}.`
                    : `ML flow classifier detected high-byte outbound asymmetry characteristic of data exfiltration.`
            });
        }

        // 8. Impact (TA0040 - T1498 Network Denial of Service)
        if (/DDOS|DOS|SYN_FLOOD|UDP_FLOOD/i.test(evType)) {
            nodes.push({
                stage_order: 8,
                tactic_id: 'TA0040',
                tactic_name: 'Impact',
                technique_id: 'T1498',
                technique_name: 'Network Denial of Service',
                certainty_tier: isNids ? 'OBSERVED' : 'INFERRED',
                confidence: isNids ? 0.95 : 0.84,
                affected_service: serviceLabel,
                rationale: `Detected high-rate volumetric denial-of-service flood targeting ${serviceLabel}.`
            });
        }

        // Fallback if event didn't match a specific pattern above
        if (nodes.length === 0) {
            nodes.push({
                stage_order: 1,
                tactic_id: 'TA0043',
                tactic_name: 'Reconnaissance',
                technique_id: 'T1595',
                technique_name: 'Anomalous Network Probing',
                certainty_tier: isDeception || isNids ? 'OBSERVED' : 'INFERRED',
                confidence: isDeception ? 0.90 : 0.70,
                affected_service: serviceLabel,
                rationale: `Mapped security event (${evType || 'ANOMALY'}) from ${ev.source_service || 'sensor'}.`
            });
        }

        return nodes;
    }

    /**
     * Identify missing intermediate kill-chain transitions and insert SUSPECTED bridge stages
     * with decayed confidence (0.50) and explicit upstream/downstream evidence references.
     */
    _inferSuspectedBridgeStages(existingStages) {
        const bridges = [];
        const presentOrders = new Set(existingStages.map(s => s.stage_order));

        // Bridge 1: If Reconnaissance (1) and Execution (5) or C2 (6) exist, but Initial Access (2) is missing
        if (presentOrders.has(1) && (presentOrders.has(5) || presentOrders.has(6) || presentOrders.has(7)) && !presentOrders.has(2)) {
            const upstream = existingStages.find(s => s.stage_order === 1);
            const downstream = existingStages.find(s => s.stage_order >= 5);
            bridges.push({
                node_id: crypto.randomUUID(),
                stage_order: 2,
                tactic_id: 'TA0001',
                tactic_name: 'Initial Access',
                technique_id: 'T1190',
                technique_name: 'Suspected Initial Access Bridge (Unobserved Entry Vector)',
                certainty_tier: 'SUSPECTED',
                confidence: 0.52,
                first_observed_at: upstream.last_observed_at,
                last_observed_at: downstream.first_observed_at,
                evidence_event_ids: [
                    ...(upstream.evidence_event_ids.slice(0, 2)),
                    ...(downstream.evidence_event_ids.slice(0, 2))
                ],
                telemetry_sources: ['attack-chain-gap-inference'],
                affected_services: downstream.affected_services,
                rationale: `SUSPECTED intermediate stage: Attacker progressed from confirmed Reconnaissance (${upstream.technique_id}) to ${downstream.tactic_name} (${downstream.technique_id}) without a directly logged Initial Access event.`
            });
        }

        // Bridge 2: If Credential Access (3) and Exfiltration (7) exist, but Discovery (4) / Execution (5) are missing
        if (presentOrders.has(3) && presentOrders.has(7) && !presentOrders.has(4) && !presentOrders.has(5)) {
            const upstream = existingStages.find(s => s.stage_order === 3);
            const downstream = existingStages.find(s => s.stage_order === 7);
            bridges.push({
                node_id: crypto.randomUUID(),
                stage_order: 4,
                tactic_id: 'TA0007',
                tactic_name: 'Discovery',
                technique_id: 'T1083',
                technique_name: 'Suspected File & Directory Discovery Prior to Exfiltration',
                certainty_tier: 'SUSPECTED',
                confidence: 0.48,
                first_observed_at: upstream.last_observed_at,
                last_observed_at: downstream.first_observed_at,
                evidence_event_ids: [
                    ...(upstream.evidence_event_ids.slice(0, 2)),
                    ...(downstream.evidence_event_ids.slice(0, 2))
                ],
                telemetry_sources: ['attack-chain-gap-inference'],
                affected_services: downstream.affected_services,
                rationale: `SUSPECTED intermediate stage bridging confirmed Credential Access (${upstream.technique_id}) and Exfiltration (${downstream.technique_id}).`
            });
        }

        return bridges;
    }

    _generateMermaidGraph(stages) {
        const lines = ['flowchart LR'];
        stages.forEach((s, idx) => {
            const nodeId = `S${idx + 1}`;
            const label = `"${s.tactic_name}: ${s.technique_id} (${s.certainty_tier} ${Math.round(s.confidence * 100)}%)"`;
            lines.push(`  ${nodeId}[${label}]`);
            if (idx > 0) {
                lines.push(`  S${idx} --> ${nodeId}`);
            }
        });
        return lines.join('\n');
    }

    _buildAnalystSummary(incident, stages, countsByTier) {
        const tacticSequence = stages.map(s => `${s.tactic_name} (${s.technique_id}/${s.certainty_tier})`).join(' -> ');
        return (
            `Reconstructed ${stages.length}-stage MITRE ATT&CK kill chain for indicator ${incident.source_ip} ` +
            `(Incident ${incident.incident_id}). Ontological breakdown: ${countsByTier.OBSERVED} OBSERVED, ` +
            `${countsByTier.INFERRED} INFERRED, ${countsByTier.SUSPECTED} SUSPECTED. ` +
            `Progression: ${tacticSequence}.`
        );
    }

    _buildMitigationRecommendations(stages) {
        const recs = [];
        const tactics = new Set(stages.map(s => s.tactic_id));
        if (tactics.has('TA0006')) {
            recs.push('Enforce SSH public-key authentication and rate-limit authentication attempts via fail2ban/iptables.');
        }
        if (tactics.has('TA0002') || tactics.has('TA0011')) {
            recs.push('Immediately quarantine source IP at perimeter firewall and inspect outbound egress rules for C2 callbacks.');
        }
        if (tactics.has('TA0043') || tactics.has('TA0007')) {
            recs.push('Deploy adaptive decoy listeners on scanned ports to divert attacker enumeration away from production assets.');
        }
        if (tactics.has('TA0010')) {
            recs.push('Revoke active session tokens and block outbound transfers to flagged external destinations.');
        }
        if (recs.length === 0) {
            recs.push('Maintain enhanced telemetry monitoring and verify network segmentation boundaries.');
        }
        return recs;
    }

    getAllChains() {
        return Array.from(this.chainsByIncident.values()).sort(
            (a, b) => new Date(b.reconstructed_at).getTime() - new Date(a.reconstructed_at).getTime()
        );
    }

    getChainByIncident(incidentId) {
        return this.chainsByIncident.get(incidentId) || null;
    }
}

module.exports = {
    AttackChainBuilder,
    KILL_CHAIN_ORDER
};
