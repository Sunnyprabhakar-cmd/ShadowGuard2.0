/**
 * Shadow Guard 2.0 - Multi-Condition SOAR Playbook Evaluation Engine
 *
 * Evaluates multi-dimensional security context:
 *   - ML Anomaly Score & Threat Classification Confidence
 *   - Honeypot Interaction Count & Post-Auth Command / Payload Activity
 *   - Threat Intelligence Reputation Score (0-100)
 *   - Attacker Profile Explainable Risk Score (0-100)
 *   - Correlated Incident Severity (LOW, MEDIUM, HIGH, CRITICAL)
 *   - Repeated Offense Count
 *
 * Outputs structured SOAR Playbook Execution Plans with composite actions,
 * block lease durations, approval requirements, and audit rationale.
 */

'use strict';

const crypto = require('crypto');

const DEFAULT_SOAR_PLAYBOOKS = [
    {
        playbook_id: 'PB-SOAR-01',
        name: 'Critical Deception Compromise & Payload Containment',
        priority: 1,
        enabled: true,
        conditions: {
            min_attacker_risk_score: 80,
            incident_severities: ['CRITICAL'],
            require_honeypot_or_payload: true
        },
        actions: [
            { type: 'BLOCK_IP_TEMPORARY', lease_minutes: 60, require_approval: false },
            { type: 'DEPLOY_ADDITIONAL_HONEYPOT', target_policy: 'DEC-04' },
            { type: 'INCREASE_LOGGING_LEVEL', level: 'DEBUG_FULL_FORENSICS' },
            { type: 'SEND_NOTIFICATION', channel: 'SOC_CRITICAL_PAGER' },
            { type: 'ESCALATE_INCIDENT', tier: 'TIER_3_INCIDENT_RESPONSE' }
        ],
        legacy_action: 'block',
        description: 'Immediate 60-minute perimeter containment, malware trap redirection, and Tier-3 SOC escalation for confirmed interactive honeypot compromise or payload staging.'
    },
    {
        playbook_id: 'PB-SOAR-02',
        name: 'Repeat Offender Permanent Quarantine (Approval Gated)',
        priority: 2,
        enabled: true,
        conditions: {
            min_repeated_offenses: 3,
            min_threat_intel_reputation: 85
        },
        actions: [
            { type: 'BLOCK_IP_TEMPORARY', lease_minutes: 120, require_approval: false },
            { type: 'BLOCK_IP_PERMANENT', require_approval: true },
            { type: 'SEND_NOTIFICATION', channel: 'SOC_APPROVAL_QUEUE' }
        ],
        legacy_action: 'block',
        description: 'Applies immediate 120-minute temporary block and queues a permanent firewall ban for human SOC analyst approval.'
    },
    {
        playbook_id: 'PB-SOAR-03',
        name: 'High-Confidence Multi-Source Intrusion Containment',
        priority: 3,
        enabled: true,
        conditions: {
            min_classification_confidence: 0.85,
            min_attacker_risk_score: 60,
            incident_severities: ['HIGH', 'CRITICAL']
        },
        actions: [
            { type: 'BLOCK_IP_TEMPORARY', lease_minutes: 30, require_approval: false },
            { type: 'DEPLOY_ADDITIONAL_HONEYPOT', target_policy: 'DEC-01' },
            { type: 'SEND_NOTIFICATION', channel: 'SOC_ALERT_EMAIL' }
        ],
        legacy_action: 'block',
        description: 'Applies 30-minute timed IP lease block and expands decoy listeners for high-confidence NIDS/ML/Deception threats.'
    },
    {
        playbook_id: 'PB-SOAR-04',
        name: 'Active Reconnaissance & Brute-Force Deception Lure',
        priority: 4,
        enabled: true,
        conditions: {
            min_classification_confidence: 0.60,
            min_attacker_risk_score: 35,
            incident_severities: ['MEDIUM', 'HIGH']
        },
        actions: [
            { type: 'RAISE_ALERT' },
            { type: 'DEPLOY_ADDITIONAL_HONEYPOT', target_policy: 'DEC-02' },
            { type: 'INCREASE_LOGGING_LEVEL', level: 'ENHANCED' }
        ],
        legacy_action: 'alert',
        description: 'Raises SOC alert, elevates Cowrie/OpenCanary telemetry capture, and deploys honey-breadcrumbs without prematurely tipping off the scanner.'
    },
    {
        playbook_id: 'PB-SOAR-05',
        name: 'Baseline Telemetry Monitoring',
        priority: 5,
        enabled: true,
        conditions: {},
        actions: [
            { type: 'MONITOR_ONLY' }
        ],
        legacy_action: 'monitor',
        description: 'Records telemetry baseline for benign or low-confidence network flows.'
    }
];

class SoarPlaybookEngine {
    constructor() {
        this.playbooks = new Map();
        for (const pb of DEFAULT_SOAR_PLAYBOOKS) {
            this.playbooks.set(pb.playbook_id, JSON.parse(JSON.stringify(pb)));
        }
        this.offenseCounterByIp = new Map(); // source_ip -> count
        this.decisionHistory = [];
    }

    /**
     * Evaluate multi-condition SOAR playbooks against enriched security context
     */
    evaluateContext(input = {}) {
        const sourceIp = input.source_ip || input.sourceIp || input.src_ip || '0.0.0.0';
        const anomalyScore = Number(input.anomaly_score ?? input.anomalyScore ?? 0);
        const classificationConfidence = Number(input.classification_confidence ?? input.confidence ?? 0);
        const honeypotInteractions = Number(input.honeypot_interaction_count ?? input.honeypot_sessions ?? 0);
        const hasPayloadOrCmd = Boolean(input.has_payload_or_cmd || input.command_executed || input.file_sha256);
        const intelReputation = Number(input.threat_intelligence_reputation ?? input.reputation_score ?? 0);
        const attackerRiskScore = Number(input.attacker_risk_score ?? input.risk_score ?? (classificationConfidence * 100));
        const incidentSeverity = String(input.incident_severity || input.severity || 'LOW').toUpperCase();

        // Increment offense count if non-benign
        const isBenign = incidentSeverity === 'LOW' && attackerRiskScore < 30 && honeypotInteractions === 0 && classificationConfidence < 0.5;
        let offenseCount = this.offenseCounterByIp.get(sourceIp) || 0;
        if (!isBenign && sourceIp !== '0.0.0.0') {
            offenseCount += 1;
            this.offenseCounterByIp.set(sourceIp, offenseCount);
        }
        if (input.repeated_offense_count !== undefined) {
            offenseCount = Math.max(offenseCount, Number(input.repeated_offense_count));
        }

        // Sort enabled playbooks by priority ascending
        const sortedPlaybooks = Array.from(this.playbooks.values())
            .filter(p => p.enabled)
            .sort((a, b) => a.priority - b.priority);

        let selectedPlaybook = sortedPlaybooks[sortedPlaybooks.length - 1];
        const matchedReasons = [];

        for (const pb of sortedPlaybooks) {
            const c = pb.conditions || {};

            if (pb.playbook_id === 'PB-SOAR-01') {
                const sevMatch = (c.incident_severities || []).includes(incidentSeverity);
                const riskMatch = attackerRiskScore >= c.min_attacker_risk_score;
                const hpMatch = honeypotInteractions > 0 || hasPayloadOrCmd;
                if ((sevMatch || riskMatch) && (hpMatch || attackerRiskScore >= 90)) {
                    selectedPlaybook = pb;
                    matchedReasons.push(
                        `Matched ${pb.playbook_id}: Attacker risk score=${attackerRiskScore}, severity=${incidentSeverity}, honeypot_sessions=${honeypotInteractions}`
                    );
                    break;
                }
            } else if (pb.playbook_id === 'PB-SOAR-02') {
                if (offenseCount >= c.min_repeated_offenses && (intelReputation >= c.min_threat_intel_reputation || attackerRiskScore >= 85)) {
                    selectedPlaybook = pb;
                    matchedReasons.push(
                        `Matched ${pb.playbook_id}: Repeat offender (${offenseCount} offenses) with Threat Intel reputation=${intelReputation}`
                    );
                    break;
                }
            } else if (pb.playbook_id === 'PB-SOAR-03') {
                const confMatch = classificationConfidence >= c.min_classification_confidence || anomalyScore >= 0.85;
                const riskMatch = attackerRiskScore >= c.min_attacker_risk_score;
                const sevMatch = (c.incident_severities || []).includes(incidentSeverity);
                if (confMatch || riskMatch || sevMatch) {
                    selectedPlaybook = pb;
                    matchedReasons.push(
                        `Matched ${pb.playbook_id}: High-confidence threat (conf=${classificationConfidence.toFixed(2)}, risk=${attackerRiskScore}, severity=${incidentSeverity})`
                    );
                    break;
                }
            } else if (pb.playbook_id === 'PB-SOAR-04') {
                const confMatch = classificationConfidence >= c.min_classification_confidence || anomalyScore >= 0.60;
                const riskMatch = attackerRiskScore >= c.min_attacker_risk_score || honeypotInteractions > 0;
                const sevMatch = (c.incident_severities || []).includes(incidentSeverity);
                if (confMatch || riskMatch || sevMatch) {
                    selectedPlaybook = pb;
                    matchedReasons.push(
                        `Matched ${pb.playbook_id}: Active probing/brute-force (conf=${classificationConfidence.toFixed(2)}, risk=${attackerRiskScore})`
                    );
                    break;
                }
            } else if (pb.playbook_id === 'PB-SOAR-05') {
                selectedPlaybook = pb;
                matchedReasons.push('Matched PB-SOAR-05: Benign or low-risk telemetry baseline');
                break;
            }
        }

        const plan = {
            decision_id: `soar-dec-${crypto.randomUUID().slice(0, 8)}`,
            playbook_id: selectedPlaybook.playbook_id,
            playbook_name: selectedPlaybook.name,
            source_ip: sourceIp,
            legacy_action: selectedPlaybook.legacy_action,
            actions: selectedPlaybook.actions,
            evaluated_metrics: {
                anomaly_score: anomalyScore,
                classification_confidence: classificationConfidence,
                honeypot_interaction_count: honeypotInteractions,
                threat_intelligence_reputation: intelReputation,
                attacker_risk_score: attackerRiskScore,
                incident_severity: incidentSeverity,
                repeated_offense_count: offenseCount
            },
            rationale: matchedReasons.join('; '),
            decided_at: new Date().toISOString()
        };

        this.decisionHistory.unshift(plan);
        if (this.decisionHistory.length > 300) {
            this.decisionHistory.length = 300;
        }

        return plan;
    }

    listPlaybooks() {
        return Array.from(this.playbooks.values());
    }

    updatePlaybook(playbookId, updates = {}) {
        const existing = this.playbooks.get(playbookId);
        if (!existing) throw new Error(`Playbook ${playbookId} not found`);
        const updated = {
            ...existing,
            ...updates,
            playbook_id: playbookId
        };
        this.playbooks.set(playbookId, updated);
        return updated;
    }
}

module.exports = {
    SoarPlaybookEngine,
    DEFAULT_SOAR_PLAYBOOKS
};
