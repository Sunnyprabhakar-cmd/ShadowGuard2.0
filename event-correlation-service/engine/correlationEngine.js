/**
 * Shadow Guard 2.0 - Multi-Source Security Event Correlation Engine
 *
 * Implements an in-memory sliding time-window correlation engine (no Redis required)
 * that fuses telemetry across:
 *   1. Network Flow ML Anomaly & Random Forest Classification
 *   2. Suricata NIDS EVE Telemetry (Alert, DNS, HTTP, TLS, Flow)
 *   3. Cowrie SSH/Telnet Interactive Honeypot
 *   4. OpenCanary Multi-Service Decoys (FTP, SMB, HTTP, MySQL)
 *   5. Dionaea Malware Capture Honeypot
 *   6. Threat Intelligence Reputation & IOC Enrichment
 *
 * Key Capabilities:
 *   - Time-window indexing & automatic expiration pruning
 *   - Event deduplication by signature fingerprint
 *   - Multi-rule & threshold-based correlation (CORR-01 .. CORR-06)
 *   - Incident grouping (merges related events into active incident per source_ip to prevent alert storms)
 *   - Preserves complete raw event_id lineage and produces explainable correlation narratives
 */

'use strict';

const crypto = require('crypto');

const SEVERITY_RANK = {
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
};

const RANK_TO_SEVERITY = {
    1: 'LOW',
    2: 'MEDIUM',
    3: 'HIGH',
    4: 'CRITICAL'
};

class EventCorrelationEngine {
    constructor(options = {}) {
        this.windowMs = options.windowMs || Number(process.env.CORRELATION_WINDOW_MS || 15 * 60 * 1000); // 15 min window
        this.dedupWindowMs = options.dedupWindowMs || 2000; // 2s exact-event deduplication
        this.burstThreshold = options.burstThreshold || 5;

        // In-memory sliding window index: source_ip -> Array<NormalizedEvent>
        this.windowIndex = new Map();
        // Deduplication map: fingerprint -> timestampMs
        this.dedupCache = new Map();
        // Active & historical incidents: incident_id -> IncidentObject
        this.incidents = new Map();
        // Map source_ip -> active incident_id for incident grouping
        this.activeIncidentByIp = new Map();

        this.stats = {
            events_ingested: 0,
            events_deduplicated: 0,
            incidents_created: 0,
            incidents_updated: 0,
            rules_triggered: {
                'CORR-01': 0,
                'CORR-02': 0,
                'CORR-03': 0,
                'CORR-04': 0,
                'CORR-05': 0,
                'CORR-06': 0
            }
        };
    }

    /**
     * Compute deduplication fingerprint for an incoming event
     */
    _computeFingerprint(event) {
        const hpCmd = event.honeypot_metadata && event.honeypot_metadata.command_executed ? event.honeypot_metadata.command_executed : '';
        const nidsSig = event.nids_metadata && event.nids_metadata.signature_id ? event.nids_metadata.signature_id : '';
        const key = `${event.source_service}|${event.source_ip}|${event.destination_port}|${event.event_type}|${hpCmd}|${nidsSig}`;
        return crypto.createHash('sha1').update(key).digest('hex');
    }

    /**
     * Prune expired events outside the sliding correlation time window
     */
    _pruneExpired(sourceIp, nowMs) {
        const list = this.windowIndex.get(sourceIp);
        if (!list) return [];
        const cutoff = nowMs - this.windowMs;
        const valid = list.filter(ev => {
            const evTime = new Date(ev.timestamp || nowMs).getTime();
            return evTime >= cutoff;
        });
        if (valid.length === 0) {
            this.windowIndex.delete(sourceIp);
        } else {
            this.windowIndex.set(sourceIp, valid);
        }

        // Prune dedup cache occasionally
        if (this.dedupCache.size > 2000) {
            for (const [fp, ts] of this.dedupCache.entries()) {
                if (nowMs - ts > this.dedupWindowMs) this.dedupCache.delete(fp);
            }
        }
        return valid;
    }

    /**
     * Normalize either Event Contract v2 (nested telemetry/deception_context) or flat event objects
     */
    _normalizeIncomingEvent(raw) {
        if (!raw || typeof raw !== 'object') return null;
        const tel = raw.telemetry || {};
        return {
            ...raw,
            source_ip: raw.source_ip || tel.source_ip || tel.src_ip,
            destination_ip: raw.destination_ip || tel.destination_ip || tel.dst_ip,
            destination_port: raw.destination_port || tel.destination_port || tel.dst_port,
            protocol: raw.protocol || tel.protocol || 'TCP',
            source_category: raw.source_category || raw.source_domain || 'network',
            severity: String(raw.severity || 'MEDIUM').toUpperCase(),
            honeypot_metadata: raw.honeypot_metadata || raw.deception_context || null,
            nids_metadata: raw.nids_metadata || raw.nids_context || null,
            ml_metadata: raw.ml_metadata || (raw.metadata && raw.metadata.ml_metadata) || null
        };
    }

    /**
     * Correlate an incoming security event against the sliding time window for its source_ip
     */
    correlateEvent(rawEvent, context = {}) {
        const event = this._normalizeIncomingEvent(rawEvent);
        if (!event || !event.source_ip || event.source_ip === '0.0.0.0') {
            return { correlated: false, reason: 'missing_source_ip' };
        }

        this.stats.events_ingested += 1;
        const nowMs = event.timestamp ? new Date(event.timestamp).getTime() : Date.now();
        const sourceIp = String(event.source_ip).trim();

        // 1. Deduplication check (unless explicit event_id differs and has distinct command/auth sequence)
        const fp = this._computeFingerprint(event);
        const lastSeenFp = this.dedupCache.get(fp);
        if (lastSeenFp && Math.abs(nowMs - lastSeenFp) < this.dedupWindowMs && event.DuplicateAllow !== true) {
            this.stats.events_deduplicated += 1;
            return {
                correlated: false,
                deduplicated: true,
                fingerprint: fp,
                source_ip: sourceIp
            };
        }
        this.dedupCache.set(fp, nowMs);

        // 2. Insert into sliding time-window index for source_ip
        const windowEvents = this._pruneExpired(sourceIp, nowMs);
        windowEvents.push(event);
        this.windowIndex.set(sourceIp, windowEvents);

        // 3. Evaluate Correlation Rules (CORR-01 through CORR-06)
        const matchedRules = this._evaluateRules(sourceIp, windowEvents, context.threat_intel || event.threat_intel);

        // Also promote single high-confidence deception or critical events into incidents so no honeypot intrusion goes untracked
        const isDirectDeceptionHit = event.source_category === 'deception';
        const isHighSeverityEvent = event.severity === 'HIGH' || event.severity === 'CRITICAL';

        if (matchedRules.length === 0 && !isDirectDeceptionHit && !isHighSeverityEvent) {
            return {
                correlated: false,
                deduplicated: false,
                window_event_count: windowEvents.length,
                source_ip: sourceIp
            };
        }

        // 4. Create or Update Grouped Incident for this source_ip
        const incidentResult = this._createOrUpdateIncident(sourceIp, windowEvents, matchedRules, context);
        return {
            correlated: true,
            deduplicated: false,
            incident_action: incidentResult.action,
            incident: incidentResult.incident,
            matched_rules: matchedRules
        };
    }

    /**
     * Evaluate multi-source, rule-based, and threshold-based correlation rules
     */
    _evaluateRules(sourceIp, events, threatIntel = null) {
        const matched = [];

        const hasNetworkRecon = events.some(e =>
            /PORT_SCAN|RECON|SURICATA_SCAN|SYN_FLOOD/i.test(e.event_type || '') ||
            (e.nids_metadata && /scan|recon/i.test(e.nids_metadata.category || e.nids_metadata.signature || ''))
        );

        const hasHoneypotHit = events.some(e => e.source_category === 'deception' || Boolean(e.honeypot_metadata));

        const cowrieFailedAuths = events.filter(e =>
            e.honeypot_metadata && e.honeypot_metadata.auth_outcome === 'FAILED'
        );

        const hasHoneypotSuccessOrCmd = events.some(e =>
            e.honeypot_metadata && (
                e.honeypot_metadata.auth_outcome === 'SUCCESS' ||
                Boolean(e.honeypot_metadata.command_executed)
            )
        );

        const hasSuricataAlert = events.some(e => e.source_category === 'nids' || e.source_service === 'suricata-event-collector-service');
        const hasMlDetection = events.some(e =>
            e.source_category === 'network' ||
            e.source_service === 'traffic-capture-service' ||
            e.source_service === 'ml-detection-service' ||
            Boolean(e.ml_metadata)
        );

        const hasPayloadOrExfil = events.some(e =>
            (e.honeypot_metadata && Boolean(e.honeypot_metadata.file_sha256)) ||
            /EXFILTRATION|C2|MALWARE_DROP|DATA_THEFT/i.test(e.event_type || '')
        );

        // Rule CORR-01: Network Reconnaissance followed by Honeypot Interaction
        if (hasNetworkRecon && hasHoneypotHit) {
            matched.push({
                rule_id: 'CORR-01',
                name: 'Reconnaissance-to-Deception Progression',
                severity: 'HIGH',
                confidence: 0.94,
                rationale: `Source ${sourceIp} performed network reconnaissance/scanning and subsequently interacted with a deception honeypot sensor within the sliding window.`
            });
            this.stats.rules_triggered['CORR-01'] += 1;
        }

        // Rule CORR-02: Repeated Brute-Force followed by Command Execution or Shell Compromise
        if (cowrieFailedAuths.length >= 2 && hasHoneypotSuccessOrCmd) {
            matched.push({
                rule_id: 'CORR-02',
                name: 'Credential Brute-Force to Interactive Shell Compromise',
                severity: 'CRITICAL',
                confidence: 0.99,
                rationale: `Source ${sourceIp} conducted ${cowrieFailedAuths.length} failed authentication attempt(s) followed by authenticated session compromise and interactive command execution.`
            });
            this.stats.rules_triggered['CORR-02'] += 1;
        }

        // Rule CORR-03: Suricata NIDS Signature + ML Flow Anomaly Convergence
        if (hasSuricataAlert && hasMlDetection) {
            matched.push({
                rule_id: 'CORR-03',
                name: 'NIDS Signature & ML Flow Anomaly Convergence',
                severity: 'HIGH',
                confidence: 0.91,
                rationale: `Corroborated detection from both Suricata EVE signature inspection and 69-feature ML flow classification for source ${sourceIp}.`
            });
            this.stats.rules_triggered['CORR-03'] += 1;
        }

        // Rule CORR-04: Multi-Stage Payload Delivery / C2 / Data Exfiltration
        if (hasPayloadOrExfil && (hasHoneypotHit || hasSuricataAlert || hasMlDetection)) {
            matched.push({
                rule_id: 'CORR-04',
                name: 'Active Malware Staging or Data Exfiltration Kill-Chain',
                severity: 'CRITICAL',
                confidence: 0.98,
                rationale: `Detected malware binary staging (quarantined SHA-256) or C2/exfiltration activity correlated with active session telemetry from ${sourceIp}.`
            });
            this.stats.rules_triggered['CORR-04'] += 1;
        }

        // Rule CORR-05: Known High-Risk Threat Intelligence Actor Correlation
        if (threatIntel && Number(threatIntel.reputation_score || 0) >= 75) {
            matched.push({
                rule_id: 'CORR-05',
                name: 'Known Malicious Threat Actor Activity',
                severity: Number(threatIntel.reputation_score) >= 90 ? 'CRITICAL' : 'HIGH',
                confidence: 0.95,
                rationale: `Indicator ${sourceIp} matches high-confidence threat intelligence (${threatIntel.reputation_score}/100 via ${(threatIntel.sources || []).join(', ')}) during active probing.`
            });
            this.stats.rules_triggered['CORR-05'] += 1;
        }

        // Rule CORR-06: High-Frequency Event Threshold Burst
        if (events.length >= this.burstThreshold) {
            matched.push({
                rule_id: 'CORR-06',
                name: 'Sustained Multi-Event Threshold Burst',
                severity: hasHoneypotHit ? 'HIGH' : 'MEDIUM',
                confidence: 0.85,
                rationale: `Source ${sourceIp} generated ${events.length} security events within the ${Math.round(this.windowMs / 60000)}-minute correlation window (threshold=${this.burstThreshold}).`
            });
            this.stats.rules_triggered['CORR-06'] += 1;
        }

        return matched;
    }

    /**
     * Create a new correlated incident or merge into an existing open incident for source_ip
     */
    _createOrUpdateIncident(sourceIp, windowEvents, matchedRules, context = {}) {
        const existingIncidentId = this.activeIncidentByIp.get(sourceIp);
        let incident = existingIncidentId ? this.incidents.get(existingIncidentId) : null;

        // Check if existing incident is still open and within correlation window
        const nowIso = new Date().toISOString();
        const isReusable = incident && incident.status !== 'CLOSED' && incident.status !== 'RESOLVED';

        // Compute highest severity across events & matched correlation rules
        let maxRank = 2; // Minimum MEDIUM for correlated incidents
        for (const ev of windowEvents) {
            const r = SEVERITY_RANK[ev.severity] || 1;
            if (r > maxRank) maxRank = r;
        }
        for (const rule of matchedRules) {
            const r = SEVERITY_RANK[rule.severity] || 2;
            if (r > maxRank) maxRank = r;
        }
        const computedSeverity = RANK_TO_SEVERITY[maxRank] || 'HIGH';

        // Distinct telemetry sources involved
        const sourcesInvolved = Array.from(new Set(windowEvents.map(e => e.source_service || e.source_category || 'unknown')));
        const categoriesInvolved = Array.from(new Set(windowEvents.map(e => e.event_type || 'SECURITY_EVENT')));
        const eventIds = Array.from(new Set(windowEvents.map(e => e.event_id).filter(Boolean)));
        const targetedServices = Array.from(new Set(
            windowEvents
                .map(e => (e.honeypot_metadata && e.honeypot_metadata.targeted_service) || (e.destination_port ? `PORT_${e.destination_port}` : null))
                .filter(Boolean)
        ));

        // Compute aggregate confidence
        const ruleMaxConf = matchedRules.reduce((acc, r) => Math.max(acc, r.confidence || 0.8), 0.75);
        const multiSourceBonus = sourcesInvolved.length >= 2 ? 0.05 : 0;
        const confidence = Number(Math.min(0.99, ruleMaxConf + multiSourceBonus).toFixed(2));

        const recommendedResponse = this._determineRecommendedResponse(computedSeverity, matchedRules, windowEvents);

        if (!isReusable) {
            const incidentId = crypto.randomUUID();
            incident = {
                incident_id: incidentId,
                title: this._buildIncidentTitle(sourceIp, matchedRules, categoriesInvolved),
                source_ip: sourceIp,
                severity: computedSeverity,
                confidence,
                status: 'OPEN',
                first_seen: windowEvents[0].timestamp || nowIso,
                last_seen: windowEvents[windowEvents.length - 1].timestamp || nowIso,
                created_at: nowIso,
                updated_at: nowIso,
                event_count: windowEvents.length,
                event_ids: eventIds,
                sources_involved: sourcesInvolved,
                attack_categories: categoriesInvolved,
                targeted_services: targetedServices,
                matched_rules: matchedRules,
                correlation_summary: this._buildCorrelationNarrative(sourceIp, windowEvents, matchedRules, sourcesInvolved),
                recommended_action: recommendedResponse,
                events_snapshot: windowEvents.slice(-50)
            };
            this.incidents.set(incidentId, incident);
            this.activeIncidentByIp.set(sourceIp, incidentId);
            this.stats.incidents_created += 1;
            return { action: 'CREATED', incident };
        }

        // Merge into existing incident (prevents duplicate incident storms)
        incident.severity = SEVERITY_RANK[computedSeverity] > SEVERITY_RANK[incident.severity] ? computedSeverity : incident.severity;
        incident.confidence = Math.max(incident.confidence, confidence);
        incident.last_seen = windowEvents[windowEvents.length - 1].timestamp || nowIso;
        incident.updated_at = nowIso;
        incident.event_count = windowEvents.length;
        incident.event_ids = Array.from(new Set([...incident.event_ids, ...eventIds]));
        incident.sources_involved = Array.from(new Set([...incident.sources_involved, ...sourcesInvolved]));
        incident.attack_categories = Array.from(new Set([...incident.attack_categories, ...categoriesInvolved]));
        incident.targeted_services = Array.from(new Set([...incident.targeted_services, ...targetedServices]));

        // Merge unique matched rules
        const existingRuleIds = new Set(incident.matched_rules.map(r => r.rule_id));
        for (const r of matchedRules) {
            if (!existingRuleIds.has(r.rule_id)) {
                incident.matched_rules.push(r);
                existingRuleIds.add(r.rule_id);
            }
        }

        incident.title = this._buildIncidentTitle(sourceIp, incident.matched_rules, incident.attack_categories);
        incident.correlation_summary = this._buildCorrelationNarrative(
            sourceIp,
            windowEvents,
            incident.matched_rules,
            incident.sources_involved
        );
        incident.recommended_action = recommendedResponse;
        incident.events_snapshot = windowEvents.slice(-50);

        this.stats.incidents_updated += 1;
        return { action: 'UPDATED', incident };
    }

    _buildIncidentTitle(sourceIp, matchedRules, categories) {
        if (matchedRules && matchedRules.length > 0) {
            const topRule = matchedRules[matchedRules.length - 1];
            return `[${topRule.rule_id}] ${topRule.name} from ${sourceIp}`;
        }
        return `Correlated Security Incident (${categories.slice(0, 2).join(', ')}) from ${sourceIp}`;
    }

    _buildCorrelationNarrative(sourceIp, events, matchedRules, sources) {
        const ruleDescriptions = matchedRules.map(r => `${r.rule_id} (${r.name})`).join('; ');
        return (
            `Correlated ${events.length} security event(s) from indicator ${sourceIp} across ` +
            `${sources.length} telemetry source(s) [${sources.join(', ')}]. ` +
            (ruleDescriptions ? `Triggered correlation rules: ${ruleDescriptions}.` : 'Single-source high-confidence deception/NIDS trigger.')
        );
    }

    _determineRecommendedResponse(severity, matchedRules, events) {
        const hasShellOrPayload = events.some(e =>
            e.honeypot_metadata && (e.honeypot_metadata.command_executed || e.honeypot_metadata.file_sha256)
        );
        if (severity === 'CRITICAL' || hasShellOrPayload) {
            return {
                action: 'ISOLATE_AND_BLOCK_IP',
                lease_minutes: 60,
                deploy_additional_decoys: true,
                notify_soc: true,
                rationale: 'Critical multi-stage intrusion or interactive shell/payload activity confirmed.'
            };
        }
        if (severity === 'HIGH') {
            return {
                action: 'BLOCK_TEMPORARY_AND_REDIRECT_TO_DECOY',
                lease_minutes: 30,
                deploy_additional_decoys: true,
                notify_soc: true,
                rationale: 'High-confidence multi-source correlation triggered.'
            };
        }
        return {
            action: 'ALERT_AND_MONITOR',
            lease_minutes: 0,
            deploy_additional_decoys: false,
            notify_soc: true,
            rationale: 'Medium-severity anomaly or initial probing under observation.'
        };
    }

    getAllIncidents() {
        return Array.from(this.incidents.values()).sort(
            (a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
        );
    }

    getIncident(id) {
        return this.incidents.get(id) || null;
    }

    getStats() {
        return {
            ...this.stats,
            active_ip_windows: this.windowIndex.size,
            total_incidents: this.incidents.size,
            window_ms: this.windowMs
        };
    }
}

module.exports = {
    EventCorrelationEngine
};
