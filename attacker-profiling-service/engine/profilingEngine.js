/**
 * Shadow Guard 2.0 - Attacker Behaviour Profiling & Explainable Risk Scoring Engine
 *
 * Tracks source IP indicators across Network Flow ML, Suricata NIDS, and Multi-Type Honeypots.
 *
 * Architectural Safeguards:
 *  - Explicitly treats Source IP as an observed network indicator (NAT/Proxy/VPN/Botnet aware).
 *  - Zero credential retention: records attempted usernames and failure/success counts only;
 *    strips any password or hash field if present.
 *  - Explainable Risk Scoring (0-100): every point added to the risk score is backed by a named
 *    factor, explicit weight, rationale, and supporting event_id references.
 */

'use strict';

const crypto = require('crypto');

const SUSPICIOUS_COMMAND_PATTERNS = [
    { regex: /\b(wget|curl|tftp|ftpget)\b/i, tag: 'PAYLOAD_DOWNLOADER' },
    { regex: /\b(chmod\s+\+x|chmod\s+777)\b/i, tag: 'EXECUTION_PREPARATION' },
    { regex: /\/etc\/passwd|\/etc\/shadow/i, tag: 'CREDENTIAL_FILE_ACCESS' },
    { regex: /\b(uname\s+-a|cat\s+\/proc\/cpuinfo|lscpu|id|whoami)\b/i, tag: 'SYSTEM_DISCOVERY' },
    { regex: /\b(nc|ncat|netcat|bash\s+-i|\/dev\/tcp\/)\b/i, tag: 'REVERSE_SHELL' },
    { regex: /\b( crontab |systemctl|init\.d|rc\.local)\b/i, tag: 'PERSISTENCE_ATTEMPT' },
    { regex: /\b(iptables\s+-F|ufw\s+disable|setenforce\s+0)\b/i, tag: 'DEFENSE_EVASION' }
];

class AttackerProfilingEngine {
    constructor(options = {}) {
        this.profiles = new Map(); // source_ip -> profile object
        this.intelLookupFn = options.intelLookupFn || null;
    }

    /**
     * Deterministically generate profile UUID from source IP
     */
    _profileIdForIp(ip) {
        const hash = crypto.createHash('sha256').update(`sg-profile:${ip}`).digest('hex');
        return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
    }

    /**
     * Get or initialize an Attacker Profile for a source IP
     */
    getOrCreateProfile(sourceIp, timestamp = new Date().toISOString()) {
        const ip = String(sourceIp || '').trim();
        if (!ip) throw new Error('source_ip is required for attacker profiling');

        if (!this.profiles.has(ip)) {
            this.profiles.set(ip, {
                id: this._profileIdForIp(ip),
                source_ip: ip,
                indicator_disclaimer: 'Observed network indicator (source_ip). May represent a NAT gateway, VPN/Tor exit node, proxy, or compromised botnet host rather than a single human operator.',
                first_seen: timestamp,
                last_seen: timestamp,
                total_connections: 0,
                honeypot_sessions: 0,
                honeypots_touched: [],
                failed_logins: 0,
                successful_logins: 0,
                usernames_attempted: [],
                commands_observed: [],
                downloaded_files: [],
                services_targeted: [],
                ports_targeted: [],
                attack_categories: [],
                behavioural_patterns: [],
                related_event_ids: [],
                related_incident_ids: [],
                observation_windows: [],
                threat_intel: null,
                risk_assessment: {
                    final_score: 0,
                    threat_level: 'LOW',
                    confidence: 0.50,
                    recommended_action: 'MONITOR',
                    contributing_factors: [],
                    evidence_references: []
                },
                status: 'ACTIVE'
            });
        }
        return this.profiles.get(ip);
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
            honeypot_metadata: raw.honeypot_metadata || raw.deception_context || (raw.raw_context && raw.raw_context.honeypot_metadata) || null,
            nids_metadata: raw.nids_metadata || raw.nids_context || null
        };
    }

    /**
     * Ingest a normalized security event and update the attacker profile,
     * behavioural pattern flags, and explainable risk assessment.
     */
    async ingestEvent(rawEvent, externalIntel = null) {
        const event = this._normalizeIncomingEvent(rawEvent);
        if (!event || !event.source_ip || event.source_ip === '0.0.0.0') {
            return null;
        }

        const ts = event.timestamp || new Date().toISOString();
        const profile = this.getOrCreateProfile(event.source_ip, ts);

        // Update timestamps & time window buckets (5-minute window buckets to detect temporal persistence)
        if (new Date(ts) < new Date(profile.first_seen)) profile.first_seen = ts;
        if (new Date(ts) > new Date(profile.last_seen)) profile.last_seen = ts;

        const windowBucket = Math.floor(new Date(ts).getTime() / (5 * 60 * 1000));
        if (!profile.observation_windows.includes(windowBucket)) {
            profile.observation_windows.push(windowBucket);
        }

        profile.total_connections += 1;

        // Track event ID reference (cap at 200 most recent for memory safety)
        if (event.event_id && !profile.related_event_ids.includes(event.event_id)) {
            profile.related_event_ids.push(event.event_id);
            if (profile.related_event_ids.length > 200) {
                profile.related_event_ids.shift();
            }
        }

        // Track targeted service & destination port
        const dstPort = Number(event.destination_port || 0);
        if (dstPort > 0 && !profile.ports_targeted.includes(dstPort)) {
            profile.ports_targeted.push(dstPort);
        }

        const serviceName = this._inferServiceName(event);
        if (serviceName && !profile.services_targeted.includes(serviceName)) {
            profile.services_targeted.push(serviceName);
        }

        // Track attack category
        const category = event.event_type || (event.ml_Metadata && event.ml_Metadata.attack_type);
        if (category && category !== 'NORMAL' && !profile.attack_categories.includes(category)) {
            profile.attack_categories.push(category);
        }

        // Process Honeypot / Deception Telemetry (strictly privacy-preserving)
        const hpMeta = event.honeypot_metadata || (event.raw_context && event.raw_context.honeypot_metadata);
        if (event.source_category === 'deception' || hpMeta) {
            profile.honeypot_sessions += 1;
            const hpId = (hpMeta && (hpMeta.honeypot_id || hpMeta.honeypot_type)) || event.source_service || 'honeypot-generic';
            if (!profile.honeypots_touched.includes(hpId)) {
                profile.honeypots_touched.push(hpId);
            }

            if (hpMeta) {
                if (hpMeta.auth_outcome === 'FAILED') {
                    profile.failed_logins += Number(hpMeta.attempt_count || 1);
                } else if (hpMeta.auth_outcome === 'SUCCESS') {
                    profile.successful_logins += 1;
                }

                // Store ONLY username, never passwords or hashes
                if (hpMeta.username_attempted && typeof hpMeta.username_attempted === 'string') {
                    const cleanUser = hpMeta.username_attempted.slice(0, 64);
                    if (!profile.usernames_attempted.includes(cleanUser)) {
                        profile.usernames_attempted.push(cleanUser);
                    }
                }

                // Capture attacker shell commands
                if (hpMeta.command_executed && typeof hpMeta.command_executed === 'string') {
                    const cmd = hpMeta.command_executed.trim();
                    if (cmd && !profile.commands_observed.includes(cmd)) {
                        profile.commands_observed.push(cmd);
                    }
                }

                // Capture malware download metadata (hash + filename only, never executed)
                if (hpMeta.file_sha256) {
                    const exists = profile.downloaded_files.some(f => f.sha256 === hpMeta.file_sha256);
                    if (!exists) {
                        profile.downloaded_files.push({
                            sha256: hpMeta.file_sha256,
                            filename: hpMeta.file_name || 'captured_sample.bin',
                            url: hpMeta.download_url || null,
                            quarantined: true,
                            observed_at: ts
                        });
                    }
                }
            }
        }

        // Update Threat Intelligence if provided or lookup callback configured
        if (externalIntel) {
            profile.threat_intel = externalIntel;
        } else if (!profile.threat_intel && typeof this.intelLookupFn === 'function') {
            try {
                profile.threat_intel = await this.intelLookupFn(profile.source_ip, {
                    honeypot_hit: profile.honeypot_sessions > 0
                });
            } catch (_) {
                // Non-fatal if intel service unreachable
            }
        }

        // Re-evaluate Behavioural Patterns & Explainable Risk Assessment
        profile.behavioural_patterns = this._evaluateBehaviouralPatterns(profile);
        profile.risk_assessment = this._computeExplainableRiskScore(profile);

        return profile;
    }

    /**
     * Link an Incident ID to an Attacker Profile
     */
    linkIncident(sourceIp, incidentId) {
        if (!sourceIp || !incidentId) return null;
        const profile = this.getOrCreateProfile(sourceIp);
        if (!profile.related_incident_ids.includes(incidentId)) {
            profile.related_incident_ids.push(incidentId);
        }
        return profile;
    }

    _inferServiceName(event) {
        if (event.honeypot_metadata && event.honeypot_metadata.targeted_service) {
            return String(event.honeypot_metadata.targeted_service).toUpperCase();
        }
        const portMap = {
            21: 'FTP',
            22: 'SSH',
            2222: 'SSH-COWRIE',
            23: 'TELNET',
            2223: 'TELNET-COWRIE',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MYSQL',
            5432: 'POSTGRESQL',
            6379: 'REDIS',
            8080: 'HTTP-ALT'
        };
        const p = Number(event.destination_port || 0);
        return portMap[p] || (event.protocol ? String(event.protocol).toUpperCase() : null);
    }

    /**
     * Detect higher-level behavioural patterns from aggregated telemetry
     */
    _evaluateBehaviouralPatterns(profile) {
        const patterns = [];

        // 1. Repeated authentication attempts
        if (profile.failed_logins >= 3 || profile.attack_categories.some(c => /BRUTE_FORCE|AUTH_FAILURE/i.test(c))) {
            patterns.push({
                pattern_id: 'repeated_auth_attempts',
                name: 'Repeated Authentication Brute-Force',
                description: `Observed ${profile.failed_logins} failed authentication attempts across ${profile.usernames_attempted.length} distinct usernames (${profile.usernames_attempted.slice(0, 5).join(', ') || 'n/a'}).`,
                confidence: 0.95
            });
        }

        // 2. Sequential port scanning
        if (profile.ports_targeted.length >= 4 || profile.attack_categories.some(c => /PORT_SCAN|RECON/i.test(c))) {
            patterns.push({
                pattern_id: 'sequential_port_scan',
                name: 'Sequential Port Scanning',
                description: `Probed ${profile.ports_targeted.length} distinct destination ports (${profile.ports_targeted.slice(0, 8).join(', ')}).`,
                confidence: 0.90
            });
        }

        // 3. Multi-service enumeration
        if (profile.services_targeted.length >= 2) {
            patterns.push({
                pattern_id: 'service_enumeration',
                name: 'Multi-Protocol Service Enumeration',
                description: `Enumerated ${profile.services_targeted.length} distinct network services: ${profile.services_targeted.join(', ')}.`,
                confidence: 0.88
            });
        }

        // 4. Suspicious post-auth command execution
        if (profile.commands_observed.length > 0) {
            const matchedTags = new Set();
            for (const cmd of profile.commands_observed) {
                for (const rule of SUSPICIOUS_COMMAND_PATTERNS) {
                    if (rule.regex.test(cmd)) matchedTags.add(rule.tag);
                }
            }
            patterns.push({
                pattern_id: 'suspicious_command_execution',
                name: 'Interactive Shell Command Execution',
                description: `Executed ${profile.commands_observed.length} commands inside deception shell. Flagged capabilities: ${Array.from(matchedTags).join(', ') || 'SHELL_INTERACTION'}.`,
                confidence: 0.99
            });
        }

        // 5. Cross-honeypot traversal
        if (profile.honeypots_touched.length >= 2) {
            patterns.push({
                pattern_id: 'cross_honeypot_access',
                name: 'Cross-Decoy Lateral Reconnaissance',
                description: `Interacted with ${profile.honeypots_touched.length} independent honeypot sensors (${profile.honeypots_touched.join(', ')}).`,
                confidence: 0.97
            });
        }

        // 6. Malicious file / payload delivery
        if (profile.downloaded_files.length > 0) {
            patterns.push({
                pattern_id: 'malicious_file_download',
                name: 'Malware Payload Dropper Activity',
                description: `Attempted to stage ${profile.downloaded_files.length} payload(s) into quarantine (SHA-256: ${profile.downloaded_files.map(f => f.sha256.slice(0, 12)).join(', ')}...).`,
                confidence: 1.00
            });
        }

        // 7. Temporal persistence across multiple time windows
        if (profile.observation_windows.length >= 2) {
            patterns.push({
                pattern_id: 'temporal_persistence',
                name: 'Multi-Window Temporal Persistence',
                description: `Sustained adversarial activity across ${profile.observation_windows.length} distinct 5-minute observation windows.`,
                confidence: 0.86
            });
        }

        return patterns;
    }

    /**
     * Compute an Explainable Weighted Risk Score (0 - 100) with explicit factor breakdown
     */
    _computeExplainableRiskScore(profile) {
        const factors = [];
        let rawScore = 0;

        // Factor 1: Deception / Honeypot Interaction (Zero-False-Positive Signal, Weight up to 35)
        if (profile.honeypot_sessions > 0) {
            const pts = Math.min(35, 22 + (profile.honeypot_sessions - 1) * 4 + (profile.honeypots_touched.length > 1 ? 8 : 0));
            rawScore += pts;
            factors.push({
                factor: 'DECEPTION_INTERACTION',
                weight: 0.35,
                points_awarded: pts,
                max_points: 35,
                rationale: `Direct interaction with ${profile.honeypots_touched.length} decoy sensor(s) across ${profile.honeypot_sessions} session(s). Legitimate traffic never routes to deception decoys.`
            });
        }

        // Factor 2: Post-Compromise Shell Commands & Payload Staging (Weight up to 25)
        if (profile.commands_observed.length > 0 || profile.downloaded_files.length > 0) {
            let pts = 0;
            if (profile.commands_observed.length > 0) pts += Math.min(15, 10 + profile.commands_observed.length * 2);
            if (profile.downloaded_files.length > 0) pts += 12;
            pts = Math.min(25, pts);
            rawScore += pts;
            factors.push({
                factor: 'POST_AUTH_EXECUTION_AND_PAYLOAD',
                weight: 0.25,
                points_awarded: pts,
                max_points: 25,
                rationale: `Observed ${profile.commands_observed.length} interactive command(s) and ${profile.downloaded_files.length} quarantined payload sample(s).`
            });
        }

        // Factor 3: Credential Brute-Force & Account Enumeration (Weight up to 15)
        if (profile.failed_logins > 0 || profile.successful_logins > 0) {
            const pts = Math.min(15, Math.ceil(profile.failed_logins * 2.5) + (profile.successful_logins * 6));
            rawScore += pts;
            factors.push({
                factor: 'CREDENTIAL_ATTACK_INTENSITY',
                weight: 0.15,
                points_awarded: pts,
                max_points: 15,
                rationale: `${profile.failed_logins} failed and ${profile.successful_logins} successful decoy login(s) targeting ${profile.usernames_attempted.length} username(s).`
            });
        }

        // Factor 4: Network Intrusion & ML Anomaly Categories (Weight up to 15)
        const nonDeceptionCategories = profile.attack_categories.filter(c => !/^HONEYPOT/i.test(c));
        if (nonDeceptionCategories.length > 0 || profile.ports_targeted.length >= 3) {
            const pts = Math.min(15, nonDeceptionCategories.length * 6 + Math.min(6, profile.ports_targeted.length));
            rawScore += pts;
            factors.push({
                factor: 'NETWORK_AND_ML_DETECTIONS',
                weight: 0.15,
                points_awarded: pts,
                max_points: 15,
                rationale: `Triggered ${nonDeceptionCategories.length} attack categories (${nonDeceptionCategories.slice(0, 4).join(', ') || 'PORT_SWEEP'}) across ${profile.ports_targeted.length} port(s).`
            });
        }

        // Factor 5: External Threat Intelligence Reputation (Weight up to 10)
        if (profile.threat_intel && profile.threat_intel.reputation_score > 0) {
            const pts = Math.min(10, Math.round(profile.threat_intel.reputation_score / 10));
            if (pts > 0) {
                rawScore += pts;
                factors.push({
                    factor: 'THREAT_INTELLIGENCE_REPUTATION',
                    weight: 0.10,
                    points_awarded: pts,
                    max_points: 10,
                    rationale: `Threat Intel reputation score ${profile.threat_intel.reputation_score}/100 from [${(profile.threat_intel.sources || []).join(', ')}].`
                });
            }
        }

        const finalScore = Math.min(100, Math.max(0, Math.round(rawScore)));

        let threatLevel = 'LOW';
        let recommendedAction = 'MONITOR';
        if (finalScore >= 80) {
            threatLevel = 'CRITICAL';
            recommendedAction = 'ISOLATE_AND_BLOCK';
        } else if (finalScore >= 60) {
            threatLevel = 'HIGH';
            recommendedAction = 'BLOCK_TEMPORARY_AND_DEPLOY_DECOY';
        } else if (finalScore >= 35) {
            threatLevel = 'MEDIUM';
            recommendedAction = 'ALERT_AND_DEPLOY_DECOY';
        }

        // Confidence increases with multi-source corroboration
        let confidence = 0.55;
        if (profile.honeypot_sessions > 0) confidence += 0.25;
        if (nonDeceptionCategories.length > 0) confidence += 0.10;
        if (profile.threat_intel && profile.threat_intel.is_malicious) confidence += 0.08;
        confidence = Number(Math.min(0.99, confidence).toFixed(2));

        return {
            final_score: finalScore,
            threat_level: threatLevel,
            confidence,
            recommended_action: recommendedAction,
            contributing_factors: factors,
            evidence_references: profile.related_event_ids.slice(-20)
        };
    }

    getAllProfiles() {
        return Array.from(this.profiles.values()).sort(
            (a, b) => b.risk_assessment.final_score - a.risk_assessment.final_score
        );
    }

    getProfile(ip) {
        return this.profiles.get(String(ip || '').trim()) || null;
    }
}

module.exports = {
    AttackerProfilingEngine
};
