/**
 * Shadow Guard 2.0 - Policy-Driven Dynamic Deception Management Engine
 *
 * Adapts deception posture dynamically in response to observed threat activity:
 *   - DEC-01 (Port Scanning Detected)          -> Enable additional decoy service ports & recon banners
 *   - DEC-02 (Repeated SSH Brute-Force)        -> Increase Cowrie logging verbosity & deploy SSH honey-breadcrumbs
 *   - DEC-03 (SMB / Database Enumeration)      -> Activate OpenCanary SMB/MySQL decoy shares & lure tables
 *   - DEC-04 (High-Risk Attacker / Payload)    -> Enable Dionaea malware trap & redirect attacker IP to Decoy DMZ
 *
 * Safety & Governance Controls:
 *   - Strict configuration validation against allowed decoy catalog
 *   - Complete audit trail for every automated or manual deception change
 *   - Manual operator override (pause/resume auto-adaptation, force-apply, or rollback any directive)
 */

'use strict';

const crypto = require('crypto');

const ALLOWED_HONEYPOT_IDS = new Set([
    'cowrie-ssh-01',
    'opencanary-multi-01',
    'dionaea-malware-01'
]);

const ALLOWED_DECEPTION_ACTIONS = new Set([
    'ENABLE_DECOY_LISTENERS',
    'INCREASE_COWRIE_LOGGING_AND_BREADCRUMBS',
    'ACTIVATE_SMB_AND_DB_DECOYS',
    'ACTIVATE_MALWARE_TRAP_AND_REDIRECT_ATTACKER',
    'DEPLOY_HONEYTOKEN_BREADCRUMB',
    'CUSTOM_DECOY_RECONFIGURATION'
]);

const DEFAULT_POLICIES = [
    {
        policy_id: 'DEC-01',
        name: 'Reconnaissance & Port Scan Decoy Expansion',
        enabled: true,
        trigger_conditions: {
            attack_categories: ['PORT_SCAN', 'SURICATA_SCAN', 'RECONNAISSANCE', 'sequential_port_scan'],
            min_ports_probed: 3
        },
        target_honeypot_id: 'opencanary-multi-01',
        action_type: 'ENABLE_DECOY_LISTENERS',
        parameters: {
            activate_ports: [21, 80, 445, 3306, 8080],
            banner_profile: 'enterprise-linux-production-v4',
            logging_level: 'DETAILED'
        },
        rationale: 'Port scanning detected; expanding visible decoy surface to absorb reconnaissance and identify attacker tooling.'
    },
    {
        policy_id: 'DEC-02',
        name: 'SSH Brute-Force Deep Session Instrumentation & Breadcrumbs',
        enabled: true,
        trigger_conditions: {
            attack_categories: ['BRUTE_FORCE', 'HONEYPOT_AUTH_FAILURE', 'repeated_auth_attempts'],
            min_failed_logins: 3
        },
        target_honeypot_id: 'cowrie-ssh-01',
        action_type: 'INCREASE_COWRIE_LOGGING_AND_BREADCRUMBS',
        parameters: {
            tty_log_verbosity: 'DEBUG_FULL_KEYSTROKE',
            extend_session_timeout_sec: 900,
            deploy_breadcrumbs: [
                '/home/admin/.ssh/id_rsa_staging.decoy',
                '/etc/db_credentials_canary.conf',
                '/var/backups/k8s_cluster_token.honey'
            ]
        },
        rationale: 'Sustained SSH credential attack detected; elevating Cowrie session capture verbosity and planting tracked honey-breadcrumbs.'
    },
    {
        policy_id: 'DEC-03',
        name: 'SMB & Database Lateral Enumeration Decoy Activation',
        enabled: true,
        trigger_conditions: {
            attack_categories: ['OPEN_CANARY_SMB_PROBE', 'OPEN_CANARY_MYSQL_PROBE', 'SERVICE_ENUM', 'service_enumeration'],
            targeted_ports: [445, 3306, 1433, 5432]
        },
        target_honeypot_id: 'opencanary-multi-01',
        action_type: 'ACTIVATE_SMB_AND_DB_DECOYS',
        parameters: {
            smb_shares: ['\\\\DECOY-CORP\\Finance_Audit_2026', '\\\\DECOY-CORP\\IT_Vault_Backups'],
            mysql_decoy_databases: ['prod_customers_canary', 'iam_tokens_replica'],
            alert_on_read: true
        },
        rationale: 'SMB or database service enumeration detected; exposing high-interaction decoy file shares and database schemas.'
    },
    {
        policy_id: 'DEC-04',
        name: 'High-Risk Threat Actor DMZ Redirection & Malware Quarantine Trap',
        enabled: true,
        trigger_conditions: {
            min_risk_score: 75,
            threat_levels: ['HIGH', 'CRITICAL']
        },
        target_honeypot_id: 'dionaea-malware-01',
        action_type: 'ACTIVATE_MALWARE_TRAP_AND_REDIRECT_ATTACKER',
        parameters: {
            enable_dionaea_capture: true,
            quarantine_mode: 'STRICT_NOEXEC_SHA256',
            network_diversion: 'DNAT_SUSPICIOUS_FLOWS_TO_DECEPTION_DMZ'
        },
        rationale: 'High-risk threat actor or payload dropper confirmed; activating malware capture trap and diverting attacker flows into isolated Deception DMZ.'
    }
];

class AdaptiveDeceptionEngine {
    constructor(options = {}) {
        this.autoAdaptEnabled = options.autoAdaptEnabled !== false;
        this.honeypotManagerCallback = options.honeypotManagerCallback || null;

        this.policies = new Map();
        for (const p of DEFAULT_POLICIES) {
            this.policies.set(p.policy_id, { ...p });
        }

        // Active directives: directive_id -> DirectiveRecord
        this.activeDirectives = new Map();
        // Immutable audit trail
        this.auditLog = [];

        // Track current adaptive state per honeypot
        this.honeypotAdaptiveState = new Map([
            ['cowrie-ssh-01', {
                honeypot_id: 'cowrie-ssh-01',
                logging_level: 'STANDARD',
                breadcrumbs_deployed: [],
                active_directives: []
            }],
            ['opencanary-multi-01', {
                honeypot_id: 'opencanary-multi-01',
                active_ports: [21, 80, 445, 3306],
                smb_shares: [],
                mysql_decoy_databases: [],
                active_directives: []
            }],
            ['dionaea-malware-01', {
                honeypot_id: 'dionaea-malware-01',
                enabled: true,
                quarantine_mode: 'STRICT_NOEXEC_SHA256',
                diverted_attacker_ips: [],
                active_directives: []
            }]
        ]);
    }

    /**
     * Validate a deception directive configuration before applying
     */
    validateDirectiveConfig(config) {
        const errors = [];
        if (!config || typeof config !== 'object') {
            return { valid: false, errors: ['Directive configuration must be an object'] };
        }
        if (!ALLOWED_HONEYPOT_IDS.has(config.target_honeypot_id)) {
            errors.push(`Unsupported target_honeypot_id '${config.target_honeypot_id}'. Allowed: ${Array.from(ALLOWED_HONEYPOT_IDS).join(', ')}`);
        }
        if (!ALLOWED_DECEPTION_ACTIONS.has(config.action_type)) {
            errors.push(`Unsupported action_type '${config.action_type}'. Allowed: ${Array.from(ALLOWED_DECEPTION_ACTIONS).join(', ')}`);
        }
        if (config.parameters && typeof config.parameters !== 'object') {
            errors.push('Directive parameters must be a valid object');
        }
        return {
            valid: errors.length === 0,
            errors
        };
    }

    /**
     * Evaluate incoming threat telemetry (event, attacker profile, or correlated incident)
     * and trigger matching adaptive deception policies.
     */
    async evaluateAndAdapt(telemetry = {}) {
        if (!this.autoAdaptEnabled && !telemetry.force_manual) {
            return {
                adapted: false,
                reason: 'Automatic deception adaptation is currently paused by operator override',
                directives: []
            };
        }

        const sourceIp = telemetry.source_ip ||
            (telemetry.profile && telemetry.profile.source_ip) ||
            (telemetry.incident && telemetry.incident.source_ip) ||
            '0.0.0.0';

        // Collect all observed categories, ports, failed logins, and risk scores
        const categories = new Set();
        const ports = new Set();
        let failedLogins = Number(telemetry.failed_logins || 0);
        let riskScore = Number(telemetry.risk_score || 0);
        let threatLevel = String(telemetry.threat_level || telemetry.severity || 'LOW').toUpperCase();

        if (telemetry.event_type) categories.add(telemetry.event_type);
        if (Array.isArray(telemetry.attack_categories)) {
            telemetry.attack_categories.forEach(c => categories.add(c));
        }
        if (Array.isArray(telemetry.behavioural_patterns)) {
            telemetry.behavioural_patterns.forEach(p => categories.add(p.pattern_id || p));
        }
        if (telemetry.destination_port) ports.add(Number(telemetry.destination_port));
        if (Array.isArray(telemetry.ports_targeted)) {
            telemetry.ports_targeted.forEach(p => ports.add(Number(p)));
        }

        if (telemetry.profile) {
            const p = telemetry.profile;
            (p.attack_categories || []).forEach(c => categories.add(c));
            (p.behavioural_patterns || []).forEach(bp => categories.add(bp.pattern_id || bp));
            (p.ports_targeted || []).forEach(pt => ports.add(Number(pt)));
            failedLogins = Math.max(failedLogins, Number(p.failed_logins || 0));
            if (p.risk_assessment) {
                riskScore = Math.max(riskScore, Number(p.risk_assessment.final_score || 0));
                threatLevel = p.risk_assessment.threat_level || threatLevel;
            }
        }

        if (telemetry.incident) {
            const inc = telemetry.incident;
            (inc.attack_categories || []).forEach(c => categories.add(c));
            threatLevel = inc.severity || threatLevel;
            if (inc.severity === 'CRITICAL') riskScore = Math.max(riskScore, 90);
            else if (inc.severity === 'HIGH') riskScore = Math.max(riskScore, 75);
        }

        const matchedPolicies = [];

        // Check DEC-01: Port scanning
        const dec01 = this.policies.get('DEC-01');
        if (dec01 && dec01.enabled) {
            const hasScanCat = dec01.trigger_conditions.attack_categories.some(c => categories.has(c));
            if (hasScanCat || ports.size >= dec01.trigger_conditions.min_ports_probed) {
                matchedPolicies.push(dec01);
            }
        }

        // Check DEC-02: SSH Brute-Force
        const dec02 = this.policies.get('DEC-02');
        if (dec02 && dec02.enabled) {
            const hasAuthCat = dec02.trigger_conditions.attack_categories.some(c => categories.has(c));
            if (hasAuthCat || failedLogins >= dec02.trigger_conditions.min_failed_logins) {
                matchedPolicies.push(dec02);
            }
        }

        // Check DEC-03: SMB or DB Enumeration
        const dec03 = this.policies.get('DEC-03');
        if (dec03 && dec03.enabled) {
            const hasEnumCat = dec03.trigger_conditions.attack_categories.some(c => categories.has(c));
            const hasDbOrSmbPort = dec03.trigger_conditions.targeted_ports.some(p => ports.has(p));
            if (hasEnumCat || hasDbOrSmbPort) {
                matchedPolicies.push(dec03);
            }
        }

        // Check DEC-04: High-risk attacker / Malware trap & redirection
        const dec04 = this.policies.get('DEC-04');
        if (dec04 && dec04.enabled) {
            if (
                riskScore >= dec04.trigger_conditions.min_risk_score ||
                dec04.trigger_conditions.threat_levels.includes(threatLevel)
            ) {
                matchedPolicies.push(dec04);
            }
        }

        const appliedDirectives = [];
        for (const policy of matchedPolicies) {
            const directive = await this.applyDirective({
                policy_id: policy.policy_id,
                policy_name: policy.name,
                trigger_source_ip: sourceIp,
                target_honeypot_id: policy.target_honeypot_id,
                action_type: policy.action_type,
                parameters: policy.parameters,
                rationale: policy.rationale,
                operator: 'SYSTEM_ADAPTIVE_POLICY'
            });
            appliedDirectives.push(directive);
        }

        return {
            adapted: appliedDirectives.length > 0,
            source_ip: sourceIp,
            matched_policy_ids: matchedPolicies.map(p => p.policy_id),
            directives: appliedDirectives
        };
    }

    /**
     * Validate and apply a deception directive (either policy-triggered or manual override)
     */
    async applyDirective(spec) {
        const validation = this.validateDirectiveConfig(spec);
        if (!validation.valid) {
            throw new Error(`Invalid deception directive: ${validation.errors.join('; ')}`);
        }

        const nowIso = new Date().toISOString();
        const directiveId = `dec-dir-${crypto.randomUUID().slice(0, 8)}`;

        // Capture previous state snapshot for deterministic rollback
        const hpState = this.honeypotAdaptiveState.get(spec.target_honeypot_id);
        const previousSnapshot = hpState ? JSON.parse(JSON.stringify(hpState)) : null;

        // Mutate adaptive state
        if (hpState) {
            if (spec.action_type === 'ENABLE_DECOY_LISTENERS' && spec.parameters.activate_ports) {
                hpState.active_ports = Array.from(new Set([...(hpState.active_ports || []), ...spec.parameters.activate_ports]));
                hpState.banner_profile = spec.parameters.banner_profile || hpState.banner_profile;
            } else if (spec.action_type === 'INCREASE_COWRIE_LOGGING_AND_BREADCRUMBS') {
                hpState.logging_level = spec.parameters.tty_log_verbosity || 'DEBUG_FULL_KEYSTROKE';
                hpState.breadcrumbs_deployed = Array.from(
                    new Set([...(hpState.breadcrumbs_deployed || []), ...(spec.parameters.deploy_breadcrumbs || [])])
                );
            } else if (spec.action_type === 'ACTIVATE_SMB_AND_DB_DECOYS') {
                hpState.smb_shares = Array.from(new Set([...(hpState.smb_shares || []), ...(spec.parameters.smb_shares || [])]));
                hpState.mysql_decoy_databases = Array.from(
                    new Set([...(hpState.mysql_decoy_databases || []), ...(spec.parameters.mysql_decoy_databases || [])])
                );
            } else if (spec.action_type === 'ACTIVATE_MALWARE_TRAP_AND_REDIRECT_ATTACKER') {
                hpState.enabled = true;
                hpState.quarantine_mode = spec.parameters.quarantine_mode || 'STRICT_NOEXEC_SHA256';
                if (spec.trigger_source_ip && spec.trigger_source_ip !== '0.0.0.0') {
                    if (!hpState.diverted_attacker_ips.includes(spec.trigger_source_ip)) {
                        hpState.diverted_attacker_ips.push(spec.trigger_source_ip);
                    }
                }
            }
            hpState.active_directives.push(directiveId);
        }

        const directive = {
            directive_id: directiveId,
            policy_id: spec.policy_id || 'MANUAL_OVERRIDE',
            policy_name: spec.policy_name || 'Operator Manual Deception Directive',
            trigger_source_ip: spec.trigger_source_ip || 'MANUAL',
            target_honeypot_id: spec.target_honeypot_id,
            action_type: spec.action_type,
            parameters: spec.parameters || {},
            rationale: spec.rationale || 'Manual operator override',
            operator: spec.operator || 'SOC_ANALYST',
            status: 'ACTIVE',
            applied_at: nowIso,
            rolled_back_at: null,
            previous_state_snapshot: previousSnapshot
        };

        this.activeDirectives.set(directiveId, directive);
        this._recordAudit('DIRECTIVE_APPLIED', directive);

        if (typeof this.honeypotManagerCallback === 'function') {
            try {
                await this.honeypotManagerCallback(directive);
            } catch (_) {
                // Non-fatal in standalone mode
            }
        }

        return directive;
    }

    /**
     * Roll back an active deception directive and restore prior decoy state
     */
    rollbackDirective(directiveId, operator = 'SOC_ANALYST', reason = 'Manual operator rollback') {
        const directive = this.activeDirectives.get(directiveId);
        if (!directive) {
            throw new Error(`Deception directive '${directiveId}' not found`);
        }
        if (directive.status === 'ROLLED_BACK') {
            return directive;
        }

        if (directive.previous_state_snapshot) {
            this.honeypotAdaptiveState.set(
                directive.target_honeypot_id,
                JSON.parse(JSON.stringify(directive.previous_state_snapshot))
            );
        }

        directive.status = 'ROLLED_BACK';
        directive.rolled_back_at = new Date().toISOString();
        directive.rollback_operator = operator;
        directive.rollback_reason = reason;

        this._recordAudit('DIRECTIVE_ROLLED_BACK', directive);
        return directive;
    }

    setAutoAdaptMode(enabled, operator = 'SOC_ANALYST') {
        this.autoAdaptEnabled = Boolean(enabled);
        this._recordAudit(this.autoAdaptEnabled ? 'AUTO_ADAPT_RESUMED' : 'AUTO_ADAPT_PAUSED', {
            operator,
            auto_adapt_enabled: this.autoAdaptEnabled
        });
        return { auto_adapt_enabled: this.autoAdaptEnabled, operator };
    }

    _recordAudit(eventType, details) {
        this.auditLog.unshift({
            audit_id: `aud-${crypto.randomUUID().slice(0, 8)}`,
            event_type: eventType,
            timestamp: new Date().toISOString(),
            details
        });
        if (this.auditLog.length > 500) {
            this.auditLog.length = 500;
        }
    }

    getStatusSummary() {
        return {
            auto_adapt_enabled: this.autoAdaptEnabled,
            total_policies: this.policies.size,
            active_directives_count: Array.from(this.activeDirectives.values()).filter(d => d.status === 'ACTIVE').length,
            total_directives_issued: this.activeDirectives.size,
            honeypot_states: Object.fromEntries(this.honeypotAdaptiveState.entries()),
            policies: Array.from(this.policies.values()),
            recent_audit_log: this.auditLog.slice(0, 30)
        };
    }
}

module.exports = {
    AdaptiveDeceptionEngine,
    DEFAULT_POLICIES,
    ALLOWED_HONEYPOT_IDS,
    ALLOWED_DECEPTION_ACTIONS
};
