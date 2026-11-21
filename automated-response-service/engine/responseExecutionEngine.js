/**
 * Shadow Guard 2.0 - SOAR Automated Response Execution & Safety Engine
 *
 * Implements production-grade containment and orchestration safety controls:
 *   1. Immutable Critical Infrastructure Allowlist (never block localhost, gateway, DNS, internal services)
 *   2. Timed IP Block Leases with automatic expiration sweeper (`expireLeases`)
 *   3. Manual Operator Approval Queue for high-impact / permanent containment actions
 *   4. One-Click Rollback (`rollbackExecution`) with state restoration
 *   5. Immutable Audit Log for every executed, blocked, expired, approved, or rolled-back action
 */

'use strict';

const crypto = require('crypto');
const net = require('net');

// Core infrastructure IPs that can NEVER be blocked or removed from the allowlist
const IMMUTABLE_ALLOWLIST = new Map([
    ['127.0.0.1', { ip: '127.0.0.1', label: 'IPv4 Loopback', immutable: true }],
    ['::1', { ip: '::1', label: 'IPv6 Loopback', immutable: true }],
    ['10.0.0.1', { ip: '10.0.0.1', label: 'Core Network Default Gateway', immutable: true }],
    ['192.168.1.1', { ip: '192.168.1.1', label: 'Management Subnet Gateway', immutable: true }],
    ['172.28.0.1', { ip: '172.28.0.1', label: 'ShadowGuard Internal Service Bridge', immutable: true }],
    ['8.8.8.8', { ip: '8.8.8.8', label: 'Primary DNS Resolver', immutable: true }],
    ['1.1.1.1', { ip: '1.1.1.1', label: 'Secondary DNS Resolver', immutable: true }]
]);

class ResponseExecutionEngine {
    constructor(options = {}) {
        this.enableLocalIptables = Boolean(options.enableLocalIptables);
        this.iptablesExecutor = options.iptablesExecutor || null;
        this.deceptionCallback = options.deceptionCallback || null;

        // Allowlist: ip -> { ip, label, immutable, added_at }
        this.allowlist = new Map();
        for (const [ip, entry] of IMMUTABLE_ALLOWLIST.entries()) {
            this.allowlist.set(ip, { ...entry, added_at: new Date().toISOString() });
        }

        // Active IP blocks: ip -> BlockLeaseRecord
        this.activeBlocks = new Map();
        // Demo simulated IP blocks (strictly isolated from live activeBlocks): key -> BlockLeaseRecord
        this.demoSimulatedBlocks = new Map();
        // Execution records: execution_id -> ExecutionRecord
        this.executions = new Map();
        // Pending approval queue: execution_id -> ExecutionRecord
        this.pendingApprovals = new Map();
        // Immutable audit trail
        this.auditLog = [];
    }

    isValidIp(ip) {
        return typeof ip === 'string' && net.isIP(ip.trim()) !== 0;
    }

    isAllowlisted(ip) {
        if (!ip) return false;
        return this.allowlist.has(String(ip).trim());
    }

    addAllowlistIp(ip, label = 'Operator Custom Allowlist', operator = 'SOC_ANALYST') {
        const cleanIp = String(ip || '').trim();
        if (!this.isValidIp(cleanIp)) {
            throw new Error(`Invalid IP address '${cleanIp}'`);
        }
        if (IMMUTABLE_ALLOWLIST.has(cleanIp)) {
            return this.allowlist.get(cleanIp);
        }
        const entry = {
            ip: cleanIp,
            label,
            immutable: false,
            added_by: operator,
            added_at: new Date().toISOString()
        };
        this.allowlist.set(cleanIp, entry);
        this._recordAudit('ALLOWLIST_ADDED', entry);
        return entry;
    }

    removeAllowlistIp(ip, operator = 'SOC_ANALYST') {
        const cleanIp = String(ip || '').trim();
        const entry = this.allowlist.get(cleanIp);
        if (!entry) {
            throw new Error(`IP '${cleanIp}' is not in the allowlist`);
        }
        if (entry.immutable) {
            this._recordAudit('ALLOWLIST_REMOVAL_DENIED_IMMUTABLE', { ip: cleanIp, operator });
            throw new Error(`Cannot remove immutable critical infrastructure IP '${cleanIp}' (${entry.label})`);
        }
        this.allowlist.delete(cleanIp);
        this._recordAudit('ALLOWLIST_REMOVED', { ip: cleanIp, operator });
        return { removed: true, ip: cleanIp };
    }

    /**
     * Execute a SOAR response action with full allowlist, approval, and lease controls
     */
    async executeAction(spec = {}) {
        const nowMs = spec.nowMs || Date.now();
        const nowIso = new Date(nowMs).toISOString();
        const actionType = String(spec.action_type || spec.action || 'MONITOR_ONLY').toUpperCase();
        const targetIp = spec.target_ip || spec.source_ip || (spec.details && spec.details.ip) || null;
        const leaseMinutes = Number(spec.lease_minutes || (actionType === 'BLOCK_IP_PERMANENT' ? 0 : 30));
        const requireApproval = Boolean(spec.require_approval || actionType === 'BLOCK_IP_PERMANENT');
        const executionId = `exec-${crypto.randomUUID().slice(0, 8)}`;
        const eventSource = spec.event_source || (spec.details && spec.details.event_source) || null;
        const isDemoEvent = eventSource === 'demo_simulator';
        const sessionId = spec.session_id || (spec.details && spec.details.session_id) || null;
        const flowId = spec.flow_id || (spec.details && spec.details.flow_id) || null;

        const isBlockAction =
            actionType === 'BLOCK' ||
            actionType === 'BLOCK_IP_TEMPORARY' ||
            actionType === 'BLOCK_IP_PERMANENT';

        // 1. Check Immutable & Custom Allowlist before any block action
        if (isBlockAction && targetIp) {
            if (!this.isValidIp(targetIp)) {
                throw new Error(`Invalid IP address for block action: '${targetIp}'`);
            }
            if (this.isAllowlisted(targetIp)) {
                const allowEntry = this.allowlist.get(targetIp.trim());
                const rejectedRecord = {
                    execution_id: executionId,
                    action_type: actionType,
                    target_ip: targetIp,
                    status: 'REJECTED_ALLOWLIST_PROTECTED',
                    reason: `Target IP ${targetIp} is protected by allowlist (${allowEntry.label})`,
                    created_at: nowIso
                };
                this.executions.set(executionId, rejectedRecord);
                this._recordAudit('BLOCK_REJECTED_ALLOWLIST', rejectedRecord);
                return rejectedRecord;
            }
        }

        // 2. Check if Manual Approval is required
        if (requireApproval && !spec.approved_by) {
            const pendingRecord = {
                execution_id: executionId,
                action_type: actionType,
                target_ip: targetIp,
                lease_minutes: leaseMinutes,
                playbook_id: spec.playbook_id || 'MANUAL_OR_SOAR',
                incident_id: spec.incident_id || null,
                status: 'PENDING_APPROVAL',
                requested_by: spec.operator || 'SOAR_ENGINE',
                created_at: nowIso,
                details: spec.details || {}
            };
            this.executions.set(executionId, pendingRecord);
            this.pendingApprovals.set(executionId, pendingRecord);
            this._recordAudit('EXECUTION_QUEUED_FOR_APPROVAL', pendingRecord);
            return pendingRecord;
        }

        // 3. Execute the containment / orchestration action (or simulate in strict Demo Mode)
        const executionRecord = {
            execution_id: executionId,
            action_type: actionType,
            target_ip: targetIp,
            lease_minutes: isBlockAction && actionType !== 'BLOCK_IP_PERMANENT' ? leaseMinutes : null,
            playbook_id: spec.playbook_id || 'SOAR_AUTO',
            incident_id: spec.incident_id || null,
            flow_id: flowId,
            session_id: sessionId,
            event_source: eventSource,
            demo_simulated: isDemoEvent,
            status: isDemoEvent ? (isBlockAction ? 'DEMO_SIMULATED_BLOCK' : 'DEMO_SIMULATED') : 'EXECUTED',
            approved_by: isDemoEvent ? 'DEMO_SIMULATOR_GUARD' : (spec.approved_by || 'AUTO_POLICY'),
            executed_at: nowIso,
            expires_at: null,
            rolled_back_at: null,
            reason: (spec.details && spec.details.reason) || spec.reason || (isDemoEvent ? 'DEMO Simulated SOAR Action' : 'SOAR Automated Containment'),
            details: spec.details || {}
        };

        if (isDemoEvent) {
            if (isBlockAction && targetIp) {
                const isPermanent = actionType === 'BLOCK_IP_PERMANENT';
                const leaseDurationMs = isPermanent ? null : leaseMinutes * 60 * 1000;
                const expiresAtIso = isPermanent ? null : new Date(nowMs + leaseDurationMs).toISOString();
                executionRecord.expires_at = expiresAtIso;

                const demoLease = {
                    ip: targetIp.trim(),
                    execution_id: executionId,
                    flow_id: flowId,
                    session_id: sessionId,
                    event_source: 'demo_simulator',
                    demo_simulated: true,
                    block_type: isPermanent ? 'DEMO_PERMANENT' : 'DEMO_TEMPORARY_LEASE',
                    lease_minutes: isPermanent ? null : leaseMinutes,
                    blocked_at: nowIso,
                    expires_at: expiresAtIso,
                    status: 'DEMO_SIMULATED_BLOCK',
                    reason: executionRecord.reason
                };
                this.demoSimulatedBlocks.set(`${sessionId || 'demo'}:${targetIp.trim()}`, demoLease);
            }
            this.executions.set(executionId, executionRecord);
            this._recordAudit('DEMO_ACTION_SIMULATED', executionRecord);
            return executionRecord;
        }

        if (isBlockAction && targetIp) {
            const isPermanent = actionType === 'BLOCK_IP_PERMANENT';
            const leaseDurationMs = isPermanent ? null : leaseMinutes * 60 * 1000;
            const expiresAtIso = isPermanent ? null : new Date(nowMs + leaseDurationMs).toISOString();
            executionRecord.expires_at = expiresAtIso;

            const blockLease = {
                ip: targetIp.trim(),
                execution_id: executionId,
                block_type: isPermanent ? 'PERMANENT' : 'TEMPORARY_LEASE',
                lease_minutes: isPermanent ? null : leaseMinutes,
                blocked_at: nowIso,
                expires_at: expiresAtIso,
                expires_at_ms: isPermanent ? Infinity : nowMs + leaseDurationMs,
                status: 'ACTIVE_BLOCKED',
                reason: (spec.details && spec.details.reason) || spec.reason || 'SOAR Automated Containment'
            };

            this.activeBlocks.set(targetIp.trim(), blockLease);

            if (this.enableLocalIptables && typeof this.iptablesExecutor === 'function') {
                await this.iptablesExecutor('BLOCK', targetIp.trim());
            }
        } else if (actionType === 'UNBLOCK_IP' && targetIp) {
            this.activeBlocks.delete(targetIp.trim());
            if (this.enableLocalIptables && typeof this.iptablesExecutor === 'function') {
                await this.iptablesExecutor('UNBLOCK', targetIp.trim());
            }
        } else if (actionType === 'DEPLOY_ADDITIONAL_HONEYPOT' && typeof this.deceptionCallback === 'function') {
            try {
                await this.deceptionCallback({
                    source_ip: targetIp,
                    target_policy: spec.target_policy || 'DEC-01'
                });
            } catch (_) {
                // Non-fatal in standalone mode
            }
        }

        this.executions.set(executionId, executionRecord);
        this._recordAudit('ACTION_EXECUTED', executionRecord);
        return executionRecord;
    }

    /**
     * Approve a pending high-impact action in the approval queue
     */
    async approveExecution(executionId, operator = 'SOC_COMMANDER') {
        const pending = this.pendingApprovals.get(executionId);
        if (!pending) {
            throw new Error(`Pending approval '${executionId}' not found`);
        }
        this.pendingApprovals.delete(executionId);

        const executed = await this.executeAction({
            action_type: pending.action_type,
            target_ip: pending.target_ip,
            lease_minutes: pending.lease_minutes,
            playbook_id: pending.playbook_id,
            incident_id: pending.incident_id,
            approved_by: operator,
            details: pending.details
        });

        pending.status = 'APPROVED_AND_EXECUTED';
        pending.approved_by = operator;
        pending.approved_at = new Date().toISOString();
        pending.fulfilled_execution_id = executed.execution_id;

        this._recordAudit('EXECUTION_APPROVED', {
            pending_execution_id: executionId,
            fulfilled_execution_id: executed.execution_id,
            operator
        });
        return executed;
    }

    /**
     * Reject a pending action in the approval queue
     */
    rejectExecution(executionId, operator = 'SOC_COMMANDER', reason = 'Rejected by analyst') {
        const pending = this.pendingApprovals.get(executionId);
        if (!pending) {
            throw new Error(`Pending approval '${executionId}' not found`);
        }
        this.pendingApprovals.delete(executionId);
        pending.status = 'REJECTED_BY_OPERATOR';
        pending.rejected_by = operator;
        pending.rejection_reason = reason;
        pending.rejected_at = new Date().toISOString();

        this._recordAudit('EXECUTION_REJECTED', pending);
        return pending;
    }

    /**
     * One-click rollback of an executed containment action
     */
    async rollbackExecution(executionId, operator = 'SOC_ANALYST', reason = 'Manual operator rollback') {
        const execRecord = this.executions.get(executionId);
        if (!execRecord) {
            throw new Error(`Execution '${executionId}' not found`);
        }
        if (execRecord.status === 'ROLLED_BACK') {
            return execRecord;
        }

        if (execRecord.target_ip && this.activeBlocks.has(execRecord.target_ip)) {
            this.activeBlocks.delete(execRecord.target_ip);
            if (this.enableLocalIptables && typeof this.iptablesExecutor === 'function') {
                await this.iptablesExecutor('UNBLOCK', execRecord.target_ip);
            }
        }

        execRecord.status = 'ROLLED_BACK';
        execRecord.rolled_back_at = new Date().toISOString();
        execRecord.rollback_operator = operator;
        execRecord.rollback_reason = reason;

        this._recordAudit('EXECUTION_ROLLED_BACK', execRecord);
        return execRecord;
    }

    /**
     * Sweep and automatically unblock expired IP block leases
     */
    expireLeases(nowMs = Date.now()) {
        const expiredList = [];
        for (const [ip, lease] of this.activeBlocks.entries()) {
            if (lease.expires_at_ms !== Infinity && nowMs >= lease.expires_at_ms) {
                this.activeBlocks.delete(ip);
                const exec = this.executions.get(lease.execution_id);
                if (exec) {
                    exec.status = 'EXPIRED_UNBLOCKED';
                }
                const expiredRecord = {
                    ...lease,
                    status: 'EXPIRED_UNBLOCKED',
                    unblocked_at: new Date(nowMs).toISOString()
                };
                expiredList.push(expiredRecord);
                this._recordAudit('BLOCK_LEASE_EXPIRED', expiredRecord);
            }
        }
        return expiredList;
    }

    _recordAudit(eventType, details) {
        this.auditLog.unshift({
            audit_id: `resp-aud-${crypto.randomUUID().slice(0, 8)}`,
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
            active_blocks_count: this.activeBlocks.size,
            demo_simulated_blocks_count: this.demoSimulatedBlocks.size,
            pending_approvals_count: this.pendingApprovals.size,
            allowlist_count: this.allowlist.size,
            total_executions: this.executions.size,
            active_blocks: Array.from(this.activeBlocks.values()),
            demo_simulated_blocks: Array.from(this.demoSimulatedBlocks.values()),
            pending_approvals: Array.from(this.pendingApprovals.values()),
            allowlist: Array.from(this.allowlist.values()),
            recent_audit_log: this.auditLog.slice(0, 30)
        };
    }
}

module.exports = {
    ResponseExecutionEngine,
    IMMUTABLE_ALLOWLIST
};
