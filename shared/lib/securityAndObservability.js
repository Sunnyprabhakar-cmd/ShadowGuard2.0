/**
 * Shadow Guard 2.0 - Security Hardening (JWT/HMAC Auth, RBAC, Rate-Limiting)
 * & Observability (Prometheus Metrics & Structured Audit Logger)
 *
 * Zero-dependency implementation using Node.js built-in `crypto` so it runs
 * both inside Docker containers and natively on the host.
 */

'use strict';

const crypto = require('crypto');

const ROLE_HIERARCHY = {
    VIEWER: 1,
    ANALYST: 2,
    SOC_ANALYST: 2,
    ADMIN: 3
};

class SecurityAndObservabilityManager {
    constructor(options = {}) {
        this.jwtSecret = options.jwtSecret || process.env.SG_JWT_SECRET || 'shadowguard-v2-hmac-secret-key-2026';
        this.serviceApiKey = options.serviceApiKey || process.env.SG_SERVICE_API_KEY || 'sg-internal-service-key-2026';
        this.strictAuth = options.strictAuth ?? (process.env.REQUIRE_STRICT_AUTH === 'true');
        this.rateLimitMax = options.rateLimitMax || Number(process.env.RATE_LIMIT_MAX_PER_MIN || 300);

        // Rate limiting map: clientIp -> { count, windowStart }
        this.rateLimitBuckets = new Map();
        // Security audit trail
        this.securityAuditLog = [];
    }

    /**
     * Issue a signed HMAC-SHA256 JWT token
     */
    issueToken(payload = {}, expiresInSec = 3600) {
        const header = { alg: 'HS256', typ: 'JWT' };
        const nowSec = Math.floor(Date.now() / 1000);
        const body = {
            sub: payload.sub || 'soc-operator',
            role: payload.role || 'SOC_ANALYST',
            iat: nowSec,
            exp: nowSec + expiresInSec
        };

        const b64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
        const b64Payload = Buffer.from(JSON.stringify(body)).toString('base64url');
        const signingInput = `${b64Header}.${b64Payload}`;
        const signature = crypto
            .createHmac('sha256', this.jwtSecret)
            .update(signingInput)
            .digest('base64url');

        return `${signingInput}.${signature}`;
    }

    /**
     * Verify a signed HMAC-SHA256 JWT token
     */
    verifyToken(token) {
        if (!token || typeof token !== 'string') {
            return { valid: false, reason: 'missing_token' };
        }
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, reason: 'malformed_jwt' };
        }
        const [b64Header, b64Payload, signature] = parts;
        const signingInput = `${b64Header}.${b64Payload}`;
        const expectedSig = crypto
            .createHmac('sha256', this.jwtSecret)
            .update(signingInput)
            .digest('base64url');

        if (signature !== expectedSig) {
            return { valid: false, reason: 'invalid_signature' };
        }

        try {
            const decoded = JSON.parse(Buffer.from(b64Payload, 'base64url').toString('utf8'));
            const nowSec = Math.floor(Date.now() / 1000);
            if (decoded.exp && nowSec > decoded.exp) {
                return { valid: false, reason: 'token_expired' };
            }
            return { valid: true, claims: decoded };
        } catch (err) {
            return { valid: false, reason: 'invalid_payload_json' };
        }
    }

    /**
     * Check RBAC role permission against minimum required role
     */
    hasRolePermission(userRole, minRequiredRole = 'VIEWER') {
        const userRank = ROLE_HIERARCHY[String(userRole || '').toUpperCase()] || 0;
        const reqRank = ROLE_HIERARCHY[String(minRequiredRole || 'VIEWER').toUpperCase()] || 1;
        return userRank >= reqRank;
    }

    /**
     * Express middleware for RBAC & JWT / API-Key Authentication
     */
    requireRole(minRole = 'SOC_ANALYST') {
        return (req, res, next) => {
            const authHeader = req.headers.authorization || '';
            const apiKeyHeader = req.headers['x-api-key'] || '';
            const roleHeader = req.headers['x-soc-role'] || '';

            // 1. Check internal service API key
            if (apiKeyHeader && apiKeyHeader === this.serviceApiKey) {
                req.user = { sub: 'internal-service', role: 'ADMIN', auth_method: 'API_KEY' };
                return next();
            }

            // 2. Check Bearer JWT token
            if (authHeader.startsWith('Bearer ')) {
                const token = authHeader.slice(7).trim();
                const verified = this.verifyToken(token);
                if (!verified.valid) {
                    this.recordSecurityAudit('AUTH_FAILURE', {
                        reason: verified.reason,
                        path: req.path,
                        ip: req.ip
                    });
                    return res.status(401).json({ status: 'error', message: `Authentication failed: ${verified.reason}` });
                }
                if (!this.hasRolePermission(verified.claims.role, minRole)) {
                    this.recordSecurityAudit('RBAC_DENIED', {
                        sub: verified.claims.sub,
                        user_role: verified.claims.role,
                        required_role: minRole,
                        path: req.path
                    });
                    return res.status(403).json({
                        status: 'error',
                        message: `Insufficient role '${verified.claims.role}'. Requires '${minRole}' or higher.`
                    });
                }
                req.user = { ...verified.claims, auth_method: 'JWT' };
                return next();
            }

            // 3. If strictAuth is disabled (default interactive dashboard mode), honor X-SOC-Role or default to ADMIN
            if (!this.strictAuth) {
                const effectiveRole = roleHeader ? String(roleHeader).toUpperCase() : 'ADMIN';
                if (!this.hasRolePermission(effectiveRole, minRole)) {
                    this.recordSecurityAudit('RBAC_DENIED', {
                        sub: 'dashboard-operator',
                        user_role: effectiveRole,
                        required_role: minRole,
                        path: req.path
                    });
                    return res.status(403).json({
                        status: 'error',
                        message: `Insufficient role '${effectiveRole}'. Requires '${minRole}' or higher.`
                    });
                }
                req.user = { sub: 'dashboard-operator', role: effectiveRole, auth_method: 'SESSION_DEFAULT' };
                return next();
            }

            this.recordSecurityAudit('AUTH_MISSING', { path: req.path, ip: req.ip });
            return res.status(401).json({ status: 'error', message: 'Missing Authorization Bearer token or X-API-Key' });
        };
    }

    /**
     * Express middleware for per-IP rate limiting
     */
    rateLimitMiddleware() {
        return (req, res, next) => {
            const clientIp = req.ip || req.connection?.remoteAddress || '127.0.0.1';
            const now = Date.now();
            let bucket = this.rateLimitBuckets.get(clientIp);
            if (!bucket || now - bucket.windowStart >= 60000) {
                bucket = { count: 0, windowStart: now };
            }
            bucket.count += 1;
            this.rateLimitBuckets.set(clientIp, bucket);

            const remaining = Math.max(0, this.rateLimitMax - bucket.count);
            res.setHeader('X-RateLimit-Limit', String(this.rateLimitMax));
            res.setHeader('X-RateLimit-Remaining', String(remaining));

            if (bucket.count > this.rateLimitMax) {
                this.recordSecurityAudit('RATE_LIMIT_EXCEEDED', { client_ip: clientIp, path: req.path });
                return res.status(429).json({
                    status: 'error',
                    message: 'Rate limit exceeded. Please retry after current 60s window.'
                });
            }
            next();
        };
    }

    recordSecurityAudit(eventType, details = {}) {
        const entry = {
            audit_id: `sec-aud-${crypto.randomUUID().slice(0, 8)}`,
            event_type: eventType,
            timestamp: new Date().toISOString(),
            details
        };
        this.securityAuditLog.unshift(entry);
        if (this.securityAuditLog.length > 500) {
            this.securityAuditLog.length = 500;
        }
        return entry;
    }

    /**
     * Generate Prometheus exposition format metrics (`/metrics`)
     */
    formatPrometheusMetrics(snapshot = {}) {
        const lines = [
            '# HELP shadowguard_events_processed_total Total number of security telemetry events processed',
            '# TYPE shadowguard_events_processed_total counter',
            `shadowguard_events_processed_total ${Number(snapshot.events_processed || 0)}`,
            '',
            '# HELP shadowguard_threats_detected_total Total number of malicious threats detected',
            '# TYPE shadowguard_threats_detected_total counter',
            `shadowguard_threats_detected_total ${Number(snapshot.threats_detected || 0)}`,
            '',
            '# HELP shadowguard_honeypot_interactions_total Total number of deception honeypot interactions',
            '# TYPE shadowguard_honeypot_interactions_total counter',
            `shadowguard_honeypot_interactions_total ${Number(snapshot.honeypot_interactions || 0)}`,
            '',
            '# HELP shadowguard_active_incidents_gauge Current number of open correlated security incidents',
            '# TYPE shadowguard_active_incidents_gauge gauge',
            `shadowguard_active_incidents_gauge ${Number(snapshot.active_incidents || 0)}`,
            '',
            '# HELP shadowguard_tracked_attacker_profiles_gauge Current number of tracked attacker profiles',
            '# TYPE shadowguard_tracked_attacker_profiles_gauge gauge',
            `shadowguard_tracked_attacker_profiles_gauge ${Number(snapshot.attacker_profiles || 0)}`,
            '',
            '# HELP shadowguard_active_ip_blocks_gauge Current number of active firewall IP block leases',
            '# TYPE shadowguard_active_ip_blocks_gauge gauge',
            `shadowguard_active_ip_blocks_gauge ${Number(snapshot.active_ip_blocks || 0)}`,
            '',
            '# HELP shadowguard_adaptive_deception_directives_gauge Active adaptive deception directives',
            '# TYPE shadowguard_adaptive_deception_directives_gauge gauge',
            `shadowguard_adaptive_deception_directives_gauge ${Number(snapshot.active_deception_directives || 0)}`,
            '',
            '# HELP shadowguard_dashboard_ws_clients_gauge Active WebSocket clients connected to SOC Dashboard',
            '# TYPE shadowguard_dashboard_ws_clients_gauge gauge',
            `shadowguard_dashboard_ws_clients_gauge ${Number(snapshot.active_connections || 0)}`
        ];

        if (snapshot.service_health && typeof snapshot.service_health === 'object') {
            lines.push('');
            lines.push('# HELP shadowguard_service_up Health status of Shadow Guard microservices (1=healthy, 0=unhealthy)');
            lines.push('# TYPE shadowguard_service_up gauge');
            for (const [svc, info] of Object.entries(snapshot.service_health)) {
                const upVal = info && info.status === 'healthy' ? 1 : 0;
                lines.push(`shadowguard_service_up{service="${svc}"} ${upVal}`);
            }
        }

        return lines.join('\n') + '\n';
    }
}

module.exports = {
    SecurityAndObservabilityManager,
    ROLE_HIERARCHY
};
