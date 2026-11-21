/**
 * Shadow Guard 2.0 - Common Event Contract v2.0
 * Standardized schema definition and validator for all security events.
 */

const crypto = require('crypto');

const VALID_DOMAINS = new Set(['network', 'deception', 'nids', 'intel', 'orchestration']);
const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

/**
 * Creates a normalized event conforming to Common Event Contract v2.0
 */
function createEvent({
  source_domain,
  source_service,
  event_type,
  severity = 'medium',
  confidence = 0.5,
  telemetry = {},
  nids_context = null,
  deception_context = null,
  correlation_context = null,
  metadata = {}
}) {
  if (!VALID_DOMAINS.has(source_domain)) {
    throw new Error(`Invalid source_domain '${source_domain}'. Must be one of: ${[...VALID_DOMAINS].join(', ')}`);
  }

  const normalizedSeverity = String(severity).toLowerCase();
  if (!VALID_SEVERITIES.has(normalizedSeverity)) {
    throw new Error(`Invalid severity '${severity}'. Must be one of: ${[...VALID_SEVERITIES].join(', ')}`);
  }

  return {
    $schema: 'https://shadowguard.io/schemas/event-v2.json',
    event_id: `urn:uuid:${crypto.randomUUID()}`,
    schema_version: '2.0',
    timestamp: new Date().toISOString(),
    source_domain,
    source_service,
    event_type,
    severity: normalizedSeverity,
    confidence: Math.max(0.0, Math.min(1.0, Number(confidence) || 0.5)),
    telemetry: {
      source_ip: telemetry.source_ip || telemetry.src_ip || '0.0.0.0',
      source_port: Number(telemetry.source_port || telemetry.src_port) || null,
      destination_ip: telemetry.destination_ip || telemetry.dst_ip || null,
      destination_port: Number(telemetry.destination_port || telemetry.dst_port) || null,
      protocol: String(telemetry.protocol || 'TCP').toUpperCase(),
      flow_duration_seconds: Number(telemetry.flow_duration_seconds || telemetry.duration) || 0,
      packet_count: Number(telemetry.packet_count || telemetry.packets) || 0,
      byte_count: Number(telemetry.byte_count || telemetry.bytes_sent || telemetry.bytes) || 0,
      ...telemetry
    },
    nids_context,
    deception_context,
    correlation_context: correlation_context || {
      trace_id: `tr-${crypto.randomBytes(6).toString('hex')}`,
      correlation_id: null
    },
    metadata: {
      environment: process.env.NODE_ENV || 'development',
      collector: source_service,
      ...metadata
    }
  };
}

/**
 * Validates whether an incoming event strictly complies with Event Contract v2.0
 */
function validateEvent(event) {
  const errors = [];

  if (!event || typeof event !== 'object') {
    return { valid: false, errors: ['Event must be a non-null JSON object'] };
  }

  if (!event.event_id || typeof event.event_id !== 'string') {
    errors.push('Missing or invalid event_id');
  }

  if (event.schema_version !== '2.0') {
    errors.push(`Unsupported schema_version '${event.schema_version}'. Expected '2.0'`);
  }

  if (!event.timestamp || isNaN(Date.parse(event.timestamp))) {
    errors.push('Missing or invalid ISO-8601 timestamp');
  }

  if (!VALID_DOMAINS.has(event.source_domain)) {
    errors.push(`Invalid source_domain '${event.source_domain}'`);
  }

  if (!event.source_service) {
    errors.push('Missing source_service');
  }

  if (!event.event_type) {
    errors.push('Missing event_type');
  }

  if (!VALID_SEVERITIES.has(String(event.severity).toLowerCase())) {
    errors.push(`Invalid severity '${event.severity}'`);
  }

  if (typeof event.confidence !== 'number' || event.confidence < 0 || event.confidence > 1) {
    errors.push('Confidence must be a number between 0.0 and 1.0');
  }

  if (!event.telemetry || typeof event.telemetry !== 'object') {
    errors.push('Missing telemetry object');
  } else if (!event.telemetry.source_ip) {
    errors.push('telemetry.source_ip is required');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

function createNormalizedEvent(params = {}) {
  const domain = params.source_domain || params.source_category || 'network';
  const base = createEvent({
    source_domain: VALID_DOMAINS.has(domain) ? domain : 'network',
    source_service: params.source_service || 'shadowguard-service',
    event_type: params.event_type || 'SECURITY_EVENT',
    severity: params.severity || 'medium',
    confidence: params.confidence ?? 0.8,
    telemetry: params.telemetry || {
      source_ip: params.source_ip || '0.0.0.0',
      source_port: params.source_port || null,
      destination_ip: params.destination_ip || null,
      destination_port: params.destination_port || null,
      protocol: params.protocol || 'TCP'
    },
    nids_context: params.nids_context || params.nids_metadata || null,
    deception_context: params.deception_context || params.honeypot_metadata || null,
    metadata: params.metadata || {}
  });
  return {
    ...base,
    timestamp: params.timestamp || base.timestamp,
    source_category: domain,
    source_ip: base.telemetry.source_ip,
    destination_ip: base.telemetry.destination_ip,
    destination_port: base.telemetry.destination_port,
    protocol: base.telemetry.protocol,
    severity: String(params.severity || base.severity).toUpperCase(),
    honeypot_metadata: params.honeypot_metadata || params.deception_context || null,
    nids_metadata: params.nids_metadata || params.nids_context || null,
    ml_metadata: params.ml_metadata || null
  };
}

module.exports = {
  createEvent,
  createNormalizedEvent,
  validateEvent,
  VALID_DOMAINS,
  VALID_SEVERITIES
};
