/**
 * Shadow Guard 2.0 - Cowrie Honeypot Event Adapter
 * Normalizes Cowrie JSON logs into Common Event Contract v2.0.
 * Enforces strict credential privacy: NO PASSWORDS OR PASSWORD HASHES RETAINED.
 */

const { createEvent } = require('../lib/eventContract');

function normalizeCowrieEvent(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid Cowrie record: Expected JSON object');
  }

  const eventId = String(raw.eventid || 'cowrie.session.connect');
  const srcIp = raw.src_ip || '0.0.0.0';
  const dstPort = Number(raw.dst_port) || 2222;
  const protocol = dstPort === 2223 ? 'TELNET' : 'SSH';

  let eventType = 'honeypot.session.connect';
  let severity = 'low';
  let confidence = 0.90;
  let commandExecuted = null;
  let downloadSha256 = null;
  let authOutcome = null;

  switch (eventId) {
    case 'cowrie.login.failed':
      eventType = 'honeypot.auth.failed';
      severity = 'medium';
      confidence = 0.95;
      authOutcome = 'FAILED';
      break;

    case 'cowrie.login.success':
      eventType = 'honeypot.auth.success';
      severity = 'high';
      confidence = 0.98;
      authOutcome = 'SUCCESS';
      break;

    case 'cowrie.command.input':
    case 'cowrie.command.failed':
      eventType = 'honeypot.command.executed';
      severity = 'high';
      confidence = 0.99;
      commandExecuted = raw.input || null;
      break;

    case 'cowrie.session.file_download':
      eventType = 'honeypot.file.downloaded';
      severity = 'critical';
      confidence = 1.00;
      downloadSha256 = raw.shasum || null;
      break;

    case 'cowrie.session.closed':
      eventType = 'honeypot.session.closed';
      severity = 'info';
      confidence = 0.85;
      break;

    default:
      eventType = `honeypot.${eventId.replace('cowrie.', '')}`;
      severity = 'low';
  }

  // Deception Context - Strict Privacy Guard (NO password field)
  const deceptionContext = {
    honeypot_instance_id: protocol === 'TELNET' ? 'cowrie-telnet-decoy' : 'cowrie-ssh-decoy',
    decoy_type: protocol.toLowerCase(),
    session_id: raw.session || null,
    username: raw.username || null, // Username only
    auth_outcome: authOutcome,      // FAILED / SUCCESS
    command_executed: commandExecuted,
    download_sha256: downloadSha256,
    download_url: raw.url || null,
    client_version: raw.version || null
  };

  return createEvent({
    source_domain: 'deception',
    source_service: 'cowrie',
    event_type: eventType,
    severity,
    confidence,
    telemetry: {
      source_ip: srcIp,
      source_port: Number(raw.src_port) || null,
      destination_ip: raw.dst_ip || '192.168.1.150',
      destination_port: dstPort,
      protocol: protocol === 'TELNET' ? 'TCP' : 'SSH',
      flow_duration_seconds: Number(raw.duration) || 0.1
    },
    deception_context: deceptionContext,
    metadata: {
      raw_event_id: eventId,
      cowrie_timestamp: raw.timestamp || new Date().toISOString()
    }
  });
}

module.exports = {
  normalizeCowrieEvent
};
