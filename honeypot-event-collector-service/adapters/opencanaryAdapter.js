/**
 * Shadow Guard 2.0 - OpenCanary Multi-Decoy Event Adapter
 * Normalizes OpenCanary logs (HTTP, FTP, MySQL, Port Scan) into Common Event Contract v2.0.
 * Enforces strict credential privacy: NO PASSWORDS OR PASSWORD HASHES RETAINED.
 */

const { createEvent } = require('../lib/eventContract');

// OpenCanary Logtype Mapping
const OPENCANARY_LOGTYPES = {
  1000: { service: 'ftp', type: 'honeypot.port_probe', severity: 'low' },
  1001: { service: 'ftp', type: 'honeypot.auth.failed', severity: 'medium' },
  2000: { service: 'http', type: 'honeypot.http.probe', severity: 'medium' },
  3000: { service: 'ssh', type: 'honeypot.port_probe', severity: 'low' },
  4000: { service: 'smb', type: 'honeypot.smb.probe', severity: 'medium' },
  5001: { service: 'mysql', type: 'honeypot.mysql.probe', severity: 'high' },
  6001: { service: 'portscan', type: 'honeypot.port_scan', severity: 'medium' }
};

function normalizeOpenCanaryEvent(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid OpenCanary record: Expected JSON object');
  }

  const logtype = Number(raw.logtype || raw.logdata?.logtype) || 6001;
  const config = OPENCANARY_LOGTYPES[logtype] || { service: 'generic', type: 'honeypot.probe', severity: 'low' };

  const srcIp = raw.src_host || raw.src_ip || '0.0.0.0';
  const dstIp = raw.dst_host || raw.dst_ip || '192.168.1.160';
  const srcPort = Number(raw.src_port) || null;
  const dstPort = Number(raw.dst_port) || (config.service === 'http' ? 8080 : config.service === 'mysql' ? 3306 : 2121);

  const logdata = raw.logdata || {};
  const username = logdata.USERNAME || logdata.username || null;
  const authOutcome = username ? 'FAILED' : null;

  // Deception Context - Strict Privacy Guard (NO password field)
  const deceptionContext = {
    honeypot_instance_id: 'opencanary-multi-decoy',
    decoy_type: config.service,
    session_id: null,
    username: username, // Username only
    auth_outcome: authOutcome,
    probe_path: logdata.PATH || logdata.path || null,
    user_agent: logdata.USERAGENT || logdata.useragent || null,
    command_executed: null,
    download_sha256: null
  };

  return createEvent({
    source_domain: 'deception',
    source_service: 'opencanary',
    event_type: config.type,
    severity: config.severity,
    confidence: 0.92,
    telemetry: {
      source_ip: srcIp,
      source_port: srcPort,
      destination_ip: dstIp,
      destination_port: dstPort,
      protocol: 'TCP',
      flow_duration_seconds: 0.1
    },
    deception_context: deceptionContext,
    metadata: {
      node_id: raw.node_id || 'opencanary-01',
      opencanary_logtype: logtype,
      raw_timestamp: raw.utc_time || new Date().toISOString()
    }
  });
}

module.exports = {
  normalizeOpenCanaryEvent,
  OPENCANARY_LOGTYPES
};
