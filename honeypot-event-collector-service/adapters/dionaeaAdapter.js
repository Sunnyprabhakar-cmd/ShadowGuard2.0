/**
 * Shadow Guard 2.0 - Dionaea Malware Decoy Event Adapter
 * Normalizes Dionaea logs (SMB, MSSQL, Malware Downloads) into Common Event Contract v2.0.
 */

const { createEvent } = require('../lib/eventContract');

function normalizeDionaeaEvent(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid Dionaea record: Expected JSON object');
  }

  const srcIp = raw.src_ip || raw.remote_host || '0.0.0.0';
  const dstPort = Number(raw.dst_port || raw.local_port) || 445;
  const isDownload = Boolean(raw.download || raw.md5 || raw.sha256);

  const eventType = isDownload ? 'honeypot.malware.downloaded' : 'honeypot.exploit.probe';
  const severity = isDownload ? 'critical' : 'high';

  return createEvent({
    source_domain: 'deception',
    source_service: 'dionaea',
    event_type: eventType,
    severity,
    confidence: 0.99,
    telemetry: {
      source_ip: srcIp,
      source_port: Number(raw.src_port) || null,
      destination_ip: raw.dst_ip || '192.168.1.170',
      destination_port: dstPort,
      protocol: 'TCP',
      flow_duration_seconds: Number(raw.duration) || 0.5
    },
    deception_context: {
      honeypot_instance_id: 'dionaea-malware-decoy',
      decoy_type: 'malware_quarantine',
      session_id: raw.connection_id ? String(raw.connection_id) : null,
      username: null,
      auth_outcome: null,
      command_executed: null,
      download_sha256: raw.sha256 || null,
      quarantine_file: raw.quarantine_path || null
    },
    metadata: {
      dionaea_service: raw.service || 'smb',
      raw_timestamp: raw.timestamp || new Date().toISOString()
    }
  });
}

module.exports = {
  normalizeDionaeaEvent
};
