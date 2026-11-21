/**
 * Shadow Guard 2.0 - Suricata EVE JSON Adapter
 * Normalizes Suricata EVE records (alert, dns, http, tls, flow) into Common Event Contract v2.0.
 */

const { createEvent } = require('../lib/eventContract');

/**
 * Maps Suricata severity (1=High, 2=Medium, 3=Low, 4=Informational) to Shadow Guard levels
 */
function mapSuricataSeverity(severityNum) {
  switch (Number(severityNum)) {
    case 1: return 'high';
    case 2: return 'medium';
    case 3: return 'low';
    default: return 'info';
  }
}

/**
 * Transforms a raw Suricata EVE JSON record into an Event Contract v2.0 object
 */
function normalizeSuricataEvent(eveRecord) {
  if (!eveRecord || typeof eveRecord !== 'object') {
    throw new Error('Invalid Suricata record: Expected JSON object');
  }

  const eveType = String(eveRecord.event_type || 'unknown').toLowerCase();
  const srcIp = eveRecord.src_ip || '0.0.0.0';
  const dstIp = eveRecord.dest_ip || null;
  const srcPort = Number(eveRecord.src_port) || null;
  const dstPort = Number(eveRecord.dest_port) || null;
  const protocol = String(eveRecord.proto || 'TCP').toUpperCase();

  let eventType = `nids.${eveType}`;
  let severity = 'info';
  let confidence = 0.6;
  let nidsContext = {
    suricata_event_type: eveType,
    in_iface: eveRecord.in_iface || null,
    flow_id: eveRecord.flow_id ? String(eveRecord.flow_id) : null
  };

  // 1. Alert Record
  if (eveType === 'alert' && eveRecord.alert) {
    const alert = eveRecord.alert;
    severity = mapSuricataSeverity(alert.severity);
    confidence = alert.severity === 1 ? 0.95 : alert.severity === 2 ? 0.85 : 0.70;
    
    // Elevate severity if signature targets critical vectors
    const sigLower = (alert.signature || '').toLowerCase();
    if (sigLower.includes('dos') || sigLower.includes('flood') || sigLower.includes('exfiltration')) {
      severity = 'high';
    } else if (sigLower.includes('zero-day') || sigLower.includes('exploit')) {
      severity = 'critical';
    }

    nidsContext = {
      ...nidsContext,
      signature_id: alert.signature_id,
      signature_name: alert.signature,
      category: alert.category || 'Attempted Information Leak',
      action: alert.action || 'allowed',
      gid: alert.gid || 1,
      rev: alert.rev || 1,
      payload_printable: alert.payload_printable || null
    };
  }
  // 2. DNS Query / Answer Record
  else if (eveType === 'dns' && eveRecord.dns) {
    const dns = eveRecord.dns;
    severity = 'info';
    confidence = 0.5;

    nidsContext = {
      ...nidsContext,
      query_type: dns.type || 'query',
      query_name: dns.rrname || null,
      query_class: dns.rrtype || 'A',
      rcode: dns.rcode || 'NOERROR',
      answers: Array.isArray(dns.answers) ? dns.answers : []
    };
  }
  // 3. HTTP Transaction Record
  else if (eveType === 'http' && eveRecord.http) {
    const http = eveRecord.http;
    severity = http.status >= 400 ? 'low' : 'info';
    confidence = 0.6;

    nidsContext = {
      ...nidsContext,
      hostname: http.hostname || null,
      url: http.url || null,
      http_method: http.http_method || 'GET',
      http_user_agent: http.http_user_agent || null,
      http_content_type: http.http_content_type || null,
      status: http.status || 200,
      length: http.length || 0
    };
  }
  // 4. TLS Handshake Record
  else if (eveType === 'tls' && eveRecord.tls) {
    const tls = eveRecord.tls;
    severity = 'info';
    confidence = 0.6;

    nidsContext = {
      ...nidsContext,
      subject: tls.subject || null,
      issuerdn: tls.issuerdn || null,
      sni: tls.sni || null,
      version: tls.version || null,
      ja3: tls.ja3 || null,
      ja4: tls.ja4 || null,
      fingerprint: tls.fingerprint || null
    };
  }
  // 5. Flow Telemetry Record
  else if (eveType === 'flow' && eveRecord.flow) {
    const flow = eveRecord.flow;
    severity = 'info';
    confidence = 0.5;

    nidsContext = {
      ...nidsContext,
      app_proto: eveRecord.app_proto || 'unknown',
      state: flow.state || 'closed',
      reason: flow.reason || 'shutdown',
      tcp_flags: flow.tcp_flags || null
    };
  }

  // Extract flow metrics
  const flowData = eveRecord.flow || {};
  const packetCount = (Number(flowData.pkts_toserver) || 0) + (Number(flowData.pkts_toclient) || 0);
  const byteCount = (Number(flowData.bytes_toserver) || 0) + (Number(flowData.bytes_toclient) || 0);
  const flowDuration = Number(flowData.age) || 0.001;

  return createEvent({
    source_domain: 'nids',
    source_service: 'suricata',
    event_type: eventType,
    severity,
    confidence,
    telemetry: {
      source_ip: srcIp,
      source_port: srcPort,
      destination_ip: dstIp,
      destination_port: dstPort,
      protocol,
      flow_duration_seconds: flowDuration,
      packet_count: packetCount,
      byte_count: byteCount
    },
    nids_context: nidsContext,
    metadata: {
      raw_timestamp: eveRecord.timestamp || new Date().toISOString(),
      suricata_host: eveRecord.host || 'sg-suricata-node'
    }
  });
}

module.exports = {
  normalizeSuricataEvent,
  mapSuricataSeverity
};
