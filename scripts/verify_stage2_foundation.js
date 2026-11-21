/**
 * Shadow Guard 2.0 - Stage 2 Foundation Verification Suite
 * Tests PostgreSQL schema migration definitions, Common Event Contract v2.0 validation,
 * RabbitMQ topology configuration, and microservice integration.
 */

const fs = require('fs');
const path = require('path');
const { createEvent, validateEvent, VALID_DOMAINS, VALID_SEVERITIES } = require('../shared/lib/eventContract');
const RabbitMQClient = require('../shared/lib/rabbitmq');

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

async function runStage2Verification() {
  console.log('='.repeat(70));
  console.log('  SHADOW GUARD 2.0 - STAGE 2 FOUNDATION VERIFICATION');
  console.log('='.repeat(70));

  // ── 1. Database Schema & Migrations ─────────────────────────────────────────
  console.log('\n[1/4] Verifying PostgreSQL Migrations & Schema Definitions...');
  
  const initSqlPath = path.join(__dirname, '..', 'database', 'init.sql');
  assert(fs.existsSync(initSqlPath), 'database/init.sql exists');

  const initSql = fs.readFileSync(initSqlPath, 'utf8');

  // Verify Core Tables defined in schema
  const requiredTables = [
    'schema_migrations',
    'threat_logs',
    'honeypot_instances',
    'honeypot_events',
    'suricata_events',
    'attacker_profiles',
    'attacker_observations',
    'threat_intel_cache',
    'incidents',
    'incident_events',
    'mitre_techniques',
    'attack_chains',
    'attack_chain_stages',
    'playbook_executions',
    'response_actions',
    'response_approvals',
    'deception_deployments',
    'audit_logs',
    'service_metrics'
  ];

  for (const table of requiredTables) {
    const tableRegex = new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`, 'i');
    assert(tableRegex.test(initSql), `Table '${table}' declared in init.sql`);
  }

  // Verify Attack Chain Certainty Constraints
  assert(
    initSql.includes("CHECK (certainty IN ('OBSERVED', 'INFERRED', 'SUSPECTED'))"),
    'Attack Chain Certainty enum constraint (OBSERVED, INFERRED, SUSPECTED) enforced'
  );

  // Verify Credential Privacy (No password column in honeypot_events)
  const honeypotEventsDef = initSql.match(/CREATE TABLE IF NOT EXISTS honeypot_events \(([\s\S]*?)\);/i);
  if (honeypotEventsDef) {
    const def = honeypotEventsDef[1].toLowerCase();
    assert(!def.includes('password_hash') && !def.includes('raw_password'), 'Honeypot events table strictly omits password/hash columns');
    assert(def.includes('username') && def.includes('auth_outcome'), 'Honeypot events table includes username and auth_outcome');
  } else {
    assert(false, 'honeypot_events table definition found');
  }

  // Verify Backward-Compatible View
  assert(initSql.includes('CREATE OR REPLACE VIEW v_legacy_threat_logs'), 'Backward-compatible view v_legacy_threat_logs defined');

  // Verify Migration Files
  const migrationsDir = path.join(__dirname, '..', 'database', 'migrations');
  assert(fs.existsSync(migrationsDir), 'database/migrations directory exists');
  const migrationFiles = fs.readdirSync(migrationsDir);
  assert(migrationFiles.includes('001_baseline_threat_logs.sql'), '001_baseline_threat_logs.sql migration exists');
  assert(migrationFiles.includes('002_schema_v2_core.sql'), '002_schema_v2_core.sql migration exists');
  assert(migrationFiles.includes('003_indexes_and_views.sql'), '003_indexes_and_views.sql migration exists');

  // ── 2. Common Event Contract v2.0 ──────────────────────────────────────────
  console.log('\n[2/4] Verifying Common Event Contract v2.0...');

  // Test Valid Network Event Creation
  const netEvent = createEvent({
    source_domain: 'network',
    source_service: 'traffic-capture-service',
    event_type: 'event.network.raw',
    severity: 'high',
    confidence: 0.88,
    telemetry: {
      source_ip: '198.51.100.25',
      destination_ip: '192.168.1.100',
      protocol: 'TCP',
      packets: 500,
      bytes: 250000,
      duration: 1.2
    }
  });

  assert(netEvent.schema_version === '2.0', 'Schema version is 2.0');
  assert(netEvent.event_id.startsWith('urn:uuid:'), 'Event ID uses standard urn:uuid format');
  assert(netEvent.telemetry.source_ip === '198.51.100.25', 'Telemetry source IP preserved');
  assert(netEvent.correlation_context && netEvent.correlation_context.trace_id, 'Trace ID generated');

  const netValidation = validateEvent(netEvent);
  assert(netValidation.valid, 'Network event passes strict schema validation');

  // Test Honeypot Event Creation with Privacy
  const honeyEvent = createEvent({
    source_domain: 'deception',
    source_service: 'honeypot-event-collector',
    event_type: 'event.honeypot.auth.failed',
    severity: 'medium',
    confidence: 0.95,
    telemetry: {
      source_ip: '203.0.113.50',
      destination_port: 2222,
      protocol: 'TCP'
    },
    deception_context: {
      honeypot_id: 'cowrie-ssh-01',
      username: 'root',
      auth_outcome: 'FAILED'
    }
  });

  const honeyValidation = validateEvent(honeyEvent);
  assert(honeyValidation.valid, 'Deception honeypot event passes validation');

  // Test Invalid Event Validation
  const invalidEvent = { schema_version: '1.0', event_id: 'bad-id' };
  const invalidResult = validateEvent(invalidEvent);
  assert(!invalidResult.valid && invalidResult.errors.length > 0, 'Invalid event correctly rejected with validation errors');

  // ── 3. RabbitMQ Topology & Client Resilience ───────────────────────────────
  console.log('\n[3/4] Verifying RabbitMQ Topology & Client Engine...');

  const client = new RabbitMQClient({
    serviceName: 'test-verification-client',
    url: 'amqp://shadowguard:shadowguard_secret@localhost:5672'
  });

  assert(typeof client.connect === 'function', 'RabbitMQClient implements connect()');
  assert(typeof client.publish === 'function', 'RabbitMQClient implements publish()');
  assert(typeof client.subscribe === 'function', 'RabbitMQClient implements subscribe()');
  assert(client.isReady() === false, 'Client isReady() returns false before connection is active');

  // Non-blocking publish when disconnected
  const pubResult = await client.publish('test.key', { test: true });
  assert(pubResult === false, 'Publish gracefully returns false without crashing when broker is offline');

  // Verify docker-compose RabbitMQ configuration
  const composePath = path.join(__dirname, '..', 'docker-compose.yml');
  const composeContent = fs.readFileSync(composePath, 'utf8');

  assert(composeContent.includes('rabbitmq:3.13-management-alpine'), 'docker-compose declares rabbitmq:3.13-management-alpine');
  assert(composeContent.includes('5672:5672'), 'docker-compose exposes AMQP port 5672');
  assert(composeContent.includes('15672:15672'), 'docker-compose exposes Management port 15672');
  assert(composeContent.includes('sg_core_net'), 'docker-compose configures sg_core_net');
  assert(composeContent.includes('sg_deception_dmz'), 'docker-compose configures sg_deception_dmz');

  // ── 4. Service Integration & Dual Mode ────────────────────────────────────
  console.log('\n[4/4] Verifying Service Integration & Dual Ingress Mode...');

  // Check traffic-capture-service package.json
  const capturePkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'traffic-capture-service', 'package.json'), 'utf8'));
  assert(capturePkg.dependencies.amqplib !== undefined, 'traffic-capture-service includes amqplib dependency');

  // Check threat-log-database-service package.json
  const dbPkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'threat-log-database-service', 'package.json'), 'utf8'));
  assert(dbPkg.dependencies.amqplib !== undefined, 'threat-log-database-service includes amqplib dependency');
  assert(dbPkg.dependencies.pg !== undefined, 'threat-log-database-service includes pg dependency');

  // Check traffic-capture-service code
  const captureCode = fs.readFileSync(path.join(__dirname, '..', 'traffic-capture-service', 'index.js'), 'utf8');
  assert(captureCode.includes("createEvent"), 'traffic-capture-service constructs v2.0 Common Event');
  assert(captureCode.includes("rabbitmq.publish('event.network.raw'"), 'traffic-capture-service publishes to event.network.raw');
  assert(captureCode.includes("axios.post(featureExtractionUrl"), 'traffic-capture-service preserves synchronous HTTP fallback');
  assert(captureCode.includes("/health/ready"), 'traffic-capture-service implements dual health check probes');

  // Check threat-log-database-service code
  const dbCode = fs.readFileSync(path.join(__dirname, '..', 'threat-log-database-service', 'index.js'), 'utf8');
  assert(dbCode.includes("q.network.events"), 'threat-log-database-service subscribes to q.network.events');
  assert(dbCode.includes("q.correlation.events"), 'threat-log-database-service subscribes to q.correlation.events');
  assert(dbCode.includes("/api/v2/incidents"), 'threat-log-database-service exposes /api/v2/incidents');
  assert(dbCode.includes("/api/v2/attacker-profiles"), 'threat-log-database-service exposes /api/v2/attacker-profiles');
  assert(dbCode.includes("/logs"), 'threat-log-database-service preserves legacy /logs endpoint');

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log(`STAGE 2 FOUNDATION TEST RESULTS: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('='.repeat(70));

  if (failedTests > 0) {
    process.exit(1);
  }
}

runStage2Verification().catch((err) => {
  console.error('Unexpected error running verification:', err);
  process.exit(1);
});
