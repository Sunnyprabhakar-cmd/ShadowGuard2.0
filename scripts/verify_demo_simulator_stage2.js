/**
 * Stage 2 Verification: Pipeline Context Propagation & Demo Safety Guardrails
 */
'use strict';

const assert = require('assert');
const { createEvent, validateEvent } = require('../shared/lib/eventContract');
const { ResponseExecutionEngine } = require('../automated-response-service/engine/responseExecutionEngine');

let passed = 0;
let failed = 0;

function check(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  [PASS] ${name}`);
    })
    .catch((err) => {
      failed++;
      console.error(`  [FAIL] ${name}: ${err.message}`);
    });
}

async function run() {
  console.log('======================================================================');
  console.log(' STAGE 2 VERIFICATION: CONTEXT PROPAGATION & DEMO SAFETY GUARDRAILS');
  console.log('======================================================================');

  await check('1. Common Event Contract v2.0 preserves flow_id, ports, event_source, session_id', () => {
    const ev = createEvent({
      source_domain: 'network',
      source_service: 'traffic-capture-service',
      event_type: 'event.network.raw',
      severity: 'high',
      telemetry: {
        flow_id: 'demo-abc-00001',
        source_ip: '203.0.113.10',
        source_port: 44123,
        destination_ip: '192.168.1.100',
        destination_port: 22,
        protocol: 'TCP'
      },
      metadata: {
        event_source: 'demo_simulator',
        session_id: 'demo-sess-abc',
        flow_id: 'demo-abc-00001'
      }
    });
    const val = validateEvent(ev);
    assert.strictEqual(val.valid, true);
    assert.strictEqual(ev.telemetry.flow_id, 'demo-abc-00001');
    assert.strictEqual(ev.telemetry.source_port, 44123);
    assert.strictEqual(ev.telemetry.destination_port, 22);
    assert.strictEqual(ev.metadata.event_source, 'demo_simulator');
    assert.strictEqual(ev.metadata.session_id, 'demo-sess-abc');
  });

  await check('2. Demo SOAR block NEVER invokes iptablesExecutor and isolates demoSimulatedBlocks from activeBlocks', async () => {
    const iptablesCalls = [];
    const engine = new ResponseExecutionEngine({
      enableLocalIptables: true,
      iptablesExecutor: async (op, ip) => iptablesCalls.push({ op, ip })
    });

    const rec = await engine.executeAction({
      action_type: 'BLOCK_IP_TEMPORARY',
      target_ip: '203.0.113.55',
      lease_minutes: 30,
      event_source: 'demo_simulator',
      session_id: 'demo-sess-xyz',
      flow_id: 'demo-xyz-00001',
      reason: 'Port scan demo'
    });

    assert.strictEqual(iptablesCalls.length, 0, 'iptablesExecutor must NEVER be called in demo mode');
    assert.strictEqual(engine.activeBlocks.size, 0, 'Live activeBlocks must remain untouched');
    assert.strictEqual(engine.demoSimulatedBlocks.size, 1, 'Demo block must be recorded in demoSimulatedBlocks');
    assert.strictEqual(rec.demo_simulated, true);
    assert.strictEqual(rec.status, 'DEMO_SIMULATED_BLOCK');
    assert.strictEqual(rec.event_source, 'demo_simulator');
    assert.strictEqual(rec.session_id, 'demo-sess-xyz');
    assert.strictEqual(rec.flow_id, 'demo-xyz-00001');
    assert.ok(engine.auditLog.some((a) => a.event_type === 'DEMO_ACTION_SIMULATED' && a.details.session_id === 'demo-sess-xyz'));
  });

  await check('3. Missing or unknown event_source is treated as LIVE (preserves live SOAR behaviour)', async () => {
    const iptablesCalls = [];
    const engine = new ResponseExecutionEngine({
      enableLocalIptables: true,
      iptablesExecutor: async (op, ip) => iptablesCalls.push({ op, ip })
    });

    // Missing event_source
    const recMissing = await engine.executeAction({
      action_type: 'BLOCK_IP_TEMPORARY',
      target_ip: '203.0.113.88',
      lease_minutes: 15
    });
    assert.strictEqual(recMissing.demo_simulated, false);
    assert.strictEqual(recMissing.status, 'EXECUTED');
    assert.strictEqual(iptablesCalls.length, 1);
    assert.strictEqual(engine.activeBlocks.has('203.0.113.88'), true);

    // Ambiguous / unknown event_source
    const recUnknown = await engine.executeAction({
      action_type: 'BLOCK_IP_TEMPORARY',
      target_ip: '203.0.113.89',
      event_source: 'custom_sensor'
    });
    assert.strictEqual(recUnknown.demo_simulated, false);
    assert.strictEqual(recUnknown.status, 'EXECUTED');
    assert.strictEqual(iptablesCalls.length, 2);
  });

  console.log(`\nRESULTS: ${passed} PASSED, ${failed} FAILED`);
  process.exit(failed > 0 ? 1 : 0);
}

run();
