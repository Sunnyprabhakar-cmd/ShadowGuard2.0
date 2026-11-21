/**
 * Stage 3 Verification: Dashboard Backend Proxy, Session Store & Live WebSocket Stream
 */
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const {
  app,
  server,
  securityManager,
  socAggregator,
  xaiStore,
  demoSimulatorStore,
  setDemoSimulatorDispatcher,
  setDemoMlDispatcher,
  syncAndBroadcastDemoSession
} = require('../threat-dashboard-service/server');

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

function httpRequest(port, method, path, body = null, token = null) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = {};
    if (data) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const req = http.request({ hostname: '127.0.0.1', port, path, method, headers }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        let parsed = raw;
        try {
          parsed = raw ? JSON.parse(raw) : {};
        } catch (_) {}
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function connectWs(port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      const key = crypto.randomBytes(16).toString('base64');
      sock.write(
        `GET / HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
      );
    });
    const messages = [];
    let rx = Buffer.alloc(0);
    let handshakeDone = false;

    sock.on('data', (chunk) => {
      rx = Buffer.concat([rx, chunk]);
      if (!handshakeDone) {
        const idx = rx.indexOf('\r\n\r\n');
        if (idx === -1) return;
        handshakeDone = true;
        rx = rx.subarray(idx + 4);
        resolve({ sock, messages });
      }
      while (rx.length >= 2) {
        const b1 = rx[1];
        let len = b1 & 0x7f;
        let offset = 2;
        if (len === 126) {
          if (rx.length < 4) break;
          len = rx.readUInt16BE(2);
          offset = 4;
        } else if (len === 127) {
          if (rx.length < 10) break;
          len = Number(rx.readBigUInt64BE(2));
          offset = 10;
        }
        if (rx.length < offset + len) break;
        const payload = rx.subarray(offset, offset + len).toString('utf8');
        rx = rx.subarray(offset + len);
        try {
          messages.push(JSON.parse(payload));
        } catch (_) {}
      }
    });
    sock.on('error', reject);
    setTimeout(() => {
      if (!handshakeDone) reject(new Error('WebSocket handshake timeout'));
    }, 4000);
  });
}

async function run() {
  console.log('======================================================================');
  console.log(' STAGE 3 VERIFICATION: DASHBOARD PROXY, SESSION STORE & WEBSOCKET');
  console.log('======================================================================');

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const viewerToken = securityManager.issueToken({ sub: 'viewer-1', role: 'VIEWER' });
  const analystToken = securityManager.issueToken({ sub: 'analyst-1', role: 'SOC_ANALYST' });
  const adminToken = securityManager.issueToken({ sub: 'admin-1', role: 'ADMIN' });

  let simState = 'Idle';
  let simSessionId = null;
  const mockSimEvents = [];

  setDemoSimulatorDispatcher(async (method, suffix, body) => {
    if (method === 'GET' && suffix === '/status') {
      return {
        status: 200,
        data: {
          status: 'success',
          data: {
            state: simState,
            session_id: simSessionId,
            scenario: 'mixed',
            mode: 'mixed',
            speed: 'high',
            counters: { events_generated: mockSimEvents.length }
          }
        }
      };
    }
    if (method === 'POST' && suffix === '/start') {
      if (simState === 'Running' || simState === 'Paused') {
        return { status: 409, data: { status: 'error', code: 'ALREADY_RUNNING' } };
      }
      simState = 'Running';
      simSessionId = 'demo-sess-stage3';
      mockSimEvents.length = 0;
      mockSimEvents.push(
        {
          flow_id: 'demo-s3-0001',
          session_id: simSessionId,
          timestamp: new Date().toISOString(),
          src_ip: '10.0.0.50',
          dst_ip: '192.168.1.100',
          src_port: 44100,
          dst_port: 22,
          protocol: 'TCP',
          packets: 2,
          bytes: 128,
          duration: 0.05,
          attack_type: 'port_scan',
          event_source: 'demo_simulator',
          ground_truth: { canonical_category: 'port_scan', is_malicious: true }
        },
        {
          flow_id: 'demo-s3-0002',
          session_id: simSessionId,
          timestamp: new Date().toISOString(),
          src_ip: '192.168.1.25',
          dst_ip: '8.8.8.8',
          src_port: 51200,
          dst_port: 443,
          protocol: 'TCP',
          packets: 40,
          bytes: 18000,
          duration: 1.5,
          attack_type: 'normal_traffic',
          event_source: 'demo_simulator',
          ground_truth: { canonical_category: 'normal_traffic', is_malicious: false }
        }
      );
      return { status: 200, data: { status: 'success', data: { state: simState, session_id: simSessionId, scenario: body.scenario, mode: body.mode, speed: body.speed } } };
    }
    if (method === 'POST' && suffix === '/pause') {
      simState = 'Paused';
      return { status: 200, data: { status: 'success', data: { state: simState, session_id: simSessionId } } };
    }
    if (method === 'POST' && suffix === '/resume') {
      simState = 'Running';
      return { status: 200, data: { status: 'success', data: { state: simState, session_id: simSessionId } } };
    }
    if (method === 'POST' && suffix === '/stop') {
      simState = 'Stopped';
      return { status: 200, data: { status: 'success', data: { state: simState, session_id: simSessionId } } };
    }
    if (method === 'POST' && suffix === '/reset') {
      simState = 'Idle';
      simSessionId = null;
      mockSimEvents.length = 0;
      return { status: 200, data: { status: 'success', data: { state: simState, session_id: null } } };
    }
    if (method === 'GET' && suffix === '/events') {
      return { status: 200, data: { status: 'success', data: mockSimEvents } };
    }
    if (method === 'GET' && suffix === '/summary') {
      return {
        status: 200,
        data: {
          status: 'success',
          data: {
            synthetic_demo_evaluation: true,
            session_id: simSessionId,
            state: simState,
            total_events_generated: mockSimEvents.length,
            benign_events: 1,
            malicious_events: 1
          }
        }
      };
    }
    return { status: 404, data: { status: 'error' } };
  });

  setDemoMlDispatcher(async (kind, payload) => {
    if (kind === 'detect') {
      const isAttack = payload.context?.attack_type !== 'normal_traffic';
      return {
        is_anomaly: isAttack,
        random_forest: { prediction: isAttack ? 1 : 0, attack_probability: isAttack ? 0.94 : 0.04 },
        isolation_forest: { raw_decision_score: isAttack ? -0.18 : 0.14 },
        autoencoder: { reconstruction_error: isAttack ? 2.45 : 0.09 },
        tri_model_fusion: {
          is_anomaly: isAttack,
          final_decision: isAttack ? 'ANOMALY' : 'NORMAL',
          recommended_action: isAttack ? 'block' : 'monitor',
          fused_anomaly_score: isAttack ? 0.91 : 0.08,
          models_agreeing_on_anomaly: isAttack ? 3 : 0,
          auto_block_permitted: isAttack
        }
      };
    }
    return {
      explanation_generation_status: 'healthy',
      unified_top_features: [{ feature: 'packets', importance: 0.42 }]
    };
  });

  try {
    await check('1. RBAC enforces VIEWER read-only vs SOC_ANALYST/ADMIN control', async () => {
      const stViewer = await httpRequest(port, 'GET', '/api/v2/demo-simulator/status', null, viewerToken);
      assert.strictEqual(stViewer.status, 200);

      const startViewer = await httpRequest(port, 'POST', '/api/v2/demo-simulator/start', { scenario: 'mixed' }, viewerToken);
      assert.strictEqual(startViewer.status, 403);

      const stopViewer = await httpRequest(port, 'POST', '/api/v2/demo-simulator/stop', {}, viewerToken);
      assert.strictEqual(stopViewer.status, 403);
    });

    await check('2. Input validation rejects invalid scenario, mode, speed, and duration', async () => {
      const r1 = await httpRequest(port, 'POST', '/api/v2/demo-simulator/start', { scenario: 'invalid_xyz' }, analystToken);
      assert.strictEqual(r1.status, 400);
      const r2 = await httpRequest(port, 'POST', '/api/v2/demo-simulator/start', { scenario: 'mixed', speed: 'ludicrous' }, analystToken);
      assert.strictEqual(r2.status, 400);
      const r3 = await httpRequest(port, 'POST', '/api/v2/demo-simulator/start', { scenario: 'mixed', duration_seconds: -5 }, adminToken);
      assert.strictEqual(r3.status, 400);
    });

    await check('3. WebSocket broadcasts demo_simulator_state & demo_simulator_event and controls proxy cleanly', async () => {
      const wsClient = await connectWs(port);

      const startRes = await httpRequest(port, 'POST', '/api/v2/demo-simulator/start', { scenario: 'mixed', mode: 'mixed', speed: 'high' }, analystToken);
      assert.strictEqual(startRes.status, 200);

      // Duplicate start returns 409
      const dupRes = await httpRequest(port, 'POST', '/api/v2/demo-simulator/start', { scenario: 'port_scan' }, analystToken);
      assert.strictEqual(dupRes.status, 409);

      await syncAndBroadcastDemoSession();
      await new Promise((r) => setTimeout(r, 100));

      assert.ok(wsClient.messages.some((m) => m.type === 'demo_simulator_state'));
      assert.ok(wsClient.messages.some((m) => m.type === 'demo_simulator_event' && m.event_source === 'demo_simulator'));
      wsClient.sock.destroy();

      const pauseRes = await httpRequest(port, 'POST', '/api/v2/demo-simulator/pause', {}, analystToken);
      assert.strictEqual(pauseRes.status, 200);
      assert.strictEqual(pauseRes.body.data.state, 'Paused');

      const resumeRes = await httpRequest(port, 'POST', '/api/v2/demo-simulator/resume', {}, analystToken);
      assert.strictEqual(resumeRes.status, 200);
      assert.strictEqual(resumeRes.body.data.state, 'Running');

      const stopRes = await httpRequest(port, 'POST', '/api/v2/demo-simulator/stop', {}, analystToken);
      assert.strictEqual(stopRes.status, 200);
      assert.strictEqual(stopRes.body.data.state, 'Stopped');
    });

    await check('4. Session store aggregates incidents, simulated SOAR, XAI triggers, and TP/FP/FN without touching live state', async () => {
      const liveLeasesBefore = socAggregator.soarBlockLeases.length;
      const liveXaiBefore = xaiStore.explanations ? xaiStore.explanations.size : 0;

      const evRes = await httpRequest(port, 'GET', '/api/v2/demo-simulator/events?session_id=demo-sess-stage3', null, viewerToken);
      assert.strictEqual(evRes.status, 200);
      assert.strictEqual(evRes.body.count, 2);
      assert.strictEqual(evRes.body.data[0].event_source, 'demo_simulator');

      const sumRes = await httpRequest(port, 'GET', '/api/v2/demo-simulator/summary?session_id=demo-sess-stage3', null, viewerToken);
      assert.strictEqual(sumRes.status, 200);
      assert.strictEqual(sumRes.body.data.synthetic_demo_evaluation, true);
      assert.strictEqual(sumRes.body.data.true_positives, 1);
      assert.strictEqual(sumRes.body.data.true_negatives, 1);
      assert.strictEqual(sumRes.body.data.incidents_created, 1);
      assert.strictEqual(sumRes.body.data.soar_actions_simulated, 1);
      assert.strictEqual(sumRes.body.data.xai_explanations_triggered, 1);

      const badSess = await httpRequest(port, 'GET', '/api/v2/demo-simulator/events?session_id=does-not-exist', null, viewerToken);
      assert.strictEqual(badSess.status, 404);

      assert.strictEqual(socAggregator.soarBlockLeases.length, liveLeasesBefore);
      assert.strictEqual(xaiStore.explanations ? xaiStore.explanations.size : 0, liveXaiBefore);
    });

    await check('5. Demo/Live/All filtering isolates demo events from live endpoints', async () => {
      const demoThreats = await httpRequest(port, 'GET', '/api/threats?source=demo');
      assert.strictEqual(demoThreats.status, 200);
      assert.strictEqual(demoThreats.body.logs.length, 2);
      assert.ok(demoThreats.body.logs.every((l) => l.event_source === 'demo_simulator'));

      const liveThreats = await httpRequest(port, 'GET', '/api/threats?source=live');
      assert.strictEqual(liveThreats.status, 200);
      assert.ok(liveThreats.body.logs.every((l) => l.event_source !== 'demo_simulator'));

      const demoStats = await httpRequest(port, 'GET', '/api/statistics?source=demo');
      assert.strictEqual(demoStats.status, 200);
      assert.strictEqual(demoStats.body.total_events, 2);
    });

    await check('6. Reset clears demo session cleanly and simulator unavailability returns 503', async () => {
      const resetRes = await httpRequest(port, 'POST', '/api/v2/demo-simulator/reset', {}, adminToken);
      assert.strictEqual(resetRes.status, 200);
      assert.strictEqual(demoSimulatorStore.getSessionEvents(null).length, 0);

      setDemoSimulatorDispatcher(async () => {
        const err = new Error('connect ECONNREFUSED 127.0.0.1:8010');
        err.code = 'SIMULATOR_UNAVAILABLE';
        throw err;
      });
      const downRes = await httpRequest(port, 'GET', '/api/v2/demo-simulator/status', null, viewerToken);
      assert.strictEqual(downRes.status, 503);
      assert.strictEqual(downRes.body.code, 'SIMULATOR_UNAVAILABLE');
    });

    await check('7. Existing dashboard endpoints remain healthy (regression check)', async () => {
      const h = await httpRequest(port, 'GET', '/health');
      assert.strictEqual(h.status, 200);
      const ov = await httpRequest(port, 'GET', '/api/v2/soc/overview', null, viewerToken);
      assert.strictEqual(ov.status, 200);
      const ml = await httpRequest(port, 'GET', '/api/v2/soc/ml/overview', null, viewerToken);
      assert.strictEqual(ml.status, 200);
      const xai = await httpRequest(port, 'GET', '/api/v2/xai/overview', null, viewerToken);
      assert.strictEqual(xai.status, 200);
    });

    await check('8. Accounting invariant (total_generated = total_evaluated + total_unprocessed), unevaluated isolation & dedup', async () => {
      demoSimulatorStore.clearSession(null);
      const sessMeta = { session_id: 'demo-acct-1', state: 'Stopped', scenario: 'mixed', mode: 'mixed', counters: { events_generated: 3 } };
      demoSimulatorStore.updateSessionMeta(sessMeta);
      let callCount = 0;
      const rawBatch = [
        { flow_id: 'f-1', session_id: 'demo-acct-1', src_ip: '10.0.0.1', dst_ip: '192.168.1.10', protocol: 'TCP', attack_type: 'ddos', packets: 5000, bytes: 2000000, duration: 0.5, ground_truth: { is_malicious: true, canonical_category: 'ddos' } },
        { flow_id: 'f-2', session_id: 'demo-acct-1', src_ip: '10.0.0.2', dst_ip: '192.168.1.10', protocol: 'TCP', attack_type: 'port_scan', packets: 1, bytes: 64, duration: 0.1, ground_truth: { is_malicious: true, canonical_category: 'port_scan' } },
        { flow_id: 'f-1', session_id: 'demo-acct-1', src_ip: '10.0.0.1', dst_ip: '192.168.1.10', protocol: 'TCP', attack_type: 'ddos', packets: 5000, bytes: 2000000, duration: 0.5, _countDuplicateOnReingest: true, ground_truth: { is_malicious: true, canonical_category: 'ddos' } }
      ];
      await demoSimulatorStore.ingestSimulatorEvents(rawBatch, {
        sessionMeta: sessMeta,
        detectFn: async () => {
          callCount++;
          if (callCount === 2) return null; // simulate ML timeout/failure for f-2
          return {
            is_anomaly: true,
            random_forest: { prediction: 1, attack_probability: 0.99 },
            isolation_forest: { raw_decision_score: -0.2 },
            autoencoder: { reconstruction_error: 1.5 },
            tri_model_fusion: { is_anomaly: true, final_decision: 'ANOMALY', recommended_action: 'block', fusion_status: 'healthy' }
          };
        }
      });
      const sum = demoSimulatorStore.getSessionSummary('demo-acct-1', { total_events_generated: 3, benign_events: 0, malicious_events: 3 });
      assert.strictEqual(sum.total_generated, 3);
      assert.strictEqual(sum.total_received, 2);
      assert.strictEqual(sum.total_evaluated, 1);
      assert.strictEqual(sum.total_unprocessed, 2);
      assert.strictEqual(sum.total_generated, sum.total_evaluated + sum.total_unprocessed);
      assert.strictEqual(sum.duplicate_events, 1);
      assert.strictEqual(sum.true_positives + sum.false_positives + sum.true_negatives + sum.false_negatives, 1);
      assert.strictEqual(sum.evaluation_complete, false);
      assert.strictEqual(sum.evaluation_status, 'provisional');
      demoSimulatorStore.clearSession(null);
    });
  } finally {
    setDemoSimulatorDispatcher(null);
    setDemoMlDispatcher(null);
    server.close();
  }

  console.log(`\nRESULTS: ${passed} PASSED, ${failed} FAILED`);
  process.exit(failed > 0 ? 1 : 0);
}

run();
