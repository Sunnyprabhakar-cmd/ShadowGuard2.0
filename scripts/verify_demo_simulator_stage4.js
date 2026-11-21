/**
 * Stage 4 Verification: SOC Dashboard UI (Module 12: Demo Traffic Simulator)
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const appJs = fs.readFileSync(path.join(ROOT, 'threat-dashboard-service/public/app.js'), 'utf8');
const stylesCss = fs.readFileSync(path.join(ROOT, 'threat-dashboard-service/public/styles.css'), 'utf8');

const { app } = require('../threat-dashboard-service/server');

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
  console.log(' STAGE 4 VERIFICATION: SOC DASHBOARD UI (DEMO TRAFFIC SIMULATOR)');
  console.log('======================================================================');

  await check('1. Preserves all 11 existing modules and adds Module 12 (demo_simulator)', () => {
    const requiredModules = [
      'overview', 'honeypots', 'attackers', 'incidents', 'attack_chains',
      'threat_intel', 'soar', 'system_audit', 'tri_model', 'ml_benchmark',
      'xai_reasoning', 'demo_simulator'
    ];
    for (const id of requiredModules) {
      assert.ok(appJs.includes(`id: '${id}'`), `Missing navigation module '${id}'`);
    }
    assert.ok(appJs.includes('id="demo-simulator-panel"'), 'Missing Module 12 panel');
  });

  await check('2. Renders all 10 scenarios, Single/Mixed modes, Low/Med/High speeds, Duration & Controls', () => {
    const scenarios = [
      'normal_traffic', 'port_scan', 'ssh_brute_force', 'service_enumeration',
      'ddos', 'data_exfiltration', 'c2_beaconing', 'multi_vector', 'stealth_anomaly', 'mixed'
    ];
    for (const s of scenarios) {
      assert.ok(appJs.includes(`value="${s}"`), `Missing scenario option '${s}'`);
    }
    for (const id of ['demo-btn-start', 'demo-btn-pause', 'demo-btn-resume', 'demo-btn-stop', 'demo-btn-reset']) {
      assert.ok(appJs.includes(`id="${id}"`), `Missing control button '${id}'`);
    }
    assert.ok(appJs.includes("demoSimState.state === 'Running' || demoSimState.state === 'Paused'"), 'Missing duplicate-start guard');
  });

  await check('3. Enforces RBAC permissions in UI and displays backend-authoritative notice', () => {
    assert.ok(appJs.includes("const canControlDemo = socRole === 'SOC_ANALYST' || socRole === 'ADMIN'"));
    assert.ok(appJs.includes('enforced by backend RBAC'));
  });

  await check('4. Handles WebSocket demo_simulator_state, demo_simulator_event & auto-reconnection', () => {
    assert.ok(appJs.includes("data.type === 'demo_simulator_state'"));
    assert.ok(appJs.includes("data.type === 'demo_simulator_event'"));
    assert.ok(appJs.includes('connectWebSocket') && appJs.includes('setDemoWsReconnecting(true)'));
  });

  await check('5. Integrates Demo / Live / All filtering defaulting to live', () => {
    assert.ok(appJs.includes("useState('live')"));
    assert.ok(appJs.includes('/api/statistics?source=${encodeURIComponent(telemetrySourceFilter)}'));
    assert.ok(appJs.includes('/api/threats?source=${encodeURIComponent(telemetrySourceFilter)}&limit=50'));
    assert.ok(appJs.includes('id="demo-source-filter"'));
  });

  await check('6. Keeps RF probability, IF score & AE reconstruction error distinct and labels DEMO actions safely', () => {
    assert.ok(appJs.includes('RF Prob') && appJs.includes('IF Anomaly Score') && appJs.includes('AE Recon Error'));
    assert.ok(appJs.includes('DEMO / SIMULATED SAFETY MODE'));
    assert.ok(appJs.includes('No real firewall/IP blocks or external email notifications are executed'));
    assert.ok(appJs.includes('Post-Session Synthetic Evaluation Summary'));
    assert.ok(appJs.includes('TP / FP / TN / FN') && appJs.includes('Precision') && appJs.includes('Recall') && appJs.includes('F1 Score'));
  });

  await check('7. Stylesheet includes Demo Simulator responsive layout and status pills', () => {
    for (const cls of ['.demo-safety-banner', '.demo-state-pill', '.demo-controls-grid', '.demo-kpi-grid', '.demo-badge-tag']) {
      assert.ok(stylesCss.includes(cls), `Missing CSS class ${cls}`);
    }
  });

  await check('8. Dashboard server serves updated index.html, app.js, and styles.css over HTTP', async () => {
    const srv = http.createServer(app);
    await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
    const port = srv.address().port;
    const getText = (p) => new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${port}${p}`, (res) => {
        let body = '';
        res.on('data', (c) => { body += c; });
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }).on('error', reject);
    });
    try {
      const [idx, js, css] = await Promise.all([getText('/'), getText('/app.js'), getText('/styles.css')]);
      assert.strictEqual(idx.status, 200);
      assert.strictEqual(js.status, 200);
      assert.strictEqual(css.status, 200);
      assert.ok(js.body.includes('demo-simulator-panel'));
      assert.ok(css.body.includes('.demo-safety-banner'));
    } finally {
      await new Promise((resolve) => srv.close(resolve));
    }
  });

  console.log(`\nRESULTS: ${passed} PASSED, ${failed} FAILED`);
  process.exit(failed > 0 ? 1 : 0);
}

run();
