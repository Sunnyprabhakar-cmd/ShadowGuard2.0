/**
 * Shadow Guard 2.0 — One-Command Unified Service Launcher
 * =======================================================
 * Starts Shadow Guard 2.0 with a single command:
 *   - Native Host Mode (default): `node scripts/start_all_services.js`
 *     Starts `ml-detection-service` (:8001) and `threat-dashboard-service` (:7000)
 *     plus any additional microservices whose local dependencies (`node_modules`
 *     or `uvicorn`) are installed on the host.
 *   - Full 22-Container Docker Mode: `node scripts/start_all_services.js --docker`
 *     Runs `docker compose up -d --build`.
 *   - Probe & Exit Mode (CI/Verification): `node scripts/start_all_services.js --verify`
 *     Starts core services, verifies `/health` and `/xai/health`, then shuts down cleanly.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn, execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const args = new Set(process.argv.slice(2));
const USE_DOCKER = args.has('--docker');
const VERIFY_AND_EXIT = args.has('--verify');

const children = [];
let shuttingDown = false;

function hasUvicorn() {
  try {
    execFileSync('python', ['-c', 'import uvicorn, fastapi'], { stdio: 'ignore' });
    return true;
  } catch (_) {
    return false;
  }
}

function hasNodeModules(serviceDir) {
  return fs.existsSync(path.join(ROOT, serviceDir, 'node_modules'));
}

function httpGetJson(urlStr, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const req = http.get(urlStr, { timeout: timeoutMs }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, body: raw ? JSON.parse(raw) : {} });
        } catch (_) {
          resolve({ statusCode: res.statusCode, body: raw });
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

async function waitForHealth(urlStr, label, maxWaitMs = 25000) {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const res = await httpGetJson(urlStr, 1500);
      if (res.statusCode === 200) {
        console.log(`  [READY] ${label.padEnd(28)} -> ${urlStr}`);
        return true;
      }
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 400));
  }
  console.warn(`  [WARN]  ${label.padEnd(28)} -> timed out waiting for ${urlStr}`);
  return false;
}

function shutdownAll(exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('\n[ShadowGuard] Shutting down all started services...');
  for (const ch of children) {
    try {
      if (!ch.proc.killed) {
        ch.proc.kill('SIGTERM');
      }
    } catch (_) {}
  }
  setTimeout(() => {
    for (const ch of children) {
      try {
        if (!ch.proc.killed) ch.proc.kill('SIGKILL');
      } catch (_) {}
    }
    process.exit(exitCode);
  }, 800);
}

process.on('SIGINT', () => shutdownAll(0));
process.on('SIGTERM', () => shutdownAll(0));

function launchService(svc) {
  const proc = spawn(svc.cmd, svc.args, {
    cwd: svc.cwd || ROOT,
    env: { ...process.env, ...(svc.env || {}) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  proc.stdout.on('data', (chunk) => {
    const lines = chunk.toString('utf8').split(/\r?\n/).filter(Boolean);
    for (const line of lines) {
      console.log(`[${svc.name}] ${line}`);
    }
  });

  proc.stderr.on('data', (chunk) => {
    const lines = chunk.toString('utf8').split(/\r?\n/).filter(Boolean);
    for (const line of lines) {
      console.error(`[${svc.name}][err] ${line}`);
    }
  });

  proc.on('exit', (code) => {
    if (!shuttingDown && svc.critical) {
      console.error(`[ShadowGuard] Critical service '${svc.name}' exited unexpectedly (code=${code}).`);
      shutdownAll(1);
    }
  });

  children.push({ name: svc.name, proc });
}

async function main() {
  console.log('================================================================================');
  console.log(' SHADOW GUARD 2.0 — UNIFIED ONE-COMMAND SERVICE LAUNCHER');
  console.log('================================================================================\n');

  if (USE_DOCKER) {
    // Ensure Docker daemon is reachable; on Windows, auto-launch Docker Desktop if not running
    let dockerReady = false;
    try {
      execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 8000 });
      dockerReady = true;
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        console.error('\n[ShadowGuard] Error: Docker (`docker`) was not found in your PATH.');
        console.error('Install Docker Desktop for Windows from https://www.docker.com/products/docker-desktop/');
        console.error('Or run native host mode without `--docker`: node scripts/start_all_services.js\n');
        process.exit(1);
      }
      if (process.platform === 'win32') {
        const candidates = [
          path.join(process.env.LOCALAPPDATA || '', 'Programs', 'DockerDesktop', 'Docker Desktop.exe'),
          'C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe',
        ];
        const exe = candidates.find((p) => p && fs.existsSync(p));
        if (exe) {
          console.log('[ShadowGuard] Docker Engine is not running yet. Launching Docker Desktop...');
          try {
            const gui = spawn(exe, [], { detached: true, stdio: 'ignore' });
            gui.unref();
          } catch (_) {}
          for (let i = 0; i < 30; i++) {
            await new Promise((r) => setTimeout(r, 2000));
            try {
              execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 });
              dockerReady = true;
              break;
            } catch (_) {}
          }
        }
      }
    }

    if (!dockerReady) {
      console.error('\n[ShadowGuard] Error: Docker Engine is not responding (`docker info` failed).');
      console.error('Please open Docker Desktop, wait until it shows "Engine running" (green),');
      console.error('or run `wsl --shutdown` and restart Docker Desktop, then re-run:');
      console.error('  node scripts/start_all_services.js --docker\n');
      process.exit(1);
    }

    console.log('[ShadowGuard] Launching full 22-container stack via `docker compose up -d --build`...');
    const res = spawn('docker', ['compose', 'up', '-d', '--build'], { cwd: ROOT, stdio: 'inherit' });
    res.on('error', (err) => {
      console.error('\n[ShadowGuard] Failed to launch Docker Compose:', err.message);
      process.exit(1);
    });
    res.on('exit', (code) => process.exit(code || 0));
    return;
  }

  const uvicornReady = hasUvicorn();

  // Core services (zero-dependency host-ready fallbacks built in)
  const coreServices = [
    {
      name: 'ml-detection-service',
      cmd: 'python',
      args: ['ml-detection-service/main.py'],
      env: { PORT: process.env.ML_PORT || '8001' },
      healthUrl: `http://127.0.0.1:${process.env.ML_PORT || '8001'}/xai/health`,
      critical: true,
    },
    {
      name: 'threat-dashboard-service',
      cmd: 'node',
      args: ['threat-dashboard-service/server.js'],
      env: {
        PORT: process.env.PORT || '7000',
        ML_DETECTION_URL: `http://127.0.0.1:${process.env.ML_PORT || '8001'}`,
        DISABLE_XAI_PG: process.env.DISABLE_XAI_PG || 'true',
      },
      healthUrl: `http://127.0.0.1:${process.env.PORT || '7000'}/health`,
      critical: true,
    },
  ];

  // Optional auxiliary microservices (started automatically if local node_modules or uvicorn exist)
  const optionalNodeServices = [
    { dir: 'traffic-capture-service', port: '3001' },
    { dir: 'flow-feature-extraction-service', port: '3002' },
    { dir: 'threat-log-database-service', port: '3003' },
    { dir: 'playbook-decision-engine', port: '3005' },
    { dir: 'automated-response-service', port: '3006' },
    { dir: 'suricata-event-collector-service', port: '3007' },
    { dir: 'honeypot-event-collector-service', port: '3008' },
    { dir: 'honeypot-manager-service', port: '3009' },
    { dir: 'threat-intelligence-service', port: '3010' },
    { dir: 'attacker-profiling-service', port: '3011' },
    { dir: 'event-correlation-service', port: '3012' },
    { dir: 'attack-chain-service', port: '3013' },
    { dir: 'deception-manager-service', port: '3014' },
    { dir: 'alert-notification-service', port: '3015' },
  ];

  const optionalPythonServices = [
    { dir: 'threat-classification-service', port: '8002' },
    { dir: 'model-training-service', port: '8003' },
  ];

  for (const svc of coreServices) {
    console.log(`[ShadowGuard] Starting ${svc.name}...`);
    launchService(svc);
  }

  let skippedCount = 0;
  for (const svc of optionalNodeServices) {
    if (hasNodeModules(svc.dir)) {
      console.log(`[ShadowGuard] Starting ${svc.dir} (port ${svc.port})...`);
      launchService({
        name: svc.dir,
        cmd: 'node',
        args: [`${svc.dir}/index.js`],
        env: { PORT: svc.port },
        critical: false,
      });
    } else {
      skippedCount++;
    }
  }

  if (uvicornReady) {
    for (const svc of optionalPythonServices) {
      console.log(`[ShadowGuard] Starting ${svc.dir} (port ${svc.port})...`);
      launchService({
        name: svc.dir,
        cmd: 'python',
        args: ['-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', svc.port],
        cwd: path.join(ROOT, svc.dir),
        critical: false,
      });
    }
  } else {
    skippedCount += optionalPythonServices.length;
  }

  console.log('\n[ShadowGuard] Waiting for core service health checks...');
  const mlOk = await waitForHealth(coreServices[0].healthUrl, 'ml-detection-service (ML+XAI)');
  const dashOk = await waitForHealth(coreServices[1].healthUrl, 'threat-dashboard-service');

  console.log('\n================================================================================');
  console.log(` SOC Command Center UI : http://127.0.0.1:${process.env.PORT || '7000'}`);
  console.log(` ML & XAI Service API  : http://127.0.0.1:${process.env.ML_PORT || '8001'}/xai/health`);
  if (skippedCount > 0) {
    console.log(` Note: ${skippedCount} auxiliary services skipped (install per-service deps or use --docker).`);
  }
  console.log(' Press Ctrl+C to stop all services.');
  console.log('================================================================================\n');

  if (VERIFY_AND_EXIT) {
    const ok = mlOk && dashOk;
    shutdownAll(ok ? 0 : 1);
  }
}

main().catch((err) => {
  console.error('[ShadowGuard] Launcher error:', err);
  shutdownAll(1);
});
