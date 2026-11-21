const fs = require('fs');
const path = require('path');
const http = require('http');

let express;
let cors;
let bodyParser;
let axios;
let ws;

try {
  express = require('express');
  cors = require('cors');
  bodyParser = require('body-parser');
} catch (_) {
  // Zero-dependency Express-compatible HTTP router fallback for host execution
  express = function createFallbackExpressApp() {
    const middlewares = [];
    const routes = [];
    const fallbackHandlers = [];

    function compileRoutePattern(pattern) {
      const paramNames = [];
      const regexStr =
        '^' +
        pattern.replace(/:([A-Za-z0-9_]+)/g, (_, name) => {
          paramNames.push(name);
          return '([^/]+)';
        }) +
        '$';
      return { regex: new RegExp(regexStr), paramNames };
    }

    function augmentReqRes(req, res) {
      const rawUrl = req.url || '/';
      const qIdx = rawUrl.indexOf('?');
      req.path = qIdx >= 0 ? rawUrl.slice(0, qIdx) : rawUrl;
      req.query = {};
      if (qIdx >= 0) {
        const sp = new URLSearchParams(rawUrl.slice(qIdx + 1));
        for (const [k, v] of sp.entries()) {
          req.query[k] = v;
        }
      }
      req.headers = req.headers || {};
      req.ip = req.ip || req.socket?.remoteAddress || '127.0.0.1';

      if (typeof res.status !== 'function') {
        res.status = (code) => {
          res.statusCode = code;
          return res;
        };
      }
      if (typeof res.json !== 'function') {
        res.json = (obj) => {
          if (!res.headersSent) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
          }
          res.end(JSON.stringify(obj));
          return res;
        };
      }
      if (typeof res.send !== 'function') {
        res.send = (payload) => {
          if (typeof payload === 'object' && payload !== null && !Buffer.isBuffer(payload)) {
            return res.json(payload);
          }
          res.end(payload);
          return res;
        };
      }
      if (typeof res.sendFile !== 'function') {
        res.sendFile = (filePath) => {
          try {
            const ext = path.extname(filePath).toLowerCase();
            const mimeMap = {
              '.html': 'text/html; charset=utf-8',
              '.js': 'application/javascript; charset=utf-8',
              '.css': 'text/css; charset=utf-8',
              '.json': 'application/json; charset=utf-8',
              '.png': 'image/png',
              '.svg': 'image/svg+xml'
            };
            res.setHeader('Content-Type', mimeMap[ext] || 'application/octet-stream');
            res.end(fs.readFileSync(filePath));
          } catch (e) {
            res.status(404).json({ error: 'File not found' });
          }
        };
      }
    }

    function readBodyIfNeeded(req) {
      if ((req.body !== undefined && req._body) || typeof req.readable !== 'boolean') {
        req.body = req.body || {};
        return Promise.resolve();
      }
      if (req.method === 'GET' || req.method === 'HEAD' || typeof req.on !== 'function') {
        req.body = req.body || {};
        return Promise.resolve();
      }
      return new Promise((resolve) => {
        let chunks = '';
        let resolved = false;
        const done = () => {
          if (resolved) return;
          resolved = true;
          if (chunks) {
            try {
              req.body = JSON.parse(chunks);
            } catch (_) {
              req.body = {};
            }
          } else {
            req.body = req.body || {};
          }
          resolve();
        };
        req.on('data', (c) => {
          chunks += c;
        });
        req.on('end', done);
        req.on('error', done);
        if (req.readableEnded || req.complete) {
          done();
        }
      });
    }

    async function handle(req, res, out) {
      augmentReqRes(req, res);
      await readBodyIfNeeded(req);

      let mwIdx = 0;
      const runMiddlewares = () => {
        if (mwIdx >= middlewares.length) {
          return dispatchRoute();
        }
        const mw = middlewares[mwIdx++];
        mw(req, res, (err) => {
          if (err) {
            if (out) return out(err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          runMiddlewares();
        });
      };

      const dispatchRoute = () => {
        const method = String(req.method || 'GET').toUpperCase();
        for (const r of routes) {
          if (r.method !== method) continue;
          const m = r.compiled.regex.exec(req.path);
          if (!m) continue;
          req.params = {};
          r.compiled.paramNames.forEach((name, idx) => {
            req.params[name] = decodeURIComponent(m[idx + 1]);
          });
          let hIdx = 0;
          const nextHandler = (err) => {
            if (err) {
              if (out) return out(err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            if (hIdx >= r.handlers.length) return;
            const fn = r.handlers[hIdx++];
            Promise.resolve(fn(req, res, nextHandler)).catch((e) => {
              if (out) return out(e);
              res.status(500).json({ error: e.message || 'Internal server error' });
            });
          };
          return nextHandler();
        }

        // Static / 404 fallback
        for (const fb of fallbackHandlers) {
          if (fb.length <= 3) {
            return fb(req, res, () => {});
          }
        }
        res.status(404).json({ error: 'Not found' });
      };

      runMiddlewares();
    }

    const appFn = (req, res) => handle(req, res);
    appFn.handle = handle;
    appFn.use = (fn) => {
      if (typeof fn === 'function') {
        if (fn._isStaticOrMiddleware) {
          middlewares.push(fn);
        } else if (fn.length === 3) {
          middlewares.push(fn);
        } else {
          fallbackHandlers.push(fn);
        }
      }
    };
    for (const m of ['get', 'post', 'patch', 'put', 'delete']) {
      appFn[m] = (routePath, ...handlers) => {
        routes.push({
          method: m.toUpperCase(),
          routePath,
          compiled: compileRoutePattern(routePath),
          handlers
        });
      };
    }
    return appFn;
  };

  express.static = (dirName) => {
    const baseDir = path.isAbsolute(dirName) ? dirName : path.join(__dirname, dirName);
    const mw = (req, res, next) => {
      if (req.method !== 'GET' && req.method !== 'HEAD') return next();
      const rel = req.path === '/' ? '/index.html' : req.path;
      const safePath = path.normalize(path.join(baseDir, rel));
      if (!safePath.startsWith(baseDir)) return next();
      if (fs.existsSync(safePath) && fs.statSync(safePath).isFile()) {
        return res.sendFile(safePath);
      }
      next();
    };
    mw._isStaticOrMiddleware = true;
    return mw;
  };

  cors = () => {
    const mw = (req, res, next) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      next();
    };
    mw._isStaticOrMiddleware = true;
    return mw;
  };

  bodyParser = {
    json: () => {
      const mw = (req, res, next) => next();
      mw._isStaticOrMiddleware = true;
      return mw;
    }
  };
}

try {
  axios = require('axios');
} catch (_) {
  const https = require('https');
  const { URL } = require('url');

  function httpRequestFallback(method, rawUrl, bodyData, config = {}) {
    return new Promise((resolve, reject) => {
      let parsed;
      try {
        parsed = new URL(rawUrl);
      } catch (err) {
        return reject(err);
      }

      if (config.params && typeof config.params === 'object') {
        for (const [k, v] of Object.entries(config.params)) {
          if (v !== undefined && v !== null) parsed.searchParams.set(k, String(v));
        }
      }

      const transport = parsed.protocol === 'https:' ? https : http;
      const headers = Object.assign({}, config.headers || {});
      let payload = null;

      if (bodyData !== undefined && bodyData !== null && method !== 'GET') {
        payload = typeof bodyData === 'string' ? bodyData : JSON.stringify(bodyData);
        if (!headers['Content-Type'] && !headers['content-type']) {
          headers['Content-Type'] = 'application/json';
        }
        headers['Content-Length'] = Buffer.byteLength(payload);
      }

      const req = transport.request(
        parsed,
        { method, headers, timeout: config.timeout || 5000 },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let data = text;
            try {
              data = text ? JSON.parse(text) : {};
            } catch (_) {}
            const response = { data, status: res.statusCode, headers: res.headers };
            if (res.statusCode >= 200 && res.statusCode < 400) {
              resolve(response);
            } else {
              const err = new Error(`Request failed with status code ${res.statusCode}`);
              err.response = response;
              reject(err);
            }
          });
        }
      );

      req.on('timeout', () => {
        req.destroy(new Error(`timeout of ${config.timeout || 5000}ms exceeded`));
      });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  axios = {
    get: (url, config) => httpRequestFallback('GET', url, null, config),
    post: (url, data, config) => httpRequestFallback('POST', url, data, config)
  };
}

try {
  ws = require('ws');
} catch (_) {
  const crypto = require('crypto');
  const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

  function encodeWsFrame(opcode, dataBuf) {
    const len = dataBuf.length;
    let header;
    if (len < 126) {
      header = Buffer.allocUnsafe(2);
      header[0] = 0x80 | opcode;
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.allocUnsafe(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.allocUnsafe(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    return Buffer.concat([header, dataBuf]);
  }

  ws = {
    OPEN: 1,
    Server: class FallbackWebSocketServer {
      constructor(opts = {}) {
        this.clients = new Set();
        this._listeners = {};
        if (opts.server && typeof opts.server.on === 'function') {
          opts.server.on('upgrade', (req, socket) => this._handleUpgrade(req, socket));
        }
      }

      on(event, fn) {
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(fn);
        return this;
      }

      _emit(event, ...args) {
        const list = this._listeners[event];
        if (!list) return;
        for (const fn of list) {
          try { fn(...args); } catch (_) {}
        }
      }

      _handleUpgrade(req, socket) {
        const key = req.headers['sec-websocket-key'];
        if (!key) {
          socket.destroy();
          return;
        }
        const accept = crypto
          .createHash('sha1')
          .update(String(key) + WS_GUID)
          .digest('base64');

        socket.write(
          'HTTP/1.1 101 Switching Protocols\r\n' +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
        );

        const clientListeners = {};
        const client = {
          readyState: 1,
          on(event, fn) {
            if (!clientListeners[event]) clientListeners[event] = [];
            clientListeners[event].push(fn);
            return this;
          },
          send(data) {
            if (this.readyState !== 1 || socket.destroyed) return;
            const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
            socket.write(encodeWsFrame(0x1, buf));
          },
          close() {
            if (this.readyState === 3) return;
            this.readyState = 3;
            try {
              if (!socket.destroyed) socket.end(encodeWsFrame(0x8, Buffer.alloc(0)));
            } catch (_) {}
          }
        };

        const emitClient = (event, ...args) => {
          const list = clientListeners[event];
          if (!list) return;
          for (const fn of list) {
            try { fn(...args); } catch (_) {}
          }
        };

        let rxBuf = Buffer.alloc(0);
        socket.on('data', (chunk) => {
          rxBuf = Buffer.concat([rxBuf, chunk]);
          while (rxBuf.length >= 2) {
            const byte0 = rxBuf[0];
            const byte1 = rxBuf[1];
            const opcode = byte0 & 0x0f;
            const masked = (byte1 & 0x80) !== 0;
            let payloadLen = byte1 & 0x7f;
            let offset = 2;

            if (payloadLen === 126) {
              if (rxBuf.length < 4) break;
              payloadLen = rxBuf.readUInt16BE(2);
              offset = 4;
            } else if (payloadLen === 127) {
              if (rxBuf.length < 10) break;
              payloadLen = Number(rxBuf.readBigUInt64BE(2));
              offset = 10;
            }

            const maskLen = masked ? 4 : 0;
            if (rxBuf.length < offset + maskLen + payloadLen) break;

            const maskKey = masked ? rxBuf.subarray(offset, offset + 4) : null;
            offset += maskLen;
            const payload = Buffer.from(rxBuf.subarray(offset, offset + payloadLen));
            rxBuf = rxBuf.subarray(offset + payloadLen);

            if (masked && maskKey) {
              for (let i = 0; i < payload.length; i++) {
                payload[i] ^= maskKey[i & 3];
              }
            }

            if (opcode === 0x8) {
              client.close();
              break;
            } else if (opcode === 0x9) {
              if (!socket.destroyed) socket.write(encodeWsFrame(0xA, payload));
            } else if (opcode === 0x1 || opcode === 0x2) {
              emitClient('message', opcode === 0x1 ? payload.toString('utf8') : payload);
            }
          }
        });

        const cleanup = () => {
          if (client.readyState === 3 && !this.clients.has(client)) return;
          client.readyState = 3;
          this.clients.delete(client);
          emitClient('close');
        };

        socket.on('close', cleanup);
        socket.on('error', cleanup);

        this.clients.add(client);
        this._emit('connection', client, req);
      }
    }
  };
}

const geminiService = require('./geminiService');
const { SecurityAndObservabilityManager } = require('./lib/securityAndObservability');
const { SocCommandCenterAggregator } = require('./socDataAggregator');
const { XaiExplanationStore } = require('./lib/xaiStore');
const { DemoSimulatorStore } = require('./lib/demoSimulatorStore');

const app = express();
const server = http.createServer(app);
const wss = new ws.Server({ server });

const securityManager = new SecurityAndObservabilityManager();
const socAggregator = new SocCommandCenterAggregator();
const xaiStore = new XaiExplanationStore();
const demoSimulatorStore = new DemoSimulatorStore();
const DEMO_SIMULATOR_URL = process.env.DEMO_SIMULATOR_URL || 'http://demo-traffic-generator:8010';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(securityManager.rateLimitMiddleware());
app.use(express.static('public'));

// Configuration (All 16 Shadow Guard 1.0 + 2.0 Microservices)
const SERVICE_URLS = {
  traffic_capture: 'http://traffic-capture-service:3000',
  feature_extraction: 'http://flow-feature-extraction-service:3000',
  ml_detection: process.env.ML_DETECTION_URL || 'http://ml-detection-service:8000',
  classification: 'http://threat-classification-service:8000',
  decision_engine: 'http://playbook-decision-engine:3000',
  alert: 'http://alert-notification-service:3000',
  response: 'http://automated-response-service:3000',
  database: 'http://threat-log-database-service:3000',
  training: 'http://model-training-service:8000',
  suricata_collector: 'http://suricata-event-collector-service:3007',
  honeypot_manager: 'http://honeypot-manager-service:3010',
  honeypot_collector: 'http://honeypot-event-collector-service:3011',
  threat_intel: 'http://threat-intelligence-service:3012',
  deception_manager: 'http://deception-manager-service:3013',
  attacker_profiling: 'http://attacker-profiling-service:8004',
  event_correlation: 'http://event-correlation-service:8005',
  attack_chain: 'http://attack-chain-service:8006'
};

// In-memory metrics storage (production: use Redis/TimescaleDB)
const metrics = {
  events_processed: 0,
  threats_detected: 0,
  alerts_sent: 0,
  responses_executed: 0,
  last_update: Date.now(),
  active_connections: 0
};

// WebSocket broadcast function
function broadcast(data) {
  wss.clients.forEach(client => {
    if (client.readyState === ws.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

// WebSocket connection handler
wss.on('connection', (ws) => {
  metrics.active_connections = wss.clients.size;
  broadcast({ type: 'connection', active_connections: metrics.active_connections });
  
  ws.on('close', () => {
    metrics.active_connections = wss.clients.size;
    broadcast({ type: 'connection', active_connections: metrics.active_connections });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: Date.now(),
    uptime: process.uptime(),
    active_connections: metrics.active_connections
  });
});

// Get all service health status
app.get('/api/services/health', async (req, res) => {
  const health = {
    dashboard_gateway: {
      status: 'healthy',
      response_time: null,
      timestamp: Date.now()
    }
  };

  await Promise.all(
    Object.entries(SERVICE_URLS).map(async ([name, url]) => {
      try {
        const response = await axios.get(`${url}/health`, { timeout: 3000 });
        health[name] = {
          status: 'healthy',
          response_time: response.headers['x-response-time'] || null,
          timestamp: Date.now()
        };
      } catch (error) {
        const isHostDnsOrRefused =
          error && (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED' ||
            (error.message && (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED'))));
        health[name] = {
          status: 'unhealthy',
          error: isHostDnsOrRefused
            ? 'Offline in native host mode (requires Docker container mesh)'
            : error.message,
          timestamp: Date.now()
        };
      }
    })
  );

  res.json(health);
});

// Get threat logs
app.get('/api/threats', async (req, res) => {
  const sourceMode = String(req.query.source || 'live').toLowerCase();
  const limit = Number(req.query.limit || 100);
  if (sourceMode === 'demo') {
    const demoLogs = demoSimulatorStore.getSessionEvents(req.query.session_id || null, limit);
    return res.json({ total: demoLogs.length, source: 'demo', logs: demoLogs });
  }
  try {
    const response = await axios.get(
      `${SERVICE_URLS.database}/logs`,
      { timeout: 2500 }
    );
    const dbLogs = Array.isArray(response.data) ? response.data : [];
    const liveLogs = DemoSimulatorStore.filterRecordsBySource(dbLogs, sourceMode === 'all' ? 'all' : 'live');
    const combined = sourceMode === 'all'
      ? [...demoSimulatorStore.getSessionEvents(null, limit), ...liveLogs]
      : liveLogs;
    res.json({
      total: combined.length,
      source: sourceMode,
      logs: combined.slice(0, limit)
    });
  } catch (error) {
    const dets = socAggregator.getTriModelDetections({ limit }).detections || [];
    const fallbackLogs = dets.map((f) => ({
      timestamp: f.timestamp,
      src_ip: f.src_ip,
      dst_ip: f.dst_ip,
      protocol: f.protocol,
      attack_type: f.ground_truth?.attack_category === 'none' ? 'normal_traffic' : f.ground_truth?.attack_category,
      severity: f.tri_model_decision.is_anomaly ? 'high' : 'low',
      confidence: f.models.random_forest.attack_probability,
      action: f.tri_model_decision.recommended_action,
      bytes_sent: f.raw_measurements?.bytes || 0,
      duration: f.raw_measurements?.duration || 0
    }));
    const combined = sourceMode === 'all'
      ? [...demoSimulatorStore.getSessionEvents(null, limit), ...fallbackLogs]
      : fallbackLogs;
    res.json({
      total: combined.length,
      source: sourceMode,
      logs: combined.slice(0, limit)
    });
  }
});

// Get threat statistics
app.get('/api/statistics', async (req, res) => {
  const sourceMode = String(req.query.source || 'live').toLowerCase();
  if (sourceMode === 'demo') {
    const snap = demoSimulatorStore.getSessionSnapshot(req.query.session_id || null);
    const evs = snap.recent_events || [];
    return res.json({
      source: 'demo',
      total_events: snap.counters.events_generated,
      high_threats: evs.filter(e => e.detection?.is_anomaly).length,
      medium_threats: 0,
      low_threats: snap.counters.benign_events,
      blocked_ips: snap.demo_leases.length,
      alerts_sent: snap.counters.detected_threats,
      monitored_flows: snap.counters.benign_events
    });
  }
  try {
    const logsResponse = await axios.get(`${SERVICE_URLS.database}/logs`, { timeout: 2500 });
    const rawLogs = Array.isArray(logsResponse.data) ? logsResponse.data : [];
    const logs = DemoSimulatorStore.filterRecordsBySource(rawLogs, sourceMode === 'all' ? 'all' : 'live');
    const severityOf = (log) => {
      const severity = String(log.severity || log.details?.severity || '').toLowerCase();
      if (severity === 'critical' || severity === 'high') return 'high';
      if (severity === 'medium') return 'medium';
      if (severity === 'low') return 'low';
      if (log.confidence > 0.8) return 'high';
      if (log.confidence > 0.5) return 'medium';
      return 'low';
    };
    
    const stats = {
      total_events: logs.length,
      high_threats: logs.filter(l => severityOf(l) === 'high').length,
      medium_threats: logs.filter(l => severityOf(l) === 'medium').length,
      low_threats: logs.filter(l => severityOf(l) === 'low').length,
      blocked_ips: logs.filter(l => l.action === 'block').length,
      alerts_sent: logs.filter(l => l.action === 'alert' || l.action === 'block').length,
      monitored_flows: logs.filter(l => l.action === 'monitor').length
    };
    
    res.json(stats);
  } catch (error) {
    const ov = socAggregator.getTriModelOverview('VIEWER');
    const sd = ov.test_set_summary?.severity_distribution || {};
    res.json({
      total_events: ov.test_set_summary?.total_flows || 384,
      high_threats: (sd.CRITICAL_HIGH_CONFIDENCE || 75) + (sd.HIGH_MULTI_MODEL || 104),
      medium_threats: sd.MEDIUM_SINGLE_DETECTOR_REVIEW || 22,
      low_threats: sd.LOW_SUSPICIOUS_WARNING || 1,
      blocked_ips: socAggregator.soarBlockLeases.length,
      alerts_sent: (sd.CRITICAL_HIGH_CONFIDENCE || 75) + (sd.HIGH_MULTI_MODEL || 104) + (sd.MEDIUM_SINGLE_DETECTOR_REVIEW || 22),
      monitored_flows: sd.NORMAL_BENIGN || 182
    });
  }
});

// Get real-time metrics
app.get('/api/metrics', (req, res) => {
  res.json({
    ...metrics,
    timestamp: Date.now()
  });
});

// Update metrics (called by other services)
app.post('/api/metrics/event', (req, res) => {
  const { type } = req.body;
  
  if (type === 'event_processed') metrics.events_processed++;
  else if (type === 'threat_detected') metrics.threats_detected++;
  else if (type === 'alert_sent') metrics.alerts_sent++;
  else if (type === 'response_executed') metrics.responses_executed++;
  
  metrics.last_update = Date.now();
  
  broadcast({
    type: 'metrics_update',
    metrics: metrics
  });
  
  res.json({ success: true });
});

// Get models status
app.get('/api/models', async (req, res) => {
  try {
    await axios.get(`${SERVICE_URLS.training}/health`, { timeout: 1500 });
  } catch (_) {
    // Fallback to loaded Stage 4 Tri-Model status when container mesh is offline
  }
  const triOverview = socAggregator.getTriModelOverview(req.user?.role || 'VIEWER');
  const mh = triOverview.models_health || {};
  res.json({
    random_forest: {
      status: mh.random_forest?.status === 'healthy' ? 'trained' : 'degraded',
      health: mh.random_forest?.status || 'healthy',
      size: '799 KB',
      accuracy: '97.14% (SYNTHETIC BENCHMARK ONLY)',
      samples_trained: mh.random_forest?.trained_samples || 960
    },
    isolation_forest: {
      status: mh.isolation_forest?.status === 'healthy' ? 'trained' : 'degraded',
      health: mh.isolation_forest?.status || 'healthy',
      size: '1.6 MB',
      accuracy: '72.92% (SYNTHETIC BENCHMARK ONLY)',
      samples_trained: mh.isolation_forest?.trained_samples || 840
    },
    autoencoder: {
      status: mh.autoencoder?.status === 'healthy' ? 'trained' : 'degraded',
      health: mh.autoencoder?.status || 'healthy',
      model_version: mh.autoencoder?.model_version || 'ae-pytorch-v2.0.0',
      size: '48 KB (PyTorch 69->32->16->8->16->32->69)',
      threshold_percentile: mh.autoencoder?.configured_percentile || 'P97',
      threshold_value: mh.autoencoder?.configured_threshold || 0.503670,
      accuracy: '76.30% (SYNTHETIC BENCHMARK ONLY)',
      samples_trained: mh.autoencoder?.trained_samples || 840
    }
  });
});

// Get network traffic analysis
app.get('/api/traffic', async (req, res) => {
  try {
    const logsResponse = await axios.get(`${SERVICE_URLS.database}/logs`, { timeout: 2500 });
    const logs = Array.isArray(logsResponse.data) ? logsResponse.data : [];
    
    const protocolStats = {};
    logs.forEach(log => {
      const proto = log.protocol || 'unknown';
      protocolStats[proto] = (protocolStats[proto] || 0) + 1;
    });
    
    res.json({
      total_flows: logs.length,
      by_protocol: protocolStats,
      avg_bytes_sent: logs.length > 0 ? 
        logs.reduce((sum, l) => sum + (l.bytes_sent || 0), 0) / logs.length : 0,
      avg_duration: logs.length > 0 ?
        logs.reduce((sum, l) => sum + (l.duration || 0), 0) / logs.length : 0
    });
  } catch (error) {
    const dets = socAggregator.getTriModelDetections({ limit: 100 }).detections || [];
    const protocolStats = {};
    dets.forEach((f) => {
      const proto = String(f.protocol || 'TCP').toLowerCase();
      protocolStats[proto] = (protocolStats[proto] || 0) + 1;
    });
    res.json({
      total_flows: 384,
      by_protocol: protocolStats,
      avg_bytes_sent: dets.length > 0
        ? Math.round(dets.reduce((sum, f) => sum + (f.raw_measurements?.bytes || 0), 0) / dets.length)
        : 0,
      avg_duration: dets.length > 0
        ? dets.reduce((sum, f) => sum + (f.raw_measurements?.duration || 0), 0) / dets.length
        : 0
    });
  }
});

// Reload playbook rules endpoint
app.post('/api/rules/reload', async (req, res) => {
  try {
    const response = await axios.post(`${SERVICE_URLS.decision_engine}/reload-rules`);
    res.json({ success: true, message: 'Rules reloaded successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reload rules' });
  }
});

// Get current playbook rules
app.get('/api/rules', async (req, res) => {
  try {
    // Return sample rules structure
    res.json({
      benign: {
        confidence_threshold: 0.3,
        action: 'monitor',
        description: 'Monitor normal traffic'
      },
      medium_threat: {
        confidence_threshold: 0.5,
        action: 'alert',
        description: 'Send alert for medium confidence threats'
      },
      high_threat: {
        confidence_threshold: 0.8,
        action: 'block',
        description: 'Block high confidence threats'
      },
      zero_day: {
        confidence_threshold: 0.95,
        action: 'block',
        description: 'Escalate zero-day style attacks immediately'
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch rules' });
  }
});

// Get alert notification configuration
app.get('/api/alerts/config', async (req, res) => {
  try {
    const response = await axios.get(`${SERVICE_URLS.alert}/config`, { timeout: 2500 });
    res.json(response.data);
  } catch (error) {
    res.json({
      recipient: 'admin@shadowguard.com',
      recipients: ['admin@shadowguard.com'],
      criticalOnly: true
    });
  }
});

// Update alert notification configuration
app.post('/api/alerts/config', async (req, res) => {
  try {
    const response = await axios.post(`${SERVICE_URLS.alert}/config`, req.body, { timeout: 5000 });
    res.json(response.data);
  } catch (error) {
    const status = error.response?.status || 500;
    const payload = error.response?.data || { error: 'Failed to update alert config' };
    res.status(status).json(payload);
  }
});

// Gemini AI Service Endpoints (Powered by gemini-3.8-flash)
app.get('/api/gemini/status', (req, res) => {
  res.json(geminiService.getStatus());
});

app.post('/api/gemini/config', (req, res) => {
  const { apiKey } = req.body || {};
  geminiService.setApiKey(apiKey);
  res.json({
    message: apiKey ? 'Gemini API key configured' : 'Gemini API key cleared',
    status: geminiService.getStatus()
  });
});

app.post('/api/gemini/analyze', async (req, res) => {
  try {
    const { threat, apiKey } = req.body || {};
    if (!threat) {
      return res.status(400).json({ error: 'Missing threat payload for analysis' });
    }
    const analysis = await geminiService.analyzeThreat(threat, apiKey);
    res.json(analysis);
  } catch (error) {
    console.error('[Gemini /analyze error]', error);
    res.status(500).json({ error: error.message || 'Failed to analyze threat with Gemini' });
  }
});

app.post('/api/gemini/chat', async (req, res) => {
  try {
    const { message, history, context, apiKey } = req.body || {};
    if (!message) {
      return res.status(400).json({ error: 'Message cannot be empty' });
    }
    const reply = await geminiService.chatWithCopilot({
      message,
      history,
      networkContext: context || metrics,
      apiKey
    });
    res.json(reply);
  } catch (error) {
    console.error('[Gemini /chat error]', error);
    res.status(500).json({ error: error.message || 'Failed to communicate with Gemini Copilot' });
  }
});

app.post('/api/gemini/executive-briefing', async (req, res) => {
  try {
    const { threats, stats, apiKey } = req.body || {};
    let resolvedThreats = threats;
    let resolvedStats = stats;

    if (!resolvedThreats || !resolvedStats) {
      try {
        const logsRes = await axios.get(`${SERVICE_URLS.database}/logs`, { timeout: 3000 });
        resolvedThreats = Array.isArray(logsRes.data) ? logsRes.data : [];
      } catch (e) {
        resolvedThreats = [];
      }
      resolvedStats = resolvedStats || metrics;
    }

    const briefing = await geminiService.generateExecutiveBriefing({
      threats: resolvedThreats,
      stats: resolvedStats,
      apiKey
    });
    res.json(briefing);
  } catch (error) {
    console.error('[Gemini /executive-briefing error]', error);
    res.status(500).json({ error: error.message || 'Failed to generate executive briefing' });
  }
});

// Export data as JSON
app.get('/api/export/logs', async (req, res) => {
  try {
    const logsResponse = await axios.get(`${SERVICE_URLS.database}/logs`);
    const logs = Array.isArray(logsResponse.data) ? logsResponse.data : [];
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=threat-logs.json');
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to export logs' });
  }
});

// ============================================================================
// SHADOW GUARD 2.0 — UNIFIED SOC COMMAND CENTER, RBAC & OBSERVABILITY ROUTES
// ============================================================================

// Issue RBAC JWT Token for SOC Analysts / Admins / Viewers
app.post('/api/v2/auth/token', (req, res) => {
  const { username, role } = req.body || {};
  const upperRole = String(role || '').toUpperCase();
  const validRole = ['ADMIN', 'SOC_ANALYST', 'ANALYST', 'VIEWER'].includes(upperRole)
    ? (upperRole === 'ANALYST' ? 'SOC_ANALYST' : upperRole)
    : 'SOC_ANALYST';
  const token = securityManager.issueToken({
    sub: username || 'soc-operator',
    role: validRole
  });
  securityManager.recordSecurityAudit('TOKEN_ISSUED', { sub: username || 'soc-operator', role: validRole });
  res.json({
    status: 'success',
    token,
    role: validRole,
    expires_in: 3600
  });
});

// Unified SOC 2.0 Command Center Snapshot (All Pages)
app.get('/api/v2/soc/overview', securityManager.requireRole('VIEWER'), (req, res) => {
  res.json({
    status: 'success',
    data: socAggregator.getUnifiedSnapshot(req.user?.role || 'VIEWER')
  });
});

// ============================================================================
// STAGE 4: AUTOENCODER & TRI-MODEL DETECTION ENGINE SOC COMMAND CENTER ROUTES
// ============================================================================

// 1. Tri-Model Overview (Model Health, Thresholds P95/P97/P99, Severity Distribution, Timeline & Degraded State)
app.get('/api/v2/soc/ml/overview', securityManager.requireRole('VIEWER'), (req, res) => {
  const role = req.user?.role || 'VIEWER';
  res.json({
    status: 'success',
    data: socAggregator.getTriModelOverview(role)
  });
});

// 2. Explainable Tri-Model Detections (RF Probabilities, IF Scores, AE MSE, Top Features, Agreement, Rules)
app.get('/api/v2/soc/ml/detections', securityManager.requireRole('VIEWER'), (req, res) => {
  const role = req.user?.role || 'VIEWER';
  const data = socAggregator.getTriModelDetections(
    {
      policy: req.query.policy,
      decision: req.query.decision,
      agreement: req.query.agreement,
      limit: req.query.limit
    },
    role
  );
  res.json({
    status: 'success',
    data
  });
});

// 3. Individual Flow / Incident Explainable Investigation Dossier
app.get('/api/v2/soc/ml/detections/:flowId', securityManager.requireRole('VIEWER'), (req, res) => {
  const role = req.user?.role || 'VIEWER';
  const details = socAggregator.getFlowInvestigationDetails(req.params.flowId, role);
  if (!details) {
    return res.status(404).json({ status: 'error', message: `Flow '${req.params.flowId}' not found` });
  }
  res.json({
    status: 'success',
    data: details
  });
});

// 4. False-Positive (FP), False-Negative (FN) & Feature-Collision Evaluation Views (SYNTHETIC BENCHMARK ONLY)
app.get('/api/v2/soc/ml/evaluation', securityManager.requireRole('VIEWER'), (req, res) => {
  const role = req.user?.role || 'VIEWER';
  res.json({
    status: 'success',
    data: socAggregator.getEvaluationViews(role)
  });
});

// 5. Autoencoder-Only (AE_ONLY) & Single-Detector Manual Review Queue
app.get('/api/v2/soc/ml/manual-review', securityManager.requireRole('VIEWER'), (req, res) => {
  const role = req.user?.role || 'VIEWER';
  res.json({
    status: 'success',
    data: socAggregator.getManualReviewQueue(role)
  });
});

// 6. Execute Manual-Review Decision (Requires SOC_ANALYST or ADMIN; enforces AE-Only Non-Auto-Block Safety Lock)
app.post('/api/v2/soc/ml/manual-review/:flowId/decision', securityManager.requireRole('SOC_ANALYST'), (req, res) => {
  const operator = req.user?.sub || 'soc-analyst';
  const role = req.user?.role || 'SOC_ANALYST';
  const result = socAggregator.decideManualReview(req.params.flowId, {
    decision: req.body?.decision,
    analyst_notes: req.body?.analyst_notes,
    operator,
    role
  });

  if (!result.found) {
    return res.status(404).json({ status: 'error', message: result.error });
  }

  if (result.rejected_by_safety_policy) {
    securityManager.recordSecurityAudit('AE_ONLY_AUTOBLOCK_PREVENTED', {
      flow_id: req.params.flowId,
      operator,
      role,
      requested_decision: req.body?.decision
    });
    return res.status(422).json({
      status: 'rejected_by_safety_policy',
      auto_block_executed: false,
      message: result.message,
      data: result
    });
  }

  securityManager.recordSecurityAudit('ML_MANUAL_REVIEW_DECISION', {
    flow_id: req.params.flowId,
    decision: result.item.review_status,
    is_autoencoder_only: result.item.is_autoencoder_only,
    auto_block_executed: false,
    operator,
    role
  });

  broadcast({
    type: 'soc_v2_update',
    snapshot: socAggregator.getUnifiedSnapshot('VIEWER')
  });

  res.json({
    status: 'success',
    data: result
  });
});

// 7. Switch Active Tri-Model Fusion Policy (Requires SOC_ANALYST or ADMIN)
app.post('/api/v2/soc/ml/fusion-policy', securityManager.requireRole('SOC_ANALYST'), (req, res) => {
  const operator = req.user?.sub || 'soc-analyst';
  const policy = String(req.body?.policy || '').trim();
  const result = socAggregator.setActiveFusionPolicy(policy, operator);
  if (!result.success) {
    return res.status(400).json({ status: 'error', message: result.error });
  }
  securityManager.recordSecurityAudit('ML_FUSION_POLICY_UPDATED', {
    policy: result.active_fusion_policy,
    operator,
    role: req.user?.role || 'SOC_ANALYST'
  });
  res.json({
    status: 'success',
    data: result
  });
});

// 8. Configure / Simulate Degraded Model State (Restricted to ADMIN)
app.post('/api/v2/soc/ml/degraded-mode', securityManager.requireRole('ADMIN'), (req, res) => {
  const operator = req.user?.sub || 'soc-admin';
  const updatedOverview = socAggregator.setSimulatedDegradedState({
    degraded_models: req.body?.degraded_models || [],
    reason: req.body?.reason || 'admin_simulated_degradation',
    operator
  });
  securityManager.recordSecurityAudit('ML_DEGRADED_MODE_CHANGED', {
    status: updatedOverview.engine_status,
    degraded_models: updatedOverview.degraded_state.degraded_models,
    operator
  });
  res.json({
    status: 'success',
    data: updatedOverview
  });
});

// 9. Restricted Model Reload (Restricted strictly to ADMIN — VIEWER & SOC_ANALYST denied)
app.post('/api/v2/soc/ml/reload', securityManager.requireRole('ADMIN'), async (req, res) => {
  const operator = req.user?.sub || 'soc-admin';
  let liveServiceReloaded = false;
  try {
    const mlRes = await axios.post(`${SERVICE_URLS.ml_detection}/model/reload`, {}, { timeout: 2000 });
    liveServiceReloaded = Boolean(mlRes.data);
  } catch (_) {
    liveServiceReloaded = false;
  }
  const reloadSummary = socAggregator.reloadTriModelTelemetry(operator);
  reloadSummary.live_ml_service_contacted = liveServiceReloaded;
  securityManager.recordSecurityAudit('ML_MODELS_RELOADED', {
    operator,
    role: req.user?.role || 'ADMIN',
    engine_status: reloadSummary.engine_status
  });
  res.json({
    status: 'success',
    data: reloadSummary
  });
});

// 10. 6-Model Synthetic Benchmark & Research View (`SYNTHETIC BENCHMARK ONLY`)
app.get('/api/v2/soc/ml/research-benchmark', securityManager.requireRole('VIEWER'), (req, res) => {
  const role = req.user?.role || 'VIEWER';
  res.json({
    status: 'success',
    data: socAggregator.getResearchBenchmark(role)
  });
});

// Simulate a live multi-stage intrusion across Honeypots, Suricata, Profiling, Correlation, Attack Chain & SOAR
app.post('/api/v2/soc/simulate-attack', securityManager.requireRole('SOC_ANALYST'), (req, res) => {
  const { scenario } = req.body || {};
  const result = socAggregator.simulateMultiStageAttack(scenario || 'ssh_compromise');
  securityManager.recordSecurityAudit('SIMULATED_MULTI_STAGE_ATTACK', {
    operator: req.user?.sub || 'soc-operator',
    scenario: scenario || 'ssh_compromise',
    incident_id: result.incident.incident_id
  });
  broadcast({
    type: 'soc_v2_update',
    snapshot: socAggregator.getUnifiedSnapshot()
  });
  res.status(201).json({ status: 'success', data: result });
});

// Rollback an Adaptive Deception Directive
app.post('/api/v2/soc/directives/:id/rollback', securityManager.requireRole('SOC_ANALYST'), (req, res) => {
  const dir = socAggregator.adaptiveDirectives.find(d => d.directive_id === req.params.id);
  if (!dir) {
    return res.status(404).json({ status: 'error', message: 'Directive not found' });
  }
  dir.status = 'ROLLED_BACK';
  dir.rolled_back_at = new Date().toISOString();
  securityManager.recordSecurityAudit('DECEPTION_DIRECTIVE_ROLLED_BACK', {
    directive_id: dir.directive_id,
    operator: req.user?.sub || 'soc-operator'
  });
  res.json({ status: 'success', data: dir });
});

// Approve a pending SOAR permanent block request (Requires ADMIN role)
app.post('/api/v2/soc/approvals/:id/approve', securityManager.requireRole('ADMIN'), (req, res) => {
  const idx = socAggregator.soarPendingApprovals.findIndex(p => p.execution_id === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ status: 'error', message: 'Pending approval not found' });
  }
  const pending = socAggregator.soarPendingApprovals[idx];
  pending.status = 'APPROVED_AND_EXECUTED';
  const newBlock = {
    execution_id: `exec-perm-${Date.now().toString().slice(-4)}`,
    ip: pending.target_ip,
    block_type: 'PERMANENT',
    lease_minutes: null,
    playbook_id: pending.playbook_id,
    blocked_at: new Date().toISOString(),
    expires_at: 'PERMANENT',
    status: 'ACTIVE_BLOCKED',
    reason: `Approved permanent block (${pending.reason})`
  };
  socAggregator.soarBlockLeases.unshift(newBlock);
  socAggregator.soarPendingApprovals.splice(idx, 1);

  securityManager.recordSecurityAudit('SOAR_PERMANENT_BLOCK_APPROVED', {
    execution_id: pending.execution_id,
    target_ip: pending.target_ip,
    operator: req.user?.sub || 'soc-admin'
  });
  res.json({ status: 'success', data: newBlock });
});

// Rollback an active SOAR IP Block Lease
app.post('/api/v2/soc/blocks/:id/rollback', securityManager.requireRole('SOC_ANALYST'), (req, res) => {
  const blk = socAggregator.soarBlockLeases.find(b => b.execution_id === req.params.id);
  if (!blk) {
    return res.status(404).json({ status: 'error', message: 'Block lease not found' });
  }
  blk.status = 'ROLLED_BACK_UNBLOCKED';
  blk.rolled_back_at = new Date().toISOString();
  securityManager.recordSecurityAudit('SOAR_BLOCK_ROLLED_BACK', {
    execution_id: blk.execution_id,
    ip: blk.ip,
    operator: req.user?.sub || 'soc-operator'
  });
  res.json({ status: 'success', data: blk });
});

// Update Incident Status
app.patch('/api/v2/soc/incidents/:id/status', securityManager.requireRole('SOC_ANALYST'), (req, res) => {
  const inc = socAggregator.incidents.find(i => i.incident_id === req.params.id);
  if (!inc) {
    return res.status(404).json({ status: 'error', message: 'Incident not found' });
  }
  inc.status = String(req.body?.status || 'CONTAINED').toUpperCase();
  securityManager.recordSecurityAudit('INCIDENT_STATUS_UPDATED', {
    incident_id: inc.incident_id,
    status: inc.status,
    operator: req.user?.sub || 'soc-operator'
  });
  res.json({ status: 'success', data: inc });
});

// ============================================================================
// XAI STAGE 3: EXPLAINABLE AI (XAI) AUTHENTICATED API GATEWAY ROUTES
// ============================================================================

const XAI_FLOW_ID_REGEX = /^[A-Za-z0-9_.:-]{1,128}$/;
const XAI_ALLOWED_POLICIES = new Set(['weighted_consensus', 'unsupervised_ensemble', 'majority_vote']);

function getMlDetectionBaseUrl() {
  return process.env.ML_DETECTION_URL || SERVICE_URLS.ml_detection;
}

let mlXaiDispatchOverride = null;

function setMlXaiDispatcher(fn) {
  mlXaiDispatchOverride = typeof fn === 'function' ? fn : null;
}

function callMlXaiService(method, endpoint, bodyObj = null, timeoutMs = Number(process.env.XAI_ML_TIMEOUT_MS || 8000)) {
  if (mlXaiDispatchOverride) {
    return Promise.resolve(mlXaiDispatchOverride(method, endpoint, bodyObj, timeoutMs));
  }
  return new Promise((resolve, reject) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(endpoint, getMlDetectionBaseUrl());
    } catch (err) {
      return reject(Object.assign(new Error('Invalid ML service URL configuration'), { code: 'ML_CONFIG_ERROR' }));
    }

    const bodyStr = bodyObj !== null ? JSON.stringify(bodyObj) : null;
    const req = http.request(
      {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method: method.toUpperCase(),
        timeout: timeoutMs,
        headers: bodyStr
          ? {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(bodyStr),
            }
          : {},
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          raw += chunk;
        });
        res.on('end', () => {
          try {
            resolve({ statusCode: res.statusCode, body: raw ? JSON.parse(raw) : {} });
          } catch (parseErr) {
            reject(Object.assign(new Error('Invalid JSON response from ML XAI service'), { code: 'ML_BAD_GATEWAY' }));
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(Object.assign(new Error(`ML XAI service request timed out after ${timeoutMs}ms`), { code: 'ML_TIMEOUT' }));
    });

    req.on('error', (err) => {
      reject(Object.assign(new Error(err.message || 'ML XAI service unreachable'), { code: err.code || 'ML_UNAVAILABLE' }));
    });

    if (bodyStr) {
      req.write(bodyStr);
    }
    req.end();
  });
}

function sanitizeXaiForRole(payload, userRole = 'VIEWER') {
  const sanitized = socAggregator.sanitizeForRole(payload, userRole);
  const upperRole = String(userRole || 'VIEWER').toUpperCase();
  if (upperRole === 'VIEWER' && sanitized && typeof sanitized === 'object') {
    if (sanitized.flow_metadata && typeof sanitized.flow_metadata === 'object') {
      const fm = { ...sanitized.flow_metadata };
      delete fm.src_ip;
      delete fm.dst_ip;
      delete fm.src_port;
      sanitized.flow_metadata = fm;
    }
  }
  return sanitized;
}

function validateXaiExplainInput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'Request body must be a JSON object';
  }
  const { flow_id, features, raw_flow, policy = 'weighted_consensus', top_k = 5 } = body;
  if (!XAI_ALLOWED_POLICIES.has(String(policy))) {
    return `Unsupported policy '${policy}'. Allowed: weighted_consensus, unsupervised_ensemble, majority_vote`;
  }
  if (flow_id !== undefined && flow_id !== null) {
    if (typeof flow_id !== 'string' || !XAI_FLOW_ID_REGEX.test(flow_id.trim())) {
      return 'Invalid flow_id format (expected 1-128 alphanumeric/._:- characters)';
    }
  }
  if ((flow_id === undefined || flow_id === null) && features === undefined && raw_flow === undefined) {
    return 'Must provide at least one of flow_id, features (69 floats), or raw_flow';
  }
  if (features !== undefined && features !== null) {
    if (!Array.isArray(features) || features.length !== 69) {
      return 'Invalid features: expected an array of 69 finite numbers';
    }
    for (const v of features) {
      if (typeof v !== 'number' || !Number.isFinite(v)) {
        return 'Invalid features: all 69 elements must be finite numbers';
      }
    }
  }
  const tk = Number(top_k);
  if (!Number.isInteger(tk) || tk < 1 || tk > 20) {
    return 'Invalid top_k: must be an integer between 1 and 20';
  }
  return null;
}

// 1. GET /api/v2/xai/overview (VIEWER+)
app.get('/api/v2/xai/overview', securityManager.requireRole('VIEWER'), async (req, res) => {
  const role = req.user?.role || 'VIEWER';
  const operator = req.user?.sub || 'soc-viewer';
  let mlXaiHealth = { status: 'unavailable', error: 'ML service not contacted' };
  try {
    const mlRes = await callMlXaiService('GET', '/xai/health', null, 4000);
    if (mlRes.statusCode === 200) {
      mlXaiHealth = mlRes.body;
    } else {
      mlXaiHealth = { status: 'degraded', http_status: mlRes.statusCode };
    }
  } catch (err) {
    mlXaiHealth = { status: 'unavailable', reason: err.code || 'ML_UNAVAILABLE' };
  }

  const storeStats = await xaiStore.getOverviewStats();
  securityManager.recordSecurityAudit('XAI_OVERVIEW_ACCESSED', {
    operator,
    role,
    ml_xai_status: mlXaiHealth.status,
    storage_backend: storeStats.storage_backend,
  });

  const payload = {
    schema_version: 'v2.0-69dim',
    safety_policy: {
      read_only_on_predictions: true,
      preserves_weighted_consensus: true,
      ae_only_auto_block_permitted: false,
      frozen_ae_threshold_p97: 0.50367,
    },
    ml_xai_health: mlXaiHealth,
    persistence: storeStats,
    supported_methods: {
      random_forest: 'Official shap.TreeExplainer (exact TreeSHAP over Attack Probability)',
      isolation_forest: 'Reference-Population Median-Replacement Perturbation & Quantile Deviation (NOT probability)',
      autoencoder: 'PyTorch Bottleneck Per-Feature MSE Decomposition vs Frozen P97=0.503670 (NOT probability)',
    },
  };

  res.json({
    status: 'success',
    data: sanitizeXaiForRole(payload, role),
  });
});

// 2. GET /api/v2/xai/explanation/:flowId (VIEWER+)
app.get('/api/v2/xai/explanation/:flowId', securityManager.requireRole('VIEWER'), async (req, res) => {
  const role = req.user?.role || 'VIEWER';
  const operator = req.user?.sub || 'soc-viewer';
  const flowId = String(req.params.flowId || '').trim();
  const policy = String(req.query.policy || 'weighted_consensus');

  if (!XAI_FLOW_ID_REGEX.test(flowId)) {
    return res.status(400).json({ status: 'error', message: 'Invalid flowId parameter format' });
  }
  if (!XAI_ALLOWED_POLICIES.has(policy)) {
    return res.status(400).json({ status: 'error', message: `Unsupported policy '${policy}'` });
  }

  // Check LRU cache / PostgreSQL store first
  const cached = await xaiStore.getExplanationByFlowId(flowId, policy);
  if (cached.found && cached.record) {
    const expObj = cached.record.full_payload || {
      flow_id: cached.record.flow_id,
      schema_version: cached.record.feature_schema_version,
      explanation_generation_status: cached.record.explanation_status,
      final_tri_model_classification: cached.record.final_tri_model_classification,
      random_forest_explanation: cached.record.rf_shap_contributions,
      isolation_forest_explanation: cached.record.if_attribution,
      autoencoder_explanation: cached.record.ae_reconstruction_errors,
      model_agreement_and_disagreement: cached.record.unified_model_agreement,
      human_readable_soc_analyst_explanation: cached.record.analyst_explanation,
      explanation_confidence_and_limitations: cached.record.explanation_confidence_limitations,
    };
    securityManager.recordSecurityAudit('XAI_EXPLANATION_ACCESSED', {
      flow_id: flowId,
      policy,
      source: cached.source,
      operator,
      role,
    });
    return res.json({
      status: 'success',
      source: cached.source,
      data: sanitizeXaiForRole(expObj, role),
    });
  }

  // Otherwise query ML XAI service
  try {
    const mlRes = await callMlXaiService('POST', '/xai/explain', { flow_id: flowId, policy });
    if (mlRes.statusCode === 404) {
      return res.status(404).json({ status: 'error', message: `Flow '${flowId}' not found`, data: mlRes.body });
    }
    if (mlRes.statusCode !== 200) {
      return res.status(mlRes.statusCode).json({ status: 'error', message: mlRes.body?.error || 'XAI explanation failed', data: mlRes.body });
    }

    const persistInfo = await xaiStore.saveExplanation(mlRes.body, null);
    securityManager.recordSecurityAudit('XAI_EXPLANATION_ACCESSED', {
      flow_id: flowId,
      policy,
      source: 'ml_xai_service',
      explanation_id: persistInfo.explanation_id,
      storage_backend: persistInfo.storage_backend,
      operator,
      role,
    });

    return res.json({
      status: 'success',
      source: 'ml_xai_service',
      persistence: persistInfo,
      data: sanitizeXaiForRole(mlRes.body, role),
    });
  } catch (err) {
    const httpCode = err.code === 'ML_TIMEOUT' ? 504 : 503;
    securityManager.recordSecurityAudit('XAI_ML_SERVICE_ERROR', {
      flow_id: flowId,
      error_code: err.code || 'ML_UNAVAILABLE',
      operator,
      role,
    });
    return res.status(httpCode).json({
      status: 'error',
      code: err.code || 'ML_UNAVAILABLE',
      message: `ML XAI service unavailable: ${err.message}`,
    });
  }
});

// 3. POST /api/v2/xai/explanation (SOC_ANALYST+)
app.post('/api/v2/xai/explanation', securityManager.requireRole('SOC_ANALYST'), async (req, res) => {
  const role = req.user?.role || 'SOC_ANALYST';
  const operator = req.user?.sub || 'soc-analyst';
  const valErr = validateXaiExplainInput(req.body);
  if (valErr) {
    return res.status(400).json({ status: 'error', message: valErr });
  }

  try {
    const mlRes = await callMlXaiService('POST', '/xai/explain', req.body);
    if (mlRes.statusCode === 404) {
      return res.status(404).json({ status: 'error', message: `Flow '${req.body.flow_id}' not found`, data: mlRes.body });
    }
    if (mlRes.statusCode !== 200) {
      return res.status(mlRes.statusCode).json({ status: 'error', message: mlRes.body?.error || 'XAI explanation failed', data: mlRes.body });
    }

    const persistInfo = await xaiStore.saveExplanation(mlRes.body, req.body.features || null);
    securityManager.recordSecurityAudit('XAI_EXPLANATION_GENERATED', {
      flow_id: mlRes.body.flow_id,
      explanation_id: persistInfo.explanation_id,
      explanation_status: mlRes.body.explanation_generation_status,
      storage_backend: persistInfo.storage_backend,
      operator,
      role,
    });

    return res.json({
      status: 'success',
      persistence: persistInfo,
      data: sanitizeXaiForRole(mlRes.body, role),
    });
  } catch (err) {
    const httpCode = err.code === 'ML_TIMEOUT' ? 504 : 503;
    return res.status(httpCode).json({
      status: 'error',
      code: err.code || 'ML_UNAVAILABLE',
      message: `ML XAI service unavailable: ${err.message}`,
    });
  }
});

// 4. POST /api/v2/xai/explanation/batch (SOC_ANALYST+)
app.post('/api/v2/xai/explanation/batch', securityManager.requireRole('SOC_ANALYST'), async (req, res) => {
  const role = req.user?.role || 'SOC_ANALYST';
  const operator = req.user?.sub || 'soc-analyst';
  const items = req.body?.items;

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ status: 'error', message: 'Request body must include a non-empty items array' });
  }
  if (items.length > 50) {
    return res.status(400).json({ status: 'error', message: 'Batch size exceeds maximum limit of 50 items' });
  }
  for (let i = 0; i < items.length; i++) {
    const err = validateXaiExplainInput(items[i]);
    if (err) {
      return res.status(400).json({ status: 'error', message: `Invalid item at index ${i}: ${err}` });
    }
  }

  try {
    const mlRes = await callMlXaiService('POST', '/xai/explain/batch', req.body, Number(process.env.XAI_BATCH_TIMEOUT_MS || 20000));
    if (mlRes.statusCode !== 200) {
      return res.status(mlRes.statusCode).json({ status: 'error', message: mlRes.body?.error || 'Batch XAI failed', data: mlRes.body });
    }

    const batchBody = mlRes.body;
    const savedIds = [];
    for (const entry of batchBody.results || []) {
      if (entry.http_status === 200 && entry.explanation) {
        const idx = entry.index;
        const pInfo = await xaiStore.saveExplanation(entry.explanation, items[idx]?.features || null);
        savedIds.push(pInfo.explanation_id);
        entry.explanation = sanitizeXaiForRole(entry.explanation, role);
      }
    }

    securityManager.recordSecurityAudit('XAI_BATCH_EXPLANATION_GENERATED', {
      total_requested: batchBody.total_requested,
      succeeded_count: batchBody.succeeded_count,
      degraded_count: batchBody.degraded_count,
      saved_count: savedIds.length,
      operator,
      role,
    });

    return res.json({
      status: 'success',
      saved_explanation_ids: savedIds,
      data: sanitizeXaiForRole(batchBody, role),
    });
  } catch (err) {
    const httpCode = err.code === 'ML_TIMEOUT' ? 504 : 503;
    return res.status(httpCode).json({
      status: 'error',
      code: err.code || 'ML_UNAVAILABLE',
      message: `ML XAI service unavailable: ${err.message}`,
    });
  }
});

// 5. GET /api/v2/xai/diagnostics (ADMIN only)
app.get('/api/v2/xai/diagnostics', securityManager.requireRole('ADMIN'), async (req, res) => {
  const operator = req.user?.sub || 'soc-admin';
  const storeStats = await xaiStore.getOverviewStats();
  let mlHealth = { status: 'unavailable' };
  try {
    const mlRes = await callMlXaiService('GET', '/xai/health', null, 4000);
    mlHealth = mlRes.body;
  } catch (err) {
    mlHealth = { status: 'unavailable', code: err.code || 'ML_UNAVAILABLE' };
  }

  securityManager.recordSecurityAudit('XAI_ADMIN_DIAGNOSTICS_ACCESSED', {
    operator,
    role: req.user?.role || 'ADMIN',
  });

  res.json({
    status: 'success',
    data: {
      ml_xai_health: mlHealth,
      persistence: storeStats,
      ml_timeout_ms: Number(process.env.XAI_ML_TIMEOUT_MS || 8000),
      strict_auth_enabled: securityManager.strictAuth,
    },
  });
});

// Security Audit Log
app.get('/api/v2/security/audit', securityManager.requireRole('VIEWER'), (req, res) => {
  res.json({
    status: 'success',
    count: securityManager.securityAuditLog.length,
    data: securityManager.securityAuditLog
  });
});

// Prometheus Exposition Format Metrics Endpoint (`/metrics`)
app.get('/metrics', (req, res) => {
  const snap = socAggregator.getUnifiedSnapshot();
  const promText = securityManager.formatPrometheusMetrics({
    events_processed: metrics.events_processed + snap.summary_kpis.honeypot_events_24h,
    threats_detected: metrics.threats_detected + snap.summary_kpis.open_incidents,
    honeypot_interactions: snap.summary_kpis.honeypot_events_24h,
    active_incidents: snap.summary_kpis.open_incidents,
    attacker_profiles: snap.summary_kpis.tracked_attacker_profiles,
    active_ip_blocks: snap.summary_kpis.active_ip_block_leases,
    active_deception_directives: snap.summary_kpis.active_adaptive_directives,
    active_connections: metrics.active_connections
  });
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(promText);
});

// ============================================================================
// DEMO TRAFFIC SIMULATOR CONTROL, SESSION STORE & WEBSOCKET STREAMING (STAGE 3)
// ============================================================================

const DEMO_VALID_SCENARIOS = new Set([
  'normal_traffic', 'normal',
  'port_scan',
  'ssh_brute_force', 'brute_force',
  'service_enumeration',
  'ddos',
  'data_exfiltration',
  'c2_beaconing', 'malware_command_control',
  'multi_vector',
  'stealth_anomaly', 'zero_day',
  'mixed'
]);
const DEMO_VALID_MODES = new Set(['single', 'mixed']);
const DEMO_VALID_SPEEDS = new Set(['low', 'medium', 'high']);

let demoSimDispatcher = null;
let demoMlDispatcher = null;
let demoPollTimer = null;
let demoPollInFlight = false;
let demoPollPromise = null;
let lastBroadcastState = null;

function setDemoSimulatorDispatcher(fn) {
  demoSimDispatcher = typeof fn === 'function' ? fn : null;
}

function setDemoMlDispatcher(fn) {
  demoMlDispatcher = typeof fn === 'function' ? fn : null;
}

async function callDemoSimulator(method, pathSuffix, body = null, timeoutMs = 4000) {
  if (demoSimDispatcher) {
    return demoSimDispatcher(method, pathSuffix, body, timeoutMs);
  }
  const url = `${DEMO_SIMULATOR_URL}${pathSuffix}`;
  try {
    const resp = method === 'GET'
      ? await axios.get(url, { timeout: timeoutMs })
      : await axios.post(url, body || {}, { timeout: timeoutMs });
    return { status: resp.status || 200, data: resp.data };
  } catch (err) {
    if (err && err.response) {
      return { status: err.response.status, data: err.response.data };
    }
    const unavailable = new Error(`Demo simulator unavailable: ${err.message}`);
    unavailable.code = 'SIMULATOR_UNAVAILABLE';
    throw unavailable;
  }
}

async function detectViaMl(payload) {
  if (demoMlDispatcher) return demoMlDispatcher('detect', payload);
  const res = await axios.post(`${SERVICE_URLS.ml_detection}/detect`, payload, { timeout: 3000 });
  return res.data;
}

async function explainViaXai(payload) {
  if (demoMlDispatcher) return demoMlDispatcher('xai', payload);
  const res = await axios.post(`${SERVICE_URLS.ml_detection}/xai/explain`, payload, { timeout: 4000 });
  return res.data;
}

async function syncAndBroadcastDemoSession(options = {}) {
  const forceDrain = Boolean(options && options.forceDrain);
  if (demoPollInFlight) {
    if (!forceDrain || !demoPollPromise) return null;
    try { await demoPollPromise; } catch (_) {}
  }
  demoPollInFlight = true;
  const runSync = (async () => {
    try {
      const statusResp = await callDemoSimulator('GET', '/status', null, 2500);
      const simStatus = statusResp?.data?.data || null;
      if (simStatus) {
        demoSimulatorStore.updateSessionMeta(simStatus);
        const stateKey = `${simStatus.session_id || 'none'}:${simStatus.state}`;
        if (stateKey !== lastBroadcastState) {
          lastBroadcastState = stateKey;
          broadcast({
            type: 'demo_simulator_state',
            data: simStatus,
            session: demoSimulatorStore.getSessionSnapshot(simStatus.session_id)
          });
        }
        const evResp = await callDemoSimulator('GET', '/events', null, 3500);
        const rawEvents = Array.isArray(evResp?.data?.data) ? evResp.data.data : [];
        if (rawEvents.length > 0) {
          const ingested = await demoSimulatorStore.ingestSimulatorEvents(rawEvents, {
            detectFn: detectViaMl,
            xaiFn: explainViaXai,
            sessionMeta: simStatus
          });
          for (const ev of ingested) {
            broadcast({
              type: 'demo_simulator_event',
              event_source: 'demo_simulator',
              session_id: ev.session_id,
              data: ev,
              session: demoSimulatorStore.getSessionSnapshot(ev.session_id)
            });
          }
        }
        if (simStatus.state !== 'Running' && simStatus.state !== 'Paused') {
          stopDemoPoller();
        }
      }
      return simStatus;
    } catch (_) {
      return null;
    } finally {
      demoPollInFlight = false;
      demoPollPromise = null;
    }
  })();
  demoPollPromise = runSync;
  return runSync;
}

function startDemoPoller() {
  if (demoPollTimer) return;
  demoPollTimer = setInterval(() => {
    syncAndBroadcastDemoSession();
  }, 1000);
  if (typeof demoPollTimer.unref === 'function') demoPollTimer.unref();
}

function stopDemoPoller() {
  if (demoPollTimer) {
    clearInterval(demoPollTimer);
    demoPollTimer = null;
  }
}

app.get('/api/v2/demo-simulator/status', securityManager.requireRole('VIEWER'), async (req, res) => {
  try {
    const simResp = await callDemoSimulator('GET', '/status');
    const simData = simResp.data?.data || {};
    demoSimulatorStore.updateSessionMeta(simData);
    return res.json({
      status: 'success',
      data: {
        simulator: simData,
        session: demoSimulatorStore.getSessionSnapshot(simData.session_id)
      }
    });
  } catch (err) {
    return res.status(503).json({
      status: 'error',
      code: 'SIMULATOR_UNAVAILABLE',
      message: err.message
    });
  }
});

app.get('/api/v2/demo-simulator/events', securityManager.requireRole('VIEWER'), async (req, res) => {
  const sessionId = req.query.session_id ? String(req.query.session_id) : null;
  if (sessionId && !demoSimulatorStore.getSession(sessionId)) {
    return res.status(404).json({ status: 'error', code: 'SESSION_NOT_FOUND', message: `Demo session '${sessionId}' not found` });
  }
  const limit = Number(req.query.limit || 100);
  const events = demoSimulatorStore.getSessionEvents(sessionId, limit);
  res.json({
    status: 'success',
    session_id: sessionId || demoSimulatorStore.activeSessionId,
    count: events.length,
    data: events
  });
});

app.get('/api/v2/demo-simulator/summary', securityManager.requireRole('VIEWER'), async (req, res) => {
  const sessionId = req.query.session_id ? String(req.query.session_id) : null;
  if (sessionId && !demoSimulatorStore.getSession(sessionId)) {
    return res.status(404).json({ status: 'error', code: 'SESSION_NOT_FOUND', message: `Demo session '${sessionId}' not found` });
  }
  let simSummary = null;
  try {
    await syncAndBroadcastDemoSession({ forceDrain: true });
    const simResp = await callDemoSimulator('GET', '/summary');
    simSummary = simResp.data?.data || null;
  } catch (_) {
    simSummary = null;
  }
  const summary = demoSimulatorStore.getSessionSummary(sessionId, simSummary);
  if (!summary) {
    return res.status(503).json({ status: 'error', code: 'SIMULATOR_UNAVAILABLE', message: 'Demo simulator summary unavailable' });
  }
  res.json({ status: 'success', data: summary });
});

app.post('/api/v2/demo-simulator/start', securityManager.requireRole('SOC_ANALYST'), async (req, res) => {
  const body = req.body || {};
  const scenario = String(body.scenario || 'mixed').trim().toLowerCase();
  const mode = String(body.mode || (scenario === 'mixed' ? 'mixed' : 'single')).trim().toLowerCase();
  const speed = String(body.speed || 'medium').trim().toLowerCase();
  const dur = body.duration_seconds;

  if (!DEMO_VALID_SCENARIOS.has(scenario)) {
    return res.status(400).json({ status: 'error', code: 'INVALID_SCENARIO', message: `Unsupported scenario '${body.scenario}'` });
  }
  if (!DEMO_VALID_MODES.has(mode)) {
    return res.status(400).json({ status: 'error', code: 'INVALID_MODE', message: "mode must be 'single' or 'mixed'" });
  }
  if (!DEMO_VALID_SPEEDS.has(speed)) {
    return res.status(400).json({ status: 'error', code: 'INVALID_SPEED', message: "speed must be 'low', 'medium', or 'high'" });
  }
  if (dur !== undefined && dur !== null && dur !== '') {
    const numDur = Number(dur);
    if (!Number.isInteger(numDur) || numDur < 1 || numDur > 86400) {
      return res.status(400).json({ status: 'error', code: 'INVALID_DURATION', message: 'duration_seconds must be an integer between 1 and 86400' });
    }
  }

  try {
    const simResp = await callDemoSimulator('POST', '/start', {
      scenario,
      mode,
      speed,
      duration_seconds: dur === undefined || dur === '' ? null : dur
    });
    if (simResp.status >= 400) {
      return res.status(simResp.status).json(simResp.data);
    }
    const simData = simResp.data?.data || {};
    demoSimulatorStore.updateSessionMeta(simData);
    startDemoPoller();
    securityManager.recordSecurityAudit('DEMO_SIMULATOR_STARTED', {
      operator: req.user?.sub || 'soc-operator',
      session_id: simData.session_id,
      scenario,
      mode,
      speed
    });
    broadcast({
      type: 'demo_simulator_state',
      data: simData,
      session: demoSimulatorStore.getSessionSnapshot(simData.session_id)
    });
    return res.json(simResp.data);
  } catch (err) {
    return res.status(503).json({ status: 'error', code: 'SIMULATOR_UNAVAILABLE', message: err.message });
  }
});

app.post('/api/v2/demo-simulator/pause', securityManager.requireRole('SOC_ANALYST'), async (req, res) => {
  try {
    const simResp = await callDemoSimulator('POST', '/pause', {});
    if (simResp.status >= 400) return res.status(simResp.status).json(simResp.data);
    const simData = simResp.data?.data || {};
    demoSimulatorStore.updateSessionMeta(simData);
    securityManager.recordSecurityAudit('DEMO_SIMULATOR_PAUSED', {
      operator: req.user?.sub || 'soc-operator',
      session_id: simData.session_id
    });
    broadcast({ type: 'demo_simulator_state', data: simData, session: demoSimulatorStore.getSessionSnapshot(simData.session_id) });
    return res.json(simResp.data);
  } catch (err) {
    return res.status(503).json({ status: 'error', code: 'SIMULATOR_UNAVAILABLE', message: err.message });
  }
});

app.post('/api/v2/demo-simulator/resume', securityManager.requireRole('SOC_ANALYST'), async (req, res) => {
  try {
    const simResp = await callDemoSimulator('POST', '/resume', {});
    if (simResp.status >= 400) return res.status(simResp.status).json(simResp.data);
    const simData = simResp.data?.data || {};
    demoSimulatorStore.updateSessionMeta(simData);
    startDemoPoller();
    securityManager.recordSecurityAudit('DEMO_SIMULATOR_RESUMED', {
      operator: req.user?.sub || 'soc-operator',
      session_id: simData.session_id
    });
    broadcast({ type: 'demo_simulator_state', data: simData, session: demoSimulatorStore.getSessionSnapshot(simData.session_id) });
    return res.json(simResp.data);
  } catch (err) {
    return res.status(503).json({ status: 'error', code: 'SIMULATOR_UNAVAILABLE', message: err.message });
  }
});

app.post('/api/v2/demo-simulator/stop', securityManager.requireRole('SOC_ANALYST'), async (req, res) => {
  try {
    const simResp = await callDemoSimulator('POST', '/stop', {});
    if (simResp.status >= 400) return res.status(simResp.status).json(simResp.data);
    await syncAndBroadcastDemoSession({ forceDrain: true });
    stopDemoPoller();
    const simData = simResp.data?.data || {};
    demoSimulatorStore.updateSessionMeta(simData);
    securityManager.recordSecurityAudit('DEMO_SIMULATOR_STOPPED', {
      operator: req.user?.sub || 'soc-operator',
      session_id: simData.session_id
    });
    broadcast({ type: 'demo_simulator_state', data: simData, session: demoSimulatorStore.getSessionSnapshot(simData.session_id) });
    return res.json(simResp.data);
  } catch (err) {
    stopDemoPoller();
    return res.status(503).json({ status: 'error', code: 'SIMULATOR_UNAVAILABLE', message: err.message });
  }
});

app.post('/api/v2/demo-simulator/reset', securityManager.requireRole('SOC_ANALYST'), async (req, res) => {
  try {
    stopDemoPoller();
    const simResp = await callDemoSimulator('POST', '/reset', {});
    if (simResp.status >= 400) return res.status(simResp.status).json(simResp.data);
    demoSimulatorStore.clearSession(null);
    lastBroadcastState = null;
    const simData = simResp.data?.data || {};
    securityManager.recordSecurityAudit('DEMO_SIMULATOR_RESET', {
      operator: req.user?.sub || 'soc-operator'
    });
    broadcast({ type: 'demo_simulator_state', data: simData, session: demoSimulatorStore.getSessionSnapshot(null) });
    return res.json(simResp.data);
  } catch (err) {
    return res.status(503).json({ status: 'error', code: 'SIMULATOR_UNAVAILABLE', message: err.message });
  }
});

// Serve dashboard frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server when executed directly
const portArgIdx = process.argv.indexOf('--port');
const cliPort = portArgIdx !== -1 && process.argv[portArgIdx + 1] ? Number(process.argv[portArgIdx + 1]) : null;
const PORT = cliPort || process.env.PORT || 3000;
if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[dashboard] Listening on port ${PORT}`);
    console.log(`[dashboard] Dashboard available at http://localhost:${PORT}`);
  });

  // Periodic health check (every 30 seconds)
  setInterval(async () => {
    for (const [name, url] of Object.entries(SERVICE_URLS)) {
      try {
        await axios.get(`${url}/health`, { timeout: 2000 });
      } catch (error) {
        // Service unhealthy, could log or alert
      }
    }
  }, 30000);
}

module.exports = {
  app,
  server,
  securityManager,
  socAggregator,
  xaiStore,
  demoSimulatorStore,
  setMlXaiDispatcher,
  setDemoSimulatorDispatcher,
  setDemoMlDispatcher,
  syncAndBroadcastDemoSession,
  broadcast
};
