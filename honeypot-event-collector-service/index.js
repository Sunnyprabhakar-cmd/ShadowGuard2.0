const express = require('express');
const fs = require('fs');
const readline = require('readline');
const RabbitMQClient = require('./lib/rabbitmq');
const { normalizeCowrieEvent } = require('./adapters/cowrieAdapter');
const { normalizeOpenCanaryEvent } = require('./adapters/opencanaryAdapter');
const { normalizeDionaeaEvent } = require('./adapters/dionaeaAdapter');

const app = express();
const port = process.env.PORT || 3011;

app.use(express.json({ limit: '10mb' }));

// Paths to honeypot logs (read-only mounts)
const COWRIE_LOG = process.env.COWRIE_LOG_PATH || '/var/log/cowrie/cowrie.json';
const OPENCANARY_LOG = process.env.OPENCANARY_LOG_PATH || '/var/log/opencanary/opencanary.json';

// RabbitMQ Publisher Client
const rabbitmq = new RabbitMQClient({
  serviceName: 'honeypot-event-collector-service',
  url: process.env.RABBITMQ_URL || 'amqp://shadowguard:shadowguard_secret@rabbitmq:5672'
});

rabbitmq.connect().catch((err) => {
  console.warn('[honeypot-collector] RabbitMQ initial connection deferred:', err.message);
});

// Telemetry & Deduplication
const stats = {
  total_ingested: 0,
  cowrie_events: 0,
  opencanary_events: 0,
  dionaea_events: 0,
  deduplicated_events: 0,
  published_events: 0,
  errors: 0
};

// Sliding window deduplication cache (Key: src_ip + event_type + port, Value: timestamp)
const dedupCache = new Map();
const DEDUP_WINDOW_MS = 1000; // 1-second burst deduplication

function isDuplicate(normalizedEvent) {
  const key = `${normalizedEvent.telemetry.source_ip}:${normalizedEvent.event_type}:${normalizedEvent.telemetry.destination_port}`;
  const now = Date.now();
  const lastSeen = dedupCache.get(key);

  if (lastSeen && (now - lastSeen) < DEDUP_WINDOW_MS) {
    stats.deduplicated_events++;
    return true;
  }

  dedupCache.set(key, now);
  // Periodic cleanup if map grows
  if (dedupCache.size > 5000) {
    for (const [k, ts] of dedupCache.entries()) {
      if (now - ts > 10000) dedupCache.delete(k);
    }
  }
  return false;
}

/**
 * Normalizes and dispatches honeypot events to RabbitMQ
 */
async function processHoneypotRecord(type, rawRecord) {
  stats.total_ingested++;
  let normalized = null;

  try {
    switch (type.toLowerCase()) {
      case 'cowrie':
        normalized = normalizeCowrieEvent(rawRecord);
        stats.cowrie_events++;
        break;
      case 'opencanary':
        normalized = normalizeOpenCanaryEvent(rawRecord);
        stats.opencanary_events++;
        break;
      case 'dionaea':
        normalized = normalizeDionaeaEvent(rawRecord);
        stats.dionaea_events++;
        break;
      default:
        throw new Error(`Unsupported honeypot source type '${type}'`);
    }

    if (isDuplicate(normalized)) {
      return { success: true, deduplicated: true, event_id: normalized.event_id };
    }

    const decoyType = normalized.deception_context?.decoy_type || 'generic';
    const routingKey = `event.honeypot.${decoyType}.${normalized.event_type.replace('honeypot.', '')}`;

    if (rabbitmq.isReady()) {
      await rabbitmq.publish(routingKey, normalized);
      stats.published_events++;
    }

    return { success: true, event_id: normalized.event_id, routing_key: routingKey };
  } catch (error) {
    stats.errors++;
    console.error(`[honeypot-collector] Normalization error (${type}):`, error.message);
    return { success: false, error: error.message };
  }
}

// REST Ingest API for log forwarders & automated test generators
app.post('/ingest/:type', async (req, res) => {
  const { type } = req.params;
  const payload = req.body;

  if (!payload) {
    return res.status(400).json({ error: 'Missing body payload' });
  }

  if (Array.isArray(payload)) {
    const results = [];
    for (const item of payload) {
      results.push(await processHoneypotRecord(type, item));
    }
    return res.json({ processed: results.length, results });
  }

  const result = await processHoneypotRecord(type, payload);
  if (!result.success) {
    return res.status(400).json(result);
  }
  res.json({ message: `Honeypot ${type} event normalized and published`, ...result });
});

// File Tailers for Cowrie and OpenCanary (Live Deception Mode)
function watchHoneypotLog(filePath, type) {
  if (!fs.existsSync(filePath)) {
    console.log(`[honeypot-collector] Note: ${filePath} not found. Operating in REST /ingest mode.`);
    return;
  }

  console.log(`[honeypot-collector] Tailing ${type} log file: ${filePath}`);
  let lastSize = fs.statSync(filePath).size;

  fs.watchFile(filePath, { interval: 1000 }, (curr) => {
    if (curr.size > lastSize) {
      const stream = fs.createReadStream(filePath, { start: lastSize, end: curr.size });
      const rl = readline.createInterface({ input: stream });

      rl.on('line', (line) => {
        if (!line.trim()) return;
        try {
          const record = JSON.parse(line.trim());
          processHoneypotRecord(type, record);
        } catch (e) {
          // ignore malformed log fragment
        }
      });
      lastSize = curr.size;
    }
  });
}

watchHoneypotLog(COWRIE_LOG, 'cowrie');
watchHoneypotLog(OPENCANARY_LOG, 'opencanary');

// Operational Endpoints
app.get('/stats', (req, res) => {
  res.json({ ...stats, rabbitmq_ready: rabbitmq.isReady() });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', stats, rabbitmq_ready: rabbitmq.isReady() });
});

app.get('/health/live', (req, res) => {
  res.json({ status: 'alive' });
});

app.get('/health/ready', (req, res) => {
  res.json({
    status: 'ready',
    dependencies: {
      rabbitmq: rabbitmq.isReady()
    }
  });
});

app.listen(port, () => {
  console.log(`[honeypot-event-collector] Listening on port ${port}`);
});
