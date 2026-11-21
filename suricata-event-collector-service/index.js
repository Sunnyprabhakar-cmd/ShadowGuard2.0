const express = require('express');
const fs = require('fs');
const readline = require('readline');
const RabbitMQClient = require('./lib/rabbitmq');
const { normalizeSuricataEvent } = require('./adapters/suricataAdapter');

const app = express();
const port = process.env.PORT || 3007;
const eveLogPath = process.env.SURICATA_EVE_PATH || '/var/log/suricata/eve.json';

app.use(express.json({ limit: '10mb' }));

// RabbitMQ Publisher Client
const rabbitmq = new RabbitMQClient({
  serviceName: 'suricata-event-collector-service',
  url: process.env.RABBITMQ_URL || 'amqp://shadowguard:shadowguard_secret@rabbitmq:5672'
});

rabbitmq.connect().catch((err) => {
  console.warn('[suricata-collector] RabbitMQ initial connection deferred:', err.message);
});

// Ingest Statistics
const stats = {
  total_ingested: 0,
  alerts_processed: 0,
  dns_processed: 0,
  http_processed: 0,
  tls_processed: 0,
  flow_processed: 0,
  errors: 0
};

/**
 * Process a single EVE JSON record and publish to RabbitMQ
 */
async function processEveRecord(rawRecord) {
  try {
    const normalized = normalizeSuricataEvent(rawRecord);
    stats.total_ingested++;

    const routingKey = `event.${normalized.event_type}`; // e.g. event.nids.alert, event.nids.flow
    if (normalized.event_type === 'nids.alert') stats.alerts_processed++;
    else if (normalized.event_type === 'nids.dns') stats.dns_processed++;
    else if (normalized.event_type === 'nids.http') stats.http_processed++;
    else if (normalized.event_type === 'nids.tls') stats.tls_processed++;
    else if (normalized.event_type === 'nids.flow') stats.flow_processed++;

    if (rabbitmq.isReady()) {
      await rabbitmq.publish(routingKey, normalized);
    }
    return { success: true, event_id: normalized.event_id };
  } catch (error) {
    stats.errors++;
    console.error('[suricata-collector] Processing error:', error.message);
    return { success: false, error: error.message };
  }
}

// REST Ingest Endpoint (Used by PCAP replays & testing harnesses)
app.post('/ingest', async (req, res) => {
  const payload = req.body;
  if (!payload) {
    return res.status(400).json({ error: 'Missing payload' });
  }

  if (Array.isArray(payload)) {
    const results = [];
    for (const record of payload) {
      results.push(await processEveRecord(record));
    }
    return res.json({ processed: results.length, results });
  }

  const result = await processEveRecord(payload);
  if (!result.success) {
    return res.status(400).json(result);
  }
  res.json({ message: 'Suricata EVE record processed and published', ...result });
});

app.get('/stats', (req, res) => {
  res.json({ ...stats, rabbitmq_ready: rabbitmq.isReady() });
});

// Health Checks
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
      rabbitmq: rabbitmq.isReady(),
      eve_file_accessible: fs.existsSync(eveLogPath)
    }
  });
});

// File Tailer for eve.json (Live mode)
function startFileTailer() {
  if (!fs.existsSync(eveLogPath)) {
    console.log(`[suricata-collector] Note: ${eveLogPath} not found yet. Operating in REST /ingest mode until file appears.`);
    return;
  }

  console.log(`[suricata-collector] Monitoring Suricata EVE log at ${eveLogPath}...`);
  let lastSize = fs.statSync(eveLogPath).size;

  fs.watchFile(eveLogPath, { interval: 1000 }, (curr) => {
    if (curr.size > lastSize) {
      const stream = fs.createReadStream(eveLogPath, { start: lastSize, end: curr.size });
      const rl = readline.createInterface({ input: stream });

      rl.on('line', (line) => {
        if (!line.trim()) return;
        try {
          const record = JSON.parse(line.trim());
          processEveRecord(record);
        } catch (e) {
          // Ignore malformed line
        }
      });

      lastSize = curr.size;
    }
  });
}

startFileTailer();

app.listen(port, () => {
  console.log(`[suricata-event-collector] Listening on port ${port}`);
});
