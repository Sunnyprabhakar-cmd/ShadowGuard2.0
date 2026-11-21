const express = require('express');
const axios = require('axios');
const RabbitMQClient = require('./lib/rabbitmq');
const { createEvent } = require('./lib/eventContract');

const app = express();
const port = process.env.PORT || 3000;
const featureExtractionUrl = process.env.FEATURE_EXTRACTION_URL || 'http://flow-feature-extraction-service:3000/extract';

app.use(express.json());

// Initialize RabbitMQ Client
const rabbitmq = new RabbitMQClient({
  serviceName: 'traffic-capture-service',
  url: process.env.RABBITMQ_URL || 'amqp://shadowguard:shadowguard_secret@rabbitmq:5672'
});

// Attempt connection in background
rabbitmq.connect().catch((err) => {
  console.warn('[traffic-capture-service] Initial RabbitMQ connection deferred:', err.message);
});

app.post('/capture', async (req, res) => {
  const trafficData = req.body || {};
  const timestamp = new Date().toISOString();

  const sanitizedTraffic = { ...trafficData };
  delete sanitizedTraffic.ground_truth;

  // 1. Construct Normalized Event (Common Event Contract v2.0)
  let normalizedEvent = null;
  try {
    normalizedEvent = createEvent({
      source_domain: 'network',
      source_service: 'traffic-capture-service',
      event_type: 'event.network.raw',
      severity: sanitizedTraffic.flow_type === 'anomaly' ? 'high' : 'low',
      confidence: sanitizedTraffic.attack_type && sanitizedTraffic.attack_type !== 'normal_traffic' ? 0.85 : 0.5,
      telemetry: {
        flow_id: sanitizedTraffic.flow_id || null,
        source_ip: sanitizedTraffic.src_ip || sanitizedTraffic.source_ip || sanitizedTraffic.ip || '0.0.0.0',
        source_port: Number(sanitizedTraffic.src_port || sanitizedTraffic.source_port) || null,
        destination_ip: sanitizedTraffic.dst_ip || sanitizedTraffic.destination_ip || null,
        destination_port: Number(sanitizedTraffic.dst_port || sanitizedTraffic.destination_port) || null,
        protocol: sanitizedTraffic.protocol || 'TCP',
        flow_duration_seconds: Number(sanitizedTraffic.duration) || 0.001,
        packet_count: Number(sanitizedTraffic.packets || sanitizedTraffic.packet_count) || 0,
        byte_count: Number(sanitizedTraffic.bytes || sanitizedTraffic.bytes_sent) || 0,
        attack_type: sanitizedTraffic.attack_type || 'unknown'
      },
      metadata: {
        captured_at: timestamp,
        ingest_mode: 'dual_http_amqp',
        event_source: sanitizedTraffic.event_source || null,
        session_id: sanitizedTraffic.session_id || null,
        flow_id: sanitizedTraffic.flow_id || null
      }
    });
  } catch (schemaErr) {
    console.warn('[traffic-capture-service] Schema generation warning:', schemaErr.message);
  }

  // 2. Asynchronously Publish to RabbitMQ Topic Exchange (Non-blocking)
  if (normalizedEvent && rabbitmq.isReady()) {
    rabbitmq.publish('event.network.raw', normalizedEvent).catch((pubErr) => {
      console.error('[traffic-capture-service] RabbitMQ publish error:', pubErr.message);
    });
  }

  // 3. Backward Compatibility: Forward synchronously to Feature Extraction Service
  try {
    await axios.post(featureExtractionUrl, sanitizedTraffic, { timeout: 5000 });
    res.json({
      message: 'Traffic data captured and processed',
      event_id: normalizedEvent ? normalizedEvent.event_id : null,
      flow_id: sanitizedTraffic.flow_id || null,
      event_source: sanitizedTraffic.event_source || null,
      session_id: sanitizedTraffic.session_id || null,
      amqp_published: rabbitmq.isReady(),
      data: sanitizedTraffic
    });
  } catch (error) {
    console.error('[traffic-capture-service] Error forwarding to feature extraction:', error.message);
    // If AMQP publish succeeded, don't fail completely
    if (normalizedEvent && rabbitmq.isReady()) {
      res.status(202).json({
        message: 'Traffic captured to message broker, but synchronous downstream was unavailable',
        event_id: normalizedEvent.event_id,
        amqp_published: true
      });
    } else {
      res.status(500).json({ error: 'Failed to capture and forward traffic' });
    }
  }
});

// Health Probes
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    rabbitmq_connected: rabbitmq.isReady(),
    timestamp: Date.now()
  });
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
  console.log(`[traffic-capture-service] Listening on port ${port}`);
});
