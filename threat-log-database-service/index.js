const express = require('express');
const { Pool } = require('pg');
const RabbitMQClient = require('./lib/rabbitmq');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// PostgreSQL Connection Pool
const pool = new Pool({
  user: process.env.DB_USER || 'user',
  host: process.env.DB_HOST || 'postgres',
  database: process.env.DB_NAME || 'threat_logs',
  password: process.env.DB_PASS || 'password',
  port: Number(process.env.DB_PORT) || 5432,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// RabbitMQ Consumer Client
const rabbitmq = new RabbitMQClient({
  serviceName: 'threat-log-database-service',
  url: process.env.RABBITMQ_URL || 'amqp://shadowguard:shadowguard_secret@rabbitmq:5672'
});

/**
 * Handle incoming events from RabbitMQ and persist to appropriate tables
 */
async function handleRabbitMessage(event, meta) {
  const routingKey = meta.routingKey || '';
  
  try {
    // 1. Raw Network Flow or Legacy Threat Event
    if (routingKey.startsWith('event.network')) {
      const telemetry = event.telemetry || {};
      const query = `
        INSERT INTO threat_logs (type, action, details, timestamp)
        VALUES ($1, $2, $3, COALESCE($4::timestamp with time zone, NOW()))
      `;
      await pool.query(query, [
        telemetry.attack_type || event.event_type || 'network_flow',
        event.severity === 'high' ? 'alert' : 'monitor',
        JSON.stringify(event),
        event.timestamp || null
      ]);
    }
    // 2. Honeypot Deception Event
    else if (routingKey.startsWith('event.honeypot')) {
      const dec = event.deception_context || {};
      const query = `
        INSERT INTO honeypot_events (
          event_type, src_ip, src_port, dst_port, protocol, session_id, username, auth_outcome, session_metadata, timestamp
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10::timestamp with time zone, NOW()))
      `;
      await pool.query(query, [
        event.event_type,
        event.telemetry?.source_ip || '0.0.0.0',
        event.telemetry?.source_port,
        event.telemetry?.destination_port || 2222,
        event.telemetry?.protocol || 'TCP',
        dec.session_id || null,
        dec.username || null,
        dec.auth_outcome || 'FAILED',
        JSON.stringify(dec.session_metadata || {}),
        event.timestamp || null
      ]);
    }
    // 3. Correlated Incident
    else if (routingKey.startsWith('incident.')) {
      const query = `
        INSERT INTO incidents (id, title, severity, status, aggregate_confidence, summary, created_at, updated_at)
        VALUES (COALESCE($1::uuid, gen_random_uuid()), $2, $3, $4, $5, $6, NOW(), NOW())
        ON CONFLICT (id) DO UPDATE SET
          status = EXCLUDED.status,
          aggregate_confidence = EXCLUDED.aggregate_confidence,
          updated_at = NOW()
      `;
      await pool.query(query, [
        event.incident_id || null,
        event.title || 'Correlated Multi-Source Incident',
        event.severity || 'high',
        event.status || 'open',
        event.confidence || 0.85,
        event.summary || ''
      ]);
    }
    // 4. Response Action
    else if (routingKey.startsWith('action.')) {
      const query = `
        INSERT INTO response_actions (action_type, target_entity, command_executed, status, lease_duration_seconds, expires_at)
        VALUES ($1, $2, $3, $4, $5, NOW() + ($5 || ' seconds')::interval)
      `;
      await pool.query(query, [
        event.action_type || 'iptables_block',
        event.target_entity || 'unknown',
        event.command_executed || '',
        event.status || 'active',
        event.lease_duration_seconds || 3600
      ]);
    }
  } catch (err) {
    console.error(`[threat-log-database-service] Database write error on key '${routingKey}':`, err.message);
    throw err; // triggers RabbitMQ retry/DLQ policy
  }
}

// Start RabbitMQ connection and subscriptions
async function initRabbit() {
  const connected = await rabbitmq.connect();
  if (connected) {
    // Subscribe to network events, honeypot events, incidents, and actions
    await rabbitmq.subscribe('q.network.events', ['event.network.#'], handleRabbitMessage);
    await rabbitmq.subscribe('q.honeypot.events', ['event.honeypot.#'], handleRabbitMessage);
    await rabbitmq.subscribe('q.correlation.events', ['incident.#', 'action.#'], handleRabbitMessage);
  }
}
initRabbit().catch(e => console.warn('[threat-log-database-service] RabbitMQ init deferred:', e.message));

// ============================================================================
// Legacy V1 HTTP Endpoints (100% Backward Compatible)
// ============================================================================

app.post('/log', async (req, res) => {
  const logData = req.body || {};
  try {
    const query = `
      INSERT INTO threat_logs (type, action, details, timestamp)
      VALUES ($1, $2, $3, COALESCE($4::timestamp, NOW()))
      RETURNING id
    `;
    const result = await pool.query(query, [
      logData.type || 'unknown',
      logData.action || 'monitor',
      JSON.stringify(logData.details || {}),
      logData.timestamp || null,
    ]);
    res.json({ message: 'Log saved', id: result.rows[0]?.id });
  } catch (err) {
    console.error('[threat-log-database-service] Error saving log:', err);
    res.status(500).json({ error: 'Failed to save log' });
  }
});

app.get('/logs', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 100;
    const eventSourceFilter = req.query.event_source ? String(req.query.event_source).trim() : null;
    const result = await pool.query('SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT $1', [limit]);

    let normalizedLogs = result.rows.map((row) => {
      const details = row.details || {};
      const metadata = details.metadata || {};
      const telemetry = details.telemetry || {};
      const probabilities = Array.isArray(details.probabilities) ? details.probabilities : [];
      const explicitConfidence = typeof details.confidence === 'number' ? details.confidence : null;
      const confidence = explicitConfidence !== null
        ? explicitConfidence
        : (probabilities.length > 0 ? Math.max(...probabilities) : 0);
      const eventSource = details.event_source || metadata.event_source || null;

      return {
        id: row.id,
        type: row.type,
        attack_type: details.attack_type || details.attackType || telemetry.attack_type || row.type,
        action: row.action,
        severity: details.severity || null,
        timestamp: row.timestamp,
        confidence,
        flow_id: details.flow_id || metadata.flow_id || telemetry.flow_id || null,
        event_source: eventSource,
        session_id: details.session_id || metadata.session_id || null,
        demo_simulated: Boolean(details.demo_simulated || eventSource === 'demo_simulator'),
        src_ip: details.sourceIp || details.src_ip || telemetry.source_ip || null,
        dst_ip: details.dst_ip || telemetry.destination_ip || null,
        src_port: details.src_port || telemetry.source_port || null,
        dst_port: details.dst_port || telemetry.destination_port || null,
        protocol: details.protocol || telemetry.protocol || null,
        bytes_sent: details.bytes_sent || details.bytesSent || telemetry.byte_count || 0,
        duration: details.duration || telemetry.flow_duration_seconds || 0,
        details,
      };
    });

    if (eventSourceFilter === 'demo_simulator') {
      normalizedLogs = normalizedLogs.filter((l) => l.event_source === 'demo_simulator');
    } else if (eventSourceFilter === 'live') {
      normalizedLogs = normalizedLogs.filter((l) => l.event_source !== 'demo_simulator');
    }

    res.json(normalizedLogs);
  } catch (err) {
    console.error('[threat-log-database-service] Error fetching logs:', err);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

app.post('/logs/reset', async (req, res) => {
  try {
    await pool.query('TRUNCATE TABLE threat_logs RESTART IDENTITY');
    res.json({ message: 'Threat logs reset' });
  } catch (err) {
    console.error('[threat-log-database-service] Error resetting logs:', err);
    res.status(500).json({ error: 'Failed to reset logs' });
  }
});

// ============================================================================
// Shadow Guard 2.0 Relational Query Endpoints
// ============================================================================

app.get('/api/v2/incidents', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 50;
    const result = await pool.query(`
      SELECT i.*, p.source_ip, p.risk_score
      FROM incidents i
      LEFT JOIN attacker_profiles p ON i.attacker_profile_id = p.id
      ORDER BY i.created_at DESC LIMIT $1
    `, [limit]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v2/honeypot-events', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 100;
    const result = await pool.query('SELECT * FROM honeypot_events ORDER BY timestamp DESC LIMIT $1', [limit]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v2/attacker-profiles', async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 50;
    const result = await pool.query('SELECT * FROM attacker_profiles ORDER BY risk_score DESC LIMIT $1', [limit]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v2/attack-chains', async (req, res) => {
  try {
    const chainsResult = await pool.query('SELECT * FROM attack_chains ORDER BY created_at DESC LIMIT 20');
    const chains = chainsResult.rows;

    for (const chain of chains) {
      const stagesResult = await pool.query(
        'SELECT * FROM attack_chain_stages WHERE attack_chain_id = $1 ORDER BY stage_order ASC',
        [chain.id]
      );
      chain.stages = stagesResult.rows;
    }
    res.json(chains);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v2/response-actions', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM response_actions ORDER BY executed_at DESC LIMIT 50');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v2/audit-logs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// Health Probes
// ============================================================================

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

app.get('/health/ready', async (req, res) => {
  let dbOk = false;
  try {
    await pool.query('SELECT 1');
    dbOk = true;
  } catch (e) {
    dbOk = false;
  }

  const isReady = dbOk; // DB is critical dependency
  res.status(isReady ? 200 : 503).json({
    status: isReady ? 'ready' : 'unhealthy',
    dependencies: {
      postgres: dbOk,
      rabbitmq: rabbitmq.isReady()
    }
  });
});

app.listen(port, () => {
  console.log(`[threat-log-database-service] Listening on port ${port}`);
});
