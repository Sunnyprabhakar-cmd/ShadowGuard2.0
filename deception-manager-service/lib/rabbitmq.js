/**
 * Shadow Guard 2.0 - RabbitMQ Enterprise Message Broker Client
 * Handles connection lifecycle, topology declarations, dead-letter routing,
 * and reliable publish/consume workflows with retry policies.
 */

let amqp = null;
try {
  amqp = require('amqplib');
} catch (e) {
  // amqplib not installed in this environment
}

const EXCHANGE_EVENTS = process.env.RABBITMQ_EXCHANGE || 'sg.events';
const EXCHANGE_DLX = 'sg.dlx';
const QUEUE_DEADLETTER = 'q.deadletter';

class RabbitMQClient {
  constructor(options = {}) {
    this.url = options.url || process.env.RABBITMQ_URL || 'amqp://shadowguard:shadowguard_secret@localhost:5672';
    this.serviceName = options.serviceName || 'shadowguard-service';
    this.connection = null;
    this.channel = null;
    this.isConnecting = false;
    this.connected = false;
    this.reconnectTimeout = null;
    this.subscribers = [];
  }

  /**
   * Connect to RabbitMQ and initialize topology
   */
  async connect() {
    if (!amqp) {
      console.warn(`[RabbitMQ][${this.serviceName}] amqplib not installed. Running in standalone fallback mode.`);
      return false;
    }

    if (this.connected || this.isConnecting) return true;
    this.isConnecting = true;

    try {
      console.log(`[RabbitMQ][${this.serviceName}] Connecting to broker at ${this.url.replace(/:[^:]*@/, ':***@')}...`);
      this.connection = await amqp.connect(this.url, { timeout: 10000 });
      this.channel = await this.connection.createChannel();

      // Configure Channel Prefetch
      await this.channel.prefetch(10);

      // Setup Error & Close Listeners
      this.connection.on('error', (err) => {
        console.error(`[RabbitMQ][${this.serviceName}] Connection error:`, err.message);
        this._handleDisconnect();
      });

      this.connection.on('close', () => {
        console.warn(`[RabbitMQ][${this.serviceName}] Connection closed.`);
        this._handleDisconnect();
      });

      // Declare Core Topology
      await this._declareTopology();

      this.connected = true;
      this.isConnecting = false;
      console.log(`[RabbitMQ][${this.serviceName}] Connected & topology established on exchange '${EXCHANGE_EVENTS}'.`);

      // Re-establish active subscribers if recovering from disconnect
      for (const sub of this.subscribers) {
        await this._setupSubscriber(sub);
      }

      return true;
    } catch (error) {
      this.isConnecting = false;
      this.connected = false;
      console.warn(`[RabbitMQ][${this.serviceName}] Connection failed (${error.message}). Will retry in 5s.`);
      this._scheduleReconnect();
      return false;
    }
  }

  /**
   * Declare core exchange, DLX, and dead-letter queue
   */
  async _declareTopology() {
    if (!this.channel) return;

    // 1. Declare Primary Topic Exchange
    await this.channel.assertExchange(EXCHANGE_EVENTS, 'topic', { durable: true });

    // 2. Declare Dead Letter Exchange
    await this.channel.assertExchange(EXCHANGE_DLX, 'topic', { durable: true });

    // 3. Declare Dead Letter Queue and bind to DLX (# = all dead letters)
    await this.channel.assertQueue(QUEUE_DEADLETTER, { durable: true });
    await this.channel.bindQueue(QUEUE_DEADLETTER, EXCHANGE_DLX, '#');
  }

  /**
   * Publish an event to the primary topic exchange
   */
  async publish(routingKey, message, options = {}) {
    if (!this.connected || !this.channel) {
      return false;
    }

    try {
      const buffer = Buffer.from(typeof message === 'string' ? message : JSON.stringify(message));
      const publishOptions = {
        persistent: true,
        contentType: 'application/json',
        timestamp: Date.now(),
        appId: this.serviceName,
        headers: {
          'x-retry-count': 0,
          ...(options.headers || {})
        },
        ...options
      };

      return this.channel.publish(EXCHANGE_EVENTS, routingKey, buffer, publishOptions);
    } catch (err) {
      console.error(`[RabbitMQ][${this.serviceName}] Failed to publish to '${routingKey}':`, err.message);
      return false;
    }
  }

  /**
   * Subscribe a consumer queue to routing keys with dead-lettering & retry policy
   */
  async subscribe(queueName, routingKeys, onMessage, options = {}) {
    const subRecord = { queueName, routingKeys, onMessage, options };
    this.subscribers.push(subRecord);

    if (this.connected) {
      await this._setupSubscriber(subRecord);
    }
  }

  async _setupSubscriber({ queueName, routingKeys, onMessage, options }) {
    if (!this.channel) return;

    const maxRetries = options.maxRetries || 3;

    // Assert Queue configured with Dead-Letter Exchange
    await this.channel.assertQueue(queueName, {
      durable: true,
      deadLetterExchange: EXCHANGE_DLX,
      deadLetterRoutingKey: `dlq.${queueName}`
    });

    // Bind to all requested routing keys
    const keys = Array.isArray(routingKeys) ? routingKeys : [routingKeys];
    for (const key of keys) {
      await this.channel.bindQueue(queueName, EXCHANGE_EVENTS, key);
    }

    console.log(`[RabbitMQ][${this.serviceName}] Queue '${queueName}' bound to [${keys.join(', ')}]`);

    // Consume messages with error isolation and retry tracking
    await this.channel.consume(queueName, async (msg) => {
      if (!msg) return;

      try {
        const rawContent = msg.content.toString();
        let payload;
        try {
          payload = JSON.parse(rawContent);
        } catch (e) {
          payload = rawContent;
        }

        const routingKey = msg.fields.routingKey;
        await onMessage(payload, {
          routingKey,
          properties: msg.properties,
          fields: msg.fields
        });

        // Successfully processed
        this.channel.ack(msg);
      } catch (processingError) {
        console.error(`[RabbitMQ][${this.serviceName}] Consumer error on '${queueName}':`, processingError.message);

        const currentRetries = (msg.properties.headers && msg.properties.headers['x-retry-count']) || 0;
        if (currentRetries < maxRetries) {
          // Re-publish with incremented retry count and delay, then ack original
          const nextRetry = currentRetries + 1;
          console.warn(`[RabbitMQ][${this.serviceName}] Re-queuing message (Attempt ${nextRetry}/${maxRetries})...`);
          
          setTimeout(async () => {
            await this.publish(msg.fields.routingKey, msg.content, {
              headers: { ...msg.properties.headers, 'x-retry-count': nextRetry }
            });
          }, Math.pow(2, nextRetry) * 1000);

          this.channel.ack(msg);
        } else {
          // Exceeded max retries -> Reject to dead-letter queue (no requeue)
          console.error(`[RabbitMQ][${this.serviceName}] Message exceeded ${maxRetries} retries. Routing to DLQ.`);
          this.channel.nack(msg, false, false);
        }
      }
    });
  }

  _handleDisconnect() {
    this.connected = false;
    this.channel = null;
    this.connection = null;
    this._scheduleReconnect();
  }

  _scheduleReconnect() {
    if (this.reconnectTimeout) return;
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      this.connect();
    }, 5000);
  }

  async close() {
    try {
      if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
      if (this.channel) await this.channel.close();
      if (this.connection) await this.connection.close();
      this.connected = false;
    } catch (e) {
      // Ignore on close
    }
  }

  isReady() {
    return this.connected;
  }

  getStatus() {
    return {
      connected: this.connected,
      serviceName: this.serviceName,
      exchange: EXCHANGE_EVENTS,
      subscribers: this.subscribers.length
    };
  }
}

function createRabbitMQClient(options = {}) {
  return new RabbitMQClient(options);
}

RabbitMQClient.RabbitMQClient = RabbitMQClient;
RabbitMQClient.createRabbitMQClient = createRabbitMQClient;
module.exports = RabbitMQClient;
