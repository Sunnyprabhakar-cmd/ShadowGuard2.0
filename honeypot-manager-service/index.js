const express = require('express');
const net = require('net');
const registry = require('./registry');

const app = express();
const port = process.env.PORT || 3010;

app.use(express.json());

// List all registered honeypot decoys
app.get('/api/honeypots', (req, res) => {
  res.json({
    total: registry.listAll().length,
    active_decoys: registry.listAll().filter(d => d.status === 'active').length,
    honeypots: registry.listAll()
  });
});

// Get specific honeypot details
app.get('/api/honeypots/:id', (req, res) => {
  const decoy = registry.getById(req.params.id);
  if (!decoy) {
    return res.status(404).json({ error: `Honeypot '${req.params.id}' not found` });
  }
  res.json(decoy);
});

// Enable/Disable a honeypot decoy
app.post('/api/honeypots/:id/toggle', (req, res) => {
  const { active } = req.body;
  if (typeof active !== 'boolean') {
    return res.status(400).json({ error: "Missing boolean field 'active'" });
  }
  const updated = registry.toggleStatus(req.params.id, active);
  if (!updated) {
    return res.status(404).json({ error: `Honeypot '${req.params.id}' not found` });
  }
  res.json({ message: `Honeypot '${updated.name}' is now ${updated.status}`, honeypot: updated });
});

// Get active decoy port mapping
app.get('/api/honeypots/ports/active', (req, res) => {
  res.json(registry.getActivePorts());
});

// Periodic TCP health check probe for active decoys
async function probeDecoys() {
  for (const decoy of registry.listAll()) {
    if (decoy.status !== 'active') continue;
    const targetHost = process.env[decoy.internal_host.toUpperCase() + '_HOST'] || decoy.internal_host;
    const targetPort = decoy.ports[0];

    const socket = new net.Socket();
    socket.setTimeout(2000);

    socket.connect(targetPort, targetHost, () => {
      registry.updateHealth(decoy.id, 'healthy');
      socket.destroy();
    });

    socket.on('error', () => {
      // If running without live honeypot container on local machine, mark standby
      registry.updateHealth(decoy.id, 'standby');
      socket.destroy();
    });

    socket.on('timeout', () => {
      registry.updateHealth(decoy.id, 'unreachable');
      socket.destroy();
    });
  }
}

setInterval(probeDecoys, 30000);

// Health Probes
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', total_honeypots: registry.listAll().length });
});

app.get('/health/live', (req, res) => {
  res.json({ status: 'alive' });
});

app.get('/health/ready', (req, res) => {
  res.json({ status: 'ready', decoys_registered: registry.listAll().length });
});

app.listen(port, () => {
  console.log(`[honeypot-manager-service] Listening on port ${port}`);
});
