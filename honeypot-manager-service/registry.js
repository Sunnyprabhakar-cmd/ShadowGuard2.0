/**
 * Shadow Guard 2.0 - Honeypot Manager Registry
 * Maintains state, configurations, port allocations, and health for deployed decoys.
 */

const DEFAULT_DECOYS = [
  {
    id: 'hp-cowrie-ssh-01',
    name: 'cowrie-ssh-decoy',
    type: 'cowrie_ssh',
    protocol: 'SSH',
    ports: [2222],
    status: 'active',
    internal_host: 'cowrie',
    health: 'healthy',
    last_probe: null,
    sessions_active: 0,
    config: {
      banner: 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
      auth_mode: 'interactive',
      quarantine_enabled: true
    }
  },
  {
    id: 'hp-cowrie-telnet-01',
    name: 'cowrie-telnet-decoy',
    type: 'cowrie_telnet',
    protocol: 'TELNET',
    ports: [2223],
    status: 'active',
    internal_host: 'cowrie',
    health: 'healthy',
    last_probe: null,
    sessions_active: 0,
    config: {
      prompt: 'login: ',
      auth_mode: 'interactive'
    }
  },
  {
    id: 'hp-opencanary-multi-01',
    name: 'opencanary-multi-decoy',
    type: 'opencanary_multi',
    protocol: 'MULTI',
    ports: [8080, 2121, 3306],
    status: 'active',
    internal_host: 'opencanary',
    health: 'healthy',
    last_probe: null,
    sessions_active: 0,
    config: {
      services: ['http', 'ftp', 'mysql'],
      http_skin: 'basicLogin'
    }
  },
  {
    id: 'hp-dionaea-malware-01',
    name: 'dionaea-malware-decoy',
    type: 'dionaea_malware',
    protocol: 'SMB/MSSQL',
    ports: [445, 1433],
    status: 'active',
    internal_host: 'dionaea',
    health: 'healthy',
    last_probe: null,
    sessions_active: 0,
    config: {
      quarantine_dir: '/quarantine',
      hashing: 'SHA-256'
    }
  }
];

class HoneypotRegistry {
  constructor() {
    this.decoys = new Map(DEFAULT_DECOYS.map(d => [d.id, { ...d }]));
  }

  listAll() {
    return Array.from(this.decoys.values());
  }

  getById(id) {
    return this.decoys.get(id) || null;
  }

  toggleStatus(id, active) {
    const decoy = this.decoys.get(id);
    if (!decoy) return null;
    decoy.status = active ? 'active' : 'disabled';
    decoy.updated_at = new Date().toISOString();
    return decoy;
  }

  updateHealth(id, healthStatus) {
    const decoy = this.decoys.get(id);
    if (!decoy) return null;
    decoy.health = healthStatus;
    decoy.last_probe = new Date().toISOString();
    return decoy;
  }

  getActivePorts() {
    const portMap = {};
    for (const decoy of this.decoys.values()) {
      if (decoy.status === 'active') {
        decoy.ports.forEach(p => {
          portMap[p] = { id: decoy.id, name: decoy.name, type: decoy.type };
        });
      }
    }
    return portMap;
  }
}

module.exports = new HoneypotRegistry();
