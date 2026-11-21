/**
 * ShadowGuard - Gemini AI Threat Intelligence & SOC Copilot Service
 * Powered by Google Gemini 3.8 Flash (gemini-3.8-flash)
 */

// Optional HTTP and SDK imports with graceful fallbacks
let axios = null;
try {
  axios = require('axios');
} catch (e) {
  // axios not installed in current environment; will use native fetch
}

let GoogleGenAI = null;
try {
  GoogleGenAI = require('@google/genai').GoogleGenAI;
} catch (e) {
  // @google/genai not installed in this environment; will use direct REST API
}

const GEMINI_MODEL = 'gemini-3.8-flash';
let activeApiKey = process.env.GEMINI_API_KEY || '';

/**
 * Configure the Gemini API Key
 */
function setApiKey(key) {
  activeApiKey = String(key || '').trim();
}

/**
 * Get active API Key status
 */
function getStatus() {
  return {
    configured: Boolean(activeApiKey),
    model: GEMINI_MODEL,
    hasSdk: Boolean(GoogleGenAI),
    keyPrefix: activeApiKey ? `${activeApiKey.slice(0, 6)}...` : null
  };
}

/**
 * Make an API call to Gemini (using SDK or REST)
 */
async function callGemini({ prompt, systemInstruction = '', responseSchema = null, responseMimeType = null, apiKey = null }) {
  const key = apiKey || activeApiKey;
  if (!key) {
    throw new Error('GEMINI_API_KEY is not configured');
  }

  // 1. Try with @google/genai SDK if available
  if (GoogleGenAI) {
    try {
      const ai = new GoogleGenAI({ apiKey: key });
      const config = {};
      if (systemInstruction) config.systemInstruction = systemInstruction;
      if (responseMimeType) config.responseMimeType = responseMimeType;
      if (responseSchema) config.responseSchema = responseSchema;

      const response = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: prompt,
        config
      });

      return response.text;
    } catch (sdkError) {
      console.warn('[GeminiService] SDK call failed, attempting direct REST fallback:', sdkError.message);
    }
  }

  // 2. Direct REST API fallback
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${encodeURIComponent(key)}`;
  
  const payload = {
    contents: [
      {
        role: 'user',
        parts: [{ text: prompt }]
      }
    ]
  };

  if (systemInstruction) {
    payload.systemInstruction = {
      parts: [{ text: systemInstruction }]
    };
  }

  if (responseMimeType || responseSchema) {
    payload.generationConfig = {};
    if (responseMimeType) payload.generationConfig.responseMimeType = responseMimeType;
    if (responseSchema) payload.generationConfig.responseSchema = responseSchema;
  }

  let candidates = null;
  if (axios) {
    const res = await axios.post(url, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000
    });
    candidates = res.data?.candidates;
  } else {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`Gemini HTTP error ${res.status}: ${errBody}`);
    }
    const resData = await res.json();
    candidates = resData?.candidates;
  }

  if (!candidates || candidates.length === 0) {
    throw new Error('Gemini API returned no candidates');
  }

  const textPart = candidates[0].content?.parts?.map(p => p.text).join('') || '';
  return textPart;
}

/**
 * Generate fallback simulated analysis when no API key is provided
 */
function getSimulatedForensicAnalysis(threat) {
  const attackType = String(threat.attack_type || threat.type || 'unknown').toLowerCase();
  const srcIp = threat.src_ip || threat.sourceIp || '10.0.0.50';
  const dstIp = threat.dst_ip || threat.destinationIp || '192.168.1.100';
  const protocol = threat.protocol || 'TCP';
  const packets = Number(threat.packets || threat.packet_count || 100);
  const bytes = Number(threat.bytes_sent || threat.bytes || 50000);
  const duration = Number(threat.duration || 1.0);
  const confidence = Number(threat.confidence || 0.85);

  let summary = '';
  let mitre = [];
  let threatActor = '';
  let blastRadius = '';
  let playbook = [];
  let checklist = [];

  switch (attackType) {
    case 'ddos':
      summary = `Volumetric distributed denial-of-service flood targeting ${dstIp} over ${protocol}. Rapid influx of ${packets.toLocaleString()} packets in ${duration.toFixed(2)}s indicates automated botnet saturation.`;
      mitre = [
        { techniqueId: 'T1498', techniqueName: 'Network Denial of Service', tactic: 'Impact' },
        { techniqueId: 'T1498.001', techniqueName: 'Direct Network Flood', tactic: 'Impact' }
      ];
      threatActor = 'Mirai-variant or commercially rented DDoS booter service';
      blastRadius = `Network interface saturation on ${dstIp}; risk of collateral packet drops for legitimate services on subnet.`;
      playbook = [
        { action: 'Block Ingress Source', command: `iptables -A INPUT -s ${srcIp} -j DROP`, description: 'Immediately drop all incoming packets from attacker' },
        { action: 'Rate Limit Protocol', command: `iptables -A INPUT -p ${protocol.toLowerCase()} --dport 80 -m limit --limit 50/s --limit-burst 100 -j ACCEPT`, description: 'Throttle protocol bursts' }
      ];
      checklist = [
        'Check edge router bandwidth saturation and BGP Anycast routing status',
        'Inspect server CPU / SYN backlog queues (netstat -s)',
        'Verify firewall blackhole / drop rule is active in automated-response service'
      ];
      break;

    case 'port_scan':
      summary = `Horizontal port reconnaissance scan originating from ${srcIp} against internal host ${dstIp}. Sequential single-packet probes detected across common listening services.`;
      mitre = [
        { techniqueId: 'T1046', techniqueName: 'Network Service Discovery', tactic: 'Discovery' }
      ];
      threatActor = 'Automated reconnaissance script or Nmap vulnerability scanner';
      blastRadius = `Information disclosure regarding listening daemons and service versions on ${dstIp}.`;
      playbook = [
        { action: 'Block Scanning IP', command: `iptables -A INPUT -s ${srcIp} -j DROP`, description: 'Isolate scanner from network perimeter' },
        { action: 'Enable Port Knocking/Tarpit', command: `iptables -A INPUT -p tcp -m recent --name portscan --update --seconds 60 --hitcount 5 -j DROP`, description: 'Dynamic port-scan tarpit' }
      ];
      checklist = [
        'Audit open ports and close unnecessary services on target host',
        'Review authentication logs for unauthorized connection attempts post-scan',
        'Confirm iptables drop rule is persisted'
      ];
      break;

    case 'data_exfiltration':
      summary = `Anomalous outbound high-volume data transfer from internal endpoint ${srcIp} to external IP ${dstIp}. Transferred ${bytes.toLocaleString()} bytes over ${duration.toFixed(2)}s without prior baseline.`;
      mitre = [
        { techniqueId: 'T1048', techniqueName: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' },
        { techniqueId: 'T1041', techniqueName: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' }
      ];
      threatActor = 'Compromised insider host or staged ransomware exfiltration payload';
      blastRadius = `Critical data loss potential. Confidential customer records or database dumps on ${srcIp} may be compromised.`;
      playbook = [
        { action: 'Sever Outbound Session', command: `iptables -A OUTPUT -d ${dstIp} -j DROP`, description: 'Drop all egress traffic to destination drop-site' },
        { action: 'Isolate Host from Subnet', command: `iptables -A FORWARD -s ${srcIp} -j DROP`, description: 'Prevent lateral exfiltration across LAN' }
      ];
      checklist = [
        'Initiate memory and process dump on host ' + srcIp,
        'Examine network egress PCAP to inspect encrypted payload entropy and SNI',
        'Revoke active API tokens and credentials belonging to ' + srcIp
      ];
      break;

    case 'brute_force':
      summary = `High-frequency credential stuffing / dictionary attack against authentication service on ${dstIp} from ${srcIp}. Rapid bursts of short-lived sessions observed.`;
      mitre = [
        { techniqueId: 'T1110', techniqueName: 'Brute Force', tactic: 'Credential Access' },
        { techniqueId: 'T1110.001', techniqueName: 'Password Guessing', tactic: 'Credential Access' }
      ];
      threatActor = 'Automated SSH/HTTP credential stuffing tool (e.g., Hydra, Medusa)';
      blastRadius = `Account compromise on target server; potential pivot point for privilege escalation.`;
      playbook = [
        { action: 'Drop Attacker IP', command: `iptables -A INPUT -s ${srcIp} -j DROP`, description: 'Cut off brute force connection attempts' },
        { action: 'Implement Fail2Ban', command: `fail2ban-client set sshd banip ${srcIp}`, description: 'Enforce dynamic rate-based IP jail' }
      ];
      checklist = [
        'Inspect auth.log / secure log to identify targeted usernames',
        'Enforce mandatory password reset and 2FA on probed user accounts',
        'Disable password-based SSH login in favor of Ed25519 public keys'
      ];
      break;

    case 'malware_command_control':
    case 'malware_c2':
      summary = `Periodic beaconing telemetry detected between internal client ${srcIp} and remote C2 node ${dstIp}. Flow duration and packet sizing correlate with heartbeat polling.`;
      mitre = [
        { techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', tactic: 'Command and Control' },
        { techniqueId: 'T1573', techniqueName: 'Encrypted Channel', tactic: 'Command and Control' }
      ];
      threatActor = 'Active Trojan / RAT backdoor (e.g., Cobalt Strike, AsyncRAT, or Lumma Stealer)';
      blastRadius = `Host ${srcIp} is actively controlled by an external adversary with remote code execution capability.`;
      playbook = [
        { action: 'Sinkhole C2 IP', command: `iptables -A OUTPUT -d ${dstIp} -j REJECT`, description: 'Sever C&C heartbeat channel' },
        { action: 'Network Quarantine', command: `iptables -A INPUT -s ${srcIp} -j DROP`, description: 'Isolate compromised endpoint from intranet' }
      ];
      checklist = [
        'Isolate infected endpoint physically or at VLAN/switch level immediately',
        'Extract running malware binary from memory using Volatility/YARA',
        'Check DNS query logs for DGA (Domain Generation Algorithm) activity'
      ];
      break;

    case 'zero_day':
    case 'zero_day_attack':
      summary = `Multi-stage anomaly sequence deviating significantly from all established baseline flows. Multi-packet payload stage on host ${dstIp} suggests novel exploit chain.`;
      mitre = [
        { techniqueId: 'T1203', techniqueName: 'Exploitation for Client Execution', tactic: 'Execution' },
        { techniqueId: 'T1068', techniqueName: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' }
      ];
      threatActor = 'Advanced Persistent Threat (APT) group exploiting unpatched vulnerability';
      blastRadius = `Full system compromise potential. Critical risk of zero-day kernel/service persistence.`;
      playbook = [
        { action: 'Emergency Total Block', command: `iptables -A INPUT -s ${srcIp} -j DROP && iptables -A OUTPUT -d ${srcIp} -j DROP`, description: 'Complete bidirectional network partition' },
        { action: 'Snapshot & Freeze VM', command: `virsh suspend shadow-target-node`, description: 'Freeze VM state for forensic analysis' }
      ];
      checklist = [
        'Preserve raw PCAP and volatile RAM state before rebooting or power cycling',
        'Report payload hash and network signatures to internal threat intel team',
        'Perform emergency patch / WAF virtual-patching on exposed service'
      ];
      break;

    default:
      summary = `Suspicious network flow flagged by ShadowGuard ML pipeline. Source ${srcIp} communicated with ${dstIp} generating ${packets} packets.`;
      mitre = [
        { techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution' }
      ];
      threatActor = 'Unidentified external entity';
      blastRadius = `Limited telemetry available. Host ${dstIp} should be audited.`;
      playbook = [
        { action: 'Audit Source Flow', command: `iptables -A INPUT -s ${srcIp} -m limit --limit 5/m -j LOG --log-prefix "SG_AUDIT: "`, description: 'Log incoming packets for forensic inspection' }
      ];
      checklist = [
        'Review flow features in PostgreSQL database',
        'Verify if host IP belongs to known cloud provider or CDN'
      ];
  }

  return {
    isSimulation: true,
    modelUsed: 'gemini-3.8-flash (Simulated SOC Engine - Provide GEMINI_API_KEY for Live Gemini AI)',
    attackType: threat.attack_type || threat.type || 'Unknown',
    severity: threat.severity || 'high',
    confidenceScore: confidence,
    summary,
    telemetryAnalysis: {
      packetRate: `${packets} packets observed over ${duration.toFixed(2)}s duration`,
      byteVolume: `${bytes.toLocaleString()} bytes transmitted via ${protocol}`,
      anomalyIndicators: [
        `Random Forest classification confidence: ${(confidence * 100).toFixed(1)}%`,
        `Protocol: ${protocol}`,
        `Action taken: ${threat.action || 'block'}`
      ]
    },
    mitreAttack: mitre,
    threatActorProfile: threatActor,
    blastRadius,
    containmentPlaybook: playbook,
    analystChecklist: checklist,
    falsePositiveProbability: confidence > 0.85 ? 'Low (< 5%)' : 'Medium (~ 15%)'
  };
}

/**
 * Perform Deep Forensic Threat Analysis using Gemini 3.8 Flash
 */
async function analyzeThreat(threat, userApiKey = null) {
  const key = userApiKey || activeApiKey;

  if (!key) {
    return getSimulatedForensicAnalysis(threat);
  }

  const prompt = `Perform a comprehensive Level-3 SOC Forensic Investigation for the following network threat detected by ShadowGuard ML:

THREAT TELEMETRY:
- Attack Type: ${threat.attack_type || threat.type || 'Unknown'}
- Source IP: ${threat.src_ip || threat.sourceIp || 'Unknown'}
- Destination IP: ${threat.dst_ip || threat.destinationIp || 'Unknown'}
- Protocol: ${threat.protocol || 'Unknown'}
- Packet Count: ${threat.packets || threat.packet_count || 0}
- Bytes Sent: ${threat.bytes_sent || threat.bytes || 0}
- Flow Duration: ${threat.duration || 0} seconds
- ML Confidence: ${threat.confidence || 'N/A'}
- Action Taken: ${threat.action || 'N/A'}
- Severity: ${threat.severity || 'high'}
- Timestamp: ${threat.timestamp || new Date().toISOString()}

Return a valid JSON object strictly matching this schema:
{
  "attackType": "string",
  "severity": "critical" | "high" | "medium" | "low",
  "confidenceScore": number (0.0 to 1.0),
  "summary": "Detailed 2-3 sentence incident explanation",
  "telemetryAnalysis": {
    "packetRate": "Explanation of packet velocity and flow characteristics",
    "byteVolume": "Analysis of data volume and payload anomalies",
    "anomalyIndicators": ["indicator 1", "indicator 2", "indicator 3"]
  },
  "mitreAttack": [
    { "techniqueId": "Txxxx", "techniqueName": "string", "tactic": "string" }
  ],
  "threatActorProfile": "Likely threat actor or tool signature (e.g. Cobalt Strike, Mirai, Nmap, Hydra)",
  "blastRadius": "Assessment of potential collateral damage and lateral movement risk",
  "containmentPlaybook": [
    { "action": "Action Name", "command": "concrete shell command (e.g. iptables)", "description": "why this command is run" }
  ],
  "analystChecklist": [
    "Step 1 for SOC analyst",
    "Step 2 for SOC analyst",
    "Step 3 for SOC analyst"
  ],
  "falsePositiveProbability": "Low/Medium/High with short justification"
}`;

  const systemInstruction = `You are ShadowGuard AI Forensic Analyst, an autonomous cybersecurity investigator specialized in network intrusion analysis, flow telemetry diagnostics, MITRE ATT&CK mapping, and automated containment engineering. Always output valid JSON only, without markdown fences or extra commentary.`;

  try {
    const rawOutput = await callGemini({
      prompt,
      systemInstruction,
      responseMimeType: 'application/json',
      apiKey: key
    });

    const cleaned = rawOutput.replace(/```json/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(cleaned);
    parsed.isSimulation = false;
    parsed.modelUsed = 'gemini-3.8-flash (Live Google AI)';
    return parsed;
  } catch (error) {
    console.error('[GeminiService] Live analysis failed, returning contextual fallback:', error.message);
    const fallback = getSimulatedForensicAnalysis(threat);
    fallback.liveError = error.message;
    return fallback;
  }
}

/**
 * Interactive SOC Copilot Conversation
 */
async function chatWithCopilot({ message, history = [], networkContext = {}, apiKey = null }) {
  const key = apiKey || activeApiKey;

  if (!key) {
    // Contextual demo response when no API key
    const msgLower = (message || '').toLowerCase();
    let reply = '';

    if (msgLower.includes('ddos') || msgLower.includes('flood')) {
      reply = `### 🛡️ DDoS Incident Guidance\n\nBased on current network telemetry, we are observing volumetric UDP bursts exceeding **10,000 pkts/sec** towards the server.\n\n**Recommended Immediate Actions:**\n1. \`iptables -A INPUT -p udp --dport 80 -m limit --limit 50/s --limit-burst 100 -j ACCEPT\`\n2. Block offending source IPs identified in the Recent Threats table.\n3. Verify if your upstream edge ISP supports BGP Anycast routing or Flowspec blackholing.\n\n*Note: Configure your GEMINI_API_KEY in the dashboard header to unlock full live reasoning from Gemini 3.8 Flash!*`;
    } else if (msgLower.includes('exfiltration') || msgLower.includes('data')) {
      reply = `### 🚨 Data Exfiltration Analysis\n\nThe internal node \`192.168.1.50\` generated an outbound flow of **50 MB** to \`198.51.100.23\` over a 10s duration.\n\n**Containment Steps:**\n- **Immediate Drop:** \`iptables -A OUTPUT -d 198.51.100.23 -j DROP\`\n- **Quarantine Host:** Isolate host \`192.168.1.50\` from the internal subnet to halt lateral staging.\n- **Forensic Acquisition:** Capture memory dump and inspect active open file descriptors (\`lsof -p <PID>\`).`;
    } else if (msgLower.includes('rule') || msgLower.includes('firewall') || msgLower.includes('iptables')) {
      reply = `### 🔒 Active Firewall Ruleset Recommendations\n\nHere is a hardened baseline policy for currently observed attack vectors:\n\`\`\`bash\n# 1. Drop known high-confidence malicious IPs\niptables -A INPUT -s 203.0.113.1 -j DROP\niptables -A INPUT -s 10.0.0.50 -j DROP\n\n# 2. Mitigate SSH / Telnet brute forcing\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP\n\n# 3. Log dropped packets for ShadowGuard ingestion\niptables -A INPUT -m limit --limit 5/m -j LOG --log-prefix "SG_BLOCKED: "\n\`\`\``;
    } else {
      reply = `### 🤖 ShadowGuard AI SOC Copilot\n\nI am monitoring your 11-service detection mesh. Active telemetry overview:\n- **Events Processed:** ${networkContext.total_events || 0}\n- **Blocked Threats:** ${networkContext.blocked_ips || 0}\n- **High Severity Incidents:** ${networkContext.high_threats || 0}\n\nYou can ask me to:\n- Explain any specific attack scenario or IP address\n- Generate incident response runbooks and firewall rules\n- Map detected patterns to MITRE ATT&CK techniques\n- Draft an executive briefing for leadership\n\n*(Tip: Add your Gemini API Key in Settings to enable deep live reasoning with **gemini-3.8-flash**!)*`;
    }

    return {
      reply,
      isSimulation: true,
      modelUsed: 'gemini-3.8-flash (Simulated Copilot)'
    };
  }

  const systemInstruction = `You are ShadowGuard AI SOC Copilot, an elite Level-3 cybersecurity analyst and incident responder integrated into the ShadowGuard Network Threat Detection System. 
You assist human SOC operators by interpreting machine learning telemetry (Isolation Forest anomaly scores and Random Forest classifications), dissecting network packet vectors, assessing blast radius, mapping to MITRE ATT&CK tactics & techniques, and generating production-ready containment commands (iptables, nftables, Snort/Suricata, fail2ban).
Format your responses using clear GitHub-flavored markdown with code snippets, bullet points, and risk metrics where appropriate. Be concise, authoritative, and tactically precise.

CURRENT NETWORK TELEMETRY CONTEXT:
${JSON.stringify(networkContext, null, 2)}`;

  // Build conversational context
  let conversationText = '';
  if (Array.isArray(history) && history.length > 0) {
    conversationText += 'CONVERSATION HISTORY:\n';
    history.slice(-6).forEach(item => {
      conversationText += `${item.role === 'user' ? 'Operator' : 'Copilot'}: ${item.content}\n`;
    });
    conversationText += '\n';
  }
  conversationText += `Operator: ${message}\nCopilot:`;

  try {
    const replyText = await callGemini({
      prompt: conversationText,
      systemInstruction,
      apiKey: key
    });

    return {
      reply: replyText,
      isSimulation: false,
      modelUsed: 'gemini-3.8-flash'
    };
  } catch (error) {
    console.error('[GeminiService] Live chat failed, falling back:', error.message);
    return {
      reply: `⚠️ Live Gemini connection encountered an issue: ${error.message}. Please verify your API key in Settings.`,
      isSimulation: true,
      error: error.message
    };
  }
}

/**
 * Generate CISO Executive Threat Briefing
 */
async function generateExecutiveBriefing({ threats = [], stats = {}, apiKey = null }) {
  const key = apiKey || activeApiKey;

  if (!key) {
    return {
      isSimulation: true,
      modelUsed: 'gemini-3.8-flash (Simulated Briefing - Configure GEMINI_API_KEY for Live Gemini AI)',
      executiveSummary: `During the monitored period, ShadowGuard inspected ${stats.total_events || 0} network flow events. The dual ML pipeline flagged ${stats.high_threats || 0} high-severity threats, executing automated containment against ${(stats.blocked_ips || 0)} hostile sources without operator intervention. Overall perimeter health remains protected with automated response latency < 100ms.`,
      threatPosture: stats.high_threats > 5 ? 'ELEVATED - Active multi-vector targeting detected' : 'GUARDED - Routine scanning and contained probes',
      topThreatVectors: [
        { vector: 'Volumetric DDoS', count: threats.filter(t => (t.attack_type || '').includes('ddos')).length || 2, risk: 'High' },
        { vector: 'Reconnaissance / Port Scanning', count: threats.filter(t => (t.attack_type || '').includes('scan')).length || 4, risk: 'Medium' },
        { vector: 'Data Exfiltration Anomalies', count: threats.filter(t => (t.attack_type || '').includes('exfil')).length || 1, risk: 'Critical' }
      ],
      strategicRecommendations: [
        'Enforce BGP Flowspec or Cloud Scrubbing contracts to absorb volumetric layer-4 floods',
        'Deploy Zero-Trust network segmentation (micro-segmentation) to isolate internal database clusters',
        'Integrate ShadowGuard automated iptables rules into centralized SOAR platform'
      ],
      timestamp: new Date().toISOString()
    };
  }

  const prompt = `Synthesize the following security telemetry into a CISO Executive Threat Briefing:

NETWORK STATISTICS:
${JSON.stringify(stats, null, 2)}

RECENT INCIDENTS SAMPLE (${threats.length} events):
${JSON.stringify(threats.slice(0, 15).map(t => ({
  type: t.attack_type || t.type,
  src: t.src_ip,
  dst: t.dst_ip,
  action: t.action,
  confidence: t.confidence,
  severity: t.severity,
  timestamp: t.timestamp
})), null, 2)}

Return a valid JSON object matching:
{
  "executiveSummary": "Concise 3-4 sentence briefing for CISO / leadership",
  "threatPosture": "SECURE | GUARDED | ELEVATED | CRITICAL with brief explanation",
  "topThreatVectors": [
    { "vector": "Name of attack vector", "count": number, "risk": "Critical|High|Medium|Low" }
  ],
  "strategicRecommendations": [
    "Strategic recommendation 1",
    "Strategic recommendation 2",
    "Strategic recommendation 3"
  ]
}`;

  const systemInstruction = `You are a Principal Security Director delivering a high-level incident assessment to executive leadership. Focus on risk exposure, business continuity, automated mitigation effectiveness, and strategic resilience. Always return pure JSON.`;

  try {
    const rawOutput = await callGemini({
      prompt,
      systemInstruction,
      responseMimeType: 'application/json',
      apiKey: key
    });

    const cleaned = rawOutput.replace(/```json/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(cleaned);
    parsed.isSimulation = false;
    parsed.modelUsed = 'gemini-3.8-flash (Live Google AI)';
    parsed.timestamp = new Date().toISOString();
    return parsed;
  } catch (error) {
    console.error('[GeminiService] Executive briefing failed:', error.message);
    const fallback = {
      isSimulation: true,
      executiveSummary: `Automated assessment: ${stats.total_events || 0} flows analyzed with ${stats.blocked_ips || 0} active IP mitigations applied by ShadowGuard.`,
      threatPosture: 'GUARDED',
      topThreatVectors: [],
      strategicRecommendations: ['Review active alerts in dashboard'],
      liveError: error.message
    };
    return fallback;
  }
}

module.exports = {
  setApiKey,
  getStatus,
  analyzeThreat,
  chatWithCopilot,
  generateExecutiveBriefing
};
