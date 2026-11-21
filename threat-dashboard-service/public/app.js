// Wait for React to be available
if (!window.React || !window.ReactDOM) {
  console.error('React or ReactDOM not loaded');
}

console.log('Dashboard app.js loaded, React version:', window.React?.version);

const { useState, useEffect, useRef } = React;

// Simple markdown formatter fallback
function renderMarkdown(content) {
  if (!content) return '';
  let formatted = String(content)
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/gim, '<em>$1</em>')
    .replace(/```([\s\S]*?)```/gim, '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/gim, '<code>$1</code>')
    .replace(/^\- (.*$)/gim, '<li>$1</li>')
    .replace(/\n\n/gim, '<br/><br/>')
    .replace(/\n/gim, '<br/>');
  return formatted;
}

function Dashboard() {
  const [stats, setStats] = useState({
    total_events: 0,
    high_threats: 0,
    medium_threats: 0,
    low_threats: 0,
    blocked_ips: 0,
    alerts_sent: 0,
    monitored_flows: 0
  });
  
  const [services, setServices] = useState({});
  const [threats, setThreats] = useState([]);
  const [models, setModels] = useState({});
  const [traffic, setTraffic] = useState({});
  const [metrics, setMetrics] = useState({});
  const [refreshRate, setRefreshRate] = useState(5000);
  const [isConnected, setIsConnected] = useState(false);
  const [alertEmail, setAlertEmail] = useState('admin@shadowguard.com');
  const [criticalOnly, setCriticalOnly] = useState(true);
  const [alertConfigMessage, setAlertConfigMessage] = useState('');

  // ── Gemini AI State ────────────────────────────────────────────────────────
  const [geminiStatus, setGeminiStatus] = useState({ configured: false, model: 'gemini-3.8-flash' });
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [apiSaveStatus, setApiSaveStatus] = useState('');

  // Investigation Modal State
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [investigatingThreat, setInvestigatingThreat] = useState(null);
  const [investigationResult, setInvestigationResult] = useState(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);

  // Copilot Chat Drawer State
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    {
      role: 'assistant',
      content: '👋 **Welcome to ShadowGuard AI SOC Copilot.** I am powered by **Google Gemini 3.8 Flash**.\n\nI continuously monitor your network telemetry, correlate multi-service anomalies, map attack patterns to **MITRE ATT&CK**, and provide automated containment runbooks. How can I assist your investigation today?',
      timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatSending, setIsChatSending] = useState(false);
  const chatMessagesEndRef = useRef(null);

  // Executive Briefing State
  const [isBriefingOpen, setIsBriefingOpen] = useState(false);
  const [briefingData, setBriefingData] = useState(null);
  const [briefingLoading, setBriefingLoading] = useState(false);

  // ── Shadow Guard 2.0 SOC Command Center State (8 Core + 2 Tri-Model Modules) ──
  const [activeModule, setActiveModule] = useState('overview');
  const [socSnapshot, setSocSnapshot] = useState(null);
  const [securityAudit, setSecurityAudit] = useState([]);
  const [socActionBanner, setSocActionBanner] = useState('');

  // ── Stage 4: PyTorch Autoencoder & Tri-Model Detection State ───────────────
  const [socRole, setSocRole] = useState('ADMIN');
  const [triModelOverview, setTriModelOverview] = useState(null);
  const [triModelDetections, setTriModelDetections] = useState([]);
  const [manualReviewData, setManualReviewData] = useState({ queue: [], audit_log: [] });
  const [evaluationViews, setEvaluationViews] = useState(null);
  const [researchBenchmark, setResearchBenchmark] = useState(null);
  const [selectedPolicy, setSelectedPolicy] = useState('weighted_consensus');
  const [agreementFilter, setAgreementFilter] = useState('ALL');
  const [evalSubTab, setEvalSubTab] = useState('false_positives');
  const [inspectedFlowDossier, setInspectedFlowDossier] = useState(null);

  // ── Stage 4 XAI: Module 11 Explainable AI & Threat Reasoning State ─────────
  const [xaiOverview, setXaiOverview] = useState(null);
  const [xaiOverviewLoading, setXaiOverviewLoading] = useState(false);
  const [xaiOverviewError, setXaiOverviewError] = useState(null);
  const [xaiFlowInput, setXaiFlowInput] = useState('flow-atk-01404');
  const [xaiExplanation, setXaiExplanation] = useState(null);
  const [xaiExplanationSource, setXaiExplanationSource] = useState('');
  const [xaiLoading, setXaiLoading] = useState(false);
  const [xaiError, setXaiError] = useState(null);
  const [xaiSearchFilter, setXaiSearchFilter] = useState('');
  const [xaiClassFilter, setXaiClassFilter] = useState('ALL');
  const [xaiStatusFilter, setXaiStatusFilter] = useState('ALL');
  const [xaiAgreementFilter, setXaiAgreementFilter] = useState('ALL');
  const [xaiSortOrder, setXaiSortOrder] = useState('DESC');
  const [xaiExpandedPanels, setXaiExpandedPanels] = useState({
    rf: true,
    if: true,
    ae: true,
    feature69: false,
  });
  const [xaiDiagnostics, setXaiDiagnostics] = useState(null);

  // ── Stage 4 Demo Simulator: Module 12 Demo Traffic Simulator State ────────
  const [telemetrySourceFilter, setTelemetrySourceFilter] = useState('live');
  const [demoSimState, setDemoSimState] = useState({
    state: 'Idle',
    session_id: null,
    scenario: 'mixed',
    mode: 'mixed',
    speed: 'medium',
    events_per_sec: 2.5,
    duration_seconds: null,
    elapsed_seconds: 0,
    counters: {
      events_generated: 0,
      benign_events: 0,
      malicious_events: 0,
      delivered_events: 0,
      failed_events: 0,
      category_counts: {}
    },
    available_scenarios: [
      'normal_traffic', 'port_scan', 'ssh_brute_force', 'service_enumeration',
      'ddos', 'data_exfiltration', 'c2_beaconing', 'multi_vector', 'stealth_anomaly', 'mixed'
    ]
  });
  const [demoSession, setDemoSession] = useState({
    session_id: null,
    event_source: 'demo_simulator',
    state: 'Idle',
    counters: {
      events_generated: 0,
      benign_events: 0,
      malicious_events: 0,
      detected_threats: 0,
      incidents_generated: 0,
      soar_actions_simulated: 0,
      xai_explanations_triggered: 0
    },
    category_counts: {},
    protocol_counts: {},
    incidents: [],
    soar_actions: [],
    demo_leases: [],
    xai_triggers: [],
    recent_events: []
  });
  const [demoSummary, setDemoSummary] = useState(null);
  const [demoScenario, setDemoScenario] = useState('mixed');
  const [demoMode, setDemoMode] = useState('mixed');
  const [demoSpeed, setDemoSpeed] = useState('medium');
  const [demoDuration, setDemoDuration] = useState('');
  const [demoActionLoading, setDemoActionLoading] = useState(false);
  const [demoActionError, setDemoActionError] = useState(null);
  const [demoActionSuccess, setDemoActionSuccess] = useState('');
  const [demoWsReconnecting, setDemoWsReconnecting] = useState(false);

  const wsRef = useRef(null);
  const dataFetchIntervalRef = useRef(null);

  // Scroll chat to bottom
  useEffect(() => {
    if (chatMessagesEndRef.current) {
      chatMessagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages, isCopilotOpen]);

  // Fetch alert config and Gemini status on mount
  const fetchAlertConfig = async () => {
    try {
      const res = await fetch('/api/alerts/config');
      if (!res.ok) return;
      const data = await res.json();
      setAlertEmail(data.recipient || (data.recipients || []).join(', ') || 'admin@shadowguard.com');
      setCriticalOnly(Boolean(data.criticalOnly));
    } catch (error) {
      console.error('Failed to fetch alert config:', error);
    }
  };

  const fetchGeminiStatus = async () => {
    try {
      const res = await fetch('/api/gemini/status');
      if (res.ok) {
        const data = await res.json();
        setGeminiStatus(data);
      }
    } catch (e) {
      console.warn('Failed to fetch Gemini status:', e);
    }
  };

  // WebSocket connection with graceful auto-reconnection
  useEffect(() => {
    let unmounted = false;
    let reconnectTimer = null;

    const connectWebSocket = () => {
      if (unmounted) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = new WebSocket(`${protocol}//${window.location.host}`);
      wsRef.current = socket;

      socket.onopen = () => {
        if (unmounted) return;
        console.log('Connected to dashboard WebSocket');
        setIsConnected(true);
        setDemoWsReconnecting(false);
      };

      socket.onmessage = (event) => {
        if (unmounted) return;
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'metrics_update') {
            setMetrics(data.metrics);
          } else if (data.type === 'demo_simulator_state') {
            if (data.data) setDemoSimState((prev) => ({ ...prev, ...data.data }));
            if (data.session) setDemoSession(data.session);
          } else if (data.type === 'demo_simulator_event') {
            if (data.session) {
              setDemoSession(data.session);
            } else if (data.data) {
              setDemoSession((prev) => {
                const existing = prev.recent_events || [];
                const deduped = existing.some((e) => e.flow_id === data.data.flow_id)
                  ? existing
                  : [data.data, ...existing].slice(0, 100);
                return { ...prev, recent_events: deduped };
              });
            }
          }
        } catch (parseErr) {
          console.warn('WebSocket message parse error:', parseErr);
        }
      };

      socket.onerror = () => {
        if (unmounted) return;
        setIsConnected(false);
      };

      socket.onclose = () => {
        if (unmounted) return;
        setIsConnected(false);
        setDemoWsReconnecting(true);
        if (!reconnectTimer) {
          reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            connectWebSocket();
          }, 2500);
        }
      };
    };

    connectWebSocket();

    return () => {
      unmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // Fetch data periodically
  useEffect(() => {
    fetchAlertConfig();
    fetchGeminiStatus();

    const fetchData = async () => {
      try {
        const statsRes = await fetch(`/api/statistics?source=${encodeURIComponent(telemetrySourceFilter)}`);
        if (statsRes.ok) setStats(await statsRes.json());

        const servicesRes = await fetch('/api/services/health');
        if (servicesRes.ok) setServices(await servicesRes.json());

        const threatsRes = await fetch(`/api/threats?source=${encodeURIComponent(telemetrySourceFilter)}&limit=50`);
        if (threatsRes.ok) {
          const data = await threatsRes.json();
          setThreats(data.logs || []);
        }

        const modelsRes = await fetch('/api/models');
        if (modelsRes.ok) setModels(await modelsRes.json());

        const trafficRes = await fetch('/api/traffic');
        if (trafficRes.ok) setTraffic(await trafficRes.json());

        const socRes = await fetch('/api/v2/soc/overview', {
          headers: { 'X-SOC-Role': socRole }
        });
        if (socRes.ok) {
          const socJson = await socRes.json();
          setSocSnapshot(socJson.data);
          if (socJson.data.tri_model_overview) {
            setTriModelOverview(socJson.data.tri_model_overview);
          }
        }

        const [mlOverviewRes, mlDetRes, mlRevRes, mlEvalRes, mlBenchRes] = await Promise.all([
          fetch('/api/v2/soc/ml/overview', { headers: { 'X-SOC-Role': socRole } }),
          fetch(`/api/v2/soc/ml/detections?policy=${selectedPolicy}&limit=60`, { headers: { 'X-SOC-Role': socRole } }),
          fetch('/api/v2/soc/ml/manual-review', { headers: { 'X-SOC-Role': socRole } }),
          fetch('/api/v2/soc/ml/evaluation', { headers: { 'X-SOC-Role': socRole } }),
          fetch('/api/v2/soc/ml/research-benchmark', { headers: { 'X-SOC-Role': socRole } })
        ]);

        if (mlOverviewRes.ok) {
          const j = await mlOverviewRes.json();
          setTriModelOverview(j.data);
        }
        if (mlDetRes.ok) {
          const j = await mlDetRes.json();
          setTriModelDetections(j.data.detections || []);
        }
        if (mlRevRes.ok) {
          const j = await mlRevRes.json();
          setManualReviewData(j.data || { queue: [], audit_log: [] });
        }
        if (mlEvalRes.ok) {
          const j = await mlEvalRes.json();
          setEvaluationViews(j.data);
        }
        if (mlBenchRes.ok) {
          const j = await mlBenchRes.json();
          setResearchBenchmark(j.data);
        }

        const auditRes = await fetch('/api/v2/security/audit', {
          headers: { 'X-SOC-Role': socRole }
        });
        if (auditRes.ok) {
          const auditJson = await auditRes.json();
          setSecurityAudit(auditJson.data || []);
        }

        // Fetch XAI Overview (Module 11)
        setXaiOverviewLoading(true);
        try {
          const xaiOvRes = await fetch('/api/v2/xai/overview', {
            headers: { 'X-SOC-Role': socRole }
          });
          if (xaiOvRes.ok) {
            const xaiOvJson = await xaiOvRes.json();
            setXaiOverview(xaiOvJson.data || null);
            setXaiOverviewError(null);
          } else {
            const errJ = await xaiOvRes.json().catch(() => ({}));
            setXaiOverviewError(errJ.message || `HTTP ${xaiOvRes.status}`);
          }
        } catch (xaiErr) {
          setXaiOverviewError(xaiErr.message || 'XAI Overview API unreachable');
        } finally {
          setXaiOverviewLoading(false);
        }

        if (socRole === 'ADMIN') {
          try {
            const diagRes = await fetch('/api/v2/xai/diagnostics', {
              headers: { 'X-SOC-Role': socRole }
            });
            if (diagRes.ok) {
              const diagJ = await diagRes.json();
              setXaiDiagnostics(diagJ.data || null);
            }
          } catch (_) {}
        } else {
          setXaiDiagnostics(null);
        }

        // Sync Demo Traffic Simulator Status (Module 12)
        try {
          const demoRes = await fetch('/api/v2/demo-simulator/status', {
            headers: { 'X-SOC-Role': socRole }
          });
          if (demoRes.ok) {
            const demoJson = await demoRes.json();
            if (demoJson.data?.simulator) {
              setDemoSimState((prev) => ({ ...prev, ...demoJson.data.simulator }));
            }
            if (demoJson.data?.session) {
              setDemoSession(demoJson.data.session);
            }
            const st = demoJson.data?.simulator?.state;
            if (st === 'Stopped' || st === 'Completed') {
              const sumRes = await fetch('/api/v2/demo-simulator/summary', {
                headers: { 'X-SOC-Role': socRole }
              });
              if (sumRes.ok) {
                const sumJson = await sumRes.json();
                setDemoSummary(sumJson.data || null);
              }
            }
          }
        } catch (_) {}
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };

    fetchData();
    dataFetchIntervalRef.current = setInterval(fetchData, refreshRate);

    return () => {
      if (dataFetchIntervalRef.current) clearInterval(dataFetchIntervalRef.current);
    };
  }, [refreshRate, selectedPolicy, socRole, telemetrySourceFilter]);

  // ── Gemini Handlers ────────────────────────────────────────────────────────

  const saveGeminiKey = async () => {
    setApiSaveStatus('Saving...');
    try {
      const res = await fetch('/api/gemini/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: apiKeyInput.trim() })
      });
      if (res.ok) {
        const data = await res.json();
        setGeminiStatus(data.status);
        setApiSaveStatus(data.status.configured ? '✓ API Key configured for Live Gemini!' : 'API Key cleared');
        setTimeout(() => setApiSaveStatus(''), 3000);
      } else {
        setApiSaveStatus('✗ Failed to save API key');
      }
    } catch (err) {
      setApiSaveStatus('✗ Error connecting to server');
    }
  };

  const handleInvestigateThreat = async (threat) => {
    setInvestigatingThreat(threat);
    setIsInvestigating(true);
    setInvestigationLoading(true);
    setInvestigationResult(null);

    try {
      const res = await fetch('/api/gemini/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat })
      });

      if (res.ok) {
        const data = await res.json();
        setInvestigationResult(data);
      } else {
        setInvestigationResult({
          error: 'Failed to complete AI forensic investigation.',
          summary: 'An error occurred while contacting the Gemini service.'
        });
      }
    } catch (e) {
      setInvestigationResult({
        error: e.message,
        summary: 'Network error contacting Gemini service.'
      });
    } finally {
      setInvestigationLoading(false);
    }
  };

  const handleSendChatMessage = async (presetText = null) => {
    const textToSend = presetText || chatInput;
    if (!textToSend.trim() || isChatSending) return;

    const userMsg = {
      role: 'user',
      content: textToSend.trim(),
      timestamp: new Date().toLocaleTimeString()
    };

    const newHistory = [...chatMessages, userMsg];
    setChatMessages(newHistory);
    if (!presetText) setChatInput('');
    setIsChatSending(true);

    try {
      const res = await fetch('/api/gemini/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textToSend.trim(),
          history: newHistory.map(m => ({ role: m.role, content: m.content })),
          context: {
            ...stats,
            recentThreatsSample: threats.slice(0, 5).map(t => ({
              type: t.attack_type,
              src: t.src_ip,
              dst: t.dst_ip,
              action: t.action,
              confidence: t.confidence
            }))
          }
        })
      });

      if (res.ok) {
        const data = await res.json();
        setChatMessages(prev => [
          ...prev,
          {
            role: 'assistant',
            content: data.reply || 'No response returned from Gemini.',
            isSimulation: data.isSimulation,
            timestamp: new Date().toLocaleTimeString()
          }
        ]);
      } else {
        setChatMessages(prev => [
          ...prev,
          {
            role: 'assistant',
            content: '⚠️ Failed to connect to Gemini SOC Copilot.',
            timestamp: new Date().toLocaleTimeString()
          }
        ]);
      }
    } catch (e) {
      setChatMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ Error contacting copilot: ${e.message}`,
          timestamp: new Date().toLocaleTimeString()
        }
      ]);
    } finally {
      setIsChatSending(false);
    }
  };

  const handleOpenExecutiveBriefing = async () => {
    setIsBriefingOpen(true);
    setBriefingLoading(true);
    setBriefingData(null);

    try {
      const res = await fetch('/api/gemini/executive-briefing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threats, stats })
      });

      if (res.ok) {
        const data = await res.json();
        setBriefingData(data);
      }
    } catch (err) {
      console.error('Error generating executive briefing:', err);
    } finally {
      setBriefingLoading(false);
    }
  };

  const copyToClipboard = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const sendThreatToCopilot = (threat, analysis) => {
    setIsInvestigating(false);
    setIsCopilotOpen(true);
    const prompt = `Explain attack vector for ${threat.attack_type || threat.type} from source ${threat.src_ip} targeting ${threat.dst_ip}. What additional perimeter hardening do you advise?`;
    handleSendChatMessage(prompt);
  };

  // ── Existing Dashboard Handlers ────────────────────────────────────────────

  const saveAlertConfig = async () => {
    setAlertConfigMessage('');
    const normalized = alertEmail.trim();
    const recipients = normalized.split(',').map((entry) => entry.trim()).filter(Boolean);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!recipients.length || !recipients.every((entry) => emailRegex.test(entry))) {
      setAlertConfigMessage('Please enter valid comma-separated email addresses');
      return;
    }

    try {
      const res = await fetch('/api/alerts/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipients: normalized, criticalOnly })
      });

      const data = await res.json();
      if (!res.ok) {
        setAlertConfigMessage(data.error || 'Failed to save email settings');
        return;
      }

      setAlertEmail(data.recipient || normalized);
      setCriticalOnly(Boolean(data.criticalOnly));
      setAlertConfigMessage('Email settings saved');
    } catch (error) {
      setAlertConfigMessage('Failed to save email settings');
    }
  };

  const reloadRules = async () => {
    try {
      const res = await fetch('/api/rules/reload', { method: 'POST' });
      if (res.ok) {
        alert('Playbook rules reloaded successfully');
      }
    } catch (error) {
      alert('Failed to reload rules: ' + error.message);
    }
  };

  const exportLogs = async () => {
    try {
      const res = await fetch('/api/export/logs');
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threat-logs-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      alert('Failed to export logs: ' + error.message);
    }
  };

  const getStatusColor = (status) => status === 'healthy' ? 'healthy' : 'unhealthy';

  const getThreatColor = (confidence) => {
    if (confidence > 0.8) return 'high-threat';
    if (confidence > 0.5) return 'medium-threat';
    return 'low-threat';
  };

  const getSeverityClass = (threat) => {
    const severity = String(threat.severity || threat.details?.severity || '').toLowerCase();
    if (severity === 'critical' || severity === 'high') return 'high-threat';
    if (severity === 'medium') return 'medium-threat';
    if (severity === 'low') return 'low-threat';
    return getThreatColor(threat.confidence || 0);
  };

  const formatAttackType = (threat) => {
    const rawType = threat.attack_type || threat.attackType || threat.details?.attack_type ||
      threat.details?.attackType || threat.type || 'unknown';
    const normalizedType = String(rawType).trim();
    const labels = {
      port_scan: 'Port Scan',
      ddos: 'DDoS',
      ddos_attack: 'DDoS',
      data_exfiltration: 'Data Exfiltration',
      normal_traffic: 'Normal Traffic',
      brute_force: 'Brute Force',
      brute_force_attack: 'Brute Force',
      malware_c2: 'Malware C&C',
      malware_command_control: 'Malware C&C',
      multi_vector: 'Multi-Vector',
      zero_day: 'Zero-Day',
      zero_day_attack: 'Zero-Day',
      response: 'Response',
      unknown: 'Unknown'
    };
    const key = normalizedType.toLowerCase().replace(/\s+/g, '_');
    if (labels[key]) return labels[key];
    if (/^\d+$/.test(normalizedType)) return `Class ${normalizedType}`;
    return normalizedType.replace(/[_-]+/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
  };

  // ── Shadow Guard 2.0 Interactive SOC Command Center Handlers ───────────────
  const refreshSocSnapshot = async (overridePolicy = null) => {
    const pol = overridePolicy || selectedPolicy;
    try {
      const [socRes, auditRes, mlOverviewRes, mlDetRes, mlRevRes] = await Promise.all([
        fetch('/api/v2/soc/overview', { headers: { 'X-SOC-Role': socRole } }),
        fetch('/api/v2/security/audit', { headers: { 'X-SOC-Role': socRole } }),
        fetch('/api/v2/soc/ml/overview', { headers: { 'X-SOC-Role': socRole } }),
        fetch(`/api/v2/soc/ml/detections?policy=${pol}&limit=60`, { headers: { 'X-SOC-Role': socRole } }),
        fetch('/api/v2/soc/ml/manual-review', { headers: { 'X-SOC-Role': socRole } })
      ]);
      if (socRes.ok) {
        const j = await socRes.json();
        setSocSnapshot(j.data);
      }
      if (auditRes.ok) {
        const a = await auditRes.json();
        setSecurityAudit(a.data || []);
      }
      if (mlOverviewRes.ok) {
        const o = await mlOverviewRes.json();
        setTriModelOverview(o.data);
      }
      if (mlDetRes.ok) {
        const d = await mlDetRes.json();
        setTriModelDetections(d.data.detections || []);
      }
      if (mlRevRes.ok) {
        const r = await mlRevRes.json();
        setManualReviewData(r.data || { queue: [], audit_log: [] });
      }
    } catch (e) {
      console.warn('Failed to refresh SOC v2 snapshot:', e);
    }
  };

  // ── Stage 4: PyTorch Autoencoder & Tri-Model Detection Handlers ────────────
  const handleSwitchFusionPolicy = async (policy) => {
    setSelectedPolicy(policy);
    try {
      const res = await fetch('/api/v2/soc/ml/fusion-policy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SOC-Role': socRole },
        body: JSON.stringify({ policy })
      });
      if (res.ok) {
        setSocActionBanner(`✓ Active Tri-Model Fusion Policy switched to '${policy}'`);
        await refreshSocSnapshot(policy);
        setTimeout(() => setSocActionBanner(''), 4000);
      } else {
        const err = await res.json();
        setSocActionBanner(`✗ RBAC / Policy Error (${res.status}): ${err.message}`);
        setTimeout(() => setSocActionBanner(''), 5000);
      }
    } catch (_) {}
  };

  const handleManualReviewDecision = async (flowId, decision, notes = 'Reviewed via SOC Command Center') => {
    try {
      const res = await fetch(`/api/v2/soc/ml/manual-review/${flowId}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SOC-Role': socRole },
        body: JSON.stringify({ decision, analyst_notes: notes })
      });
      const j = await res.json();
      if (res.status === 422 && j.status === 'rejected_by_safety_policy') {
        setSocActionBanner(`🔒 ${j.message}`);
        await refreshSocSnapshot();
        setTimeout(() => setSocActionBanner(''), 6000);
        return;
      }
      if (!res.ok) {
        setSocActionBanner(`✗ RBAC Denied (${res.status}): ${j.message}`);
        await refreshSocSnapshot();
        setTimeout(() => setSocActionBanner(''), 5000);
        return;
      }
      setSocActionBanner(`✓ Recorded manual-review decision '${decision}' for flow ${flowId} (Auto-Block: FORBIDDEN)`);
      await refreshSocSnapshot();
      setTimeout(() => setSocActionBanner(''), 5000);
    } catch (_) {}
  };

  const handleInspectFlow = async (flowId) => {
    try {
      const res = await fetch(`/api/v2/soc/ml/detections/${flowId}`, {
        headers: { 'X-SOC-Role': socRole }
      });
      if (res.ok) {
        const j = await res.json();
        setInspectedFlowDossier(j.data);
      }
    } catch (_) {}
  };

  const handleSimulateDegradedMode = async (degradedModels = [], reason = 'simulated_model_unavailability') => {
    try {
      const res = await fetch('/api/v2/soc/ml/degraded-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SOC-Role': socRole },
        body: JSON.stringify({ degraded_models: degradedModels, reason })
      });
      const j = await res.json();
      if (!res.ok) {
        setSocActionBanner(`✗ RBAC Denied (${res.status}): ${j.message}`);
        setTimeout(() => setSocActionBanner(''), 5000);
        return;
      }
      setSocActionBanner(
        degradedModels.length === 0
          ? '✓ Restored all 3 ML models (Random Forest, Isolation Forest, PyTorch Autoencoder) to HEALTHY status'
          : `⚠️ Simulated ${j.data.engine_status.toUpperCase()} state for [${degradedModels.join(', ')}] — Auto-Block inhibited`
      );
      await refreshSocSnapshot();
      setTimeout(() => setSocActionBanner(''), 5000);
    } catch (_) {}
  };

  const handleReloadMlModels = async () => {
    try {
      const res = await fetch('/api/v2/soc/ml/reload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-SOC-Role': socRole }
      });
      const j = await res.json();
      if (!res.ok) {
        setSocActionBanner(`✗ RBAC Denied (${res.status}): ${j.message}`);
        setTimeout(() => setSocActionBanner(''), 5000);
        return;
      }
      setSocActionBanner(`✓ Reloaded PyTorch Autoencoder, Random Forest & Isolation Forest artifacts (Status: ${j.data.engine_status})`);
      await refreshSocSnapshot();
      setTimeout(() => setSocActionBanner(''), 5000);
    } catch (_) {}
  };

  const handleSimulateAttack = async (scenario = 'ssh_compromise') => {
    try {
      const res = await fetch('/api/v2/soc/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      if (res.ok) {
        const j = await res.json();
        setSocActionBanner(`✓ Injected simulated multi-stage intrusion (${j.data.incident.incident_id}) across Honeypot, Correlation, Attack Chain & SOAR!`);
        await refreshSocSnapshot();
        setTimeout(() => setSocActionBanner(''), 5000);
      }
    } catch (err) {
      setSocActionBanner('✗ Failed to trigger simulation');
    }
  };

  const handleRollbackDirective = async (directiveId) => {
    try {
      const res = await fetch(`/api/v2/soc/directives/${directiveId}/rollback`, { method: 'POST' });
      if (res.ok) {
        setSocActionBanner(`✓ Rolled back Adaptive Deception Directive ${directiveId}`);
        await refreshSocSnapshot();
        setTimeout(() => setSocActionBanner(''), 4000);
      }
    } catch (_) {}
  };

  const handleApprovePermanentBlock = async (executionId) => {
    try {
      const res = await fetch(`/api/v2/soc/approvals/${executionId}/approve`, { method: 'POST' });
      if (res.ok) {
        setSocActionBanner(`✓ Approved permanent firewall block (${executionId})`);
        await refreshSocSnapshot();
        setTimeout(() => setSocActionBanner(''), 4000);
      }
    } catch (_) {}
  };

  const handleRollbackSoarBlock = async (executionId) => {
    try {
      const res = await fetch(`/api/v2/soc/blocks/${executionId}/rollback`, { method: 'POST' });
      if (res.ok) {
        setSocActionBanner(`✓ Rolled back IP block lease ${executionId}`);
        await refreshSocSnapshot();
        setTimeout(() => setSocActionBanner(''), 4000);
      }
    } catch (_) {}
  };

  const handleUpdateIncidentStatus = async (incidentId, status) => {
    try {
      const res = await fetch(`/api/v2/soc/incidents/${incidentId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        setSocActionBanner(`✓ Updated incident ${incidentId} status to ${status}`);
        await refreshSocSnapshot();
        setTimeout(() => setSocActionBanner(''), 4000);
      }
    } catch (_) {}
  };

  const socKpis = socSnapshot?.summary_kpis || {};

  // ── Module 11: Explainable AI (XAI) Investigation Handlers ─────────────────
  const toggleXaiPanel = (panelKey) => {
    setXaiExpandedPanels((prev) => ({ ...prev, [panelKey]: !prev[panelKey] }));
  };

  const handleInvestigateXaiFlow = async (flowIdArg, usePost = false) => {
    const targetId = String(flowIdArg ?? xaiFlowInput ?? '').trim();
    if (!targetId) {
      setXaiError('Please enter or select a valid Flow ID.');
      return;
    }
    setXaiFlowInput(targetId);
    setXaiLoading(true);
    setXaiError(null);
    try {
      const res = usePost
        ? await fetch('/api/v2/xai/explanation', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-SOC-Role': socRole },
            body: JSON.stringify({ flow_id: targetId, policy: selectedPolicy, top_k: 5 }),
          })
        : await fetch(
            `/api/v2/xai/explanation/${encodeURIComponent(targetId)}?policy=${encodeURIComponent(selectedPolicy)}`,
            { headers: { 'X-SOC-Role': socRole } }
          );
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        setXaiError(json.message || `Failed to load explanation (HTTP ${res.status})`);
        setXaiLoading(false);
        return;
      }
      setXaiExplanation(json.data || null);
      setXaiExplanationSource(json.source || (usePost ? 'ml_xai_service' : 'api_gateway'));

      const ovRes = await fetch('/api/v2/xai/overview', { headers: { 'X-SOC-Role': socRole } });
      if (ovRes.ok) {
        const ovJ = await ovRes.json();
        setXaiOverview(ovJ.data || null);
      }
    } catch (err) {
      setXaiError(err.message || 'XAI explanation API unreachable');
    } finally {
      setXaiLoading(false);
    }
  };

  // ── Module 12: Demo Traffic Simulator Control Handlers ─────────────────────
  const canControlDemo = socRole === 'SOC_ANALYST' || socRole === 'ADMIN';

  const refreshDemoStatusAndSummary = async () => {
    try {
      const stRes = await fetch('/api/v2/demo-simulator/status', {
        headers: { 'X-SOC-Role': socRole }
      });
      if (!stRes.ok) {
        const errJson = await stRes.json().catch(() => ({}));
        setDemoActionError(errJson.message || `Simulator unavailable (HTTP ${stRes.status})`);
        return;
      }
      const stJson = await stRes.json();
      if (stJson.data?.simulator) setDemoSimState((prev) => ({ ...prev, ...stJson.data.simulator }));
      if (stJson.data?.session) setDemoSession(stJson.data.session);
      setDemoActionError(null);
    } catch (err) {
      setDemoActionError(err.message || 'Demo simulator service unreachable');
    }
  };

  const fetchDemoSummary = async (sessionId = null) => {
    try {
      const url = sessionId
        ? `/api/v2/demo-simulator/summary?session_id=${encodeURIComponent(sessionId)}`
        : '/api/v2/demo-simulator/summary';
      const res = await fetch(url, { headers: { 'X-SOC-Role': socRole } });
      if (res.ok) {
        const j = await res.json();
        setDemoSummary(j.data || null);
      }
    } catch (_) {}
  };

  const handleDemoControl = async (action) => {
    if (!canControlDemo) {
      setDemoActionError(`Role '${socRole}' is read-only. Switch to SOC_ANALYST or ADMIN to control the simulator.`);
      return;
    }
    if (demoActionLoading) return;
    if (action === 'start' && (demoSimState.state === 'Running' || demoSimState.state === 'Paused')) {
      setDemoActionError(`Simulation is already ${demoSimState.state}. Stop or reset before starting again.`);
      return;
    }

    setDemoActionLoading(true);
    setDemoActionError(null);
    setDemoActionSuccess('');

    try {
      const payload = action === 'start'
        ? {
            scenario: demoScenario,
            mode: demoScenario === 'mixed' ? 'mixed' : demoMode,
            speed: demoSpeed,
            duration_seconds: demoDuration === '' ? null : Number(demoDuration)
          }
        : {};

      const res = await fetch(`/api/v2/demo-simulator/${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SOC-Role': socRole
        },
        body: JSON.stringify(payload)
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        setDemoActionError(json.message || `Action '${action}' failed (HTTP ${res.status})`);
        return;
      }

      if (json.data) {
        setDemoSimState((prev) => ({ ...prev, ...json.data }));
      }
      if (action === 'start') {
        setDemoSummary(null);
        setDemoActionSuccess(`Demo simulation started (${demoScenario} • ${demoSpeed})`);
      } else if (action === 'pause') {
        setDemoActionSuccess('Demo simulation paused.');
      } else if (action === 'resume') {
        setDemoActionSuccess('Demo simulation resumed.');
      } else if (action === 'stop') {
        setDemoActionSuccess('Demo simulation stopped. Post-session evaluation ready.');
        await fetchDemoSummary(json.data?.session_id || demoSimState.session_id);
      } else if (action === 'reset') {
        setDemoSummary(null);
        setDemoSession((prev) => ({
          ...prev,
          session_id: null,
          state: 'Idle',
          counters: {
            events_generated: 0,
            benign_events: 0,
            malicious_events: 0,
            detected_threats: 0,
            incidents_generated: 0,
            soar_actions_simulated: 0,
            xai_explanations_triggered: 0
          },
          category_counts: {},
          protocol_counts: {},
          incidents: [],
          soar_actions: [],
          demo_leases: [],
          xai_triggers: [],
          recent_events: []
        }));
        setDemoActionSuccess('Demo session reset to Idle.');
      }
      await refreshDemoStatusAndSummary();
    } catch (err) {
      setDemoActionError(err.message || `Failed to execute '${action}'`);
    } finally {
      setDemoActionLoading(false);
    }
  };

  return (
    <div className="dashboard">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="header-brand">
            <h1>🛡️ Shadow Guard 2.0</h1>
            <span className="subtitle">Cyber Deception, Suricata NIDS, Attacker Profiling, Attack Chains & Autonomous SOAR + Gemini Copilot</span>
          </div>

          <div className="header-controls">
            <span className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
              {isConnected ? '● Live Mesh' : '○ Offline'}
            </span>

            {/* Gemini Status & Actions */}
            <button
              className={`gemini-pill-btn ${geminiStatus.configured ? 'live' : 'demo'}`}
              onClick={() => setIsSettingsOpen(true)}
              title="Click to configure Gemini API Key"
            >
              <span className="sparkle">✨</span>
              <span>{geminiStatus.configured ? 'Gemini 3.8 Flash (Live)' : 'Gemini AI (Demo Mode)'}</span>
              <span className="gear-icon">⚙️</span>
            </button>

            <button className="gemini-action-btn copilot-toggle-btn" onClick={() => setIsCopilotOpen(!isCopilotOpen)}>
              🤖 AI Copilot
            </button>

            <button className="gemini-action-btn briefing-btn" onClick={handleOpenExecutiveBriefing}>
              📑 CISO Brief
            </button>

            <div className="alert-settings">
              <input
                type="text"
                value={alertEmail}
                onChange={(e) => setAlertEmail(e.target.value)}
                placeholder="alert1@example.com, alert2@example.com"
                className="alert-email-input"
              />
              <label className="critical-only-toggle">
                <input
                  type="checkbox"
                  checked={criticalOnly}
                  onChange={(e) => setCriticalOnly(e.target.checked)}
                />
                Critical only
              </label>
              <button onClick={saveAlertConfig}>Save</button>
            </div>

            <select value={refreshRate} onChange={(e) => setRefreshRate(Number(e.target.value))}>
              <option value={3000}>Refresh: 3s</option>
              <option value={5000}>Refresh: 5s</option>
              <option value={10000}>Refresh: 10s</option>
            </select>
            <button onClick={reloadRules}>⚙️ Rules</button>
            <button onClick={exportLogs}>📥 Export</button>
          </div>
        </div>
        {alertConfigMessage && <div className="alert-config-message">{alertConfigMessage}</div>}
      </header>

      {/* 10-Page SOC Command Center Navigation Bar (8 Core + 2 Tri-Model & Autoencoder Modules) */}
      <nav className="soc-module-nav">
        <div className="soc-module-nav-inner">
          {[
            { id: 'overview', label: '1. Overview Dashboard', badge: null },
            { id: 'honeypots', label: '2. Honeypot & Deception', badge: socKpis.active_honeypots || 3 },
            { id: 'attackers', label: '3. Attacker Profiling', badge: socKpis.tracked_attacker_profiles || 3 },
            { id: 'incidents', label: '4. Incident Correlation', badge: socKpis.open_incidents || 3 },
            { id: 'attack_chains', label: '5. MITRE Attack Chains', badge: socKpis.reconstructed_attack_chains || 2 },
            { id: 'threat_intel', label: '6. Threat Intelligence', badge: (socSnapshot?.threat_intel || []).length || 5 },
            { id: 'soar', label: '7. SOAR & Block Leases', badge: socKpis.active_ip_block_leases || 2 },
            { id: 'system_audit', label: '8. System & Security Audit', badge: Object.keys(services).length || 17 },
            { id: 'tri_model', label: '9. Tri-Model & Autoencoder', badge: (manualReviewData?.pending_items_count ?? 8) },
            { id: 'ml_benchmark', label: '10. Synthetic Benchmark & FP/FN', badge: '6 Models' },
            { id: 'xai_reasoning', label: '11. Explainable AI & Threat Reasoning', badge: xaiOverview?.persistence?.total_explanations ?? 'XAI' },
            { id: 'demo_simulator', label: '12. Demo Traffic Simulator', badge: demoSimState?.state || 'Idle' }
          ].map(tab => (
            <button
              key={tab.id}
              className={`soc-nav-tab ${activeModule === tab.id ? 'active' : ''}`}
              onClick={() => setActiveModule(tab.id)}
            >
              <span>{tab.label}</span>
              {tab.badge !== null && <span className="soc-tab-badge">{tab.badge}</span>}
            </button>
          ))}
          <select
            value={socRole}
            onChange={(e) => setSocRole(e.target.value)}
            title="Active RBAC Role for SOC Command Center Requests"
            style={{ marginLeft: 'auto', background: '#1e2638', border: '1px solid #4a5568' }}
          >
            <option value="ADMIN">RBAC: ADMIN</option>
            <option value="SOC_ANALYST">RBAC: SOC_ANALYST</option>
            <option value="VIEWER">RBAC: VIEWER (Read-Only)</option>
          </select>
          <button
            className="soc-simulate-btn"
            style={{ marginLeft: '6px' }}
            onClick={() => handleSimulateAttack('ssh_compromise')}
            title="Inject live multi-stage Cowrie + Suricata + Attack Chain + SOAR intrusion"
          >
            ⚡ Simulate Multi-Stage Intrusion
          </button>
        </div>
      </nav>

      {/* Degraded-Model Fail-Safe Indicator Banner */}
      {triModelOverview?.degraded_state?.is_degraded && (
        <div className="soc-degraded-banner">
          <div>
            <strong>⚠️ TRI-MODEL ENGINE DEGRADED STATE ({triModelOverview.engine_status.toUpperCase()}):</strong>{' '}
            Degraded Models: <code>{triModelOverview.degraded_state.degraded_models.join(', ')}</code> —{' '}
            {triModelOverview.degraded_state.active_warnings?.[0] || triModelOverview.degraded_state.fail_safe_policy}
          </div>
          {socRole === 'ADMIN' && (
            <button className="btn-investigate" onClick={() => handleSimulateDegradedMode([])}>
              ✓ Restore All 3 Models Healthy
            </button>
          )}
        </div>
      )}

      {socActionBanner && (
        <div className="soc-action-banner">{socActionBanner}</div>
      )}

      {/* Render Selected SOC 2.0 Module Panel (Pages 2 - 8) */}
      {activeModule === 'honeypots' && socSnapshot && (
        <section className="card soc-module-panel">
          <div className="soc-panel-header">
            <h2>🍯 Multi-Type Honeypot Infrastructure & Adaptive Deception DMZ</h2>
            <div className="soc-panel-actions">
              <button onClick={() => handleSimulateAttack('ssh_compromise')}>+ Simulate Cowrie SSH Compromise</button>
              <button onClick={() => handleSimulateAttack('smb_lateral')}>+ Simulate OpenCanary SMB Enumeration</button>
            </div>
          </div>
          <div className="soc-cards-grid-3">
            {socSnapshot.honeypots.map(hp => (
              <div key={hp.honeypot_id} className="soc-subcard">
                <div className="soc-subcard-header">
                  <strong>{hp.name}</strong>
                  <span className="status-badge healthy">{hp.status}</span>
                </div>
                <p className="soc-meta-line"><strong>ID:</strong> <code>{hp.honeypot_id}</code> • <strong>Zone:</strong> {hp.network_zone}</p>
                <p className="soc-meta-line"><strong>Ports:</strong> {hp.ports.join(', ')} • <strong>Logging:</strong> <code>{hp.logging_level}</code></p>
                <p className="soc-meta-line"><strong>24h Telemetry:</strong> {hp.total_events_24h} events | {hp.failed_logins_24h} auth fails | {hp.commands_captured_24h} shell cmds | {hp.quarantined_files_24h} quarantined files</p>
                {hp.breadcrumbs_deployed && (
                  <p className="soc-meta-line"><strong>Honey-Breadcrumbs:</strong> <code>{hp.breadcrumbs_deployed.join(', ')}</code></p>
                )}
              </div>
            ))}
          </div>

          <h3 style={{ marginTop: '20px', marginBottom: '10px' }}>Active Adaptive Deception Directives (DEC-01 .. DEC-04)</h3>
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Directive ID</th>
                  <th>Policy</th>
                  <th>Trigger IP</th>
                  <th>Target Honeypot</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th>Control</th>
                </tr>
              </thead>
              <tbody>
                {socSnapshot.adaptive_directives.map(d => (
                  <tr key={d.directive_id}>
                    <td><code>{d.directive_id}</code></td>
                    <td><strong>{d.policy_id}</strong> — {d.policy_name}</td>
                    <td><code>{d.trigger_source_ip}</code></td>
                    <td><code>{d.target_honeypot_id}</code></td>
                    <td>{d.action_type}</td>
                    <td><span className={`status-badge ${d.status === 'ACTIVE' ? 'healthy' : 'unhealthy'}`}>{d.status}</span></td>
                    <td>
                      {d.status === 'ACTIVE' && (
                        <button className="btn-investigate" onClick={() => handleRollbackDirective(d.directive_id)}>
                          ↩ Rollback
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3 style={{ marginTop: '20px', marginBottom: '10px' }}>Live Deception Telemetry Stream (Zero Plaintext/Hash Password Retention)</h3>
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Sensor</th>
                  <th>Source IP</th>
                  <th>Service</th>
                  <th>Event Type</th>
                  <th>Username Attempted</th>
                  <th>Auth Outcome</th>
                  <th>Command / Quarantined SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {socSnapshot.honeypot_events.map(ev => (
                  <tr key={ev.event_id}>
                    <td>{new Date(ev.timestamp).toLocaleTimeString()}</td>
                    <td><code>{ev.honeypot_id}</code></td>
                    <td><code>{ev.source_ip}</code></td>
                    <td>{ev.targeted_service}</td>
                    <td><strong>{ev.event_type}</strong></td>
                    <td><code>{ev.username_attempted || 'n/a'}</code></td>
                    <td>{ev.auth_outcome}</td>
                    <td>
                      {ev.command_executed && <div><code>$ {ev.command_executed}</code></div>}
                      {ev.file_sha256 && <div style={{ fontSize: '11px', color: '#f6ad55' }}>SHA256: {ev.file_sha256.slice(0, 24)}... (noexec)</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeModule === 'attackers' && socSnapshot && (
        <section className="card soc-module-panel">
          <h2>🕵️ Attacker Behaviour Profiling & Explainable Risk Scoring (0–100)</h2>
          <p className="soc-disclaimer-note">
            ℹ️ <strong>Indicator Attribution Note:</strong> Source IP addresses represent observed network indicators (which may include Tor exit nodes, NAT gateways, VPNs, or botnet hosts) rather than guaranteed single human identities. Passwords and password hashes are never stored.
          </p>
          <div className="soc-cards-grid-1">
            {socSnapshot.attacker_profiles.map(prof => (
              <div key={prof.id} className="soc-subcard">
                <div className="soc-subcard-header">
                  <div>
                    <h3>Indicator: <code>{prof.source_ip}</code> ({prof.threat_intel?.country_code} — {prof.threat_intel?.asn})</h3>
                    <span className="soc-meta-line">Connections: {prof.total_connections} | Honeypot Sessions: {prof.honeypot_sessions} | Failed Logins: {prof.failed_logins} | Usernames: <code>{prof.usernames_attempted.join(', ')}</code></span>
                  </div>
                  <div className="soc-risk-pill">
                    <span className="risk-number">{prof.risk_assessment.final_score}/100</span>
                    <span className="risk-label">{prof.risk_assessment.threat_level} ({Math.round(prof.risk_assessment.confidence * 100)}% conf)</span>
                  </div>
                </div>
                <p className="soc-meta-line"><strong>Behavioural Patterns:</strong> {prof.behavioural_patterns.map(bp => `${bp.name} (${Math.round(bp.confidence * 100)}%)`).join(' • ')}</p>
                {prof.commands_observed.length > 0 && (
                  <p className="soc-meta-line"><strong>Captured Shell Commands:</strong> <code>{prof.commands_observed.join(' ; ')}</code></p>
                )}
                <div className="threats-table" style={{ marginTop: '10px' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Contributing Risk Factor</th>
                        <th>Weight</th>
                        <th>Points Awarded</th>
                        <th>Explainable Rationale</th>
                      </tr>
                    </thead>
                    <tbody>
                      {prof.risk_assessment.contributing_factors.map((f, i) => (
                        <tr key={i}>
                          <td><strong>{f.factor}</strong></td>
                          <td>{f.weight}</td>
                          <td><strong>+{f.points_awarded}</strong> / {f.max_points}</td>
                          <td>{f.rationale}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeModule === 'incidents' && socSnapshot && (
        <section className="card soc-module-panel">
          <h2>🚨 Multi-Source Correlated Security Incidents (In-Memory Sliding Window)</h2>
          <div className="soc-cards-grid-1">
            {socSnapshot.incidents.map(inc => (
              <div key={inc.incident_id} className="soc-subcard">
                <div className="soc-subcard-header">
                  <div>
                    <h3>{inc.title}</h3>
                    <span className="soc-meta-line">
                      <strong>Incident ID:</strong> <code>{inc.incident_id}</code> • <strong>Events Grouped:</strong> {inc.event_count} • <strong>Confidence:</strong> {Math.round(inc.confidence * 100)}%
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span className="severity-badge high-threat">{inc.severity}</span>
                    <span className="status-badge healthy">{inc.status}</span>
                    <button className="btn-investigate" onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'CONTAINED')}>Mark Contained</button>
                    <button className="btn-investigate" onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'CLOSED')}>Close</button>
                  </div>
                </div>
                <p className="soc-meta-line" style={{ marginTop: '8px' }}>{inc.correlation_summary}</p>
                <p className="soc-meta-line"><strong>Telemetry Sources Correlated:</strong> <code>{inc.sources_involved.join(', ')}</code></p>
                <p className="soc-meta-line"><strong>Matched Correlation Rules:</strong> {inc.matched_rules.map(r => `${r.rule_id} (${r.name})`).join(' | ')}</p>
                <p className="soc-meta-line"><strong>Recommended SOAR Action:</strong> <code>{inc.recommended_action.action}</code> — {inc.recommended_action.rationale}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeModule === 'attack_chains' && socSnapshot && (
        <section className="card soc-module-panel">
          <h2>⛓️ Evidence-Based MITRE ATT&CK Kill-Chain Reconstruction</h2>
          <p className="soc-disclaimer-note">
            🔬 <strong>Ontological Certainty Tiers:</strong> <code>OBSERVED</code> (Direct Honeypot or Suricata SID match) • <code>INFERRED</code> (ML Flow Classifier / Statistical Anomaly) • <code>SUSPECTED</code> (Hypothesized intermediate bridge connecting two non-adjacent confirmed stages with decayed confidence).
          </p>
          {socSnapshot.attack_chains.map(chain => (
            <div key={chain.chain_id} className="soc-subcard" style={{ marginBottom: '18px' }}>
              <div className="soc-subcard-header">
                <div>
                  <h3>Chain <code>{chain.chain_id}</code> — Incident <code>{chain.incident_id}</code> (Source: <code>{chain.source_ip}</code>)</h3>
                  <span className="soc-meta-line">{chain.analyst_summary}</span>
                </div>
                <div>
                  <span className="status-badge healthy">OBSERVED: {chain.certainty_breakdown.OBSERVED}</span>{' '}
                  <span className="status-badge trained">INFERRED: {chain.certainty_breakdown.INFERRED}</span>{' '}
                  <span className="status-badge demo">SUSPECTED: {chain.certainty_breakdown.SUSPECTED}</span>
                </div>
              </div>
              <div className="threats-table" style={{ marginTop: '12px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Order</th>
                      <th>MITRE Tactic</th>
                      <th>Technique</th>
                      <th>Certainty Tier</th>
                      <th>Confidence</th>
                      <th>Affected Service</th>
                      <th>Evidence Rationale & Event IDs</th>
                    </tr>
                  </thead>
                  <tbody>
                    {chain.stages.map((st, idx) => (
                      <tr key={idx}>
                        <td>#{st.stage_order}</td>
                        <td><strong>{st.tactic_name}</strong> (<code>{st.tactic_id}</code>)</td>
                        <td><code>{st.technique_id}</code> — {st.technique_name}</td>
                        <td>
                          <span className={`certainty-badge tier-${st.certainty_tier.toLowerCase()}`}>
                            {st.certainty_tier}
                          </span>
                        </td>
                        <td>{Math.round(st.confidence * 100)}%</td>
                        <td>{st.affected_services.join(', ')}</td>
                        <td>
                          <div>{st.rationale}</div>
                          <div style={{ fontSize: '11px', color: '#a0aec0' }}>Evidence: <code>{st.evidence_event_ids.join(', ')}</code></div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </section>
      )}

      {activeModule === 'threat_intel' && socSnapshot && (
        <section className="card soc-module-panel">
          <h2>🌐 Threat Intelligence Enrichment & TTL Indicator Cache</h2>
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Indicator Value</th>
                  <th>Reputation Score</th>
                  <th>Country / ASN / Family</th>
                  <th>Categories</th>
                  <th>Sources</th>
                  <th>Confidence</th>
                  <th>Cache Status</th>
                </tr>
              </thead>
              <tbody>
                {socSnapshot.threat_intel.map((ioc, i) => (
                  <tr key={i}>
                    <td><strong>{ioc.indicator_type.toUpperCase()}</strong></td>
                    <td><code>{ioc.indicator_value}</code></td>
                    <td><span className="severity-badge high-threat">{ioc.reputation_score}/100</span></td>
                    <td>{ioc.country_code !== 'N/A' ? `${ioc.country_code} — ` : ''}{ioc.asn}</td>
                    <td>{ioc.categories.join(', ')}</td>
                    <td>{ioc.sources.join(', ')}</td>
                    <td>{Math.round(ioc.confidence * 100)}%</td>
                    <td><span className="status-badge healthy">{ioc.cache_hit ? 'TTL CACHE HIT' : 'FRESH LOOKUP'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeModule === 'soar' && socSnapshot && (
        <section className="card soc-module-panel">
          <h2>⚡ SOAR Playbook Execution, Timed IP Block Leases, Approvals & Allowlist</h2>
          <h3 style={{ marginTop: '12px', marginBottom: '8px' }}>Pending Manual Operator Approvals (Permanent Firewall Bans)</h3>
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Execution ID</th>
                  <th>Action</th>
                  <th>Target IP</th>
                  <th>Playbook</th>
                  <th>Reason</th>
                  <th>Operator Decision</th>
                </tr>
              </thead>
              <tbody>
                {socSnapshot.soar_pending_approvals.length === 0 ? (
                  <tr><td colSpan="6" className="empty">No pending approvals in queue</td></tr>
                ) : (
                  socSnapshot.soar_pending_approvals.map(p => (
                    <tr key={p.execution_id}>
                      <td><code>{p.execution_id}</code></td>
                      <td><strong>{p.action_type}</strong></td>
                      <td><code>{p.target_ip}</code></td>
                      <td><code>{p.playbook_id}</code></td>
                      <td>{p.reason}</td>
                      <td>
                        <button className="btn-investigate" onClick={() => handleApprovePermanentBlock(p.execution_id)}>
                          ✓ Approve Permanent Block
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <h3 style={{ marginTop: '20px', marginBottom: '8px' }}>Active Timed IP Block Leases & One-Click Rollback</h3>
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Execution ID</th>
                  <th>Blocked IP</th>
                  <th>Block Type</th>
                  <th>Lease</th>
                  <th>Expires At</th>
                  <th>Status</th>
                  <th>Reason</th>
                  <th>Rollback</th>
                </tr>
              </thead>
              <tbody>
                {socSnapshot.soar_block_leases.map(b => (
                  <tr key={b.execution_id}>
                    <td><code>{b.execution_id}</code></td>
                    <td><code>{b.ip}</code></td>
                    <td>{b.block_type}</td>
                    <td>{b.lease_minutes ? `${b.lease_minutes} mins` : 'PERMANENT'}</td>
                    <td>{b.expires_at === 'PERMANENT' ? 'NEVER' : new Date(b.expires_at).toLocaleTimeString()}</td>
                    <td><span className={`status-badge ${b.status === 'ACTIVE_BLOCKED' ? 'healthy' : 'unhealthy'}`}>{b.status}</span></td>
                    <td>{b.reason}</td>
                    <td>
                      {b.status === 'ACTIVE_BLOCKED' && (
                        <button className="btn-investigate" onClick={() => handleRollbackSoarBlock(b.execution_id)}>
                          ↩ Unblock / Rollback
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h3 style={{ marginTop: '20px', marginBottom: '8px' }}>Immutable Critical Infrastructure Allowlist (Never Blocked)</h3>
          <div className="soc-cards-grid-3">
            {socSnapshot.allowlist.map(al => (
              <div key={al.ip} className="soc-subcard">
                <strong><code>{al.ip}</code></strong> — {al.label}{' '}
                <span className="status-badge healthy">{al.immutable ? 'IMMUTABLE' : 'CUSTOM'}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeModule === 'system_audit' && (
        <section className="card soc-module-panel">
          <div className="soc-panel-header">
            <h2>🔐 System Health, Prometheus Telemetry & RBAC Security Audit Trail</h2>
            <a href="/metrics" target="_blank" rel="noreferrer" className="btn-investigate" style={{ textDecoration: 'none' }}>
              📈 View Raw Prometheus /metrics
            </a>
          </div>
          <div className="threats-table" style={{ marginTop: '12px' }}>
            <table>
              <thead>
                <tr>
                  <th>Audit ID</th>
                  <th>Timestamp</th>
                  <th>Security Event Type</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {securityAudit.length === 0 ? (
                  <tr><td colSpan="4" className="empty">No security audit events recorded in this session yet</td></tr>
                ) : (
                  securityAudit.map(aud => (
                    <tr key={aud.audit_id}>
                      <td><code>{aud.audit_id}</code></td>
                      <td>{new Date(aud.timestamp).toLocaleTimeString()}</td>
                      <td><strong>{aud.event_type}</strong></td>
                      <td><code>{JSON.stringify(aud.details)}</code></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* =====================================================================
          MODULE 9: STAGE 4 TRI-MODEL & PYTORCH AUTOENCODER DETECTION ENGINE
          ===================================================================== */}
      {activeModule === 'tri_model' && triModelOverview && (
        <section className="card soc-module-panel" id="tri-model-detection-panel">
          <div className="soc-panel-header">
            <div>
              <h2>🧠 Tri-Model Detection Engine (Random Forest + Isolation Forest + PyTorch Autoencoder)</h2>
              <span className="soc-meta-line">
                <strong>Engine Status:</strong>{' '}
                <span className={`status-badge ${triModelOverview.engine_status === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                  {triModelOverview.engine_status.toUpperCase()}
                </span>{' '}
                • <strong>Active Fusion Policy:</strong> <code>{selectedPolicy}</code>{' '}
                • <strong>Configured AE Threshold:</strong> <code>{triModelOverview.models_health?.autoencoder?.configured_percentile} = {triModelOverview.models_health?.autoencoder?.configured_threshold}</code>{' '}
                • <strong>Active RBAC Role:</strong> <code>{socRole}</code>
              </span>
            </div>
            <div className="soc-panel-actions" style={{ flexWrap: 'wrap' }}>
              <select
                value={selectedPolicy}
                onChange={(e) => handleSwitchFusionPolicy(e.target.value)}
                title="Select Tri-Model Detection Fusion Policy"
              >
                <option value="weighted_consensus">Policy: Weighted Consensus (RF + IF + AE)</option>
                <option value="unsupervised_ensemble">Policy: IF + AE Unsupervised Ensemble</option>
                <option value="majority_vote">Policy: Majority Vote (2-of-3)</option>
              </select>
              <button className="btn-investigate" onClick={() => handleSimulateDegradedMode(['isolation_forest'], 'simulated_if_unavailable')}>
                ⚠️ Test Partial Degraded (IF Offline)
              </button>
              <button className="btn-investigate" onClick={() => handleSimulateDegradedMode(['random_forest', 'isolation_forest', 'autoencoder'], 'simulated_all_models_offline')}>
                🚨 Test Full Degraded
              </button>
              <button className="btn-investigate" onClick={() => handleSimulateDegradedMode([])}>
                ✓ Restore Healthy
              </button>
              <button className="btn-investigate" onClick={handleReloadMlModels}>
                🔄 Reload Models (ADMIN)
              </button>
            </div>
          </div>

          <div className="soc-disclaimer-note">
            📐 <strong>Metric Semantics Distinction (Probabilities vs. Anomaly Scores):</strong>{' '}
            <strong>Random Forest</strong> outputs a calibrated supervised class probability <code>P(attack | x) ∈ [0.0, 1.0]</code>.{' '}
            <strong>Isolation Forest</strong> outputs an unsupervised isolation path decision score (<code>raw &lt; 0</code> = outlier) and normalized anomaly index (<em>NOT a probability</em>).{' '}
            <strong>PyTorch Autoencoder</strong> outputs 69-feature <code>Mean Squared Reconstruction Error (MSE)</code> evaluated against frozen validation threshold <code>P97 = 0.503670</code> (<em>NOT a probability</em>).
          </div>

          {/* 3 Individual Model Health & Threshold Cards */}
          <div className="soc-cards-grid-3" style={{ marginBottom: '20px' }}>
            {/* Card 1: Random Forest */}
            <div className="soc-subcard">
              <div className="soc-subcard-header">
                <div>
                  <strong>🌲 {triModelOverview.models_health?.random_forest?.display_name}</strong>
                  <div className="soc-meta-line">ID: <code>{triModelOverview.models_health?.random_forest?.model_id}</code></div>
                </div>
                <span className={`status-badge ${triModelOverview.models_health?.random_forest?.status === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                  {triModelOverview.models_health?.random_forest?.status?.toUpperCase()}
                </span>
              </div>
              <p className="soc-meta-line"><strong>Paradigm:</strong> {triModelOverview.models_health?.random_forest?.paradigm}</p>
              <p className="soc-meta-line"><strong>Metric Type:</strong> <span className="certainty-badge tier-observed">SUPERVISED PROBABILITY [0, 1]</span></p>
              <p className="soc-meta-line"><strong>Decision Rule:</strong> <code>attack_probability = 1 - P(benign) &gt;= {triModelOverview.models_health?.random_forest?.decision_threshold}</code></p>
              <p className="soc-meta-line"><strong>Training Split:</strong> {triModelOverview.models_health?.random_forest?.trained_samples} flows (840 normal + 120 attack)</p>
            </div>

            {/* Card 2: Isolation Forest */}
            <div className="soc-subcard">
              <div className="soc-subcard-header">
                <div>
                  <strong>🏝️ {triModelOverview.models_health?.isolation_forest?.display_name}</strong>
                  <div className="soc-meta-line">ID: <code>{triModelOverview.models_health?.isolation_forest?.model_id}</code></div>
                </div>
                <span className={`status-badge ${triModelOverview.models_health?.isolation_forest?.status === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                  {triModelOverview.models_health?.isolation_forest?.status?.toUpperCase()}
                </span>
              </div>
              <p className="soc-meta-line"><strong>Paradigm:</strong> {triModelOverview.models_health?.isolation_forest?.paradigm}</p>
              <p className="soc-meta-line"><strong>Metric Type:</strong> <span className="certainty-badge tier-inferred">UNSUPERVISED ANOMALY SCORE</span></p>
              <p className="soc-meta-line"><strong>Decision Rule:</strong> <code>raw_decision_score &lt; {triModelOverview.models_health?.isolation_forest?.decision_threshold}</code></p>
              <p className="soc-meta-line"><strong>Training Split:</strong> {triModelOverview.models_health?.isolation_forest?.trained_samples} normal-only flows</p>
            </div>

            {/* Card 3: PyTorch Autoencoder */}
            <div className="soc-subcard" style={{ borderLeft: '3px solid #667eea' }}>
              <div className="soc-subcard-header">
                <div>
                  <strong>🔥 {triModelOverview.models_health?.autoencoder?.display_name}</strong>
                  <div className="soc-meta-line">Version: <code>{triModelOverview.models_health?.autoencoder?.model_id}</code> ({triModelOverview.models_health?.autoencoder?.framework})</div>
                </div>
                <span className={`status-badge ${triModelOverview.models_health?.autoencoder?.status === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                  {triModelOverview.models_health?.autoencoder?.status?.toUpperCase()}
                </span>
              </div>
              <p className="soc-meta-line"><strong>Architecture:</strong> <code>{triModelOverview.models_health?.autoencoder?.architecture}</code></p>
              <p className="soc-meta-line"><strong>Metric Type:</strong> <span className="certainty-badge tier-suspected">RECONSTRUCTION ERROR (MSE)</span></p>
              <p className="soc-meta-line">
                <strong>Configured Threshold ({triModelOverview.models_health?.autoencoder?.configured_percentile}):</strong>{' '}
                <code>MSE &gt; {triModelOverview.models_health?.autoencoder?.configured_threshold}</code> (Val FPR: 3.33%)
              </p>
              <p className="soc-meta-line">
                <strong>Tiers:</strong> <code>P95={triModelOverview.models_health?.autoencoder?.thresholds?.P95?.value}</code> (Suspicious) |{' '}
                <code>P97={triModelOverview.models_health?.autoencoder?.thresholds?.P97?.value}</code> (Anomaly) |{' '}
                <code>P99={triModelOverview.models_health?.autoencoder?.thresholds?.P99?.value}</code> (High-Conf)
              </p>
            </div>
          </div>

          {/* Anomaly Severity Distribution & Chronological Detection Timeline */}
          <div className="soc-cards-grid-3" style={{ marginBottom: '20px' }}>
            <div className="soc-subcard">
              <h3>📊 Anomaly Severity Distribution (384 Held-Out Flows)</h3>
              <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(triModelOverview.test_set_summary?.severity_distribution || {}).map(([tier, count]) => (
                  <div key={tier} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                    <span><code>{tier}</code></span>
                    <strong>{count} flows</strong>
                  </div>
                ))}
              </div>
            </div>

            <div className="soc-subcard">
              <h3>🤝 Tri-Model Agreement / Disagreement Breakdown</h3>
              <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(triModelOverview.test_set_summary?.agreement_breakdown || {}).map(([pat, count]) => (
                  <div key={pat} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px' }}>
                    <span><code>{pat}</code></span>
                    <strong>{count} flows</strong>
                  </div>
                ))}
              </div>
            </div>

            <div className="soc-subcard">
              <h3>⏱️ Detection Timeline (8 Chronological Windows)</h3>
              <div className="threats-table" style={{ marginTop: '8px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Win</th>
                      <th>Anom</th>
                      <th>AE</th>
                      <th>RF</th>
                      <th>IF</th>
                      <th>Mean MSE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(triModelOverview.detection_timeline || []).map(w => (
                      <tr key={w.window_id}>
                        <td><code>{w.window_id}</code></td>
                        <td><strong>{w.anomalous_flows}</strong>/{w.total_flows}</td>
                        <td>{w.ae_anomalies}</td>
                        <td>{w.rf_anomalies}</td>
                        <td>{w.if_anomalies}</td>
                        <td><code>{w.mean_ae_mse}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Explainable Flow Detections Table */}
          <div className="soc-panel-header" style={{ marginTop: '16px' }}>
            <h3>🔍 Explainable Flow Detections (Top Contributing AE Features, RF Probability, IF Score & Decision Rule)</h3>
            <div className="soc-panel-actions">
              <select value={agreementFilter} onChange={(e) => setAgreementFilter(e.target.value)}>
                <option value="ALL">Filter Agreement: All Patterns ({triModelDetections.length})</option>
                <option value="ALL_3_MODELS_AGREE">ALL_3_MODELS_AGREE</option>
                <option value="RF_AND_AE_AGREE">RF_AND_AE_AGREE</option>
                <option value="RF_AND_IF_AGREE">RF_AND_IF_AGREE</option>
                <option value="AE_ONLY">AE_ONLY (Autoencoder-Only Anomaly)</option>
                <option value="IF_ONLY">IF_ONLY (Isolation Forest-Only Anomaly)</option>
                <option value="RF_SUPERVISED_ONLY">RF_SUPERVISED_ONLY</option>
                <option value="ALL_3_NORMAL">ALL_3_NORMAL</option>
              </select>
            </div>
          </div>

          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Source → Target</th>
                  <th>RF Attack Prob (Probability)</th>
                  <th>IF Score (Anomaly Score)</th>
                  <th>Autoencoder MSE (Threshold P97=0.5037)</th>
                  <th>Top Contributing AE Features</th>
                  <th>Model Agreement</th>
                  <th>Final Decision & Rule</th>
                  <th>Action & Safety</th>
                  <th>Dossier</th>
                </tr>
              </thead>
              <tbody>
                {triModelDetections
                  .filter(f => agreementFilter === 'ALL' || f.tri_model_decision.agreement_pattern === agreementFilter)
                  .slice(0, 30)
                  .map(f => {
                    const rf = f.models.random_forest;
                    const ifm = f.models.isolation_forest;
                    const ae = f.models.autoencoder;
                    const dec = f.tri_model_decision;
                    const topFeat = (ae.top_contributing_features || []).slice(0, 2);
                    return (
                      <tr key={f.flow_id} className={dec.is_anomaly ? 'high-threat' : ''}>
                        <td><code>{f.flow_id}</code></td>
                        <td>
                          <code>{f.src_ip}</code> → <code>{f.dst_ip}:{f.dst_port}</code> ({f.protocol})
                        </td>
                        <td>
                          <strong>{(rf.attack_probability * 100).toFixed(1)}%</strong>{' '}
                          <span className={`status-badge ${rf.is_anomaly ? 'unhealthy' : 'healthy'}`}>
                            {rf.is_anomaly ? 'ATTACK' : 'BENIGN'}
                          </span>
                          <div style={{ fontSize: '10px', color: '#a0aec0' }}>[PROBABILITY] ({rf.status})</div>
                        </td>
                        <td>
                          <strong>raw: {ifm.raw_decision_score}</strong> (idx: {ifm.normalized_anomaly_score?.toFixed(2)})
                          <div style={{ fontSize: '10px', color: '#a0aec0' }}>[ANOMALY SCORE] ({ifm.status})</div>
                        </td>
                        <td>
                          <strong>MSE: {ae.reconstruction_error}</strong>{' '}
                          <span className={`status-badge ${ae.is_anomaly ? 'unhealthy' : ae.decision === 'suspicious' ? 'demo' : 'healthy'}`}>
                            {ae.decision.toUpperCase()}
                          </span>
                          <div style={{ fontSize: '10px', color: '#a0aec0' }}>[MSE vs P97={ae.configured_threshold}] ({ae.status})</div>
                        </td>
                        <td>
                          {topFeat.map(tf => (
                            <div key={tf.feature_index} style={{ fontSize: '11px' }}>
                              <code>{tf.feature_name}</code>: {(tf.error_share * 100).toFixed(1)}% (sq={tf.squared_error})
                            </div>
                          ))}
                        </td>
                        <td>
                          <code>{dec.agreement_pattern}</code>
                          <div style={{ fontSize: '10px', color: '#a0aec0' }}>
                            Agree: {(dec.models_agreeing_on_anomaly || []).join(', ') || 'none'}
                          </div>
                        </td>
                        <td>
                          <strong>{dec.final_decision.toUpperCase()}</strong> ({dec.fusion_policy})
                          <div style={{ fontSize: '11px', color: '#cbd5e0' }}>Rule: <code>{dec.decision_rule}</code></div>
                        </td>
                        <td>
                          <span className="action">{dec.recommended_action}</span>
                          <div style={{ fontSize: '10px', color: dec.auto_block_permitted ? '#68d391' : '#f6ad55' }}>
                            {dec.auto_block_permitted ? 'Auto-Block Allowed' : '🔒 Auto-Block Forbidden'}
                          </div>
                        </td>
                        <td>
                          <button className="btn-ai-investigate" onClick={() => handleInspectFlow(f.flow_id)}>
                            🔍 Inspect Flow
                          </button>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>

          {/* Manual-Review Queue for Autoencoder-Only (AE_ONLY) & Single-Detector Anomalies */}
          <div className="soc-subcard" style={{ marginTop: '24px', borderLeft: '4px solid #ed8936' }}>
            <div className="soc-panel-header">
              <div>
                <h3>🛡️ Manual-Review Queue for Autoencoder-Only (AE_ONLY) & Single-Detector Anomalies</h3>
                <p className="soc-meta-line">
                  🔒 <strong>Mandatory Safety Guardrail:</strong> {manualReviewData.safety_policy || 'Autoencoder-only anomalies (AE_ONLY) never independently authorize IP blocking.'}
                </p>
              </div>
              <span className="certainty-badge tier-suspected">
                AE_ONLY Items: {manualReviewData.ae_only_items_count ?? 4} | Pending Review: {manualReviewData.pending_items_count ?? 8}
              </span>
            </div>

            <div className="threats-table">
              <table>
                <thead>
                  <tr>
                    <th>Review ID / Flow ID</th>
                    <th>Source IP → Port</th>
                    <th>Trigger Detector</th>
                    <th>AE MSE vs P97</th>
                    <th>RF Attack Prob</th>
                    <th>IF Raw Score</th>
                    <th>Top AE Feature</th>
                    <th>Safety Lock</th>
                    <th>Review Status</th>
                    <th>SOC Analyst Decision (Audit Logged)</th>
                  </tr>
                </thead>
                <tbody>
                  {(manualReviewData.queue || []).map(item => (
                    <tr key={item.review_id}>
                      <td>
                        <code>{item.flow_id}</code>
                        <div style={{ fontSize: '10px', color: '#a0aec0' }}>{item.review_id}</div>
                      </td>
                      <td><code>{item.src_ip}</code> → <code>{item.dst_port}/{item.protocol}</code></td>
                      <td>
                        <span className={`certainty-badge ${item.is_autoencoder_only ? 'tier-suspected' : 'tier-inferred'}`}>
                          {item.trigger_source}
                        </span>
                      </td>
                      <td><strong>{item.ae_reconstruction_error}</strong> (P97={item.ae_threshold_p97})</td>
                      <td>{(item.rf_attack_probability * 100).toFixed(1)}%</td>
                      <td>{item.if_raw_decision_score}</td>
                      <td>
                        {item.top_contributing_features?.[0] && (
                          <code>{item.top_contributing_features[0].feature_name} ({(item.top_contributing_features[0].error_share * 100).toFixed(1)}%)</code>
                        )}
                      </td>
                      <td>
                        <span className="status-badge unhealthy">🔒 AUTO-BLOCK FORBIDDEN</span>
                      </td>
                      <td>
                        <span className={`status-badge ${item.review_status === 'PENDING_ANALYST_REVIEW' ? 'demo' : 'healthy'}`}>
                          {item.review_status}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          <button
                            className="btn-investigate"
                            onClick={() => handleManualReviewDecision(item.flow_id, 'DISMISS_FALSE_POSITIVE', 'Verified benign burst / false positive')}
                          >
                            ✓ Dismiss FP
                          </button>
                          <button
                            className="btn-investigate"
                            onClick={() => handleManualReviewDecision(item.flow_id, 'ESCALATE_TO_INCIDENT', 'Escalated for NIDS/Honeypot correlation (No Auto-Block)')}
                          >
                            🚨 Escalate (No Block)
                          </button>
                          {item.is_autoencoder_only && (
                            <button
                              className="btn-investigate"
                              style={{ background: 'rgba(229, 62, 62, 0.25)', border: '1px solid #e53e3e' }}
                              onClick={() => handleManualReviewDecision(item.flow_id, 'AUTO_BLOCK_IP', 'Attempted AE-only auto-block test')}
                              title="Verify safety guardrail: AE-only auto-block will be rejected with HTTP 422"
                            >
                              🔒 Test Block Lock
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Immutable Manual-Review Audit Log */}
            {manualReviewData.audit_log && manualReviewData.audit_log.length > 0 && (
              <div style={{ marginTop: '14px' }}>
                <h4>Immutable Manual-Review Audit Trail ({manualReviewData.audit_log.length} Recorded Actions)</h4>
                <div className="threats-table" style={{ marginTop: '6px' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Audit ID</th>
                        <th>Timestamp</th>
                        <th>Flow ID</th>
                        <th>Trigger</th>
                        <th>Outcome / Decision</th>
                        <th>Operator (Role)</th>
                        <th>Auto-Block Executed</th>
                        <th>Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {manualReviewData.audit_log.map(entry => (
                        <tr key={entry.audit_id}>
                          <td><code>{entry.audit_id}</code></td>
                          <td>{new Date(entry.timestamp).toLocaleTimeString()}</td>
                          <td><code>{entry.flow_id}</code></td>
                          <td><code>{entry.trigger_source}</code></td>
                          <td><strong>{entry.outcome === 'REJECTED_BY_AE_ONLY_SAFETY_POLICY' ? entry.outcome : entry.decision}</strong></td>
                          <td><code>{entry.operator} ({entry.role})</code></td>
                          <td><code>{String(entry.auto_block_executed)}</code></td>
                          <td>{entry.reason || entry.analyst_notes}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      {/* =====================================================================
          MODULE 10: STAGE 4 SYNTHETIC BENCHMARK & FP/FN RESEARCH EVALUATION
          ===================================================================== */}
      {activeModule === 'ml_benchmark' && researchBenchmark && (
        <section className="card soc-module-panel" id="synthetic-benchmark-panel">
          <div className="soc-panel-header">
            <div>
              <h2>🔬 6-Model Research & Benchmark Evaluation View</h2>
              <span className="soc-meta-line">
                Comparing Supervised Random Forest, Isolation Forest, PyTorch Autoencoder (P95/P97/P99), and Tri-Model Ensembles on the Held-Out 384-Flow Test Set (182 Normal + 202 Attack)
              </span>
            </div>
            <span className="certainty-badge tier-suspected" style={{ fontSize: '13px', padding: '6px 12px' }}>
              ⚠️ {researchBenchmark.benchmark_classification || 'SYNTHETIC BENCHMARK ONLY'}
            </span>
          </div>

          <div className="soc-disclaimer-note" style={{ borderLeftColor: '#ed8936', background: 'rgba(237, 137, 54, 0.14)' }}>
            ⚠️ <strong>{researchBenchmark.benchmark_classification}:</strong> {researchBenchmark.scientific_disclaimer}
          </div>

          {/* 6-Way Model Comparison Table */}
          <h3 style={{ marginBottom: '10px' }}>1. Six-Model Held-Out Test Set Comparison (384 Flows — SYNTHETIC BENCHMARK ONLY)</h3>
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Model / Fusion Policy</th>
                  <th>Paradigm</th>
                  <th>Operating Point</th>
                  <th>Confusion Matrix (TN / FP / FN / TP)</th>
                  <th>Accuracy</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1 Score</th>
                  <th>False Positive Rate (FPR)</th>
                </tr>
              </thead>
              <tbody>
                {(researchBenchmark.models_comparison || []).map(m => (
                  <tr key={m.model_id}>
                    <td><strong>{m.display_name}</strong></td>
                    <td>{m.paradigm}</td>
                    <td><code>{m.operating_point}</code></td>
                    <td>
                      <code>TN={m.confusion_matrix.tn}, FP={m.confusion_matrix.fp}, FN={m.confusion_matrix.fn}, TP={m.confusion_matrix.tp}</code>
                    </td>
                    <td><strong>{m.accuracy_pct.toFixed(2)}%</strong> ({m.accuracy})</td>
                    <td>{m.precision_pct.toFixed(2)}% ({m.precision})</td>
                    <td>{m.recall_pct.toFixed(2)}% ({m.recall})</td>
                    <td><strong>{m.f1.toFixed(4)}</strong></td>
                    <td>{m.fpr_pct.toFixed(2)}% ({m.fpr})</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Autoencoder Threshold Calibration Sweep (P95 vs P97 Frozen vs P99) */}
          <h3 style={{ marginTop: '22px', marginBottom: '10px' }}>2. PyTorch Autoencoder Validation Threshold Calibration Sweep (P95 vs. Frozen P97 vs. P99)</h3>
          <p className="soc-meta-line" style={{ marginBottom: '10px' }}>
            <strong>Why P97 (0.503670) Was Selected Before Seeing Test Data:</strong>{' '}
            {triModelOverview?.models_health?.autoencoder?.p97_selection_justification}
          </p>
          <div className="threats-table">
            <table>
              <thead>
                <tr>
                  <th>Percentile Tier</th>
                  <th>Validation Threshold (MSE)</th>
                  <th>Val Normal FPR (180 Flows)</th>
                  <th>Test Confusion Matrix (TN / FP / FN / TP)</th>
                  <th>Test Accuracy</th>
                  <th>Test Precision</th>
                  <th>Test Recall</th>
                  <th>Test F1</th>
                  <th>Test FPR</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(researchBenchmark.autoencoder_threshold_sweep || {}).map(([pct, s]) => (
                  <tr key={pct} style={pct === 'P97' ? { borderLeft: '3px solid #48bb78', background: 'rgba(72, 187, 120, 0.07)' } : {}}>
                    <td>
                      <strong>{pct}</strong> {pct === 'P97' && <span className="status-badge healthy">FROZEN PRIMARY</span>}
                    </td>
                    <td><code>{s.threshold}</code></td>
                    <td><strong>{s.val_normal_fpr_pct.toFixed(2)}%</strong></td>
                    <td><code>TN={s.confusion_matrix.tn}, FP={s.confusion_matrix.fp}, FN={s.confusion_matrix.fn}, TP={s.confusion_matrix.tp}</code></td>
                    <td>{s.accuracy_pct.toFixed(2)}%</td>
                    <td>{s.precision_pct.toFixed(2)}%</td>
                    <td>{s.recall_pct.toFixed(2)}%</td>
                    <td><strong>{s.f1.toFixed(4)}</strong></td>
                    <td>{s.fpr_pct.toFixed(2)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* False-Positive, False-Negative & Feature-Collision Evaluation Views */}
          {evaluationViews && (
            <div className="soc-subcard" style={{ marginTop: '24px' }}>
              <div className="soc-panel-header">
                <div>
                  <h3>3. False-Positive (FP), False-Negative (FN) & Cross-Label Feature-Collision Evaluation Views</h3>
                  <p className="soc-meta-line">{evaluationViews.reconciliation_explanation}</p>
                </div>
                <div className="soc-panel-actions">
                  <button
                    className={`soc-nav-tab ${evalSubTab === 'false_positives' ? 'active' : ''}`}
                    onClick={() => setEvalSubTab('false_positives')}
                  >
                    False Positives ({evaluationViews.false_positives?.length || 7})
                  </button>
                  <button
                    className={`soc-nav-tab ${evalSubTab === 'false_negatives' ? 'active' : ''}`}
                    onClick={() => setEvalSubTab('false_negatives')}
                  >
                    False Negatives ({evaluationViews.false_negatives?.length || 8})
                  </button>
                  <button
                    className={`soc-nav-tab ${evalSubTab === 'feature_collisions' ? 'active' : ''}`}
                    onClick={() => setEvalSubTab('feature_collisions')}
                  >
                    Feature Collisions ({evaluationViews.feature_collisions?.length || 4})
                  </button>
                </div>
              </div>

              <div className="threats-table">
                <table>
                  <thead>
                    <tr>
                      <th>Flow ID</th>
                      <th>Ground Truth Label & Profile</th>
                      <th>Raw Scalar Inputs (packets, bytes, duration)</th>
                      <th>RF Attack Prob</th>
                      <th>IF Raw Score</th>
                      <th>AE Reconstruction MSE</th>
                      <th>Agreement Pattern</th>
                      <th>Weighted Fusion Decision & Rule</th>
                      <th>Inspect</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(evaluationViews[evalSubTab] || []).map(f => (
                      <tr key={f.flow_id}>
                        <td><code>{f.flow_id}</code></td>
                        <td>
                          <strong>{f.ground_truth.binary_label.toUpperCase()}</strong> ({f.ground_truth.traffic_profile} / {f.ground_truth.attack_category})
                          {f.ground_truth.is_feature_collision_ambiguity && (
                            <div><span className="certainty-badge tier-suspected">FEATURE COLLISION</span></div>
                          )}
                        </td>
                        <td>
                          <code>pkts={f.raw_measurements.packets}, bytes={f.raw_measurements.bytes}, dur={f.raw_measurements.duration}s</code>
                        </td>
                        <td>{(f.models.random_forest.attack_probability * 100).toFixed(1)}%</td>
                        <td>{f.models.isolation_forest.raw_decision_score}</td>
                        <td><strong>{f.models.autoencoder.reconstruction_error}</strong></td>
                        <td><code>{f.tri_model_decision.agreement_pattern}</code></td>
                        <td>
                          <strong>{f.tri_model_decision.final_decision.toUpperCase()}</strong> — <code>{f.tri_model_decision.decision_rule}</code>
                        </td>
                        <td>
                          <button className="btn-ai-investigate" onClick={() => handleInspectFlow(f.flow_id)}>
                            🔍 Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 69-Feature Mathematical Limitations Summary */}
          {researchBenchmark.feature_mathematics_audit && (
            <div className="soc-subcard" style={{ marginTop: '20px' }}>
              <h3>4. 69-Feature Mathematical Redundancy & Irreducible Collision Limitation</h3>
              <p className="soc-meta-line">{researchBenchmark.feature_mathematics_audit.scientific_limitations_note}</p>
              <p className="soc-meta-line">
                <strong>Raw Scalar Inputs:</strong> <code>{(researchBenchmark.feature_mathematics_audit.raw_independent_inputs || []).join(', ')}</code> (Intrinsic rank ≤ 3) •{' '}
                <strong>Meaningful Base/Rate Features:</strong> {researchBenchmark.feature_mathematics_audit.meaningful_base_features_count} •{' '}
                <strong>Duplicate Polynomial Columns (f_25..f_39):</strong> {researchBenchmark.feature_mathematics_audit.duplicate_polynomial_columns_count} •{' '}
                <strong>Rank-1 Collinear Padding Columns (f_55..f_68):</strong> {researchBenchmark.feature_mathematics_audit.collinear_padding_columns_count}
              </p>
            </div>
          )}
        </section>
      )}

      {/* ===================================================================
          MODULE 11: EXPLAINABLE AI (XAI) & THREAT REASONING
          =================================================================== */}
      {activeModule === 'xai_reasoning' && (
        <section className="card soc-module-panel" id="xai-reasoning-panel">
          <div className="soc-panel-header">
            <div>
              <h2>🔍 Explainable AI (XAI) & Threat Reasoning (Module 11)</h2>
              <span className="soc-meta-line">
                Read-Only Explanation Layer over Frozen Tri-Model Engine • Preserves{' '}
                <code>weighted_consensus</code> &amp; <code>P97 = 0.503670</code> • Active Role:{' '}
                <code>{socRole}</code>
              </span>
            </div>
            <div className="soc-panel-actions">
              <button
                className="btn-investigate"
                onClick={() => handleInvestigateXaiFlow(xaiFlowInput, false)}
                disabled={xaiLoading}
              >
                {xaiLoading ? '⏳ Loading...' : '🔄 Refresh Explanation'}
              </button>
            </div>
          </div>

          {/* 1. XAI Overview Metrics (Real API-backed from GET /api/v2/xai/overview) */}
          {xaiOverviewLoading && !xaiOverview && (
            <div className="xai-loading-box">⏳ Loading XAI Overview from <code>/api/v2/xai/overview</code>...</div>
          )}
          {xaiOverviewError && (
            <div className="xai-error-banner">
              <strong>⚠️ XAI Overview API Unavailable:</strong> {xaiOverviewError} — Existing detection modules remain unaffected.
            </div>
          )}

          {xaiOverview && (
            <div className="xai-overview-section">
              <div className="xai-kpi-grid">
                <div className="xai-kpi-card">
                  <span className="xai-kpi-label">Total Explanations</span>
                  <span className="xai-kpi-val">{xaiOverview.persistence?.total_explanations ?? 0}</span>
                  <span className="xai-kpi-sub">Backend: {xaiOverview.persistence?.storage_backend || 'unknown'}</span>
                </div>
                <div className="xai-kpi-card">
                  <span className="xai-kpi-label">Malicious Flows Explained</span>
                  <span className="xai-kpi-val text-danger">{xaiOverview.persistence?.malicious_flows_explained ?? 0}</span>
                  <span className="xai-kpi-sub">Suspicious: {xaiOverview.persistence?.suspicious_flows_explained ?? 0}</span>
                </div>
                <div className="xai-kpi-card">
                  <span className="xai-kpi-label">Benign Flows Explained</span>
                  <span className="xai-kpi-val text-success">{xaiOverview.persistence?.benign_flows_explained ?? 0}</span>
                  <span className="xai-kpi-sub">Cache: {xaiOverview.persistence?.lru_cache_entries ?? 0}/{xaiOverview.persistence?.lru_cache_capacity ?? 256}</span>
                </div>
                <div className="xai-kpi-card">
                  <span className="xai-kpi-label">Partial / Degraded</span>
                  <span className="xai-kpi-val text-warning">{xaiOverview.persistence?.partially_degraded_explanations ?? 0}</span>
                  <span className="xai-kpi-sub">Failures: {xaiOverview.persistence?.explanation_generation_failures ?? 0}</span>
                </div>
                <div className="xai-kpi-card">
                  <span className="xai-kpi-label">Model Agreement Stats</span>
                  <span className="xai-kpi-val" style={{ fontSize: '14px' }}>
                    3/3 Atk: {xaiOverview.persistence?.agreement_statistics?.unanimous_anomaly ?? 0} • 3/3 Norm: {xaiOverview.persistence?.agreement_statistics?.unanimous_normal ?? 0}
                  </span>
                  <span className="xai-kpi-sub">Dissent: {xaiOverview.persistence?.agreement_statistics?.disagreement ?? 0}</span>
                </div>
              </div>
            </div>
          )}

          {/* 2. Interactive Flow Investigation & Controls */}
          <div className="xai-investigation-bar">
            <div className="xai-input-group">
              <label htmlFor="xai-flow-id-input">Flow ID:</label>
              <input
                id="xai-flow-id-input"
                type="text"
                value={xaiFlowInput}
                onChange={(e) => setXaiFlowInput(e.target.value)}
                placeholder="e.g. flow-atk-01404 or flow-norm-00293"
                aria-label="Search by Flow ID"
              />
              <select
                aria-label="Select recent flow"
                value=""
                onChange={(e) => {
                  if (e.target.value) handleInvestigateXaiFlow(e.target.value, false);
                }}
              >
                <option value="">Quick-Select Recent Flow...</option>
                {(triModelDetections || []).slice(0, 15).map((f) => (
                  <option key={f.flow_id} value={f.flow_id}>
                    {f.flow_id} ({f.tri_model_decision?.final_decision || 'unknown'})
                  </option>
                ))}
              </select>
              <button
                className="btn-ai-investigate"
                onClick={() => handleInvestigateXaiFlow(xaiFlowInput, false)}
                disabled={xaiLoading}
              >
                🔍 Investigate (GET)
              </button>
              {socRole !== 'VIEWER' ? (
                <button
                  className="btn-investigate"
                  onClick={() => handleInvestigateXaiFlow(xaiFlowInput, true)}
                  disabled={xaiLoading}
                  title="Generate fresh explanation via POST /api/v2/xai/explanation (SOC_ANALYST / ADMIN)"
                >
                  ⚡ Request Fresh Explanation (POST)
                </button>
              ) : (
                <span className="xai-rbac-note" title="Backend enforces 403 for VIEWER on POST">
                  🔒 VIEWER: Read-Only Mode
                </span>
              )}
            </div>
          </div>

          {/* Recent Explanation Activity + Filters */}
          <div className="xai-recent-section">
            <div className="xai-filter-row">
              <strong>Recent Explanation Activity</strong>
              <input
                type="text"
                placeholder="Filter Flow ID..."
                value={xaiSearchFilter}
                onChange={(e) => setXaiSearchFilter(e.target.value)}
                aria-label="Filter recent explanations by flow ID"
              />
              <select value={xaiClassFilter} onChange={(e) => setXaiClassFilter(e.target.value)} aria-label="Filter by classification">
                <option value="ALL">All Classifications</option>
                <option value="anomalous">Anomalous</option>
                <option value="suspicious">Suspicious</option>
                <option value="normal">Normal</option>
              </select>
              <select value={xaiStatusFilter} onChange={(e) => setXaiStatusFilter(e.target.value)} aria-label="Filter by explanation status">
                <option value="ALL">All Statuses</option>
                <option value="healthy">Healthy</option>
                <option value="partially_degraded">Partially Degraded</option>
                <option value="degraded">Degraded</option>
              </select>
              <select value={xaiAgreementFilter} onChange={(e) => setXaiAgreementFilter(e.target.value)} aria-label="Filter by model agreement">
                <option value="ALL">All Consensus</option>
                <option value="AGREE">Unanimous Agreement</option>
                <option value="DISAGREE">Model Disagreement</option>
              </select>
              <select value={xaiSortOrder} onChange={(e) => setXaiSortOrder(e.target.value)} aria-label="Sort by timestamp">
                <option value="DESC">Newest First</option>
                <option value="ASC">Oldest First</option>
              </select>
            </div>

            {(() => {
              const recent = (xaiOverview?.persistence?.recent_explanations || [])
                .filter((r) => !xaiSearchFilter || String(r.flow_id).toLowerCase().includes(xaiSearchFilter.toLowerCase()))
                .filter((r) => xaiClassFilter === 'ALL' || r.final_decision === xaiClassFilter)
                .filter((r) => xaiStatusFilter === 'ALL' || r.explanation_status === xaiStatusFilter)
                .filter((r) => {
                  if (xaiAgreementFilter === 'AGREE') return !r.has_model_disagreement;
                  if (xaiAgreementFilter === 'DISAGREE') return Boolean(r.has_model_disagreement);
                  return true;
                })
                .sort((a, b) => {
                  const ta = new Date(a.created_at || 0).getTime();
                  const tb = new Date(b.created_at || 0).getTime();
                  return xaiSortOrder === 'DESC' ? tb - ta : ta - tb;
                });

              if (recent.length === 0) {
                return (
                  <div className="xai-empty-state">
                    No stored explanations match the current filter. Enter a Flow ID above (e.g. <code>flow-atk-01404</code>) and click <strong>Investigate</strong>.
                  </div>
                );
              }
              return (
                <div className="table-responsive">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Flow ID</th>
                        <th>Timestamp</th>
                        <th>Classification</th>
                        <th>System Action</th>
                        <th>Status</th>
                        <th>Consensus</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recent.slice(0, 10).map((item) => (
                        <tr key={item.explanation_id || item.flow_id}>
                          <td><code>{item.flow_id}</code></td>
                          <td>{item.created_at ? new Date(item.created_at).toLocaleString() : '—'}</td>
                          <td><span className={`severity-badge ${item.final_decision === 'anomalous' ? 'high' : 'low'}`}>{String(item.final_decision || '').toUpperCase()}</span></td>
                          <td><code>{item.recommended_action}</code> (auto_block={String(item.auto_block_permitted)})</td>
                          <td><span className={`status-badge ${item.explanation_status === 'healthy' ? 'healthy' : 'unhealthy'}`}>{item.explanation_status}</span></td>
                          <td><code>{item.consensus_state}</code></td>
                          <td>
                            <button className="btn-investigate" onClick={() => handleInvestigateXaiFlow(item.flow_id, false)}>
                              View
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </div>

          {xaiError && (
            <div className="xai-error-banner">
              <strong>⚠️ Explanation Error:</strong> {xaiError}
            </div>
          )}

          {/* 3. Active Flow Explanation Details */}
          {xaiExplanation && (
            <div className="xai-detail-container">
              {/* Degraded Banner if partially_degraded or degraded */}
              {xaiExplanation.explanation_generation_status !== 'healthy' && (
                <div className="soc-degraded-banner" style={{ marginBottom: '14px' }}>
                  <div>
                    <strong>⚠️ DEGRADED / PARTIAL EXPLANATION ({String(xaiExplanation.explanation_generation_status).toUpperCase()}):</strong>{' '}
                    Unavailable explainers: <code>{(xaiExplanation.degraded_explainers || []).join(', ') || 'all'}</code>. Automatic IP blocking is strictly disabled.
                  </div>
                </div>
              )}

              {/* Flow Header Summary */}
              <div className="xai-flow-header-grid">
                <div><strong>Flow ID:</strong> <code>{xaiExplanation.flow_id}</code></div>
                <div><strong>Timestamp:</strong> {xaiExplanation.flow_metadata?.timestamp || 'Ad-hoc / Live'}</div>
                <div><strong>Final System Classification:</strong> <span className="highlight">{String(xaiExplanation.final_tri_model_classification?.final_decision || '').toUpperCase()}</span></div>
                <div><strong>Existing System Action (Not XAI):</strong> <code>{xaiExplanation.final_tri_model_classification?.recommended_action}</code> (auto_block={String(xaiExplanation.final_tri_model_classification?.auto_block_permitted)})</div>
                <div><strong>Explanation Status:</strong> <code>{xaiExplanation.explanation_generation_status}</code> ({xaiExplanationSource})</div>
                <div><strong>Model Availability:</strong> Healthy=[{(xaiExplanation.healthy_explainers || []).join(', ')}]</div>
              </div>

              {/* Human-Readable Threat Reasoning */}
              <div className="xai-panel-card">
                <h3>🧠 Human-Readable Threat Reasoning (Evidence-Grounded, Non-Causal)</h3>
                <p className="xai-narrative-text">
                  {xaiExplanation.human_readable_soc_analyst_explanation?.full_narrative}
                </p>
                <div className="xai-uncertainty-note">
                  <strong>Observed Evidence vs. Interpretation:</strong>{' '}
                  {xaiExplanation.model_agreement_and_disagreement?.disagreement_explanation}
                  {' '}• <strong>Reliability Tier:</strong> <code>{xaiExplanation.explanation_confidence_and_limitations?.explanation_reliability_tier}</code>
                </div>
                {(xaiExplanation.human_readable_soc_analyst_explanation?.analyst_investigation_checklist || []).length > 0 && (
                  <ul className="xai-checklist">
                    {xaiExplanation.human_readable_soc_analyst_explanation.analyst_investigation_checklist.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Feature Correlation Transparency (3 Raw Measurements -> 69 Features) */}
              <div className="xai-panel-card xai-transparency-box">
                <h3>📐 69-Feature Correlation Transparency (3 Raw Measurements Only)</h3>
                <p className="soc-meta-line">
                  The canonical <code>v2.0-69dim</code> schema is derived deterministically from only <strong>three underlying raw measurements</strong>:{' '}
                  <strong>Packet Count</strong> (<code>{xaiExplanation.flow_metadata?.packets ?? '—'}</code>),{' '}
                  <strong>Byte Count</strong> (<code>{xaiExplanation.flow_metadata?.bytes ?? '—'}</code>), and{' '}
                  <strong>Flow Duration</strong> (<code>{xaiExplanation.flow_metadata?.duration ?? '—'}s</code>).
                  It includes 13 exact polynomial duplicates (<code>f_25..f_39</code>) and 14 collinear harmonic padding columns (<code>f_55..f_68</code>), which distribute attribution across correlated features rather than 69 independent signals.
                </p>
                <div className="xai-3scalar-grid">
                  {['random_forest_explanation', 'isolation_forest_explanation', 'autoencoder_explanation'].map((mKey) => {
                    const mObj = xaiExplanation[mKey];
                    const shares = mObj?.raw_measurement_attribution;
                    if (!shares) return null;
                    return (
                      <div key={mKey} className="xai-scalar-card">
                        <strong>{mKey.replace('_explanation', '').replace('_', ' ').toUpperCase()}</strong>
                        <div>Packets Share: <code>{((shares.packets?.share_of_total || 0) * 100).toFixed(1)}%</code></div>
                        <div>Bytes Share: <code>{((shares.bytes?.share_of_total || 0) * 100).toFixed(1)}%</code></div>
                        <div>Duration Share: <code>{((shares.duration?.share_of_total || 0) * 100).toFixed(1)}%</code></div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Three-Model Comparison Section */}
              <div className="xai-panel-card">
                <h3>⚖️ Three-Model Comparison (Distinct Mathematical Scales — Never Averaged)</h3>
                <div className="table-responsive">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Model</th>
                        <th>Output</th>
                        <th>Explanation</th>
                        <th>Verdict</th>
                        <th>Measured Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td><strong>Random Forest</strong></td>
                        <td>Attack probability</td>
                        <td>SHAP (<code>{xaiExplanation.random_forest_explanation?.is_exact_shap ? 'Exact TreeSHAP' : 'Fallback'}</code>)</td>
                        <td><code>{xaiExplanation.model_agreement_and_disagreement?.per_model_verdict?.random_forest}</code></td>
                        <td><code>P(attack) = {xaiExplanation.random_forest_explanation?.attack_probability ?? 'N/A'}</code></td>
                      </tr>
                      <tr>
                        <td><strong>Isolation Forest</strong></td>
                        <td>Anomaly score (NOT probability)</td>
                        <td>Perturbation attribution</td>
                        <td><code>{xaiExplanation.model_agreement_and_disagreement?.per_model_verdict?.isolation_forest}</code></td>
                        <td><code>anom_score = {xaiExplanation.isolation_forest_explanation?.anomaly_score ?? 'N/A'}</code> (raw={xaiExplanation.isolation_forest_explanation?.raw_decision_score ?? 'N/A'})</td>
                      </tr>
                      <tr>
                        <td><strong>Autoencoder</strong></td>
                        <td>Reconstruction error (NOT probability)</td>
                        <td>Reconstruction attribution</td>
                        <td><code>{xaiExplanation.model_agreement_and_disagreement?.per_model_verdict?.autoencoder}</code></td>
                        <td><code>MSE = {xaiExplanation.autoencoder_explanation?.reconstruction_error ?? 'N/A'}</code> vs <code>P97 = 0.503670</code></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <p className="soc-meta-line" style={{ marginTop: '8px' }}>
                  <strong>Consensus:</strong> <code>{xaiExplanation.model_agreement_and_disagreement?.consensus_state}</code> •{' '}
                  <strong>Unanimous:</strong> {String(xaiExplanation.model_agreement_and_disagreement?.models_agree)} •{' '}
                  <strong>Shared Raw Drivers:</strong>{' '}
                  <code>{(xaiExplanation.shared_contributing_measurements?.shared_raw_measurements || []).map((s) => s.raw_measurement).join(', ') || 'none'}</code>
                </p>
              </div>

              {/* Collapsible Model Panel 1: Random Forest SHAP */}
              <div className="xai-panel-card">
                <div className="xai-collapse-header" onClick={() => toggleXaiPanel('rf')} role="button" tabIndex={0}>
                  <h3>🌲 Random Forest SHAP Explanation (Click to {xaiExpandedPanels.rf ? 'Collapse' : 'Expand'})</h3>
                  <span>P(attack)={xaiExplanation.random_forest_explanation?.attack_probability ?? 'N/A'} • Base={xaiExplanation.random_forest_explanation?.base_expected_value_attack ?? 'N/A'}</span>
                </div>
                {xaiExpandedPanels.rf && (
                  <div className="xai-collapse-body">
                    <p className="soc-meta-line">
                      Positive SHAP values increase the attack-class probability; negative SHAP values decrease it toward normal. SHAP values are feature attributions, not causal proof.
                    </p>
                    {xaiExplanation.random_forest_explanation?.status === 'healthy' ? (
                      <div className="xai-two-col">
                        <div>
                          <h4>Top Positive (Attack-Pushing) Features</h4>
                          {(xaiExplanation.random_forest_explanation.top_positive_attack_contributors || []).map((f) => (
                            <div key={f.feature_name} className="xai-bar-row">
                              <span className="xai-bar-lbl" title={f.human_label}>{f.feature_name}</span>
                              <div className="xai-bar-track"><div className="xai-bar-fill pos" style={{ width: `${Math.min(100, Math.abs(f.shap_value_attack) * 800)}%` }} /></div>
                              <code>+{f.shap_value_attack.toFixed(4)}</code>
                            </div>
                          ))}
                          <h4 style={{ marginTop: '10px' }}>Top Negative (Benign-Pushing) Features</h4>
                          {(xaiExplanation.random_forest_explanation.top_negative_benign_contributors || []).map((f) => (
                            <div key={f.feature_name} className="xai-bar-row">
                              <span className="xai-bar-lbl" title={f.human_label}>{f.feature_name}</span>
                              <div className="xai-bar-track"><div className="xai-bar-fill neg" style={{ width: `${Math.min(100, Math.abs(f.shap_value_attack) * 800)}%` }} /></div>
                              <code>{f.shap_value_attack.toFixed(4)}</code>
                            </div>
                          ))}
                        </div>
                        <div>
                          <h4>Global RF SHAP Importance (Top Features)</h4>
                          {(xaiOverview?.ml_xai_health?.global_rf_shap_importance?.top_features || []).slice(0, 6).map((gf) => (
                            <div key={gf.feature_name} className="xai-bar-row">
                              <span className="xai-bar-lbl">{gf.feature_name}</span>
                              <div className="xai-bar-track"><div className="xai-bar-fill global" style={{ width: `${Math.min(100, (gf.shap_importance_share || 0) * 500)}%` }} /></div>
                              <code>{(gf.mean_abs_shap || 0).toFixed(4)}</code>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="xai-empty-state">Random Forest explanation unavailable ({xaiExplanation.random_forest_explanation?.degraded_reason}).</div>
                    )}
                  </div>
                )}
              </div>

              {/* Collapsible Model Panel 2: Isolation Forest */}
              <div className="xai-panel-card">
                <div className="xai-collapse-header" onClick={() => toggleXaiPanel('if')} role="button" tabIndex={0}>
                  <h3>🧊 Isolation Forest Explainability (Click to {xaiExpandedPanels.if ? 'Collapse' : 'Expand'})</h3>
                  <span>Method: <code>reference_population_perturbation_and_quantile_deviation</code></span>
                </div>
                {xaiExpandedPanels.if && (
                  <div className="xai-collapse-body">
                    <p className="soc-meta-line">
                      <strong>Note:</strong> Isolation Forest anomaly score is an unsupervised tree-depth metric, <strong>NOT a probability</strong>. Compared against {xaiExplanation.isolation_forest_explanation?.reference_population_size ?? 840} normal reference flows (threshold={xaiExplanation.isolation_forest_explanation?.decision_threshold ?? -0.024499}).
                    </p>
                    {xaiExplanation.isolation_forest_explanation?.status === 'healthy' ? (
                      <div className="table-responsive">
                        <table className="soc-table">
                          <thead>
                            <tr><th>Feature</th><th>Flow Value</th><th>Normal Median</th><th>Robust Z</th><th>Deviation Status</th><th>Perturbation Shift</th></tr>
                          </thead>
                          <tbody>
                            {(xaiExplanation.isolation_forest_explanation.top_influential_features || []).map((f) => (
                              <tr key={f.feature_name}>
                                <td><code>{f.feature_name}</code></td>
                                <td>{f.flow_value}</td>
                                <td>{f.normal_median}</td>
                                <td>{f.robust_z_score}</td>
                                <td><span className="severity-badge medium">{f.population_deviation_status}</span></td>
                                <td><code>{f.effective_isolation_influence}</code></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="xai-empty-state">Isolation Forest explanation unavailable ({xaiExplanation.isolation_forest_explanation?.degraded_reason}).</div>
                    )}
                  </div>
                )}
              </div>

              {/* Collapsible Model Panel 3: PyTorch Autoencoder */}
              <div className="xai-panel-card">
                <div className="xai-collapse-header" onClick={() => toggleXaiPanel('ae')} role="button" tabIndex={0}>
                  <h3>🧬 PyTorch Autoencoder Reconstruction Explainability (Click to {xaiExpandedPanels.ae ? 'Collapse' : 'Expand'})</h3>
                  <span>MSE={xaiExplanation.autoencoder_explanation?.reconstruction_error ?? 'N/A'} vs Frozen P97=0.503670</span>
                </div>
                {xaiExpandedPanels.ae && (
                  <div className="xai-collapse-body">
                    <p className="soc-meta-line">
                      <strong>Note:</strong> Reconstruction error (MSE) is an anomaly measurement, <strong>NOT a probability</strong>. Thresholds: <code>P95 = 0.409105</code> • <strong><code>P97 = 0.503670</code> (Frozen Primary)</strong> • <code>P99 = 0.645935</code>.
                    </p>
                    {xaiExplanation.autoencoder_explanation?.status === 'healthy' ? (
                      <div className="xai-two-col">
                        <div>
                          <h4>Top 5 Anomalous Features (Ranked Bar Chart)</h4>
                          {(xaiExplanation.autoencoder_explanation.top_anomalous_features || []).map((f) => (
                            <div key={f.feature_name} className="xai-bar-row">
                              <span className="xai-bar-lbl">#{f.rank} {f.feature_name}</span>
                              <div className="xai-bar-track"><div className="xai-bar-fill ae" style={{ width: `${Math.min(100, (f.error_share || 0) * 400)}%` }} /></div>
                              <code>{f.squared_error.toFixed(4)} ({(f.error_share * 100).toFixed(1)}%)</code>
                            </div>
                          ))}
                        </div>
                        <div className="table-responsive">
                          <h4>Original vs. Reconstructed (Scaled Z)</h4>
                          <table className="soc-table">
                            <thead>
                              <tr><th>Feature</th><th>Input Z</th><th>Reconstructed Z</th><th>Sq Error</th></tr>
                            </thead>
                            <tbody>
                              {(xaiExplanation.autoencoder_explanation.top_anomalous_features || []).map((f) => (
                                <tr key={f.feature_name}>
                                  <td><code>{f.feature_name}</code></td>
                                  <td>{f.preprocessed_input_z}</td>
                                  <td>{f.reconstructed_output_z}</td>
                                  <td><code>{f.squared_error}</code></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ) : (
                      <div className="xai-empty-state">Autoencoder explanation unavailable ({xaiExplanation.autoencoder_explanation?.degraded_reason}).</div>
                    )}
                  </div>
                )}
              </div>

              {/* ADMIN-Only Diagnostics Panel */}
              {socRole === 'ADMIN' && xaiDiagnostics && (
                <div className="xai-panel-card">
                  <h3>🛠️ ADMIN XAI Diagnostics</h3>
                  <p className="soc-meta-line">
                    Storage Backend: <code>{xaiDiagnostics.persistence?.storage_backend}</code> • Strict Auth: <code>{String(xaiDiagnostics.strict_auth_enabled)}</code> • ML Timeout: <code>{xaiDiagnostics.ml_timeout_ms}ms</code>
                  </p>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {/* ===================================================================
          MODULE 12: DEMO TRAFFIC SIMULATOR (LIVE SYNTHETIC PIPELINE DEMO)
          =================================================================== */}
      {activeModule === 'demo_simulator' && (
        <section className="card soc-module-panel" id="demo-simulator-panel">
          <div className="soc-panel-header">
            <div>
              <h2>🚦 Demo Traffic Simulator (Module 12)</h2>
              <span className="soc-meta-line">
                Synthetic Traffic → Real Capture → 69-Feature Extraction → RF + IF + PyTorch AE → XAI → Simulated SOAR •{' '}
                <strong>State:</strong>{' '}
                <span className={`demo-state-pill state-${String(demoSimState.state || 'Idle').toLowerCase()}`}>
                  {demoSimState.state || 'Idle'}
                </span>{' '}
                • <strong>Session:</strong> <code>{demoSimState.session_id || 'None'}</code>{' '}
                • <strong>Elapsed:</strong> <code>{demoSimState.elapsed_seconds ?? 0}s</code>{' '}
                • <strong>Role:</strong> <code>{socRole}</code>
              </span>
            </div>
            <div className="soc-panel-actions">
              <label className="demo-filter-label">
                Dashboard Telemetry Filter:{' '}
                <select
                  id="demo-source-filter"
                  value={telemetrySourceFilter}
                  onChange={(e) => setTelemetrySourceFilter(e.target.value)}
                >
                  <option value="live">Live Only (Default)</option>
                  <option value="demo">Demo Only</option>
                  <option value="all">All (Live + Demo)</option>
                </select>
              </label>
              <button className="btn-investigate" onClick={refreshDemoStatusAndSummary}>
                🔄 Refresh Status
              </button>
            </div>
          </div>

          <div className="demo-safety-banner">
            <strong>⚠️ DEMO / SIMULATED SAFETY MODE:</strong> All events carry <code>event_source: "demo_simulator"</code> and are isolated from live production telemetry.
            No real firewall/IP blocks or external email notifications are executed.
            {demoWsReconnecting && <span className="demo-ws-reconnecting"> • ⏳ WebSocket reconnecting...</span>}
          </div>

          {!canControlDemo && (
            <div className="xai-rbac-note" style={{ marginTop: '8px' }}>
              🔒 Read-Only Role ({socRole}): Switch to <code>SOC_ANALYST</code> or <code>ADMIN</code> to Start/Pause/Stop/Reset simulations (enforced by backend RBAC).
            </div>
          )}
          {demoActionError && (
            <div className="xai-error-banner">
              <strong>⚠️ Simulator Error:</strong> {demoActionError}
            </div>
          )}
          {demoActionSuccess && (
            <div className="demo-success-banner">
              ✓ {demoActionSuccess}
            </div>
          )}

          {/* 1. Simulation Controls */}
          <div className="demo-controls-grid">
            <div className="demo-control-field">
              <label htmlFor="demo-scenario-select">Scenario (10 Supported)</label>
              <select
                id="demo-scenario-select"
                value={demoScenario}
                onChange={(e) => {
                  const val = e.target.value;
                  setDemoScenario(val);
                  if (val === 'mixed') setDemoMode('mixed');
                }}
                disabled={!canControlDemo || demoSimState.state === 'Running' || demoSimState.state === 'Paused'}
              >
                <option value="mixed">10. Mixed Traffic Simulation</option>
                <option value="normal_traffic">1. Normal / Benign Traffic</option>
                <option value="port_scan">2. Port Scanning</option>
                <option value="ssh_brute_force">3. SSH Brute Force</option>
                <option value="service_enumeration">4. Service Enumeration</option>
                <option value="ddos">5. DDoS / Flood Activity</option>
                <option value="data_exfiltration">6. Data Exfiltration</option>
                <option value="c2_beaconing">7. C2 Beaconing</option>
                <option value="multi_vector">8. Multi-Vector Attack</option>
                <option value="stealth_anomaly">9. Stealth / Anomalous Activity</option>
              </select>
            </div>

            <div className="demo-control-field">
              <label htmlFor="demo-mode-select">Mode</label>
              <select
                id="demo-mode-select"
                value={demoScenario === 'mixed' ? 'mixed' : demoMode}
                onChange={(e) => setDemoMode(e.target.value)}
                disabled={!canControlDemo || demoScenario === 'mixed' || demoSimState.state === 'Running' || demoSimState.state === 'Paused'}
              >
                <option value="single">Single Scenario</option>
                <option value="mixed">Mixed (Normal + Malicious)</option>
              </select>
            </div>

            <div className="demo-control-field">
              <label htmlFor="demo-speed-select">Simulation Speed</label>
              <select
                id="demo-speed-select"
                value={demoSpeed}
                onChange={(e) => setDemoSpeed(e.target.value)}
                disabled={!canControlDemo || demoSimState.state === 'Running' || demoSimState.state === 'Paused'}
              >
                <option value="low">Low (~1 ev/sec)</option>
                <option value="medium">Medium (~2.5 ev/sec)</option>
                <option value="high">High (~8 ev/sec)</option>
              </select>
            </div>

            <div className="demo-control-field">
              <label htmlFor="demo-duration-select">Duration</label>
              <select
                id="demo-duration-select"
                value={demoDuration}
                onChange={(e) => setDemoDuration(e.target.value)}
                disabled={!canControlDemo || demoSimState.state === 'Running' || demoSimState.state === 'Paused'}
              >
                <option value="">Until Manually Stopped</option>
                <option value="15">15 seconds</option>
                <option value="30">30 seconds</option>
                <option value="60">60 seconds</option>
                <option value="120">120 seconds</option>
              </select>
            </div>
          </div>

          <div className="demo-action-buttons">
            <button
              id="demo-btn-start"
              className="btn-primary"
              onClick={() => handleDemoControl('start')}
              disabled={!canControlDemo || demoActionLoading || demoSimState.state === 'Running' || demoSimState.state === 'Paused'}
            >
              {demoActionLoading ? '⏳ Working...' : '▶ Start Demo Simulation'}
            </button>
            {demoSimState.state === 'Paused' ? (
              <button
                id="demo-btn-resume"
                className="btn-investigate"
                onClick={() => handleDemoControl('resume')}
                disabled={!canControlDemo || demoActionLoading}
              >
                ▶ Resume
              </button>
            ) : (
              <button
                id="demo-btn-pause"
                className="btn-investigate"
                onClick={() => handleDemoControl('pause')}
                disabled={!canControlDemo || demoActionLoading || demoSimState.state !== 'Running'}
              >
                ⏸ Pause
              </button>
            )}
            <button
              id="demo-btn-stop"
              className="btn-danger"
              onClick={() => handleDemoControl('stop')}
              disabled={!canControlDemo || demoActionLoading || (demoSimState.state !== 'Running' && demoSimState.state !== 'Paused')}
            >
              ⏹ Stop Simulation
            </button>
            <button
              id="demo-btn-reset"
              className="btn-secondary"
              onClick={() => handleDemoControl('reset')}
              disabled={!canControlDemo || demoActionLoading}
            >
              🔄 Reset Demo Session
            </button>
          </div>

          {/* 2. Live Session Counters */}
          <div className="demo-kpi-grid">
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">Events Generated</div>
              <div className="demo-kpi-value">{demoSession.counters?.events_generated ?? demoSimState.counters?.events_generated ?? 0}</div>
            </div>
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">Benign Events</div>
              <div className="demo-kpi-value text-success">{demoSession.counters?.benign_events ?? demoSimState.counters?.benign_events ?? 0}</div>
            </div>
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">Malicious Events</div>
              <div className="demo-kpi-value text-danger">{demoSession.counters?.malicious_events ?? demoSimState.counters?.malicious_events ?? 0}</div>
            </div>
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">Detected Threats</div>
              <div className="demo-kpi-value text-warning">{demoSession.counters?.detected_threats ?? 0}</div>
            </div>
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">Incidents Created</div>
              <div className="demo-kpi-value">{demoSession.counters?.incidents_generated ?? 0}</div>
            </div>
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">SOAR Simulated</div>
              <div className="demo-kpi-value">{demoSession.counters?.soar_actions_simulated ?? 0}</div>
            </div>
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">XAI Triggers</div>
              <div className="demo-kpi-value">{demoSession.counters?.xai_explanations_triggered ?? 0}</div>
            </div>
            <div className="demo-kpi-card">
              <div className="demo-kpi-label">Rate / Elapsed</div>
              <div className="demo-kpi-value">{demoSimState.events_per_sec ?? 0}/s • {demoSimState.elapsed_seconds ?? 0}s</div>
            </div>
          </div>

          {/* 3. Category & Protocol Distribution */}
          <div className="soc-cards-grid-2" style={{ marginTop: '14px' }}>
            <div className="demo-subpanel">
              <h3>📊 Attack Category Distribution</h3>
              {Object.keys(demoSession.category_counts || {}).length === 0 ? (
                <div className="xai-empty-state">No demo events generated yet. Click <strong>Start Demo Simulation</strong> above.</div>
              ) : (
                <div className="demo-bars-list">
                  {Object.entries(demoSession.category_counts).map(([cat, count]) => {
                    const maxCat = Math.max(1, ...Object.values(demoSession.category_counts));
                    const pct = Math.round((count / maxCat) * 100);
                    return (
                      <div key={cat} className="demo-bar-row">
                        <span className="demo-bar-label"><code>{cat}</code></span>
                        <div className="demo-bar-track">
                          <div
                            className={`demo-bar-fill ${cat === 'normal_traffic' ? 'benign' : 'attack'}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="demo-bar-count">{count}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="demo-subpanel">
              <h3>🌐 Protocol Distribution & Active Filter</h3>
              <div className="demo-bars-list">
                {Object.keys(demoSession.protocol_counts || {}).length === 0 ? (
                  <div className="xai-empty-state">Awaiting synthetic flow protocol telemetry...</div>
                ) : (
                  Object.entries(demoSession.protocol_counts).map(([proto, count]) => (
                    <div key={proto} className="demo-bar-row">
                      <span className="demo-bar-label"><code>{proto}</code></span>
                      <div className="demo-bar-track">
                        <div className="demo-bar-fill proto" style={{ width: '100%' }} />
                      </div>
                      <span className="demo-bar-count">{count}</span>
                    </div>
                  ))
                )}
              </div>
              <p className="soc-meta-line" style={{ marginTop: '10px' }}>
                Overview KPIs currently filtered by: <code>{telemetrySourceFilter.toUpperCase()}</code>
              </p>
            </div>
          </div>

          {/* 4. Live Event Stream & Tri-Model Detection Results */}
          <div className="demo-subpanel" style={{ marginTop: '14px' }}>
            <h3>⚡ Live Demo Event Stream &amp; Tri-Model Detection Results</h3>
            <p className="soc-meta-line">
              RF outputs probability [0–1]; Isolation Forest outputs raw decision score (negative = anomalous); PyTorch Autoencoder outputs MSE reconstruction error (distinct from probability).
            </p>
            {(demoSession.recent_events || []).length === 0 ? (
              <div className="xai-empty-state">No live demo events streamed yet.</div>
            ) : (
              <div className="soc-table-wrap">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Flow ID</th>
                      <th>Src → Dst (Ports)</th>
                      <th>Proto</th>
                      <th>Category</th>
                      <th>RF Prob</th>
                      <th>IF Anomaly Score</th>
                      <th>AE Recon Error</th>
                      <th>Fusion Decision</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(demoSession.recent_events || []).slice(0, 25).map((ev) => (
                      <tr key={ev.flow_id}>
                        <td>{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '-'}</td>
                        <td><code>{ev.flow_id}</code></td>
                        <td>
                          <code>{ev.src_ip}:{ev.src_port}</code> → <code>{ev.dst_ip}:{ev.dst_port}</code>
                        </td>
                        <td>{ev.protocol}</td>
                        <td><code>{ev.canonical_category || ev.attack_type}</code></td>
                        <td>{typeof ev.detection?.rf_probability === 'number' ? ev.detection.rf_probability.toFixed(3) : 'N/A'}</td>
                        <td>{typeof ev.detection?.if_anomaly_score === 'number' ? ev.detection.if_anomaly_score.toFixed(4) : 'N/A'}</td>
                        <td>{typeof ev.detection?.ae_reconstruction_error === 'number' ? ev.detection.ae_reconstruction_error.toFixed(4) : 'N/A'}</td>
                        <td>
                          <span className={`status-badge ${ev.detection?.is_anomaly ? 'unhealthy' : 'healthy'}`}>
                            {ev.detection?.tri_model_decision || 'NORMAL'}
                          </span>
                          {ev.detection?.model_disagreement && <span className="demo-disagree-tag"> Disagreement</span>}
                        </td>
                        <td><span className="demo-badge-tag">DEMO ({ev.event_source})</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* 5. Correlated Demo Incidents, Simulated SOAR & XAI Triggers */}
          <div className="soc-cards-grid-2" style={{ marginTop: '14px' }}>
            <div className="demo-subpanel">
              <h3>🚨 Demo Correlated Incidents &amp; MITRE ATT&amp;CK</h3>
              {(demoSession.incidents || []).length === 0 ? (
                <div className="xai-empty-state">No demo incidents correlated yet.</div>
              ) : (
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Incident</th>
                        <th>Source IP</th>
                        <th>Events</th>
                        <th>MITRE Techniques</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(demoSession.incidents || []).slice(0, 10).map((inc) => (
                        <tr key={inc.incident_id}>
                          <td><code>{inc.incident_id}</code><br />{inc.title}</td>
                          <td><code>{(inc.source_ips || []).join(', ')}</code></td>
                          <td>{inc.correlated_events}</td>
                          <td>{(inc.mitre_techniques || []).join(', ') || 'None'}</td>
                          <td><span className="demo-badge-tag">DEMO ({inc.status})</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="demo-subpanel">
              <h3>🛡️ Simulated SOAR Actions &amp; XAI Triggers (DEMO ONLY)</h3>
              {(demoSession.soar_actions || []).length === 0 ? (
                <div className="xai-empty-state">No simulated SOAR actions recorded yet.</div>
              ) : (
                <div className="soc-table-wrap">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Playbook</th>
                        <th>Simulated Decision</th>
                        <th>Target IP</th>
                        <th>Review</th>
                        <th>XAI</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(demoSession.soar_actions || []).slice(0, 10).map((act) => (
                        <tr key={act.action_id}>
                          <td><code>{act.playbook_triggered}</code></td>
                          <td><span className="demo-badge-tag">{act.response_decision}</span></td>
                          <td><code>{act.target_ip}</code></td>
                          <td>{act.manual_review_required ? 'Manual Review' : 'Auto Simulated'}</td>
                          <td>
                            <button
                              className="btn-investigate"
                              onClick={() => {
                                setXaiFlowInput(act.flow_id);
                                setActiveModule('xai_reasoning');
                              }}
                            >
                              XAI →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* 6. Post-Session Ground-Truth Evaluation Summary */}
          {demoSummary && (
            <div className="demo-subpanel demo-summary-panel" style={{ marginTop: '14px' }}>
              <h3>
                📋 Post-Session Synthetic Evaluation Summary{' '}
                {demoSummary.evaluation_status === 'provisional' ? (
                  <span className="demo-badge-tag">PROVISIONAL / INCOMPLETE</span>
                ) : (
                  <span className="status-badge healthy">COMPLETE</span>
                )}
              </h3>
              <p className="soc-meta-line">
                <strong>Notice:</strong> {demoSummary.note} (Session <code>{demoSummary.session_id || 'N/A'}</code> •{' '}
                Generated: <code>{demoSummary.total_generated ?? demoSummary.total_events_generated}</code> •{' '}
                Evaluated: <code>{demoSummary.total_evaluated ?? 0}</code> •{' '}
                Unprocessed: <code>{demoSummary.total_unprocessed ?? 0}</code> •{' '}
                Duplicates: <code>{demoSummary.duplicate_events ?? 0}</code>)
              </p>
              {(() => {
                const tp = demoSummary.true_positives || 0;
                const fp = demoSummary.false_positives || 0;
                const tn = demoSummary.true_negatives || 0;
                const fn = demoSummary.false_negatives || 0;
                const prec = tp + fp > 0 ? tp / (tp + fp) : null;
                const rec = tp + fn > 0 ? tp / (tp + fn) : null;
                const f1 = prec !== null && rec !== null && (prec + rec) > 0 ? (2 * prec * rec) / (prec + rec) : null;
                return (
                  <div className="demo-kpi-grid" style={{ marginTop: '10px' }}>
                    <div className="demo-kpi-card"><div className="demo-kpi-label">Generated / Evaluated</div><div className="demo-kpi-value">{demoSummary.total_generated ?? demoSummary.total_events_generated} / {demoSummary.total_evaluated ?? 0}</div></div>
                    <div className="demo-kpi-card"><div className="demo-kpi-label">Unprocessed / Dupes</div><div className="demo-kpi-value">{demoSummary.total_unprocessed ?? 0} / {demoSummary.duplicate_events ?? 0}</div></div>
                    <div className="demo-kpi-card"><div className="demo-kpi-label">TP / FP / TN / FN</div><div className="demo-kpi-value">{tp} / {fp} / {tn} / {fn}</div></div>
                    <div className="demo-kpi-card"><div className="demo-kpi-label">Precision</div><div className="demo-kpi-value">{prec !== null ? `${(prec * 100).toFixed(1)}%` : 'N/A'}</div></div>
                    <div className="demo-kpi-card"><div className="demo-kpi-label">Recall</div><div className="demo-kpi-value">{rec !== null ? `${(rec * 100).toFixed(1)}%` : 'N/A'}</div></div>
                    <div className="demo-kpi-card"><div className="demo-kpi-label">F1 Score</div><div className="demo-kpi-value">{f1 !== null ? f1.toFixed(3) : 'N/A'}</div></div>
                    <div className="demo-kpi-card"><div className="demo-kpi-label">Incidents / SOAR</div><div className="demo-kpi-value">{demoSummary.incidents_created} / {demoSummary.soar_actions_simulated}</div></div>
                  </div>
                );
              })()}
            </div>
          )}
        </section>
      )}

      {/* Overview Page Tri-Model & PyTorch Autoencoder Summary Strip */}
      {activeModule === 'overview' && triModelOverview && (
        <section className="card soc-module-panel" style={{ marginBottom: '0' }}>
          <div className="soc-panel-header" style={{ marginBottom: '8px' }}>
            <div>
              <h2>🧠 Tri-Model Anomaly Detection Engine (RF + IF + PyTorch Autoencoder v2.0.0)</h2>
              <span className="soc-meta-line">
                <strong>Status:</strong>{' '}
                <span className={`status-badge ${triModelOverview.engine_status === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                  {triModelOverview.engine_status.toUpperCase()}
                </span>{' '}
                • <strong>Fusion Policy:</strong> <code>{selectedPolicy}</code>{' '}
                • <strong>PyTorch AE Threshold:</strong> <code>P97 = {triModelOverview.models_health?.autoencoder?.configured_threshold}</code>{' '}
                • <strong>AE-Only Manual Review Queue:</strong> <code>{manualReviewData.ae_only_items_count ?? 4} AE_ONLY flows (Auto-Block Forbidden)</code>
              </span>
            </div>
            <div className="soc-panel-actions">
              <button className="btn-ai-investigate" onClick={() => setActiveModule('tri_model')}>
                Open Tri-Model & Explainable Detection →
              </button>
              <button className="btn-investigate" onClick={() => setActiveModule('ml_benchmark')}>
                View Synthetic Benchmark (6 Models) →
              </button>
            </div>
          </div>
        </section>
      )}

      {/* ── Modal: Individual Flow Explainable Investigation Dossier ──────── */}
      {inspectedFlowDossier && (
        <div className="modal-overlay" onClick={() => setInspectedFlowDossier(null)}>
          <div className="modal-container forensic-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span className="icon">🔍</span>
                <h3>Explainable Tri-Model Flow Investigation Dossier: <code>{inspectedFlowDossier.flow?.flow_id}</code></h3>
                <span className="engine-badge">{inspectedFlowDossier.benchmark_classification}</span>
              </div>
              <button className="close-btn" onClick={() => setInspectedFlowDossier(null)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="telemetry-banner">
                <div className="telemetry-item">
                  <span className="lbl">Endpoints:</span>
                  <span className="val font-mono">
                    {inspectedFlowDossier.flow?.src_ip}:{inspectedFlowDossier.flow?.src_port} → {inspectedFlowDossier.flow?.dst_ip}:{inspectedFlowDossier.flow?.dst_port} ({inspectedFlowDossier.flow?.protocol})
                  </span>
                </div>
                <div className="telemetry-item">
                  <span className="lbl">Raw 3-Scalar Inputs:</span>
                  <span className="val font-mono">
                    pkts={inspectedFlowDossier.flow?.raw_measurements?.packets}, bytes={inspectedFlowDossier.flow?.raw_measurements?.bytes}, dur={inspectedFlowDossier.flow?.raw_measurements?.duration}s
                  </span>
                </div>
                <div className="telemetry-item">
                  <span className="lbl">Final Decision:</span>
                  <span className="val highlight">{inspectedFlowDossier.flow?.tri_model_decision?.final_decision?.toUpperCase()}</span>
                </div>
                <div className="telemetry-item">
                  <span className="lbl">Recommended Action:</span>
                  <span className="val tag">{inspectedFlowDossier.flow?.tri_model_decision?.recommended_action}</span>
                </div>
                <div className="telemetry-item">
                  <span className="lbl">Auto-Block Permitted:</span>
                  <span className="val">{inspectedFlowDossier.flow?.tri_model_decision?.auto_block_permitted ? 'YES' : 'NO (LOCKED)'}</span>
                </div>
              </div>

              <div className="soc-disclaimer-note">
                {inspectedFlowDossier.explainability_summary?.distinction_note}
              </div>

              <div className="soc-cards-grid-3" style={{ marginBottom: '16px' }}>
                <div className="soc-subcard">
                  <strong>1. Random Forest (Supervised Probability)</strong>
                  <p className="soc-meta-line">Attack Probability: <strong>{(inspectedFlowDossier.flow?.models?.random_forest?.attack_probability * 100).toFixed(2)}%</strong></p>
                  <p className="soc-meta-line">Benign Probability: {(inspectedFlowDossier.flow?.models?.random_forest?.benign_probability * 100).toFixed(2)}%</p>
                  <p className="soc-meta-line">Threshold: <code>{inspectedFlowDossier.flow?.models?.random_forest?.decision_threshold}</code></p>
                </div>
                <div className="soc-subcard">
                  <strong>2. Isolation Forest (Unsupervised Outlier Score)</strong>
                  <p className="soc-meta-line">Raw Decision Score: <strong>{inspectedFlowDossier.flow?.models?.isolation_forest?.raw_decision_score}</strong></p>
                  <p className="soc-meta-line">Normalized Anomaly Index: {inspectedFlowDossier.flow?.models?.isolation_forest?.normalized_anomaly_score}</p>
                  <p className="soc-meta-line">Threshold: <code>&lt; {inspectedFlowDossier.flow?.models?.isolation_forest?.decision_threshold}</code></p>
                </div>
                <div className="soc-subcard">
                  <strong>3. PyTorch Autoencoder (Reconstruction MSE)</strong>
                  <p className="soc-meta-line">Reconstruction Error (MSE): <strong>{inspectedFlowDossier.flow?.models?.autoencoder?.reconstruction_error}</strong></p>
                  <p className="soc-meta-line">Configured Threshold (P97): <code>{inspectedFlowDossier.flow?.models?.autoencoder?.configured_threshold}</code></p>
                  <p className="soc-meta-line">Decision Tier: <strong>{inspectedFlowDossier.flow?.models?.autoencoder?.decision?.toUpperCase()}</strong></p>
                </div>
              </div>

              <h4>Top 5 Contributing Autoencoder Features (Squared Reconstruction Error Breakdown)</h4>
              <div className="threats-table" style={{ marginTop: '8px', marginBottom: '16px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Feature Index</th>
                      <th>Feature Name</th>
                      <th>Squared Error</th>
                      <th>Share of Total Reconstruction Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(inspectedFlowDossier.explainability_summary?.top_contributing_features || []).map(tf => (
                      <tr key={tf.feature_index}>
                        <td><code>#{tf.feature_index}</code></td>
                        <td><code>{tf.feature_name}</code></td>
                        <td><strong>{tf.squared_error}</strong></td>
                        <td><strong>{(tf.error_share * 100).toFixed(2)}%</strong></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <h4>Model Agreement & Decision Rule Explanation</h4>
              <p className="soc-meta-line">
                <strong>Agreement Pattern:</strong> <code>{inspectedFlowDossier.explainability_summary?.agreement_pattern}</code> •{' '}
                <strong>Models Agreeing on Anomaly:</strong> <code>{(inspectedFlowDossier.explainability_summary?.models_agreeing_on_anomaly || []).join(', ') || 'None'}</code> •{' '}
                <strong>Decision Rule:</strong> <code>{inspectedFlowDossier.explainability_summary?.decision_rule}</code>
              </p>
              <p className="soc-meta-line">
                <strong>Safety Rationale:</strong> {inspectedFlowDossier.explainability_summary?.safety_rationale}
              </p>
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setInspectedFlowDossier(null)}>Close Dossier</button>
            </div>
          </div>
        </div>
      )}

      {/* Key Metrics */}
      <section className="metrics-section">
        <div className="metric-card high">
          <div className="metric-value">{stats.high_threats}</div>
          <div className="metric-label">High Threats</div>
          <div className="metric-icon">🔴</div>
        </div>
        <div className="metric-card medium">
          <div className="metric-value">{stats.medium_threats}</div>
          <div className="metric-label">Medium Threats</div>
          <div className="metric-icon">🟠</div>
        </div>
        <div className="metric-card low">
          <div className="metric-value">{stats.low_threats}</div>
          <div className="metric-label">Low Threats</div>
          <div className="metric-icon">🟡</div>
        </div>
        <div className="metric-card">
          <div className="metric-value">{stats.total_events}</div>
          <div className="metric-label">Total Events</div>
          <div className="metric-icon">📊</div>
        </div>
        <div className="metric-card">
          <div className="metric-value">{stats.blocked_ips}</div>
          <div className="metric-label">Blocked IPs</div>
          <div className="metric-icon">🚫</div>
        </div>
        <div className="metric-card">
          <div className="metric-value">{stats.alerts_sent}</div>
          <div className="metric-label">Alerts Sent</div>
          <div className="metric-icon">🔔</div>
        </div>
      </section>

      {/* Main Content Grid */}
      <div className="dashboard-grid">
        {/* Services Health */}
        <section className="card services-card">
          <h2>Service Health</h2>
          <div className="services-list">
            {Object.entries(services).map(([name, data]) => (
              <div key={name} className={`service-item ${getStatusColor(data.status)}`}>
                <span className="service-label">{name.replace(/_/g, ' ')}</span>
                <span className={`status-badge ${data.status}`}>
                  {data.status === 'healthy' ? '✓' : '✗'} {data.status}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* ML Models Status */}
        <section className="card models-card">
          <h2>ML Models</h2>
          <div className="models-list">
            {Object.entries(models).map(([name, data]) => (
              <div key={name} className="model-item">
                <div className="model-name">{name.replace(/_/g, ' ')}</div>
                <div className="model-status">
                  <span className="status-badge trained">✓ {data.status}</span>
                  <span className="model-size">{data.size}</span>
                </div>
                <div className="model-details">
                  Trained on {data.samples_trained} samples
                </div>
              </div>
            ))}
            {/* Gemini Copilot Card */}
            <div className="model-item gemini-model-item">
              <div className="model-name">✨ Gemini AI SOC Analyst</div>
              <div className="model-status">
                <span className={`status-badge ${geminiStatus.configured ? 'trained' : 'demo'}`}>
                  {geminiStatus.configured ? '✓ Live Active' : '● Ready / Demo'}
                </span>
                <span className="model-size">gemini-3.8-flash</span>
              </div>
              <div className="model-details">
                Forensics, ATT&CK mapping, & Auto-Mitigation
              </div>
            </div>
          </div>
        </section>

        {/* Traffic Analysis */}
        <section className="card traffic-card">
          <h2>Network Traffic</h2>
          <div className="traffic-stats">
            <div className="traffic-stat">
              <span className="label">Total Flows</span>
              <span className="value">{traffic.total_flows || 0}</span>
            </div>
            <div className="traffic-stat">
              <span className="label">Avg Duration</span>
              <span className="value">{(traffic.avg_duration || 0).toFixed(2)}s</span>
            </div>
            <div className="traffic-stat">
              <span className="label">Avg Bytes</span>
              <span className="value">{(traffic.avg_bytes_sent || 0).toLocaleString()}</span>
            </div>
          </div>
          <div className="protocols">
            <h3>By Protocol</h3>
            {traffic.by_protocol && Object.entries(traffic.by_protocol).map(([proto, count]) => (
              <div key={proto} className="protocol-item">
                <span>{proto.toUpperCase()}</span>
                <span className="count">{count}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Recent Threats Table with AI Forensic Action */}
      <section className="card threats-card">
        <div className="threats-card-header">
          <h2>Recent Threat Events (Last 50)</h2>
          <div className="gemini-hint-badge">
            ✨ Click <strong>🤖 AI Investigate</strong> on any event for Level-3 Gemini Forensics
          </div>
        </div>

        <div className="threats-table">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Type of Attack</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Action</th>
                <th>Status</th>
                <th>AI Forensics</th>
              </tr>
            </thead>
            <tbody>
              {threats.length === 0 ? (
                <tr><td colSpan="9" className="empty">No threat events recorded</td></tr>
              ) : (
                threats.map((threat, idx) => (
                  <tr key={idx} className={getSeverityClass(threat)}>
                    <td>{new Date(threat.timestamp).toLocaleTimeString()}</td>
                    <td className="ip font-mono">{threat.src_ip || 'N/A'}</td>
                    <td className="ip font-mono">{threat.dst_ip || 'N/A'}</td>
                    <td><span className="attack-type">{formatAttackType(threat)}</span></td>
                    <td className="action">{threat.severity || threat.details?.severity || 'N/A'}</td>
                    <td className="confidence">{(threat.confidence || 0).toFixed(2)}</td>
                    <td className="action">{threat.action || 'N/A'}</td>
                    <td className="status">
                      {threat.action === 'block' ? '🚫' : threat.action === 'alert' ? '🔔' : '👁️'}
                    </td>
                    <td>
                      <button
                        className="btn-ai-investigate"
                        onClick={() => handleInvestigateThreat(threat)}
                      >
                        🤖 AI Investigate
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── Modal: AI Forensic Investigation ─────────────────────────────── */}
      {isInvestigating && (
        <div className="modal-overlay" onClick={() => setIsInvestigating(false)}>
          <div className="modal-container forensic-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span className="icon">🛡️</span>
                <h3>Gemini Forensic Incident Investigation</h3>
                <span className="engine-badge">Powered by gemini-3.8-flash</span>
              </div>
              <button className="close-btn" onClick={() => setIsInvestigating(false)}>✕</button>
            </div>

            <div className="modal-body">
              {investigatingThreat && (
                <div className="telemetry-banner">
                  <div className="telemetry-item">
                    <span className="lbl">Targeted Attack:</span>
                    <span className="val highlight">{formatAttackType(investigatingThreat)}</span>
                  </div>
                  <div className="telemetry-item">
                    <span className="lbl">Source IP:</span>
                    <span className="val font-mono">{investigatingThreat.src_ip || 'N/A'}</span>
                  </div>
                  <div className="telemetry-item">
                    <span className="lbl">Target IP:</span>
                    <span className="val font-mono">{investigatingThreat.dst_ip || 'N/A'}</span>
                  </div>
                  <div className="telemetry-item">
                    <span className="lbl">ML Confidence:</span>
                    <span className="val">{((investigatingThreat.confidence || 0) * 100).toFixed(1)}%</span>
                  </div>
                  <div className="telemetry-item">
                    <span className="lbl">Response Action:</span>
                    <span className="val tag">{investigatingThreat.action || 'block'}</span>
                  </div>
                </div>
              )}

              {investigationLoading && (
                <div className="loading-state">
                  <div className="spinner"></div>
                  <p>Consulting Google Gemini 3.8 Flash for threat forensics, MITRE ATT&CK mapping, and containment playbooks...</p>
                </div>
              )}

              {!investigationLoading && investigationResult && (
                <div className="forensic-content">
                  {investigationResult.isSimulation && (
                    <div className="sim-notice">
                      💡 <strong>Simulation Engine active.</strong> To activate real-time Live Gemini 3.8 Flash analysis, click the <em>Gemini AI</em> button in the header and provide your API key.
                    </div>
                  )}

                  {/* Summary & Threat Actor */}
                  <div className="forensic-section">
                    <h4>📋 Executive Incident Summary</h4>
                    <p className="summary-text">{investigationResult.summary}</p>
                    {investigationResult.threatActorProfile && (
                      <div className="actor-profile">
                        <strong>Identified Signature / Profile:</strong> {investigationResult.threatActorProfile}
                      </div>
                    )}
                  </div>

                  {/* MITRE ATT&CK Mapping */}
                  {investigationResult.mitreAttack && investigationResult.mitreAttack.length > 0 && (
                    <div className="forensic-section">
                      <h4>🎯 MITRE ATT&CK Framework Mapping</h4>
                      <div className="mitre-cards">
                        {investigationResult.mitreAttack.map((m, i) => (
                          <div key={i} className="mitre-card">
                            <span className="mitre-id">{m.techniqueId}</span>
                            <span className="mitre-name">{m.techniqueName}</span>
                            <span className="mitre-tactic">{m.tactic}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Telemetry Diagnostics */}
                  {investigationResult.telemetryAnalysis && (
                    <div className="forensic-section">
                      <h4>📊 Network Flow Telemetry Diagnostics</h4>
                      <div className="diag-grid">
                        <div className="diag-box">
                          <span className="diag-title">Packet Velocity</span>
                          <span>{investigationResult.telemetryAnalysis.packetRate}</span>
                        </div>
                        <div className="diag-box">
                          <span className="diag-title">Byte Payload</span>
                          <span>{investigationResult.telemetryAnalysis.byteVolume}</span>
                        </div>
                      </div>
                      {investigationResult.telemetryAnalysis.anomalyIndicators && (
                        <ul className="anomaly-list">
                          {investigationResult.telemetryAnalysis.anomalyIndicators.map((item, idx) => (
                            <li key={idx}>{item}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}

                  {/* Containment Playbook Commands */}
                  {investigationResult.containmentPlaybook && (
                    <div className="forensic-section">
                      <h4>⚡ Automated Incident Containment Playbook</h4>
                      <div className="playbook-list">
                        {investigationResult.containmentPlaybook.map((step, idx) => (
                          <div key={idx} className="playbook-item">
                            <div className="playbook-header">
                              <span className="playbook-num">{idx + 1}</span>
                              <span className="playbook-act">{step.action}</span>
                              <span className="playbook-desc">{step.description}</span>
                            </div>
                            <div className="command-bar">
                              <code>{step.command}</code>
                              <button
                                className="copy-btn"
                                onClick={() => copyToClipboard(step.command, idx)}
                              >
                                {copiedIndex === idx ? '✓ Copied' : '📋 Copy'}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Analyst Checklist & Blast Radius */}
                  <div className="forensic-grid">
                    {investigationResult.blastRadius && (
                      <div className="forensic-section">
                        <h4>💥 Blast Radius Assessment</h4>
                        <p>{investigationResult.blastRadius}</p>
                      </div>
                    )}

                    {investigationResult.analystChecklist && (
                      <div className="forensic-section">
                        <h4>✅ SOC Analyst Investigation Checklist</h4>
                        <ul className="checklist">
                          {investigationResult.analystChecklist.map((check, i) => (
                            <li key={i}>{check}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button
                className="btn-chat-link"
                onClick={() => sendThreatToCopilot(investigatingThreat, investigationResult)}
              >
                💬 Ask Copilot About This Threat
              </button>
              <button className="btn-secondary" onClick={() => setIsInvestigating(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Drawer: Interactive Gemini SOC Copilot ────────────────────────── */}
      {isCopilotOpen && (
        <div className="copilot-drawer">
          <div className="copilot-header">
            <div className="copilot-title">
              <span className="sparkle">🤖</span>
              <div>
                <h3>Gemini SOC Copilot</h3>
                <span className="copilot-sub">Model: gemini-3.8-flash | Real-Time Telemetry Grounded</span>
              </div>
            </div>
            <button className="close-btn" onClick={() => setIsCopilotOpen(false)}>✕</button>
          </div>

          {/* Quick Action Chips */}
          <div className="copilot-chips">
            <button onClick={() => handleSendChatMessage('Explain the latest high-threat attack detected.')}>
              🚨 Latest Attack
            </button>
            <button onClick={() => handleSendChatMessage('Generate an iptables containment ruleset for active hostile IPs.')}>
              🛡️ Firewall Rules
            </button>
            <button onClick={() => handleSendChatMessage('Assess the overall threat blast radius and active vectors.')}>
              📊 Blast Radius
            </button>
            <button onClick={() => handleSendChatMessage('What MITRE ATT&CK techniques should we prioritize defending against right now?')}>
              🎯 MITRE Tactics
            </button>
          </div>

          {/* Messages */}
          <div className="copilot-messages">
            {chatMessages.map((msg, index) => (
              <div key={index} className={`chat-message ${msg.role}`}>
                <div className="message-header">
                  <span className="sender">{msg.role === 'user' ? 'Operator' : '✨ Gemini Copilot'}</span>
                  <span className="time">{msg.timestamp}</span>
                </div>
                <div
                  className="message-body"
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }}
                />
              </div>
            ))}
            {isChatSending && (
              <div className="chat-message assistant typing">
                <div className="spinner-dots">
                  <span></span><span></span><span></span>
                </div>
                <em>Gemini 3.8 Flash is analyzing telemetry...</em>
              </div>
            )}
            <div ref={chatMessagesEndRef} />
          </div>

          {/* Input */}
          <form
            className="copilot-input-area"
            onSubmit={(e) => {
              e.preventDefault();
              handleSendChatMessage();
            }}
          >
            <input
              type="text"
              placeholder="Ask Gemini SOC Copilot about threats, IPs, mitigations..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              disabled={isChatSending}
            />
            <button type="submit" disabled={isChatSending || !chatInput.trim()}>
              Send
            </button>
          </form>
        </div>
      )}

      {/* Floating Copilot Toggle Button */}
      <button
        className="floating-copilot-btn"
        onClick={() => setIsCopilotOpen(!isCopilotOpen)}
        title="Open Gemini SOC Copilot"
      >
        <span className="icon">🤖</span>
        <span className="label">Gemini Copilot</span>
      </button>

      {/* ── Modal: CISO Executive Threat Briefing ─────────────────────────── */}
      {isBriefingOpen && (
        <div className="modal-overlay" onClick={() => setIsBriefingOpen(false)}>
          <div className="modal-container briefing-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span className="icon">📑</span>
                <h3>CISO Executive Threat Briefing</h3>
                <span className="engine-badge">Generated by Gemini 3.8 Flash</span>
              </div>
              <button className="close-btn" onClick={() => setIsBriefingOpen(false)}>✕</button>
            </div>

            <div className="modal-body">
              {briefingLoading && (
                <div className="loading-state">
                  <div className="spinner"></div>
                  <p>Synthesizing telemetry, risk exposure, and incident trends with Gemini 3.8 Flash...</p>
                </div>
              )}

              {!briefingLoading && briefingData && (
                <div className="briefing-content">
                  <div className="posture-card">
                    <span className="posture-label">Perimeter Threat Posture:</span>
                    <span className="posture-value">{briefingData.threatPosture || 'GUARDED'}</span>
                  </div>

                  <div className="briefing-section">
                    <h4>Executive Summary</h4>
                    <p className="summary-text">{briefingData.executiveSummary}</p>
                  </div>

                  {briefingData.topThreatVectors && briefingData.topThreatVectors.length > 0 && (
                    <div className="briefing-section">
                      <h4>Active Attack Vectors</h4>
                      <table className="briefing-table">
                        <thead>
                          <tr>
                            <th>Attack Vector</th>
                            <th>Occurrences</th>
                            <th>Risk Tier</th>
                          </tr>
                        </thead>
                        <tbody>
                          {briefingData.topThreatVectors.map((v, i) => (
                            <tr key={i}>
                              <td>{v.vector}</td>
                              <td>{v.count}</td>
                              <td><span className={`risk-tag ${String(v.risk).toLowerCase()}`}>{v.risk}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {briefingData.strategicRecommendations && (
                    <div className="briefing-section">
                      <h4>Strategic Security Recommendations</h4>
                      <ul className="rec-list">
                        {briefingData.strategicRecommendations.map((rec, i) => (
                          <li key={i}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button
                className="btn-primary"
                onClick={() => {
                  const blob = new Blob([JSON.stringify(briefingData, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `CISO-Briefing-${Date.now()}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                📥 Download JSON
              </button>
              <button className="btn-secondary" onClick={() => setIsBriefingOpen(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Modal: Gemini API Settings ────────────────────────────────────── */}
      {isSettingsOpen && (
        <div className="modal-overlay" onClick={() => setIsSettingsOpen(false)}>
          <div className="modal-container settings-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span className="icon">⚙️</span>
                <h3>Google Gemini API Configuration</h3>
              </div>
              <button className="close-btn" onClick={() => setIsSettingsOpen(false)}>✕</button>
            </div>

            <div className="modal-body">
              <div className="gemini-info-box">
                <p>
                  ShadowGuard uses <strong>Google Gemini 3.8 Flash (<code>gemini-3.8-flash</code>)</strong> for real-time Level-3 threat forensics, autonomous incident containment playbooks, and interactive SOC assistant reasoning.
                </p>
                <div className="status-indicator-box">
                  <span>Current Status:</span>
                  <strong className={geminiStatus.configured ? 'text-success' : 'text-warning'}>
                    {geminiStatus.configured ? '● Live API Connected' : '○ Demo Mode (Simulation Active)'}
                  </strong>
                </div>
              </div>

              <div className="input-group">
                <label>Gemini API Key:</label>
                <input
                  type="password"
                  placeholder="AIzaSy..."
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                />
                <span className="help-text">
                  Get a free Gemini API key from <a href="https://aistudio.google.com/" target="_blank" rel="noreferrer">Google AI Studio</a>.
                </span>
              </div>

              {apiSaveStatus && <div className="api-status-msg">{apiSaveStatus}</div>}
            </div>

            <div className="modal-footer">
              <button className="btn-primary" onClick={saveGeminiKey}>
                Save & Apply Key
              </button>
              <button className="btn-secondary" onClick={() => setIsSettingsOpen(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="footer">
        <p>Shadow Guard - Real-time Threat Detection & Response System • Powered by Google Gemini AI</p>
        <p>Last updated: {new Date().toLocaleTimeString()}</p>
      </footer>
    </div>
  );
}

// Render when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    const root = ReactDOM.createRoot(document.getElementById('root'));
    root.render(React.createElement(Dashboard));
  });
} else {
  const root = ReactDOM.createRoot(document.getElementById('root'));
  root.render(React.createElement(Dashboard));
}
