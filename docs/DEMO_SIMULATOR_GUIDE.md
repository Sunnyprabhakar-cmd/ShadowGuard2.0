# Shadow Guard 2.0 — Demo Traffic Simulator Architecture & Operations Guide

## 1. Overview & Purpose

The **Demo Traffic Simulator (Module 12)** enables live, interactive SOC demonstrations without physical network hardware or external attack infrastructure. Unlike the legacy `auto_demo.py` loop that automatically generated traffic on container startup, the refactored simulator starts strictly in **`Idle`** mode and only emits synthetic flows when explicitly triggered by an authorized operator (`SOC_ANALYST` or `ADMIN`) from the SOC Dashboard or Control API.

---

## 2. End-to-End Pipeline Architecture

```text
SOC Dashboard (Module 12: Demo Traffic Simulator)
  │  POST /api/v2/demo-simulator/{start,pause,resume,stop,reset}
  ▼
Dashboard Backend Gateway (threat-dashboard-service:7000)
  │  Proxies controls to port 8010 + polls/streams via WebSocket (ws://)
  ▼
Demo Traffic Simulator Service (auto_demo.py:8010)
  │  Generates synthetic flows with flow_id, session_id, event_source="demo_simulator"
  │  (ground_truth isolated locally; NEVER sent to ML inference)
  ▼
Traffic Capture Service (traffic-capture-service:3000/capture)
  ├─▶ RabbitMQ Topic Exchange (sg.events / event.network.raw) [Event Contract v2.0]
  └─▶ Flow Feature Extraction (flow-feature-extraction-service:3000/extract -> 69 features)
        └─▶ ML Detection Service (ml-detection-service:8000/detect & /xai/explain)
              ├─▶ Random Forest (probability)
              ├─▶ Isolation Forest (raw anomaly score)
              ├─▶ PyTorch Autoencoder (MSE reconstruction error, P97 = 0.503670)
              └─▶ Tri-Model Fusion + XAI Explanation
                    └─▶ Threat Classification → Playbook Decision Engine → Alert Suppression → Simulated SOAR → Threat Log DB
```

### Component Responsibilities
| Component | Responsibility |
|---|---|
| `auto_demo.py` (`demo-traffic-generator:8010`) | Thread-safe `DemoTrafficSimulator` HTTP control server starting in `Idle`. Generates varied synthetic flows for 10 scenarios and tracks isolated `ground_truth`. |
| `traffic-capture-service` | Strips any `ground_truth`, constructs Common Event Contract v2.0 (`event.network.raw`), publishes to RabbitMQ, and forwards to feature extraction. |
| `flow-feature-extraction-service` | Computes the canonical 69-feature vector while preserving `flow_id`, `src_port`, `dst_port`, `event_source`, and `session_id` in context. |
| `ml-detection-service` | Runs Random Forest, Isolation Forest, PyTorch Autoencoder, Tri-Model Fusion, and Stage 1/2 XAI (`POST /xai/explain`). Explicitly strips `ground_truth`. |
| `playbook-decision-engine` | Applies strict `event_source === 'demo_simulator'` check, sets `demo_simulated: true` and `auto_block_permitted: false`. |
| `alert-notification-service` | Suppresses external email (`nodemailer`) and external Gemini calls when `event_source === 'demo_simulator'`. |
| `automated-response-service` | Never invokes `iptablesExecutor` or modifies live `activeBlocks` for demo events; records into `demoSimulatedBlocks` and `DEMO_ACTION_SIMULATED` audit entries. |
| `threat-log-database-service` | Persists logs with `flow_id`, `src_port`, `dst_port`, `event_source`, `session_id`, and `demo_simulated`, supporting `?event_source=demo_simulator\|live`. |
| `threat-dashboard-service` | Exposes RBAC-protected `/api/v2/demo-simulator/*` endpoints, `DemoSimulatorStore` session analytics, Demo/Live/All filtering, and WebSocket broadcasts (`demo_simulator_state`, `demo_simulator_event`). |

---

## 3. Supported Scenarios & Modes

| # | Scenario Key | Description | `flow_type` |
|---|---|---|---|
| 1 | `normal_traffic` | Benign TCP/UDP web, DNS, and cloud sync flows | `normal` |
| 2 | `port_scan` | Rapid small-packet TCP probes across target ports | `anomaly` |
| 3 | `ssh_brute_force` | Repeated short TCP/22 login attempts (`brute_force`) | `anomaly` |
| 4 | `service_enumeration` | Multi-port service banner/discovery probes | `anomaly` |
| 5 | `ddos` | High-packet, high-byte UDP/TCP flood waves | `anomaly` |
| 6 | `data_exfiltration` | Large outbound byte transfers over TCP | `anomaly` |
| 7 | `c2_beaconing` | Periodic command-and-control beacons (`malware_command_control`) | `anomaly` |
| 8 | `multi_vector` | Combined scan, flood, brute-force, and exfiltration flows | `anomaly` |
| 9 | `stealth_anomaly` | Low-and-slow / anomalous zero-day-like traffic (`zero_day`) | `anomaly` |
| 10 | `mixed` | ~35% normal traffic + ~65% distributed malicious scenarios | `normal` + `anomaly` |

- **Modes**: `single` (selected scenario only) or `mixed` (normal + malicious blend).
- **Speeds**: `low` (~1 ev/sec), `medium` (~2.5 ev/sec), `high` (~8 ev/sec).
- **Duration**: `null` (run until manually stopped) or `1..86400` seconds (auto-transitions to `Completed`).

---

## 4. Control & Dashboard API Reference

### Dashboard Gateway Endpoints (`threat-dashboard-service:7000`)
- `GET /api/v2/demo-simulator/status` (`VIEWER`+) — Current simulator state (`Idle | Running | Paused | Stopped | Completed`) and session snapshot.
- `GET /api/v2/demo-simulator/events?session_id=&limit=100` (`VIEWER`+) — Session-scoped enriched events (`404` if unknown `session_id`).
- `GET /api/v2/demo-simulator/summary?session_id=` (`VIEWER`+) — Post-session synthetic evaluation summary (`TP`, `FP`, `TN`, `FN`, incidents, simulated SOAR, XAI triggers).
- `POST /api/v2/demo-simulator/start` (`SOC_ANALYST`+)
  - Request: `{"scenario":"mixed","mode":"mixed","speed":"high","duration_seconds":30}`
  - Response (`200`): `{"status":"success","message":"Demo simulation started","data":{"state":"Running","session_id":"demo-sess-...","events_per_sec":8}}`
  - Duplicate start while `Running`/`Paused`: `409 Conflict` (`ALREADY_RUNNING`).
- `POST /api/v2/demo-simulator/pause` (`SOC_ANALYST`+)
- `POST /api/v2/demo-simulator/resume` (`SOC_ANALYST`+)
- `POST /api/v2/demo-simulator/stop` (`SOC_ANALYST`+)
- `POST /api/v2/demo-simulator/reset` (`SOC_ANALYST`+)
- `GET /api/threats?source=live|demo|all` & `GET /api/statistics?source=live|demo|all` — Source-filtered telemetry (defaults to `live`).

### WebSocket Events (`ws://127.0.0.1:7000`)
- `demo_simulator_state`: `{ type: "demo_simulator_state", data: <simStatus>, session: <sessionSnapshot> }`
- `demo_simulator_event`: `{ type: "demo_simulator_event", event_source: "demo_simulator", session_id, data: <enrichedEvent>, session: <sessionSnapshot> }`

---

## 5. Safety, Ground-Truth Isolation & RBAC

1. **Ground-Truth Isolation**: `auto_demo.py` strips `ground_truth` from `capture_payload`. `traffic-capture-service`, `ml-detection-service`, and `threat-classification-service` also explicitly strip `ground_truth` if ever supplied. `ground_truth` is used **only** for post-session evaluation (`/summary`).
2. **Demo SOAR Safety**: Server-side guards check `event_source === 'demo_simulator'` strictly. Missing or unknown `event_source` is treated as live (preserving production SOAR behavior). Demo events never execute `iptables`, never modify live `activeBlocks`, and suppress external emails.
3. **RBAC**: `VIEWER` can inspect status, events, and summaries (`403` on control mutations); `SOC_ANALYST` and `ADMIN` can Start/Pause/Resume/Stop/Reset.

---

## 6. Using Module 12 in the SOC Dashboard

1. Open `http://127.0.0.1:7000/` and confirm **`● Live Mesh`** in the header.
2. Select **`12. Demo Traffic Simulator`** in the navigation bar.
3. Choose a **Scenario**, **Mode**, **Simulation Speed**, and **Duration**, then click **`▶ Start Demo Simulation`**.
4. Observe live WebSocket updates across KPI cards, **Attack Category Distribution**, **Live Demo Event Stream & Tri-Model Detection Results** (with RF probability, IF anomaly score, and AE reconstruction error kept distinct), **Demo Correlated Incidents & MITRE ATT&CK**, and **Simulated SOAR Actions & XAI Triggers**.
5. Click **`⏹ Stop Simulation`** to review the **Post-Session Synthetic Evaluation Summary** (`TP / FP / TN / FN`, `Precision`, `Recall`, `F1 Score`), then **`🔄 Reset Demo Session`** to return cleanly to `Idle`.

---

## 7. Verification Commands & Known Limitations

- **Demo Simulator Suites**:
  - `node scripts/verify_demo_simulator_stage1.js` (`4 passed, 0 failed`)
  - `node scripts/verify_demo_simulator_stage2.js` (`3 passed, 0 failed`)
  - `node scripts/verify_demo_simulator_stage3.js` (`7 passed, 0 failed`)
  - `node scripts/verify_demo_simulator_stage4.js` (`8 passed, 0 failed`)
- **Master Verification Suite**: `node scripts/run_all_verifications.js`

### Known Limitations
- **In-memory session storage**: `DemoSimulatorStore` retains session analytics in memory (capped at **500 events per session**); resetting or restarting `threat-dashboard-service` clears in-memory demo sessions.
- **Synthetic dataset vs. real-world generalization**: Synthetic flows are generated to exercise the 69-feature pipeline and tri-model engine for live demonstration. Post-session `TP/FP/FN` metrics reflect synthetic demo evaluation only (for example, small-packet `port_scan` or `service_enumeration` flows can overlap with normal flows in the frozen 69-feature space) and must not be interpreted as real-world production IDS accuracy.
