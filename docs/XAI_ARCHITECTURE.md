# Shadow Guard 2.0 — Complete System & XAI Architecture

## 1. End-to-End Architectural Planes (Detection vs. Explanation vs. Correlation vs. Response)

Shadow Guard 2.0 enforces a strict separation of concerns across four operational planes so that **Explanation** never alters **Detection** or **SOAR Response**:

```mermaid
flowchart LR
  subgraph Detection["1. Detection Plane (Read-Only Targets)"]
    SUR["Suricata NIDS\n(EVE JSON)"]
    HP["Honeypots\n(Cowrie, OpenCanary, Dionaea)\nin sg_deception_dmz"]
    ML["ml-detection-service (:8001)\nRF + IF + PyTorch AE (P97=0.503670)\nweighted_consensus"]
  end

  subgraph Correlation["2. Intelligence & Correlation Plane"]
    TI["Threat Intel\n(IOC Cache)"]
    AP["Attacker Profiling\n(5-Factor Risk 0-100)"]
    EC["Event Correlation\n(CORR-01..06, 15m Window)"]
    AC["MITRE ATT&CK\nKill-Chain Builder"]
  end

  subgraph Response["3. Safety-Gated SOAR Plane"]
    DEC["Deception Manager\n(DEC-01..04)"]
    PDE["Playbook Engine\n(PB-SOAR-01..05)\nAE_ONLY Never Auto-Blocks"]
    ARS["Automated Response\n(Timed Leases, Allowlist, Rollback)"]
  end

  subgraph Explanation["4. Read-Only XAI Plane (Stages 1-4)"]
    XAI_CORE["xai_explainer.py\nTreeSHAP | IF Perturb | AE MSE"]
    XAI_UNI["unified_xai_engine.py\nUnifiedTriModelExplainer"]
    XAI_GW["threat-dashboard-service (:7000)\n/api/v2/xai/* (JWT/RBAC + Audit)"]
    XAI_DB["PostgreSQL 15\n004_xai_explanations.sql"]
    XAI_UI["React SOC Dashboard\nModule 11: XAI & Threat Reasoning"]
  end

  SUR & HP & ML -->|"RabbitMQ shadowguard.events"| Correlation --> Response
  ML -.->|"Read-Only Model Artifacts & Scores"| XAI_CORE --> XAI_UNI --> XAI_GW
  XAI_GW --> XAI_DB
  XAI_GW --> XAI_UI
```

## 2. Component Inventory & Data Flow
1. **React/JavaScript SOC Dashboard (`threat-dashboard-service/public/app.js`, `:7000`)**: 11 modules (Modules 1–10 core/tri-model/benchmark + **Module 11: Explainable AI & Threat Reasoning**), sending `X-SOC-Role` / `Authorization: Bearer <JWT>` headers.
2. **Node.js/Express API Gateway (`server.js`)**: Enforces JWT/API-Key/RBAC (`VIEWER`, `SOC_ANALYST`, `ADMIN`), role-based IP sanitization, timeouts (`8000 ms`), Prometheus `/metrics`, and `securityAuditLog`.
3. **PostgreSQL 15 (`001`–`004` migrations)**: 18 total tables (`threat_logs` + 17 v2 core tables + `xai_explanations` with JSONB columns, B-Tree/GIN indexes, and `uq_xai_flow_policy_signature`).
4. **Python ML & XAI Service (`ml-detection-service/main.py`)**: Serves `/detect`, `/detect/autoencoder`, `/detect/tri-model`, `/xai/health`, `/xai/explain`, and `/xai/explain/batch` over shared frozen artifacts (`random_forest_69_v2.pkl`, `isolation_forest_69_v2.pkl`, `autoencoder_model.pt`, `autoencoder_preprocessor.pkl`).
5. **Deception, Correlation & SOAR Microservices**: Suricata NIDS, Cowrie (zero-password retention), OpenCanary, Dionaea (`noexec` quarantine), Threat Intel, 5-factor Attacker Profiling, `CORR-01..06` correlation, MITRE ATT&CK kill chains, `DEC-01..04` adaptive deception, and `PB-SOAR-01..05` playbooks with timed leases and `AE_ONLY` non-auto-block guardrails.
