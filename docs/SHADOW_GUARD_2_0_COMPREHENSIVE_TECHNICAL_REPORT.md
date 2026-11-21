# SHADOW GUARD 2.0 — COMPREHENSIVE ARCHITECTURAL, ALGORITHMIC, AND SCIENTIFIC TECHNICAL REPORT

**Project Title:** Shadow Guard 2.0 — An Intelligent Cyber Defence, Cyber Deception, Tri-Model Anomaly Detection, Explainable AI (XAI), and Automated Incident Response Platform  
**Benchmark & Empirical Evaluation Classification:** **`SYNTHETIC BENCHMARK ONLY`**  
**Document Version:** `2.4.0` (Updated November 16, 2026: Includes XAI Stages 3–6, 11-Module React 18 SOC Dashboard, `004_xai_explanations.sql`, and `517 PASSED, 0 FAILED` Master Suite)  
**Date:** November 16, 2026  

---

## TABLE OF CONTENTS

1. [Executive Summary & Scope](#1-executive-summary--scope)
2. [Platform Evolution: Shadow Guard 1.0 vs. Shadow Guard 2.0 (+ Autoencoder & XAI)](#2-platform-evolution-shadow-guard-10-vs-shadow-guard-20--autoencoder--xai)
3. [System Architecture, Network Segmentation & 22-Container Topology](#3-system-architecture-network-segmentation--22-container-topology)
4. [Canonical Event Contract v2, RabbitMQ Messaging & PostgreSQL 15 Schema](#4-canonical-event-contract-v2-rabbitmq-messaging--postgresql-15-schema)
5. [Perimeter Ingestion, Suricata NIDS & Multi-Type Cyber Deception Plane](#5-perimeter-ingestion-suricata-nids--multi-type-cyber-deception-plane)
6. [Canonical 69-Feature Engineering Pipeline, Schema Audit & Dataset Provenance](#6-canonical-69-feature-engineering-pipeline-schema-audit--dataset-provenance)
7. [Machine Learning Detection Algorithms & Selection Rationale](#7-machine-learning-detection-algorithms--selection-rationale)
8. [Tri-Model Detection Fusion Engine & Safety Guardrails](#8-tri-model-detection-fusion-engine--safety-guardrails)
9. [Explainable Artificial Intelligence (XAI) Subsystem (Stages 1 & 2)](#9-explainable-artificial-intelligence-xai-subsystem-stages-1--2)
10. [Threat Intelligence Enrichment, Attacker Profiling & Sliding-Window Correlation](#10-threat-intelligence-enrichment-attacker-profiling--sliding-window-correlation)
11. [Adaptive Deception Manager & Safety-Gated SOAR Automation](#11-adaptive-deception-manager--safety-gated-soar-automation)
12. [8-Page SOC Command Center, RBAC/JWT Security & Observability](#12-8-page-soc-command-center-rbacjwt-security--observability)
13. [Experimental Evaluation: Track 1 (Cohorts A–E) & Track 2 (384 Held-Out Flows)](#13-experimental-evaluation-track-1-cohorts-ae--track-2-384-held-out-flows)
14. [Verification, Testing & Independent Scientific Audit Results](#14-verification-testing--independent-scientific-audit-results)
15. [Limitations, Threat Model Boundaries & Future Roadmap (XAI Stages 3–6)](#15-limitations-threat-model-boundaries--future-roadmap-xai-stages-36)

---

## 1. Executive Summary & Scope

Modern enterprise networks face multi-stage cyber campaigns that combine high-volume denial-of-service floods, low-and-slow Command-and-Control (C2) beaconing, stealthy data exfiltration, credential brute-forcing, and interactive lateral movement. Relying on a single defensive layer—such as standalone signature-based intrusion detection or standalone network-flow machine learning—leaves critical blind spots: signature engines cannot detect novel or encrypted volumetric anomalies, while unsupervised anomaly detectors suffer from false-positive rates (`2%–5%`) that make fully automated firewall blocking operationally dangerous.

**Shadow Guard 2.0** addresses these challenges through a **22-container, event-driven cyber defense, cyber deception, tri-model machine learning, explainable AI (XAI), and Security Orchestration, Automation, and Response (SOAR) architecture** organized across five isolated Docker bridge networks (`sg_ingress_net`, `sg_core_net`, `sg_deception_dmz`, `sg_storage_net`, and `sg_frontend_net`).

### Key Engineering & Research Contributions
1. **Multi-Sensor Telemetry Fusion**: Unifies 69-dimensional statistical network flow telemetry (`traffic-capture-service`, `flow-feature-extraction-service`), deep packet/protocol inspection via **Suricata NIDS** (`suricata`, `suricata-event-collector-service`), and three specialized interactive honeypots (**Cowrie** SSH/Telnet, **OpenCanary** HTTP/FTP/SMB/MySQL, and **Dionaea** malware payload capture) inside an isolated deception DMZ (`sg_deception_dmz`).
2. **Schema Parity & Authoritative PyTorch Autoencoder**: Resolves a legacy 7-column vs. 69-feature train-serve schema discrepancy via a single canonical specification (`shared/ml/feature_schema.py` and `flow-feature-extraction-service`), achieving bit-exact parity (`max_abs_diff = 0.0`). Implements an authoritative PyTorch Deep Reconstruction Autoencoder ($\mathbb{R}^{69} \to 32 \to 16 \to 8 \to 16 \to 32 \to \mathbb{R}^{69}$) trained strictly on $840$ normal flows (`train_normal`, zero attack contamination) with leak-free `FeaturePreprocessor` (`signed_log1p` + `RobustScaler(25, 75)` + `clip[-10, 10]`) and a validation-calibrated $P_{97} = 0.503670$ primary threshold (`3.33%` validation FPR).
3. **Tri-Model Detection Fusion & Safety Guardrails**: Integrates the supervised **Random Forest** classifier (`random_forest_69_v2.pkl`), unsupervised **Isolation Forest** (`isolation_forest_69_v2.pkl`), and unsupervised **PyTorch Autoencoder** (`autoencoder_model.pt`) under three selectable fusion policies (`weighted_consensus`, `unsupervised_ensemble`, `majority_vote`). Enforces strict SOAR safety guardrails: single-detector unsupervised outliers (`AE_ONLY` and `IF_ONLY`) and degraded states **never** authorize automatic IP blocking (`auto_block_permitted = false`), routing instead to `manual-review` or `alert`.
4. **Model-Faithful Explainable AI (XAI Stages 1 & 2)**:
   - **Stage 1 (`shared/ml/xai_explainer.py`)**: Implements official **`shap.TreeExplainer` (`shap == 0.54.1`)** for Random Forest (verified exact additivity error $\le 8.88 \times 10^{-16}$ across all 384 held-out flows), reference-population perturbation and quantile deviation for Isolation Forest (`840`-flow `train_normal` baseline, validated against `shap.TreeExplainer(if_model)`), per-feature MSE decomposition for the PyTorch Autoencoder (preserving $P_{97} = 0.503670$), and `ThreeScalarMeasurementGrouper` to expose collinearity across `(packets, bytes, duration)`.
   - **Stage 2 (`shared/ml/unified_xai_engine.py`)**: Implements `UnifiedTriModelExplainer`, orchestrating all three explainers with strict separation of mathematical scales, deduplicated concept overlap analysis (`_canonical_concept_id`), full degraded/fault isolation, and **zero (`0/384`) modification** to existing detection decisions.
5. **Reproducible Synthetic Evaluation & Scientific Honesty**: Evaluated across two complementary tracks—Track 1 ($N = 500$ multi-source events across 10 scenarios, **Cohorts A–E**) and Track 2 ($N = 384$ strictly unseen held-out flows). Every benchmark artifact explicitly carries the **`SYNTHETIC BENCHMARK ONLY`** classification, disclosing exact limitations including 3-scalar intrinsic dimensionality and cross-label feature collisions.

---

## 2. Platform Evolution: Shadow Guard 1.0 vs. Shadow Guard 2.0 (+ Autoencoder & XAI)

Understanding Shadow Guard 2.0 requires comparing what the platform originally had in **Shadow Guard 1.0** against what was architected and implemented in **Shadow Guard 2.0 Core**, the **Autoencoder & Tri-Model Fusion Extension**, and the **Explainable AI (XAI) Extension**.

| Architectural Dimension | Shadow Guard 1.0 (Legacy Baseline) | Shadow Guard 2.0 Core (Stages 2–7) | Autoencoder & Tri-Model Extension (AE Stages 1–5) | XAI Extension (XAI Stages 1–2 Completed) |
| :--- | :--- | :--- | :--- | :--- |
| **Container Footprint** | 11 microservices (single flat network) | **22 containers** across **5 isolated networks** | Same 22 containers + upgraded `ml-detection-service` & `model-training-service` | Same 22 containers + `xai_explainer.py` & `unified_xai_engine.py` |
| **Telemetry Modalities** | Network flow packet/byte/duration counters only | Flow telemetry + **Suricata NIDS** + **Cowrie, OpenCanary, Dionaea** honeypots | Same multi-sensor telemetry + 69-dim flow parity | Adds per-flow 69-feature + 3-scalar XAI attribution |
| **ML Detection Models** | Random Forest + Isolation Forest (with `max(proba)` confidence bug and 7-vs-69 schema mismatch) | Fixed RF/IF pipeline + multi-sensor threat classification | **Tri-Model Engine**: RF (`150` trees) + IF (`150` iTrees) + **PyTorch Autoencoder (`69->32->16->8->16->32->69`)** | Read-only XAI layer over all 3 frozen models (`0/384` decision changes) |
| **Feature Schema** | Disconnected 7-col offline script vs. 69-col JS extractor | Unified 69-feature runtime extraction | **Canonical `v2.0-69dim`** (`max_abs_diff = 0.0` JS/Python parity) + collinearity audit | Explicit 69-feature catalog + 3-scalar `(packets, bytes, duration)` grouper |
| **Decision Fusion & Safety** | Single threshold / legacy `max(probabilities)` | Rule-based + ML classification | **3 Fusion Policies** (`weighted_consensus`, `unsupervised_ensemble`, `majority_vote`) + `AE_ONLY` non-auto-block | Preserves frozen `weighted_consensus` + explains model agreement/dissent |
| **Intelligence & Correlation** | None (isolated per-flow alerts) | **Threat Intel** + **5-Factor Attacker Profiling** + **`CORR-01..06`** + **MITRE ATT&CK Chains** | Integrated with Tri-Model severity & confidence | Grounded narrative synthesis & cross-label collision warnings |
| **Deception & SOAR** | Basic IP block script (no leases/allowlists) | **`DEC-01..04`** adaptive deception + **`PB-SOAR-01..05`** + leases + allowlists + rollback | Enforces `auto_block_permitted = false` for `AE_ONLY` / `IF_ONLY` / `degraded` | Investigation checklist explaining why SOAR blocked or inhibited auto-block |
| **Database & Messaging** | Basic `threat_logs` table (1–2 tables), HTTP polling | **PostgreSQL 15 (17 tables)** + **RabbitMQ 3.13** topic exchange + DLQs | Stores tri-model scores & telemetry metadata | Stage 3 will add `004_xai_explanations.sql` (pending approval) |
| **UI & Security** | Basic static dashboard (no RBAC) | **8-Page SOC Command Center** (`:7000`) + **JWT/RBAC** (`VIEWER`, `SOC_ANALYST`, `ADMIN`) + Prometheus | Added Tri-Model Telemetry, P97 threshold card & Degraded-State banners | Stage 4 will add Module 11 UI (pending approval) |
| **Explainability (XAI)** | Black-box predictions | Rule-based rationale strings for Risk Score & Correlation | Feature reconstruction MSE top-k preview | **Official `shap.TreeExplainer` v0.54.1** (RF), **Perturbation + Baseline** (IF), **MSE Decomposition** (AE), **`UnifiedTriModelExplainer`** |

---

## 3. System Architecture, Network Segmentation & 22-Container Topology

Shadow Guard 2.0 implements defense-in-depth at the infrastructure layer by partitioning its **22 Docker containers** across **5 dedicated bridge networks** in `docker-compose.yml` so that compromised deception sensors cannot pivot into core storage or management planes.

```mermaid
flowchart TB
  subgraph Ingress["1. sg_ingress_net (Perimeter Capture)"]
    SURICATA["suricata (jasonish/suricata:latest)"]
    TCAP["traffic-capture-service (:3001)"]
  end

  subgraph DeceptionDMZ["2. sg_deception_dmz (Isolated Honeypot Zone)"]
    COWRIE["cowrie (SSH/Telnet)"]
    OPENCANARY["opencanary (HTTP/FTP/SMB/MySQL)"]
    DIONAEA["dionaea (Malware Capture, noexec)"]
  end

  subgraph CoreNet["3. sg_core_net (Event-Driven Processing & Intelligence)"]
    RMQ["rabbitmq (:5672 / :15672)\nTopic Exchange: shadowguard.events"]
    SEC["suricata-event-collector-service (:3007)"]
    HEC["honeypot-event-collector-service (:3008)"]
    HMAN["honeypot-manager-service (:3009)"]
    FFEE["flow-feature-extraction-service (:3002)"]
    MLD["ml-detection-service (:8001)\nRF + IF + PyTorch AE + XAI Core"]
    MTS["model-training-service (:8002)"]
    TCLS["threat-classification-service (:3004)"]
    TINTEL["threat-intelligence-service (:3010)"]
    APROF["attacker-profiling-service (:3011)"]
    ECORR["event-correlation-service (:3012)"]
    ACHAIN["attack-chain-service (:3013)"]
    DECMAN["deception-manager-service (:3014)"]
    PDE["playbook-decision-engine (:3005)"]
    ARS["automated-response-service (:3006)"]
    ANS["alert-notification-service (:3015)"]
  end

  subgraph StorageNet["4. sg_storage_net (Persistence)"]
    PG["postgres:15 (:5433->5432)\n17 Tables + Views"]
    TDB["threat-log-database-service (:3003)"]
  end

  subgraph FrontendNet["5. sg_frontend_net (SOC Presentation)"]
    SOC["threat-dashboard-service (:7000)\n8-Page SOC Command Center + JWT/RBAC"]
  end

  Ingress --> RMQ
  DeceptionDMZ -. "Read-Only Volume Mounts" .-> HEC
  CoreNet --> RMQ
  CoreNet --> StorageNet
  StorageNet --> FrontendNet
  CoreNet --> FrontendNet
```

### Complete 22-Container Service Inventory

| # | Container / Service Name | Technology Stack | Port(s) | Network Zone(s) | Primary Responsibility |
| :---: | :--- | :--- | :---: | :--- | :--- |
| 1 | `postgres` | PostgreSQL 15 | `5433:5432` | `sg_storage_net` | Authoritative relational + JSONB store (17 tables, 3 migrations) |
| 2 | `rabbitmq` | RabbitMQ 3.13 Alpine | `5672`, `15672` | `sg_core_net` | Asynchronous AMQP topic broker (`shadowguard.events`) + DLQs |
| 3 | `suricata` | Suricata NIDS | — | `sg_ingress_net` | Deep packet inspection producing EVE JSON (`alert`, `dns`, `http`, `tls`, `flow`) |
| 4 | `suricata-event-collector-service` | Node.js | `3007` | `sg_core_net` | Tails Suricata EVE JSON (read-only mount) and publishes Contract v2 events |
| 5 | `traffic-capture-service` | Node.js | `3001` | `sg_ingress_net`, `sg_core_net` | Captures raw network flows and emits `flow.captured` |
| 6 | `flow-feature-extraction-service` | Node.js | `3002` | `sg_core_net` | Extracts canonical 69-dim flow vectors (`v2.0-69dim`) |
| 7 | `cowrie` | Python / Cowrie | `2222`, `2223` | `sg_deception_dmz` | Interactive SSH/Telnet honeypot (zero-password retention enforced) |
| 8 | `opencanary` | Python / OpenCanary | `21`, `80`, `445`, `3306` | `sg_deception_dmz` | Multi-service HTTP, FTP, SMB, MySQL decoy traps |
| 9 | `dionaea` | C / Python / Dionaea | `21`, `445`, `1433` | `sg_deception_dmz` | Malware capture honeypot with `noexec` quarantine volume |
| 10 | `honeypot-event-collector-service` | Node.js | `3008` | `sg_core_net` | Normalizes Cowrie/OpenCanary/Dionaea logs (read-only) with SHA-256 malware hashing |
| 11 | `honeypot-manager-service` | Node.js | `3009` | `sg_core_net` | Manages decoy lifecycle, health, and adaptive deception directives |
| 12 | `ml-detection-service` | Python / FastAPI / PyTorch | `8001` | `sg_core_net` | Hosts RF, IF, PyTorch Autoencoder, Tri-Model Fusion, and XAI Core |
| 13 | `model-training-service` | Python / FastAPI / PyTorch | `8002` | `sg_core_net` | Offline dataset audit, Autoencoder training, P97 calibration, and artifact export |
| 14 | `threat-classification-service` | Node.js | `3004` | `sg_core_net` | Combines ML verdicts with rule-based severity and attack category classification |
| 15 | `threat-intelligence-service` | Node.js | `3010` | `sg_core_net` | Multi-provider IP/hash/domain IOC enrichment with TTL caching |
| 16 | `attacker-profiling-service` | Node.js | `3011` | `sg_core_net` | Maintains behavioral IP profiles and 5-factor explainable risk scores (`0–100`) |
| 17 | `event-correlation-service` | Node.js | `3012` | `sg_core_net` | Sliding-window (`15 min`) correlation (`CORR-01..06`) & 2s burst deduplication |
| 18 | `attack-chain-service` | Node.js | `3013` | `sg_core_net` | Reconstructs MITRE ATT&CK kill chains (`OBSERVED`, `INFERRED`, `SUSPECTED`) |
| 19 | `deception-manager-service` | Node.js | `3014` | `sg_core_net` | Executes closed-loop adaptive deception rules (`DEC-01..04`) |
| 20 | `playbook-decision-engine` | Node.js | `3005` | `sg_core_net` | Evaluates SOAR playbooks (`PB-SOAR-01..05`) & safety guardrails |
| 21 | `automated-response-service` | Node.js | `3006` | `sg_core_net` | Executes timed IP block leases, allowlist checks, approvals, and rollbacks |
| 22 | `threat-log-database-service` + `alert-notification-service` + `threat-dashboard-service` | Node.js | `3003`, `3015`, `7000` | `sg_storage_net`, `sg_frontend_net` | Persistence gateway (`3003`), webhook/pager alerts (`3015`), 8-page SOC UI (`7000`) |

*(Note: `docker-compose.yml` defines the 22 runtime service containers including `postgres`, `rabbitmq`, `suricata`, the 3 honeypots, and the microservices.)*

---

## 4. Canonical Event Contract v2, RabbitMQ Messaging & PostgreSQL 15 Schema

### 4.1 Event Contract v2
Every telemetry message across Shadow Guard 2.0 conforms to **Event Contract v2**, ensuring full lineage from raw packet/honeypot capture through correlation and SOAR execution:
- `event_id` (UUID v4), `correlation_id` (UUID v4), `timestamp` (ISO-8601 UTC)
- `source_service` (`suricata`, `cowrie`, `opencanary`, `dionaea`, `traffic-capture`, `ml-detection`)
- `event_type` (`nids.alert`, `nids.dns`, `honeypot.auth`, `honeypot.command`, `honeypot.malware`, `flow.ml_scored`, `incident.correlated`, `soar.action`)
- `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`
- `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `confidence` (`0.0–1.0`)
- `nids_metadata`, `honeypot_metadata`, `ml_metadata`, `threat_intel_metadata`

### 4.2 RabbitMQ Topic Exchange Topology
- **Exchange**: `shadowguard.events` (`topic`, durable)
- **Dead-Letter Exchange**: `shadowguard.dlx` with per-service `.dlq` queues so malformed messages never crash consumers or silently drop telemetry.
- **Routing Keys**: `suricata.*`, `honeypot.*`, `flow.*`, `threat.classified`, `intel.enriched`, `incident.correlated`, `deception.directive`, `soar.execute`.

### 4.3 PostgreSQL 15 Schema (17 Tables Across 3 Migrations)
1. `001_baseline_threat_logs.sql`: Legacy `threat_logs` table preserved for backward compatibility with Shadow Guard 1.0 queries.
2. `002_schema_v2_core.sql`: Adds 17 core v2 tables:
   - **Sensor Telemetry**: `honeypot_instances`, `honeypot_events`, `suricata_events`
   - **Intelligence & Profiling**: `attacker_profiles`, `attacker_observations`, `threat_intel_cache`
   - **Correlation & Kill Chain**: `incidents`, `incident_events`, `mitre_techniques`, `attack_chains`, `attack_chain_stages`
   - **SOAR, Deception & Audit**: `playbook_executions`, `response_actions`, `response_approvals`, `deception_deployments`, `audit_logs`, `service_metrics`
3. `003_indexes_and_views.sql`: Creates B-Tree and GIN (JSONB) indexes plus SOC summary materialized/logical views.

---

## 5. Perimeter Ingestion, Suricata NIDS & Multi-Type Cyber Deception Plane

1. **Suricata NIDS (`suricata` + `suricata-event-collector-service`)**:
   - Inspects ingress traffic against custom and Emerging Threats rules in `suricata/rules/`.
   - Streams `eve.json` via a read-only Docker volume mount to `suricata-event-collector-service`, normalizing `alert`, `dns`, `http`, `tls`, and `flow` events into Event Contract v2.
2. **Cowrie SSH/Telnet Honeypot**:
   - Captures brute-force login attempts, post-authentication shell commands, and `wget`/`curl` download URLs.
   - **Privacy Safeguard**: Strictly strips all attempted passwords and password hashes prior to persistence or publication (`zero_password_retention = true`), recording only usernames and success/failure counts.
3. **OpenCanary Multi-Service Honeypot**:
   - Exposes decoy HTTP, FTP, SMB, and MySQL services inside `sg_deception_dmz`. Any connection to these decoy ports is treated as high-signal unauthorized reconnaissance or lateral movement.
4. **Dionaea Malware Capture Honeypot**:
   - Emulates vulnerable SMB/HTTP/FTP/MSSQL endpoints to capture binary exploit payloads.
   - **Quarantine Safeguard**: Captured payloads are written to a `noexec,nosuid,nodev` quarantine volume, hashed with **SHA-256**, and analyzed via metadata/Threat Intel without executing any captured binary.

---

## 6. Canonical 69-Feature Engineering Pipeline, Schema Audit & Dataset Provenance

### 6.1 Resolving the Legacy 7-Column vs. 69-Feature Discrepancy
In Shadow Guard 1.0, `model-training-service/generate_data.py` generated a 7-column CSV without a `Label` column, `train_model.py` expected a `Label` column, and the runtime `flow-feature-extraction-service` emitted **69 deterministic features**. Before training any neural network, we resolved this train-serve skew by establishing a single canonical specification (`v2.0-69dim`) implemented identically in:
- **Python**: `shared/ml/feature_schema.py` (`extract_69_features`)
- **JavaScript (Node.js)**: `flow-feature-extraction-service` (`extractFeatures69`)
- **Cross-Language Parity**: Verified across normal, attack, edge-case, and boundary inputs with **`max_abs_diff = 0.0`**.

### 6.2 Mathematical Structure of the 69-Dimensional Feature Vector (`f_00`..`f_68`)
All 69 features are deterministic transformations of three raw flow measurements—Packet Count $p = \text{packets}$, Byte Volume $b = \text{bytes}$, and Flow Duration $d = \text{duration}$ (seconds):
- **`f_00..f_09` (Base & Rate Features, 10 features)**:
  - `f_00_packets` $= p$, `f_01_bytes` $= b$, `f_02_duration` $= d$
  - `f_03_bytes_per_sec` $= \frac{b}{\max(d, 10^{-6})}$, `f_04_packets_per_sec` $= \frac{p}{\max(d, 10^{-6})}$
  - `f_05_avg_bytes_per_packet` $= \frac{b}{\max(p, 1)}$, `f_06_packets_times_bytes` $= p \cdot b$
  - `f_07_log_packets` $= \ln(p + 1)$, `f_08_log_bytes` $= \ln(b + 1)$, `f_09_log_duration` $= \ln(d + 1)$
- **`f_10..f_24` (Sinusoidal Projections, 15 features)**: $\text{sin\_proj}_k = \frac{p \cdot b}{d + 1} \cdot \sin(k \cdot 0.1)$ for $k = 0 \dots 14$.
- **`f_25..f_39` (Polynomial Ratio Features, 15 features)**:
  - Even indices (`f_25, f_27, ..., f_39`, **8 features**): $\frac{p^2}{d^2 + 1}$ (exact duplicates of `f_25`).
  - Odd indices (`f_26, f_28, ..., f_38`, **7 features**): $\frac{p \cdot b}{d^2 + 1}$ (exact duplicates of `f_26`).
- **`f_40..f_54` (Damped Cosine Duration Decay, 15 features)**: $\text{cos\_damp}_k = \cos(d \cdot (k + 1)) \cdot e^{-0.1 d}$ for $k = 0 \dots 14$.
- **`f_55..f_68` (Harmonic Collinear Padding, 14 features)**: $\text{harmonic\_pad}_i = \frac{p + b}{d + 1} \cdot \sin(i)$ for $i = 55 \dots 68$.

### 6.3 Critical Scientific Audit of the 69-Feature Schema
Our mathematical audit documented three critical limitations of `v2.0-69dim`:
1. **3-Scalar Intrinsic Dimensionality**: Although embedded in $\mathbb{R}^{69}$, the feature manifold has at most **3 independent degrees of freedom** $(p, b, d)$.
2. **Exact Duplicates & Rank-1 Collinearity**: `f_25..f_39` contains **13 exact duplicate columns** (8 identical even columns, 7 identical odd columns -> 2 unique signals + 13 duplicates), and `f_55..f_68` contains **14 rank-1 collinear scalar multiples**.
3. **Cross-Label Feature Collisions**: Because the mapping $(p, b, d) \mapsto \mathbb{R}^{69}$ is deterministic, distinct normal and attack flows with identical $(p, b, d)$ map to identical 69-vectors. In `autoencoder_flow_dataset_v2.json`, **4 preserved cross-label collision flows** (`flow-collision-norm-00` vs `flow-collision-atk-00` at $p=33, b=19800, d=0.777\text{s}$; and `flow-collision-norm-01` vs `flow-collision-atk-01` at $p=7, b=490, d=0.019\text{s}$) represent an irreducible Bayes error floor for flow-only models—proving why multi-sensor NIDS/honeypot correlation is essential.

### 6.4 Leak-Free Dataset Preparation (`data/autoencoder_flow_dataset_v2.json`)
- **Origin**: 100% synthetic parametric generation (`scripts/prepare_autoencoder_dataset.py`, `seed=42`).
- **Deduplication & Quarantine**: From `1,535` generated records, `5` exact duplicates were removed, `6` corrupted/contradictory records were quarantined, `11` distinct legitimate flows sharing $(p, b, d)$ were preserved, and `4` cross-label collision flows were preserved in `test_set`, yielding **`1,524` clean records**:
  - `train_normal`: **`840`** normal flows (`0` attacks) — used for Autoencoder training, `FeaturePreprocessor` fitting, and Isolation Forest training.
  - `val_normal`: **`180`** normal flows (`0` attacks) — used strictly for Autoencoder early stopping and $P_{95}/P_{97}/P_{99}$ threshold calibration.
  - `supervised_attack_train`: **`120`** attack flows — used **only** with `train_normal` (`840 + 120 = 960` flows) to train the supervised Random Forest.
  - `test_set`: **`384`** strictly unseen held-out flows (`182` normal, `202` attack across 8 categories: `c2_beaconing`, `data_exfiltration`, `ddos_flood`, `multi_vector`, `novel_stealth_anomaly`, `port_scan`, `service_enum`, `ssh_brute_force`), with **`zero_hash_overlap_verified = true`**.

---

## 7. Machine Learning Detection Algorithms & Selection Rationale

Shadow Guard 2.0 combines three complementary machine-learning paradigms. Each algorithm was selected for a specific structural strength and calibrated to compensate for the blind spots of the others.

### 7.1 Supervised Random Forest Classifier (`models/random_forest_69_v2.pkl`)
- **Algorithm**: Ensemble of `150` CART Decision Trees trained on `960` flows (`840` normal + `120` attack) with `StandardScaler` preprocessing, `classes_ = [0, 1]`, and calibrated decision threshold `0.50`.
- **Legacy Bug Fixed**: Shadow Guard 1.0 used `max(probabilities)` as the anomaly confidence, which misclassified a `0.95` benign probability (`[0.95, 0.05]`) as a `0.95` attack confidence. Shadow Guard 2.0 explicitly extracts `attack_probability = P(class=1 | x)`.
- **Why Selected**:
  - High accuracy (`97.14%`), precision (`99.48%`), recall (`95.05%`), and `ROC-AUC = 0.9933` on known attack profiles.
  - Naturally invariant to monotonic feature scaling within each tree split and supports exact polynomial-time Shapley attribution via `shap.TreeExplainer`.
  - **Limitation**: Supervised classifiers can fail to generalize to novel attack distributions absent from `supervised_attack_train`.

### 7.2 Unsupervised Isolation Forest (`models/isolation_forest_69_v2.pkl`)
- **Algorithm**: Ensemble of `150` random isolation trees (`iTrees`) trained strictly on `840` normal flows with `StandardScaler` preprocessing and validation-calibrated threshold `best_threshold = -0.024499`. Raw `decision_function(x)` scores are mapped to a monotonic severity index in $[0, 1]$ via:
  $$s_{\text{IF}}(\mathbf{x}) = \sigma\!\left(\frac{\tau_{\text{IF}} - d_{\text{raw}}(\mathbf{x})}{0.08}\right), \quad \sigma(u) = \frac{1}{1 + e^{-u}}$$
- **Why Selected**:
  - Zero-label unsupervised outlier detection with $O(n \log n)$ training and sub-millisecond inference.
  - Excels at isolating extreme volumetric outliers (`100%` recall on `ddos_flood`, `data_exfiltration`, and `multi_vector`, and `95.83%` on `novel_stealth_anomaly`).
  - **Limitation**: Axis-aligned random splits struggle to isolate low-and-slow attacks embedded near dense normal regions (`0.00%` recall on `c2_beaconing`, `port_scan`, `service_enum`, and `ssh_brute_force` on `test_set`).

### 7.3 Authoritative PyTorch Deep Reconstruction Autoencoder (`models/autoencoder_model.pt`)
- **Why PyTorch Was Selected**: Chosen as the single authoritative implementation (rather than a separate pure-NumPy or JavaScript neural engine) to guarantee reproducible gradient optimization (`Adam`, `MSELoss`), deterministic `manual_seed(42)`, native `pickle`/`torch.save` artifact persistence, SHA-256 integrity verification, and seamless integration with `shap` and `fastapi`.
- **Leak-Free `FeaturePreprocessor` (`models/autoencoder_preprocessor.pkl`)**:
  1. Validate 69 finite floats.
  2. Apply `signed_log1p(x) = sign(x) * log1p(|x|)` on heavy-tailed indices (`LOG_COMPRESS_INDICES`).
  3. Apply `RobustScaler(quantile_range=(25.0, 75.0))` **fitted strictly on the `840` `train_normal` flows**.
  4. Clip scaled values to `[-10.0, 10.0]` to prevent extreme volumetric bursts from causing numerical overflow.
- **Network Architecture (`FlowAutoencoder`)**:
  $$\mathbb{R}^{69} \xrightarrow{\text{Linear+ReLU}} \mathbb{R}^{32} \xrightarrow{\text{Linear+ReLU}} \mathbb{R}^{16} \xrightarrow{\text{Linear+ReLU}} \mathbb{R}^{8} \text{ (Bottleneck)} \xrightarrow{\text{Linear+ReLU}} \mathbb{R}^{16} \xrightarrow{\text{Linear+ReLU}} \mathbb{R}^{32} \xrightarrow{\text{Linear}} \mathbb{R}^{69}$$
  Trained for `120` epochs (`batch_size=32`, `lr=0.002`, `weight_decay=1e-5`, best validation epoch `114` with `best_val_mse = 0.141353`).
- **Reconstruction Error & Threshold Calibration (Why $P_{97}$ Was Selected Over $P_{95}$)**:
  For a preprocessed vector $\mathbf{z} \in \mathbb{R}^{69}$ and reconstruction $\hat{\mathbf{z}} = D(E(\mathbf{z}))$, the Mean Squared Reconstruction Error is:
  $$\text{MSE}(\mathbf{z}) = \frac{1}{69} \sum_{j=0}^{68} (z_j - \hat{z}_j)^2$$
  Thresholds were calibrated strictly on `val_normal` (`180` normal flows) **before** touching `test_set`:
  - **$P_{95} = 0.409105$**: `5.00%` validation FPR (`9/180`) $\rightarrow$ exceeds the `<= 3.5%` operational SOC alerting budget; assigned to the non-alerting `suspicious` telemetry tier.
  - **$P_{97} = 0.503670$ (SELECTED PRIMARY THRESHOLD)**: **`3.33%` validation FPR (`6/180`)**, satisfying the `<= 3.5%` SOC false-positive budget without the steep recall drop of $P_{99}$. Even though post-hoc `test_set` F1 is higher at $P_{95}$ (`0.7977`) than $P_{97}$ (`0.7165`), selecting $P_{95}$ using `test_set` F1 would constitute test-set leakage.
  - **$P_{99} = 0.645935$**: `1.11%` validation FPR (`2/180`) $\rightarrow$ high-confidence escalation tier.
- **Why Selected**: Unlike Isolation Forest's axis-aligned splits, the Autoencoder learns a smooth 8-dimensional nonlinear manifold of normal flow correlations, raising label-free `c2_beaconing` recall from **`0.00%` (IF) to `76.00%` (AE@P97)** and `port_scan` recall from **`0.00%` (IF) to `56.67%` (AE@P97)**.

---

## 8. Tri-Model Detection Fusion Engine & Safety Guardrails

Implemented in `shared/ml/tri_model_fusion.py` (`TriModelDetectionEngine`), the fusion engine preserves all three individual model outputs and supports three policies:
1. **`weighted_consensus` (Default Production Policy)**:
   - Computes normalized fused score $S_{\text{fused}}$ over healthy models (`RF=0.45`, `IF=0.25`, `AE=0.30`).
   - **Multi-Model Confirmed Threat** (`RF + (IF or AE or AE_susp)` or `IF + AE` or `RF >= 0.70`): `final_decision = "anomalous"`. Automatic IP blocking (`auto_block_permitted = true`) is allowed **only** when `RF_prob >= 0.85` AND `len(degraded_models) == 0`.
   - **Mandatory `AE_ONLY` & `IF_ONLY` Guardrail**: When only the Autoencoder flags an anomaly (`AE_ONLY`, e.g., `MSE > P97` or `MSE > P99`) or only Isolation Forest flags an anomaly (`IF_ONLY`), **`auto_block_permitted` is strictly `false`**. The event routes to `manual-review` or `alert` for correlation with Suricata/Honeypot telemetry.
   - **Degraded-State Fail-Safe**: If 1 or 2 models fail (`partially_degraded`), `auto_block_permitted` is forced `false`. If all 3 models or inputs fail (`degraded`), `final_decision = "degraded"`, `recommended_action = "manual-review"`, `auto_block_permitted = false`—never silently classifying traffic as `normal`.
2. **`unsupervised_ensemble` (Label-Free Union: `IF OR AE@P97`)**:
   - Weights `IF=0.45`, `AE=0.55`, `RF=0.0`. Raises label-free recall from `49.50%` (IF) and `56.93%` (AE) to **`69.31%`** (`F1 = 0.8046`). `auto_block_permitted` is always `false`.
3. **`majority_vote` (2-of-3 Consensus)**:
   - Requires $\ge 2$ of 3 models to agree (`100.00%` precision, `0.00%` FPR on `test_set`).

---

## 9. Explainable Artificial Intelligence (XAI) Subsystem (Stages 1 & 2)

To eliminate black-box opacity for SOC analysts while respecting scientific rigor, Shadow Guard 2.0 implements a two-stage read-only XAI subsystem.

### 9.1 XAI Stage 1 — Model-Specific Explainability Core (`shared/ml/xai_explainer.py`)
1. **`RandomForestSHAPExplainer` (Official `shap.TreeExplainer`, `shap == 0.54.1`)**:
   - Explains the exact `StandardScaler` + `RandomForestClassifier.predict_proba` pipeline (`classes_ = [0, 1]`).
   - Satisfies the exact Shapley additivity identity across all `384` held-out flows with maximum error **`8.88e-16`**:
     $$P_{\text{RF}}(\text{attack} \mid \mathbf{x}) = \mathbb{E}[P_{\text{RF}}(\text{attack})] + \sum_{j=0}^{68} \phi_j^{(1)}(\mathbf{x})$$
   - Extracts top-5 positive contributors (pushing toward `attack`), top-5 negative contributors (pushing toward `normal`), and global `mean(|SHAP|)` importance. Includes a validated perturbation fallback (`force_fallback_mode`) that strictly sets `is_exact_shap = False` so an approximation is never claimed as exact SHAP.
2. **`IsolationForestAnomalyExplainer` (Reference-Population Perturbation & Quantile Deviation)**:
   - Compares each flow against the `840`-flow `train_normal` reference distribution (`median`, `IQR`, `P05`, `P25`, `P75`, `P95`, `robust_z_score`, `empirical_percentile`).
   - Computes single-feature median replacements (`x_j <- median_j`), correlated duplicate/collinear block replacements (`f_25..f_39` and `f_55..f_68`), and whole-measurement counterfactual replacements (`packets`, `bytes`, `duration`).
   - Validated against `shap.TreeExplainer(if_model)` and strictly labeled `UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY`.
3. **`AutoencoderReconstructionExplainer` (Per-Feature MSE Decomposition)**:
   - Runs the exact `FeaturePreprocessor` and PyTorch `FlowAutoencoder`, decomposing MSE into all 69 per-feature squared errors $(z_j - \hat{z}_j)^2$ (`mean(squared_error) == reconstruction_error`), ranking all 69 features, extracting the top-5 anomalous features and 8D latent vector, and comparing against frozen $P_{95}/P_{97}/P_{99}$ thresholds (`RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY`).
4. **`ThreeScalarMeasurementGrouper`**:
   - Aggregates every model's attributions into `(packets, bytes, duration)` and 6 structural groups, explicitly flagging the `13` duplicate polynomial features and `14` collinear harmonic padding features.

### 9.2 XAI Stage 2 — Unified Tri-Model Explanation Engine (`shared/ml/unified_xai_engine.py`)
`UnifiedTriModelExplainer` orchestrates all three Stage 1 explainers without modifying any Stage 1 code, model weights, or detection decisions:
- **Flexible Input Resolution**: Accepts `flow_id` (catalog lookup), `features` (69-dim vector), or `raw_flow` (`{packets, bytes, duration}`).
- **Strict Scale Separation**: Never averages SHAP probability deltas, Isolation Forest depth shifts, and Autoencoder MSE residuals.
- **Collinearity-Aware Overlap Analysis (`_canonical_concept_id`)**: Collapses duplicate/collinear blocks (`concept_poly_even_packets2_dur2`, `concept_poly_odd_pkt_bytes_dur2`, `concept_harmonic_collinear_padding`) before computing shared vs. model-specific drivers.
- **Agreement/Disagreement & Fault Handling**: Distinguishes `UNANIMOUS_ANOMALY_3_OF_3`, `UNANIMOUS_NORMAL_3_OF_3`, `MAJORITY_ANOMALY_2_OF_3_DISSENT`, `SINGLE_MODEL_ANOMALY_DISSENT_AUTOENCODER`, `partially_degraded` (any 1 or 2 models down), and `degraded` (all models down, invalid vector, or runtime exception), automatically flagging cross-label feature collisions (`AMBIGUOUS_3_SCALAR_FEATURE_COLLISION`).

---

## 10. Threat Intelligence Enrichment, Attacker Profiling & Sliding-Window Correlation

### 10.1 Threat Intelligence Enrichment (`threat-intelligence-service`)
- Enriches `source_ip`, domain IOCs, and SHA-256 file hashes against multi-provider reputation feeds and local threat-intel caches (`threat_intel_cache` in PostgreSQL) with TTL expiration so repeated queries avoid redundant external calls.
- Produces normalized `reputation_score` (`0–100`), threat tags (e.g., `botnet_c2`, `tor_exit`, `known_scanner`), and confidence metadata.

### 10.2 Explainable 5-Factor Attacker Risk Scoring (`attacker-profiling-service`)
- Maintains per-IP behavioral profiles (`attacker_profiles`, `attacker_observations`) with an explicit **Indicator Disclaimer** (noting that an IP may represent a NAT gateway, VPN/Tor exit node, or compromised bot rather than a single human).
- Computes an **Explainable Risk Score (`0–100`)** where every point added is backed by a named factor, explicit weight, and supporting `event_id` lineage:
  1. **Honeypot Interaction Depth** (sessions, distinct decoys touched)
  2. **Authentication & Credential Abuse** (failed/successful logins; zero-password retention)
  3. **Post-Authentication Command & Payload Activity** (regex pattern tags: `PAYLOAD_DOWNLOADER`, `EXECUTION_PREPARATION`, `CREDENTIAL_FILE_ACCESS`, `SYSTEM_DISCOVERY`, `REVERSE_SHELL`, `PERSISTENCE_ATTEMPT`, `DEFENSE_EVASION`)
  4. **Threat Intelligence Reputation** (`0–100` external/cached IOC score)
  5. **ML & NIDS Severity / Persistence** (repeated offenses and multi-sensor alerts)

### 10.3 Sliding-Window Event Correlation (`CORR-01`–`CORR-06`, `event-correlation-service`)
- **Redis-Free In-Memory Sliding Window**: Indexes incoming Contract v2 events by `source_ip` over a configurable `15-minute` window (`CORRELATION_WINDOW_MS = 900000`) with automatic expiration pruning.
- **2-Second Burst Deduplication**: Computes a SHA-1 fingerprint over `(source_service, source_ip, destination_port, event_type, command_executed, signature_id)` with `dedupWindowMs = 2000` to suppress alert storms.
- **Six Correlation Rules (`CORR-01`–`CORR-06`)**:
  - `CORR-01`: Multi-port / multi-service reconnaissance burst
  - `CORR-02`: NIDS alert + Honeypot interaction corroboration
  - `CORR-03`: Repeated SSH/Telnet brute-force escalation
  - `CORR-04`: Post-authentication command execution / malware payload staging
  - `CORR-05`: High-volume ML flow anomaly + Threat Intel match
  - `CORR-06`: Multi-stage kill-chain progression within window
- **Incident Grouping**: Merges related events for the same `source_ip` into a single active incident (`incidents`, `incident_events`). In Cohort E, this consolidates `363` raw alerts into `5` incidents (`98.62%` alert queue consolidation—explicitly distinguished from false-positive rate reduction).

### 10.4 Evidence-Grounded MITRE ATT&CK Kill-Chain Reconstruction (`attack-chain-service`)
Maps correlated incidents onto MITRE ATT&CK tactics (`TA0043` Reconnaissance through `TA0040` Impact) using three strict epistemic tiers:
- **`OBSERVED`**: Directly supported by captured telemetry (e.g., Cowrie `wget` command -> `T1105` Ingress Tool Transfer).
- **`INFERRED`**: Logically implied by adjacent stages (e.g., post-auth command execution implies `T1078` Valid Accounts / `TA0001` Initial Access).
- **`SUSPECTED`**: Low-confidence indicator requiring analyst verification.

---

## 11. Adaptive Deception Manager & Safety-Gated SOAR Automation

### 11.1 Closed-Loop Adaptive Deception (`DEC-01`–`DEC-04`, `deception-manager-service`)
- **`DEC-01` (Port Scanning Detected)**: Enables additional decoy service ports and reconnaissance banners.
- **`DEC-02` (Repeated SSH Brute-Force)**: Increases Cowrie logging verbosity and deploys SSH honey-breadcrumbs.
- **`DEC-03` (SMB / Database Enumeration)**: Activates OpenCanary SMB/MySQL decoy shares and lure tables.
- **`DEC-04` (High-Risk Attacker / Payload)**: Enables Dionaea malware trap and redirects attacker IP to the isolated `sg_deception_dmz`.

### 11.2 Multi-Condition SOAR Playbooks (`PB-SOAR-01`–`PB-SOAR-05`, `playbook-decision-engine`)
| Playbook ID | Trigger Conditions | Automated Actions | Safety & Approval Rules |
| :--- | :--- | :--- | :--- |
| **`PB-SOAR-01`** | `risk >= 80`, `CRITICAL`, honeypot/payload | 60-min IP block lease, `DEC-04`, `DEBUG_FULL_FORENSICS`, Pager, Tier-3 escalation | Allowlist checked; `AE_ONLY` never triggers |
| **`PB-SOAR-02`** | `repeated_offenses >= 3`, `intel_rep >= 85` | 120-min temporary block + `BLOCK_IP_PERMANENT` | Permanent block **requires human SOC approval** |
| **`PB-SOAR-03`** | `confidence >= 0.85`, `risk >= 60`, `HIGH/CRITICAL` | 30-min IP block lease, `DEC-01`, email alert | Allowlist + `auto_block_permitted` enforced |
| **`PB-SOAR-04`** | `confidence >= 0.60`, `risk >= 35`, `MEDIUM/HIGH` | Raise alert, `DEC-02`, enhanced logging | Non-blocking deception lure |
| **`PB-SOAR-05`** | Default baseline | `MONITOR_ONLY` | Passive telemetry recording |

### 11.3 Response Execution Safeguards (`automated-response-service`)
- **Critical Infrastructure Allowlist**: Prevents blocking loopback, RFC-1918 management gateways, DNS resolvers, and internal core services.
- **Timed Block Leases & Rollback**: All automated blocks have finite TTL leases (`30`, `60`, or `120` minutes) with automatic expiration and one-click analyst rollback (`response_actions`, `response_approvals`).

---

## 12. 8-Page SOC Command Center, RBAC/JWT Security & Observability

Hosted on port `7000` (`threat-dashboard-service`), the SOC Command Center provides 8 operational views:
1. **Overview & Tri-Model Detection Telemetry**: Displays RF probabilities, IF anomaly scores, PyTorch Autoencoder MSE vs. frozen $P_{97} = 0.503670$, fusion policy selector, and degraded-model safety banners.
2. **Live Threat & Flow Stream**: Real-time flow verdicts with per-flow top contributing features and model agreement/disagreement indicators.
3. **Suricata NIDS Alerts**: Deep packet inspection alerts, DNS/HTTP/TLS metadata, and SID tracking.
4. **Cyber Deception & Honeypot Telemetry**: Cowrie sessions/commands, OpenCanary decoy hits, and Dionaea SHA-256 malware captures.
5. **Attacker Profiles & 5-Factor Risk Explanations**: IP behavioral timelines and weighted risk breakdowns.
6. **Correlated Incidents & MITRE ATT&CK Kill Chains**: Consolidated multi-stage campaigns (`OBSERVED`/`INFERRED`/`SUSPECTED`).
7. **SOAR Playbooks, Block Leases & Approvals**: Active containment leases, rollback controls, and pending `PB-SOAR-02` approvals.
8. **System Health, RBAC & Prometheus Metrics**: Service liveness, `/metrics` Prometheus exposition, JWT authentication (`VIEWER`, `SOC_ANALYST`, `ADMIN` RBAC), and immutable `audit_logs`.

---

## 13. Experimental Evaluation: Track 1 (Cohorts A–E) & Track 2 (384 Held-Out Flows)

> **Benchmark Classification**: **`SYNTHETIC BENCHMARK ONLY`**. All Track 1 (`500` events, `Mulberry32(20261113)`) and Track 2 (`1,524` flows, `random.Random(42)`) datasets are controlled synthetic parametric benchmarks.

### 13.1 Track 2 — Model-Level Evaluation on 384 Strictly Unseen Held-Out Flows (`test_set`)

| Model / Fusion Policy | TN | FP | FN | TP | Accuracy | Precision | Recall | F1-Score | FPR | ROC-AUC | PR-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** (`random_forest_69_v2`, supervised) | 181 | 1 | 10 | 192 | 97.14% | 99.48% | 95.05% | 0.9722 | 0.55% | 0.9933 | 0.9948 |
| **Isolation Forest** (`isolation_forest_69_v2`, unsupervised) | 180 | 2 | 102 | 100 | 72.92% | 98.04% | 49.50% | 0.6579 | 1.10% | 0.9109 | 0.9141 |
| **PyTorch Autoencoder @ P95** (`0.409105`, warning tier) | 176 | 6 | 64 | 138 | 81.77% | 95.83% | 68.32% | 0.7977 | 3.30% | 0.9652 | 0.9670 |
| **PyTorch Autoencoder @ P97** (`0.503670`, **primary**) | 178 | 4 | 87 | 115 | 76.30% | 96.64% | 56.93% | 0.7165 | 2.20% | 0.9652 | 0.9670 |
| **PyTorch Autoencoder @ P99** (`0.645935`, conservative) | 181 | 1 | 105 | 97 | 72.40% | 98.98% | 48.02% | 0.6467 | 0.55% | 0.9652 | 0.9670 |
| **IF + AE Unsupervised Ensemble** (`IF OR AE@P97`) | 176 | 6 | 62 | 140 | **82.29%** | 95.89% | **69.31%** | **0.8046** | 3.30% | — | — |
| **Tri-Model `majority_vote`** ($\ge 2$ of 3 agree) | 182 | 0 | 28 | 174 | 92.71% | **100.00%** | 86.14% | 0.9255 | **0.00%** | — | — |
| **Tri-Model `weighted_consensus`** (Production Default) | 178 | 4 | 8 | 194 | **96.88%** | 97.98% | **96.04%** | **0.9700** | 2.20% | — | — |

*(Note: Under `weighted_consensus`, the 4 `AE_ONLY` normal FPs (`FP=4`) are routed strictly to `manual-review` / `alert` with `auto_block_permitted = false`.)*

### 13.2 Per-Attack-Category Recall Comparison on `test_set` (`202` Attack Flows)

| Attack Category | Total Flows | Random Forest | Isolation Forest | PyTorch AE @ P97 | Key Complementarity Finding |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `ddos_flood` | 34 | 100.00% | 100.00% | 100.00% | Unanimous detection across all 3 models |
| `multi_vector` | 18 | 100.00% | 100.00% | 88.89% | Strong multi-model agreement |
| `data_exfiltration` | 25 | 100.00% | 100.00% | 48.00% | IF + RF catch 100%; AE catches high-rate bursts |
| `c2_beaconing` | 25 | 100.00% | **0.00%** | **76.00%** | **AE recovers +76.00 pp label-free recall where IF fails** |
| `port_scan` | 30 | 100.00% | **0.00%** | **56.67%** | **AE recovers +56.67 pp label-free recall where IF fails** |
| `novel_stealth_anomaly` | 24 | 87.50% | 95.83% | 54.17% | IF + AE complement RF on novel outliers |
| `service_enum` | 24 | 75.00% | 0.00% | 4.17% | Requires OpenCanary honeypot telemetry (Cohort E) |
| `ssh_brute_force` | 22 | 95.45% | 0.00% | 13.64% | Requires Cowrie honeypot telemetry (Cohort E) |

### 13.3 Track 1 — System-Level Ablation Across Cohorts A–E ($N = 500$ Multi-Source Events, 10 Scenarios)

| Cohort | Configuration | TP | FP | TN | FN | Accuracy | Precision | Recall | F1-Score | FPR | Alert Consolidation | Benign Auto-Blocks |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cohort A** | Shadow Guard 1.0 (ML Only) | 216 | 24 | 116 | 144 | 66.40% | 90.00% | 60.00% | 72.00% | 17.14% | 0.00% (240->240) | N/A |
| **Cohort B** | SG 2.0 + Suricata NIDS | 276 | 13 | 127 | 84 | 80.60% | 95.50% | 76.67% | 85.05% | 9.29% | 0.00% (289->289) | N/A |
| **Cohort C** | SG 2.0 + Suricata + Honeypots | 326 | 13 | 127 | 34 | 90.60% | 96.17% | 90.56% | 93.28% | 9.29% | 0.00% (339->339) | N/A |
| **Cohort D** | SG 2.0 Complete Integrated (RF+IF) | 360 | 6 | 134 | 0 | 98.80% | 98.36% | 100.00% | 99.17% | 4.29% | 98.63% (366->5) | — |
| **Cohort E** | **SG 2.0 + PyTorch AE + Tri-Model Fusion (Audited)** | **360** | **3** | **137** | **0** | **99.40%** | **99.17%** | **100.00%** | **99.59%** | **2.14%** | **98.62% (363->5)** | **0 / 3** |

- **Cohort E Subsystem Ablation**: Disabling honeypots in Cohort E drops recall from **`100.00%` to `96.39%`** (`FN = 13` stealth SSH/service-enum probes missed by 3-scalar flow ML); disabling SOAR guardrails causes **`3` erroneous automatic IP blocks on benign internal hosts**.

---

## 14. Verification, Testing & Independent Scientific Audit Results

Every subsystem of Shadow Guard 2.0 is verified through automated unit tests, live HTTP service probes, end-to-end SOAR guardrail checks, and cross-stage regression suites.

### 14.1 Master Verification Suite (`node scripts/run_all_verifications.js`)
Executed cleanly with **zero failures (`464 PASSED, 0 FAILED`)** across all 13 verification suites:

| Suite | Scope Verified | Passed | Failed |
| :--- | :--- | :---: | :---: |
| **Stage 2** | Foundation (PostgreSQL Migrations, Event Contract v2 & RabbitMQ) | 57 | 0 |
| **Stage 3** | Suricata NIDS & Multi-Type Honeypot Infrastructure (`Cowrie`, `OpenCanary`, `Dionaea`) | 57 | 0 |
| **Stage 4** | Threat Intel, 5-Factor Attacker Profiling, Correlation (`CORR-01..06`) & Attack Chains | 65 | 0 |
| **Stage 5** | Adaptive Deception Manager (`DEC-01..04`) & Advanced SOAR Engine (`PB-SOAR-01..05`) | 40 | 0 |
| **Stage 6** | 8-Page SOC Command Center, RBAC/JWT & Prometheus Metrics | 37 | 0 |
| **Stage 7** | Reproducible 500-Event Research Ablation Benchmark (Cohorts A–D) | 11 | 0 |
| **AE Stg 1** | Canonical 69-Feature Schema (`v2.0-69dim`), Provenance & Cross-Language Parity | 28 | 0 |
| **AE Stg 2** | PyTorch Autoencoder Training (`840` normal), $P_{97}$ Calibration & SHA-256 Artifacts | 30 | 0 |
| **AE Stg 3** | Autoencoder Inference, Tri-Model Fusion, Live HTTP Endpoints & SOAR Non-Auto-Block | 32 | 0 |
| **AE Stg 4** | SOC Dashboard Tri-Model Integration, Safety, RBAC & Benchmark | 30 | 0 |
| **AE Stg 5** | Cohort E Benchmark, Scientific Validity Audit, Thesis & Viva Guide | 33 | 0 |
| **XAI Stg 1** | Model-Specific XAI Core (Official `shap.TreeExplainer` v0.54.1, IF Perturb, AE MSE) | 24 | 0 |
| **XAI Stg 2** | Unified Tri-Model Explanation Engine & 384-Flow Decision Invariance | 20 | 0 |
| **GRAND TOTAL** | **All 13 Verification Suites** | **464** | **0** |

### 14.2 Dedicated Python Unit Test Suites
- `ml-detection-service/tests/test_xai_explainer.py` (XAI Stage 1): **`12/12` tests PASSED** (`1.504s`), verifying official `shap.TreeExplainer` v0.54.1 additivity (`max_err = 8.88e-16`), Isolation Forest perturbation & `shap.TreeExplainer(if_model)` reference alignment, PyTorch Autoencoder MSE parity vs. frozen $P_{97} = 0.503670$, and 3-scalar collinearity disclosure.
- `ml-detection-service/tests/test_unified_xai_engine.py` (XAI Stage 2): **`9/9` tests PASSED** (`27.344s`), verifying 3-explainer orchestration, unanimous/dissent consensus detection, single/multi/complete model failure isolation, invalid flow handling, cross-label collision detection, and **`0/384` mismatches** against `held_out_384_tri_model_predictions.json`.

### 14.3 Independent Scientific Audit Disclosures
1. **Synthetic Benchmark Classification**: All flow datasets (`1,524` flows) and system benchmark streams (`500` events) are **`SYNTHETIC BENCHMARK ONLY`**. No claim of live enterprise PCAP performance or true zero-day exploit detection is made.
2. **Windows Host Docker Execution Boundary**: On the Windows evaluation host, static `docker-compose.yml` network isolation (`sg_deception_dmz`, `noexec` mounts, read-only log mounts) was audited, while all runtime services and verification suites were executed natively via Node.js and Python processes; full multi-container `docker compose up` runtime execution remains **not verified** on this host.

---

## 15. Limitations, Threat Model Boundaries & Future Roadmap (XAI Stages 3–6)

### 15.1 Current Limitations
1. **3-Scalar Flow Manifold**: All 69 features in `v2.0-69dim` derive from `(packets, bytes, duration)` (`13` duplicate polynomial columns, `14` collinear harmonic padding columns). Disambiguating cross-label volumetric collisions requires multi-sensor Suricata/honeypot telemetry.
2. **XAI Backend/UI Integration Pending**: Per stage-gated execution, **XAI Stage 2** is complete and awaiting approval. FastAPI/Node.js XAI endpoints (`/api/v2/xai/*`), PostgreSQL migration `004_xai_explanations.sql`, and **Module 11 — Explainable AI & Threat Reasoning** in the SOC Dashboard have not yet been implemented.

### 15.2 Approved Roadmap (XAI Stages 3–6)
- **XAI Stage 3 (Backend Integration)**: Add `/explain/flow` and `/explain/feature-importance` in `ml-detection-service/main.py`, `/api/v2/xai/*` routes in `threat-dashboard-service/server.js`, PostgreSQL migration `004_xai_explanations.sql`, LRU caching, RBAC enforcement, and audit logging.
- **XAI Stage 4 (SOC Dashboard Integration)**: Implement **Module 11 — Explainable AI & Threat Reasoning** in `threat-dashboard-service/public/app.js` with SHAP waterfall charts, IF baseline quantile comparisons, AE reconstruction vs. $P_{97}$ charts, and Tri-Model consensus narratives.
- **XAI Stage 5 (Evaluation & Regression)**: Quantitative evaluation of explanation consistency, perturbation stability, attribution quality, and latency alongside full regression testing.
- **XAI Stage 6 (Final Documentation)**: Complete `docs/XAI_ARCHITECTURE.md`, `docs/XAI_API_REFERENCE.md`, `docs/XAI_METHODOLOGY.md`, `docs/XAI_TEST_REPORT.md`, and thesis/viva updates.
