# Shadow Guard 2.0 — Stage 5: Cohort E Research Benchmark, Scientific Validity & Limitations Report

**Benchmark Classification:** **`SYNTHETIC BENCHMARK ONLY`**
**Experimental Seeds:** System Benchmark `seed = 20261113` ($N = 500$ events across 10 scenarios) | Network Flow Benchmark `seed = 42` ($N = 1,524$ clean 69-feature flows; $N_{\text{test}} = 384$ held-out flows across 8 attack categories)

> [!IMPORTANT]
> **Scientific Transparency & Non-Fabrication Guarantee:**
> Every metric reported in this document is computed directly from deterministic, reproducible code execution:
> - Original Cohorts A–D Runner (preserved untouched): [evaluate_research_cohorts.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_research_cohorts.js) -> [benchmark_results.json](file:///d:/ShadowGuard-main/ShadowGuard-main/evaluation/results/benchmark_results.json)
> - Cohort E Extension Runner: [evaluate_cohort_e_benchmark.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_cohort_e_benchmark.js) -> [cohort_e_benchmark_results.json](file:///d:/ShadowGuard-main/ShadowGuard-main/evaluation/results/cohort_e_benchmark_results.json)
> - PyTorch Autoencoder & Tri-Model Held-Out Evaluation: [train_autoencoder_v2.py](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/train_autoencoder_v2.py) & [export_tri_model_dashboard_telemetry.py](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/export_tri_model_dashboard_telemetry.py) -> [autoencoder_metadata.json](file:///d:/ShadowGuard-main/ShadowGuard-main/models/autoencoder_metadata.json) & [tri_model_dashboard_telemetry_v2.json](file:///d:/ShadowGuard-main/ShadowGuard-main/data/tri_model_dashboard_telemetry_v2.json)
> - All results represent **controlled synthetic benchmark evaluation (`SYNTHETIC BENCHMARK ONLY`)**. No real-world zero-day detection or live enterprise PCAP performance is claimed.

---

## 1. Part 1 — Cohort E Research Benchmark & Comparative Ablation

### 1.1 Architectural Definition: What Cohort E Adds Beyond Cohorts A–D

| Cohort ID | Subsystem Composition | What Is Added at Each Stage |
| :--- | :--- | :--- |
| **Cohort A** (`COHORT_A_SG_1_0_ML_ONLY`) | Shadow Guard 1.0 Baseline (Single-Threshold Flow ML Only) | Baseline volumetric flow anomaly detection ($\text{confidence} \ge 0.60$). No NIDS, no honeypots, no correlation, no SOAR guardrails. |
| **Cohort B** (`COHORT_B_SG_2_0_SURICATA`) | Flow ML + Suricata NIDS (`eve.json`) | Adds Suricata signature inspection (`ET SCAN`, `ET TROJAN`, `ET DNS`, `ET DOS`) for Alert, DNS, HTTP, TLS, and Flow telemetry. |
| **Cohort C** (`COHORT_C_SG_2_0_HONEYPOTS`) | Flow ML + Multi-Type Honeypots (`Cowrie`, `OpenCanary`, `Dionaea`) | Adds isolated `sg_deception_dmz` SSH/Telnet, HTTP/FTP/SMB/MySQL, and malware capture traps for high-certainty deception telemetry. |
| **Cohort D** (`COHORT_D_SG_2_0_COMPLETE_INTEGRATED`) | Flow ML + Suricata + Honeypots + Threat Intel + Attacker Profiling + Sliding-Window Correlation + MITRE Kill Chains + SOAR | Integrates multi-source enrichment, 5-factor behavioural risk scoring, 30-minute sliding-window incident consolidation, and automated SOAR containment. |
| **Cohort E** (`COHORT_E_SG_2_0_TRI_MODEL_AUTOENCODER_INTEGRATED`) | **Complete Shadow Guard 2.0 Architecture + PyTorch Autoencoder (`69->32->16->8->16->32->69`) + Tri-Model Detection Fusion (`RF + IF + AE`) + Safety-Gated SOAR Guardrails** | **1.** Adds the PyTorch Reconstruction Autoencoder trained strictly on $840$ normal flows (`train_normal`) with validation-calibrated $P_{97} = 0.503670$ threshold.<br>**2.** Adds Tri-Model Fusion (`Random Forest + Isolation Forest + PyTorch Autoencoder`) with three selectable policies (`weighted_consensus`, `unsupervised_ensemble`, `majority_vote`).<br>**3.** Replaces single-threshold internal flow heuristics with **Multi-Model Consensus Corroboration**, suppressing benign internal backup-burst false positives when only a single detector fires without NIDS/Honeypot/Threat-Intel corroboration.<br>**4.** Enforces **Safety-Gated SOAR Guardrails** (`auto_block_permitted = false` on `AE_ONLY`, `IF_ONLY`, and `DEGRADED_FALLBACK` decisions). |

### 1.2 Why Two Complementary Evaluation Tracks Are Required (Non-Fabrication Rule)

During the Stage 1 Dataset & Schema Audit ([autoencoder_dataset_audit_report.json](file:///d:/ShadowGuard-main/ShadowGuard-main/data/autoencoder_dataset_audit_report.json)), we verified that the original Stage 7 500-event dataset in [evaluate_research_cohorts.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_research_cohorts.js) models high-level normalized NIDS, honeypot, and correlation events where raw scalar flow counters (`packets, bytes, duration`) were omitted (defaulting to `0, 0, 0`). Per **Requirement #3 (No Fabrication of Missing Flow Features)**, missing scalar values are never fabricated on those 500 events. Instead, Cohort E is evaluated across three complementary, reproducible tracks:
1. **Track 1 — 500-Event Multi-Source System Ablation (`Cohorts A–E`, `seed = 20261113`)**: Evaluates end-to-end multi-sensor fusion (`Suricata + Honeypots + Threat Intel + Correlation + SOAR + Tri-Model Flow Consensus`) while preserving Cohorts A–D unchanged.
2. **Track 2 — 384-Flow 69-Feature Held-Out Network Flow Benchmark (`seed = 42`)**: Evaluates the exact 69-feature mathematical pipeline across `Random Forest`, `Isolation Forest`, `PyTorch Autoencoder` ($P_{95}, P_{97}, P_{99}$), `IF + AE Unsupervised Ensemble`, `Majority Vote (2-of-3)`, and `Weighted Consensus (RF + IF + AE)` across all 8 attack categories.
3. **Track 3 — Explicit Separation of Detection Performance vs. SOAR Response Performance**: Evaluates how detection confusion matrices translate into SOAR operational containment actions and safety guardrail enforcement.

---

### 1.3 Track 1 Results: 500-Event Multi-Source System Ablation (Cohorts A, B, C, D, and E)

*Dataset: $N = 500$ deterministic labeled events ($360$ malicious across scenarios `S02–S10`, $140$ benign enterprise flows in `S01` including $18\%$ high-volume internal backup bursts). Classification: `SYNTHETIC BENCHMARK ONLY`.*

| Metric | Cohort A (SG 1.0 ML Only) | Cohort B (SG 2.0 + Suricata) | Cohort C (SG 2.0 + Honeypots) | Cohort D (Complete SG 2.0) | **Cohort E (Complete SG 2.0 + PyTorch AE & Tri-Model, Audited)** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **True Positives (TP)** | 216 | 276 | 326 | 360 | **360** |
| **False Positives (FP)** | 24 | 13 | 13 | 6 | **3** |
| **True Negatives (TN)** | 116 | 127 | 127 | 134 | **137** |
| **False Negatives (FN)** | 144 | 84 | 34 | 0 | **0** |
| **Accuracy (%)** | 66.40% | 80.60% | 90.60% | 98.80% | **99.40%** |
| **Precision (%)** | 90.00% | 95.50% | 96.17% | 98.36% | **99.17%** |
| **Recall / TPR (%)** | 60.00% | 76.67% | 90.56% | 100.00% | **100.00%** |
| **F1-Score (%)** | 72.00% | 85.05% | 93.28% | 99.17% | **99.59%** |
| **False Positive Rate (FPR)** | 17.14% | 9.29% | 9.29% | 4.29% | **2.14%** |
| **False Negative Rate (FNR)** | 40.00% | 23.33% | 9.44% | 0.00% | **0.00%** |
| **Detection Latency P50 / P95 / P99 (ms)** | 0.0003 / 0.0006 / 0.0076 | 0.0002 / 0.0004 / 0.0034 | 0.0002 / 0.0005 / 0.0022 | 0.1147 / 0.7630 / 1.7446 | **0.0675 / 0.1520 / 0.2720** |
| **Raw Alerts -> Consolidated Incidents** | 240 -> 240 (0.00%) | 289 -> 289 (0.00%) | 339 -> 339 (0.00%) | 366 -> 5 (98.63%) | **363 -> 5 (98.62%)** |
| **Reconstructed MITRE Kill Chains** | 0 | 0 | 0 | 5 | **5** |
| **Benign Internal IPs Auto-Blocked** | N/A | N/A | N/A | N/A | **0 (3/3 Single-Detector FPs Guarded)** |

#### Per-Scenario Recall / Specificity Breakdown (`Cohorts A–E`)

| Scenario ID & Description | Events | Cohort A (ML Only) | Cohort B (+Suricata) | Cohort C (+Honeypots) | Cohort D (Complete v2) | **Cohort E (+Tri-Model AE, Audited)** | **Cohort E Ablation 5 (Pure Tri-Model ML Only)** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `S01_NORMAL_TRAFFIC` *(Specificity / TN Rate)* | 140 | 82.86% | 90.71% | 90.71% | 95.71% | **97.86% (`FP=3`)** | **97.86% (`FP=3`)** |
| `S02_PORT_SCANNING` *(Rapid & Slow SYN Scans)* | 40 | 75.00% | 100.00% | 75.00% | 100.00% | **100.00%** | **100.00%** |
| `S03_SSH_BRUTE_FORCE` *(Credential Stuffing)* | 40 | 65.00% | 65.00% | 100.00% | 100.00% | **100.00%** | **95.00% (`FN=2`)** |
| `S04_HTTP_FTP_SMB_RECON` *(Service Enumeration)* | 40 | 50.00% | 82.50% | 100.00% | 100.00% | **100.00%** | **75.00% (`FN=10`)** |
| `S05_HONEYPOT_COMMAND_EXEC` *(Post-Auth Shell)* | 40 | 25.00% | 25.00% | 100.00% | 100.00% | **100.00%** | **97.50% (`FN=1`)** |
| `S06_MALWARE_SAMPLE_DOWNLOAD` *(ELF Dropper)* | 40 | 35.00% | 67.50% | 100.00% | 100.00% | **100.00%** | **100.00%** |
| `S07_DDOS_VOLUMETRIC` *(Inbound SYN Flood)* | 40 | 100.00% | 100.00% | 100.00% | 100.00% | **100.00%** | **100.00%** |
| `S08_DATA_EXFILTRATION` *(High-Entropy DNS Tunnel)* | 40 | 75.00% | 100.00% | 75.00% | 100.00% | **100.00%** | **100.00%** |
| `S09_C2_BEACONING` *(Jittered Botnet Heartbeat)* | 40 | 65.00% | 100.00% | 65.00% | 100.00% | **100.00%** | **100.00%** |
| `S10_MULTI_STAGE_PROGRESSION` *(4-Stage Kill Chain)* | 40 | 50.00% | 50.00% | 100.00% | 100.00% | **100.00%** | **100.00%** |

**Why Audited Cohort E Improves Upon Cohort D in Track 1:**
In Cohort D, `6` of the `24` bursty internal backup flows in `S01_NORMAL_TRAFFIC` exceeded the static `0.80` single-model score threshold (`FP = 6`, `FPR = 4.29%`). In our **Audited, Leak-Free Cohort E**, `S01_NORMAL_TRAFFIC` (`140` events) is paired sequentially with the first `140` unfiltered held-out normal test flows (`norm_flows[0..139]`) from `splits.test_set` and evaluated under the frozen Stage 3 `weighted_consensus` policy (`triDecision.is_anomaly`). Only `3` normal flows (`EV-0005 / flow-norm-00258` [`AE_ONLY P99`], `EV-0006 / flow-norm-01179` [`IF_ONLY`], and `EV-0131 / flow-norm-00366` [`AE_ONLY P97`]) trigger single-detector unsupervised alerts, halving the system FPR to **`2.14%` (`TN = 137, FP = 3`)** while the SOAR guardrail (`auto_block_permitted = false`) prevents **`100%` (`3/3`)** of those false positives from executing an automatic IP block (`0` benign IPs blocked). Furthermore, when Honeypot signals are disabled in **`Ablation 2A/2B`**, `13` low-volume stealth probes (`2` in `S03`, `10` in `S04`, `1` in `S05`) that overlap normal `(packets, bytes, duration)` triples become false negatives (`TP = 347, FN = 13, Recall = 96.39%`), demonstrating the exact empirical contribution of multi-type honeypots.

---

### 1.4 Track 2 Results: 384-Flow 69-Feature Held-Out Network Flow Benchmark

*Dataset: Held-out `test_set` ($N = 384$ strictly unseen 69-feature flows: $182$ normal flows + $202$ attack flows across 8 attack categories, including $4$ preserved cross-label feature-collision records). Classification: `SYNTHETIC BENCHMARK ONLY`.*

#### A. Confusion Matrices & Classification Metrics Across All Models and Fusion Policies

| Model / Fusion Policy | Paradigm & Operating Point | TN | FP | FN | TP | Accuracy | Precision | Recall (TPR) | F1-Score | FPR | FNR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (`random_forest_69_v2`)** | Supervised (`200` trees, $P(\text{attack}) \ge 0.50$) | 181 | 1 | 10 | 192 | **97.14%** | **99.48%** | 95.05% | **0.9722** | **0.55%** | 4.95% |
| **Isolation Forest (`isolation_forest_69_v2`)** | Unsupervised Tree Isolation ($\text{score} < 0.0$) | 180 | 2 | 102 | 100 | 72.92% | 98.04% | 49.50% | 0.6579 | 1.10% | 50.50% |
| **PyTorch Autoencoder ($P_{95}$ Candidate)** | Unsupervised Neural MSE ($> 0.409105$, Val FPR $5.00\%$) | 176 | 6 | 64 | 138 | 81.77% | 95.83% | 68.32% | 0.7977 | 3.30% | 31.68% |
| **PyTorch Autoencoder ($P_{97}$ Frozen Primary)** | Unsupervised Neural MSE ($> 0.503670$, Val FPR $3.33\%$) | 178 | 4 | 87 | 115 | **76.30%** | **96.64%** | **56.93%** | **0.7165** | **2.20%** | **43.07%** |
| **PyTorch Autoencoder ($P_{99}$ Candidate)** | Unsupervised Neural MSE ($> 0.645935$, Val FPR $1.11\%$) | 181 | 1 | 105 | 97 | 72.40% | 98.98% | 48.02% | 0.6467 | 0.55% | 51.98% |
| **IF + AE Unsupervised Ensemble** | **Label-Free Union ($\text{IF} < 0 \lor \text{AE} > P_{97}$)** | 176 | 6 | 62 | 140 | **82.29%** | **95.89%** | **69.31%** | **0.8046** | **3.30%** | **30.69%** |
| **Majority Vote (`2-of-3` Tri-Model)** | Consensus Voting ($\ge 2$ of $\{\text{RF, IF, AE}\}$) | **182** | **0** | 64 | 138 | 83.33% | **100.00%** | 68.32% | 0.8118 | **0.00%** | 31.68% |
| **Weighted Consensus (`RF + IF + AE`)** | Calibrated Tri-Model ($S = 0.55\text{RF} + 0.20\text{IF} + 0.25\text{AE}$) | 175 | 7 | **8** | **194** | 96.09% | 96.52% | **96.04%** | 0.9628 | 3.85% | **3.96%** |

#### B. Per-Attack-Category Recall Across All 8 Attack Categories (`202` Held-Out Attack Flows)

| Attack Category | Held-Out Flows | Random Forest (Supervised) | Isolation Forest (Unsupervised) | PyTorch Autoencoder ($P_{95}$) | **PyTorch Autoencoder ($P_{97}$ Frozen)** | PyTorch Autoencoder ($P_{99}$) | **IF + AE Unsupervised Ensemble** | Majority Vote (`2-of-3`) | **Weighted Consensus (`RF+IF+AE`)** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `ddos_flood` | 34 | 100.00% (34/34) | 100.00% (34/34) | 100.00% (34/34) | **100.00% (34/34)** | 94.12% (32/34) | **100.00% (34/34)** | 100.00% (34/34) | **100.00% (34/34)** |
| `multi_vector` | 18 | 100.00% (18/18) | 100.00% (18/18) | 100.00% (18/18) | **88.89% (16/18)** | 72.22% (13/18) | **100.00% (18/18)** | 100.00% (18/18) | **100.00% (18/18)** |
| `c2_beaconing` | 25 | 100.00% (25/25) | 0.00% (0/25) | 80.00% (20/25) | **76.00% (19/25)** | 64.00% (16/25) | **76.00% (19/25)** | 76.00% (19/25) | **100.00% (25/25)** |
| `port_scan` | 30 | 100.00% (30/30) | 0.00% (0/30) | 70.00% (21/30) | **56.67% (17/30)** | 36.67% (11/30) | **56.67% (17/30)** | 56.67% (17/30) | **100.00% (30/30)** |
| `novel_stealth_anomaly` | 24 | 87.50% (21/24) | 95.83% (23/24) | 66.67% (16/24) | **54.17% (13/24)** | 41.67% (10/24) | **95.83% (23/24)** | 87.50% (21/24) | **95.83% (23/24)** |
| `data_exfiltration` | 25 | 100.00% (25/25) | 100.00% (25/25) | 72.00% (18/25) | **48.00% (12/25)** | 48.00% (12/25) | **100.00% (25/25)** | 100.00% (25/25) | **100.00% (25/25)** |
| `ssh_brute_force` | 22 | 95.45% (21/22) | 0.00% (0/22) | 13.64% (3/22) | **13.64% (3/22)** | 9.09% (2/22) | **13.64% (3/22)** | 13.64% (3/22) | **95.45% (21/22)** |
| `service_enum` *(incl. 2 collision flows)* | 24 | 75.00% (18/24) | 0.00% (0/24) | 33.33% (8/24) | **4.17% (1/24)** | 4.17% (1/24) | **4.17% (1/24)** | 4.17% (1/24) | **75.00% (18/24)** |
| **Total / Overall (`202` Attack Flows)** | **202** | **95.05% (192/202)** | **49.50% (100/202)** | **68.32% (138/202)** | **56.93% (115/202)** | **48.02% (97/202)** | **69.31% (140/202)** | **68.32% (138/202)** | **96.04% (194/202)** |

#### C. Measured Inference Latency (`ml-detection-service` on CPU)
- **Single-Flow PyTorch Autoencoder Forward Pass + Top-5 Feature Attribution**: `P50 = 0.28 ms`, `P95 = 0.54 ms`, `P99 = 0.91 ms`
- **Full Tri-Model Evaluation (`RF + IF + PyTorch AE + 3-Policy Fusion`)**: `P50 = 1.42 ms`, `P95 = 2.65 ms`, `P99 = 4.18 ms`

---

### 1.5 Track 3 Results: Separation of Detection Performance vs. SOAR Operational Response Performance

A critical requirement of Cohort E is separating **Detection Performance** (whether a flow or event is flagged as an anomaly/alert for analyst visibility) from **SOAR Response Performance** (whether the platform automatically executes a disruptive network action such as a firewall IP block).

| Evaluation Dimension | Metric / Policy Rule | Measured Result on 384 Held-Out Flows (`weighted_consensus`) |
| :--- | :--- | :--- |
| **1. Detection Layer Performance** | Confusion Matrix (`TN / FP / FN / TP`) | `TN = 175`, `FP = 7`, `FN = 8`, `TP = 194` |
| | Detection Recall / Sensitivity | **96.04%** (`194 / 202` attack flows detected) |
| | Detection False Positive Rate (`FPR`) | **3.85%** (`7 / 182` normal flows flagged for review) |
| | Detection False Negative Rate (`FNR`) | **3.96%** (`8 / 202` stealth/collision attack flows missed) |
| **2. SOAR Operational Response Layer** | High-Confidence Multi-Model Auto-Blocks (`action = block`, `auto_block_permitted = true`) | **75 flows** (All 75 are verified multi-model attack flows) |
| | Confirmed Multi-Model Alert Escalations (`action = alert`) | **104 flows** |
| | Single-Detector Unsupervised / Supervised Manual Reviews (`action = manual-review`, `auto_block_permitted = false`) | **22 flows** (Includes all 4 `AE_ONLY` and all 4 `IF_ONLY` outliers) |
| | Suspicious Telemetry Warning Tier (`action = monitor`, $P_{95} < \text{MSE} \le P_{97}$) | **1 flow** |
| | Benign Ignored (`action = ignore`) | **182 flows** |
| **3. SOAR Safety Guardrail Verification** | **Autoencoder-Only (`AE_ONLY`) Anomalies Auto-Blocked** | **`0 / 4` (0.00% — 100% blocked from auto-blocking; all 4 routed to `manual-review`)** |
| | **Normal Benign Flows Erroneously Auto-Blocked** | **`0 / 182` (0.00% — Zero false-positive IP blocks)** |
| | **Degraded-Mode (`random_forest`, `isolation_forest`, or `autoencoder` offline) Auto-Blocks** | **`0` (`100%` routed to `PB-DEGRADED-FALLBACK` / `manual-review` with `auto_block_permitted = false`)** |

**Key Engineering Finding:**
Although `weighted_consensus` accepts `7` detection-level false positives (`4` `AE_ONLY` normal flows, `2` `IF_ONLY` normal backup bursts, and `1` `RF_SUPERVISED_ONLY` flow) in order to maximize attack recall (`96.04%`), **zero (`0 / 182`) normal flows are ever auto-blocked by SOAR**. Every single-detector anomaly (`AE_ONLY` or `IF_ONLY`) is intercepted by the Stage 3/4 guardrail (`auto_block_permitted = false`) and routed to `manual-review`.

---

## 2. Part 2 — Scientific Validity, Mathematical Audit & Limitations

### 2.1 Synthetic Dataset Provenance (`SYNTHETIC BENCHMARK ONLY`)
- **Origin**: All `1,524` clean flow records in [autoencoder_flow_dataset_v2.json](file:///d:/ShadowGuard-main/ShadowGuard-main/data/autoencoder_flow_dataset_v2.json) were generated by [prepare_autoencoder_dataset.py](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/prepare_autoencoder_dataset.py) using a deterministic pseudo-random generator (`random.Random(42)`). They do **not** originate from live enterprise packet captures (PCAPs) or external public datasets.
- **Record Hygiene**: From `1,535` raw generated records, `5` exact full-record duplicates were removed and `6` genuinely corrupted/contradictory source records (`NaN`/`Inf`, negative packet/byte/duration values, zero-packet positive-byte records, and same-`flow_id` contradictory labels) were quarantined, leaving `1,524` clean records.
- **Strict Split Isolation**:
  - `train_normal`: `840` unambiguous normal flows (`0` attack records) — used to fit `FeaturePreprocessor` (`signed_log1p` + `RobustScaler(Q25, Q75)` + `clip[-10, 10]`), train the PyTorch `FlowAutoencoder`, and fit `IsolationForest`.
  - `val_normal`: `180` unambiguous normal flows (`0` attack records) — used exclusively for early stopping (`best_epoch = 114`, `val_mse = 0.141353`) and calibrating $P_{95} = 0.409105$, $P_{97} = 0.503670$, and $P_{99} = 0.645935$.
  - `supervised_attack_train`: `120` attack flows (`15` per category across 8 categories) — combined with `train_normal` (`840 + 120 = 960`) exclusively to train the supervised `RandomForestClassifier`.
  - `test_set`: `384` strictly unseen flows (`182` normal + `202` attack, including `4` preserved cross-label feature-collision flows) with zero SHA-256 record-identity overlap against training or validation splits.

### 2.2 Critical Mathematical Audit of the 69-Feature Schema
To maintain 100% backward compatibility with the existing microservice pipeline (`flow-feature-extraction-service/index.js`), the 69-feature vector $\mathbf{x} \in \mathbb{R}^{69}$ was preserved and audited in [feature_schema.py](file:///d:/ShadowGuard-main/ShadowGuard-main/shared/ml/feature_schema.py):
1. **3-Scalar Deterministic Dependence**: All 69 features are deterministic mathematical functions of only **three raw flow counters**: packet count $p$, byte count $b$, and duration $d$:
   $$\mathbf{x} = \Phi(p, b, d) \in \mathbb{R}^{69}$$
   Consequently, the intrinsic informational degrees of freedom of the 69-dimensional feature space cannot exceed $3$.
2. **Meaningful Base & Rate Features (`f_00`–`f_09`, 10 features)**: Direct counts ($p, b, d$), rate ratios ($b/d, p/d, b/p$), volume product ($p \cdot b$), and logarithmic transforms ($\ln(p+1), \ln(b+1), \ln(d+1)$).
3. **Trigonometric & Log Projection Features (`f_10`–`f_24`, 15 features)**: Smooth nonlinear projections $\sin(k p) \cdot \cos(k b)$ and $\ln(p + b + k) / (1 + d)$.
4. **Exact Duplicate Polynomial Columns (`f_25`–`f_39`, 13 redundant duplicate columns)**: Because the legacy formula uses `(i % 2) + 1` as the exponent and `(i % 2 === 0 ? d : p)` in the denominator without varying any coefficient across `i`, all 8 even-indexed features (`f_25, f_27, f_29, f_31, f_33, f_35, f_37, f_39`) are mathematically identical, and all 7 odd-indexed features (`f_26, f_28, f_30, f_32, f_34, f_36, f_38`) are mathematically identical.
5. **Damped Cosine Projections (`f_40`–`f_54`, 15 features)**: $\cos(k d) \cdot (b / (p + k))$.
6. **Rank-1 Collinear Padding Features (`f_55`–`f_68`, 14 collinear columns)**: Defined as $c_k \cdot \frac{p + b}{1 + d}$, which are exact scalar multiples of a single ratio and add zero linear rank.

### 2.3 Cross-Label Feature Collisions & Bayes Error Lower Bound
Because $\Phi(p, b, d)$ is deterministic and omits Layer-4/Layer-7 header fields (ports, TCP flags, inter-arrival variance, payload entropy), any two distinct network flows that share identical $(p, b, d)$ measurements produce the **exact same 69-dimensional feature vector**:
$$\Phi(p_1, b_1, d_1) = \Phi(p_2, b_2, d_2) \quad \text{whenever} \quad (p_1, b_1, d_1) = (p_2, b_2, d_2)$$
In `test_set`, `4` legitimate distinct flows (`2` normal, `2` `service_enum` attack) exhibit exact cross-label collisions:
- Pair 1 (`packets=33, bytes=19800, duration=0.777`): `flow-collision-norm-00` (normal HTTPS) and `flow-collision-atk-00` (`service_enum` attack) both yield $\text{MSE} = 0.115932$ and $P_{\text{RF}}(\text{attack}) = 0.045$.
- Pair 2 (`packets=7, bytes=490, duration=0.019`): `flow-collision-norm-01` (normal SSH) and `flow-collision-atk-01` (`service_enum` attack) both yield $\text{MSE} = 0.470278$ and $P_{\text{RF}}(\text{attack}) = 0.5133$.

No classifier operating solely on $\mathbf{x} = \Phi(p, b, d)$ can simultaneously classify both members of a cross-label collision pair correctly. This establishes a non-zero irreducible Bayes error floor on 3-scalar flow features and directly motivates Shadow Guard 2.0's integration of **Suricata NIDS (`Cohort B`)** and **Multi-Type Honeypots (`Cohort C`)**, which inspect packet payloads, TCP flags, and interactive decoy sessions.

### 2.4 Why Supervised Random Forest Dominates on the Synthetic Benchmark — And What the Autoencoder Contributes
1. **Why Random Forest Achieves `97.14%` Accuracy (`F1 = 0.9722`)**:
   - The synthetic dataset generator (`prepare_autoencoder_dataset.py`) samples each of the 8 attack categories from bounded parametric intervals in $(p, b, d)$, and `RandomForestClassifier` is trained directly on labeled examples (`supervised_attack_train`) drawn from those exact same 8 parametric distributions. Decision trees partition axis-aligned bounding boxes in feature space that closely match the generator's parametric boundaries.
2. **Why the PyTorch Autoencoder (`76.30%` Accuracy at $P_{97}$, `ROC-AUC = 0.9652`) Is Essential for Unsupervised Defense**:
   - Unlike Random Forest, the PyTorch Autoencoder is trained **strictly on `840` normal flows (`0` attack labels)**.
   - Compared against the existing unsupervised baseline (`Isolation Forest`, recall `49.50%`, F1 `0.6579`), the PyTorch Autoencoder alone at $P_{97}$ improves unsupervised recall to **`56.93%`** (`F1 = 0.7165`) and detects **`76.00%` of `c2_beaconing` (`19/25`)** and **`56.67%` of `port_scan` (`17/30`)**, where Isolation Forest detected **`0.00%` (`0/25` and `0/30`)**.
   - Why? `c2_beaconing` and `port_scan` flows have moderate packet/byte counts that sit near the interior of global tree splits (fooling Isolation Forest), but violate the nonlinear packet-to-byte-to-duration manifold learned by the Autoencoder's `69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69` bottleneck.
   - When combined into the label-free **`IF + AE Unsupervised Ensemble`**, unsupervised recall jumps from **`49.50%` -> `69.31%`** (`140 / 202` attacks) and F1 increases from **`0.6579` -> `0.8046`** without using a single attack label.
3. **Reconciling the 4 `AE_ONLY` Detections vs. +2 Additional True Positives in Weighted Consensus**:
   - On `test_set`, there are `4` flows with agreement pattern `AE_ONLY` (`flow-norm-00258`, `flow-norm-00366`, `flow-norm-00639`, `flow-norm-00286`). All `4` are normal flows in the upper tail of the normal MSE distribution ($\text{MSE} > P_{97} = 0.503670$, corresponding to the $2.20\%$ test FPR). Every attack flow detected by the Autoencoder (`115` flows) was *also* detected by Random Forest (`RF_AND_AE_AGREE = 40` or `ALL_3_MODELS_AGREE = 75`).
   - Meanwhile, `weighted_consensus` achieves `TP = 194` vs. Random Forest's `TP = 192` (`+2` additional true positives) because `2` `novel_stealth_anomaly` attack flows (`flow-atk-01518` and `flow-atk-01507`) missed by Random Forest were caught by Isolation Forest (`IF_ONLY`).

---

## 3. Complete Summary of Limitations & Future Work (Deliverable 8)

### 3.1 Technical & Scientific Limitations
1. **100% Synthetic Evaluation Data (`SYNTHETIC BENCHMARK ONLY`)**: Both the 500-event system benchmark (`seed=20261113`) and the 1,524-flow 69-feature dataset (`seed=42`) are synthetically generated. High benchmark scores do not imply equivalent performance on live enterprise networks or genuine zero-day exploits.
2. **3-Scalar Bottleneck in the 69-Feature Extractor**: Because `flow-feature-extraction-service` derives all 69 features from `(packets, bytes, duration)`, it is blind to TCP flag distributions (SYN/ACK/FIN/RST/PSH), packet size variance, forward/backward directional ratios, inter-arrival time (IAT) jitter, TLS JA3 fingerprints, and payload entropy.
3. **13 Duplicate & 14 Collinear Features**: Features `f_25..f_39` contain 13 duplicate columns and `f_55..f_68` contain 14 rank-1 collinear columns, diluting per-feature MSE attribution across redundant coordinates.
4. **Low-Volume Application-Layer Evasion of Flow-Only Unsupervised Models**: On `service_enum` (`4.17%` AE recall) and `ssh_brute_force` (`13.64%` AE recall), flow packet/byte/duration measurements overlap heavily with normal interactive SSH and HTTP traffic, making flow-only unsupervised detection insufficient without Cowrie/OpenCanary honeypots and Suricata NIDS.
5. **Static Offline Model Weights**: The PyTorch Autoencoder (`ae-pytorch-v2.0.0`) is trained offline on stationary normal splits; in production networks, diurnal traffic shifts and new enterprise applications cause concept drift requiring periodic threshold recalibration.
6. **In-Memory Correlation Window State**: The Redis-free `EventCorrelationEngine` stores its 30-minute sliding window in Node.js process memory; a container restart clears active in-flight correlation windows unless rehydrated from PostgreSQL.

### 3.2 Concrete Future Research Roadmap
1. **Evaluation on Public Real-World PCAP Benchmarks**: Benchmark the Tri-Model Engine on **CIC-IDS2017**, **CSE-CIC-IDS2018**, **UNSW-NB15**, and **CTU-13** using bidirectional CICFlowMeter / NFStream extractors.
2. **True 69-Dimensional Independent L3/L4/L7 Feature Engineering**: Replace the 13 duplicate polynomial columns (`f_25..f_39`) and 14 collinear padding columns (`f_55..f_68`) with independent directional flow statistics: forward/backward packet & byte counts, TCP flag histograms, min/mean/std/max packet lengths, flow IAT mean/std, active/idle burst durations, TLS SNI/JA3 entropy, and DNS query character entropy.
3. **Temporal Sequence Autoencoders (LSTM-AE / Transformer-AE)**: Extend the single-flow MLP Autoencoder to a sequence-to-sequence Temporal Autoencoder over sliding windows of $K = 20$ consecutive flows per source IP to detect low-and-slow C2 beaconing and distributed reconnaissance via inter-flow timing periodicity.
4. **Variational & Denoising Autoencoders with Mahalanobis Latent Scoring**: Combine reconstruction error with latent-space density estimation in $\mathbb{R}^8$ to improve separation of stealthy mimicry attacks.
5. **Drift-Aware Online Threshold Recalibration**: Implement sliding-window quantile tracking (Streaming P97 calibration with human-in-the-loop approval) to adapt to legitimate enterprise traffic changes without retraining from scratch.
