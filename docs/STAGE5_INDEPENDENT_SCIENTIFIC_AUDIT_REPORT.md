# Shadow Guard 2.0 — Stage 5 Independent Scientific Audit Report

**Classification:** `SYNTHETIC BENCHMARK ONLY`  
**Audit Date:** November 15, 2026  
**Scope:** Independent Scientific Audit of Cohort E (`scripts/evaluate_cohort_e_benchmark.js`), Stage 7 Cohorts A–D (`scripts/evaluate_research_cohorts.js`), Event Schemas, Correlation Rules, Threat Intelligence, SOAR Guardrails, 26-Chapter B.Tech Thesis, Viva Defense Guide, and Docker Deployment Verification.  
**Historical Benchmark Preservation:** `evaluation/results/benchmark_results.json` and `scripts/evaluate_research_cohorts.js` (Cohorts A–D) were **not modified** (`SHA-256` byte-for-byte identical).

---

## 1. Label-Leakage, Target-Leakage & Deterministic Scenario-Shortcut Findings

### 1.1 Why the Initial Stage 5 Cohort E Result (`TP=360, FP=0, TN=140, FN=0`, `100.00%`) Was Invalid
An line-by-line code audit of the initial Stage 5 implementation of [evaluate_cohort_e_benchmark.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_cohort_e_benchmark.js) and the inherited Stage 7 benchmark generator [evaluate_research_cohorts.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_research_cohorts.js) identified **five concrete methodological flaws and leakage pathways** that artificially produced the `100.00%` (`TP=360, FP=0, TN=140, FN=0`) Cohort E result:

| Finding ID | Exact File, Function & Line References | Leakage / Shortcut Type | Technical Mechanism & Impact on Initial `100%` Result |
| :--- | :--- | :--- | :--- |
| **LEAK-01** | `scripts/evaluate_cohort_e_benchmark.js` (`buildCohortEDatasetWithTriModelTelemetry`, initial lines `86–98`) | **Post-Hoc Model-Output & Ground-Truth Selection Leakage** | Filtered `triModelDetections` using `d.ground_truth.binary_label === 'normal'` and constructed `normalCleanFlows` via `!d.models.isolation_forest.is_anomaly && !d.models.autoencoder.is_anomaly && !d.models.random_forest.is_anomaly`. This explicitly excluded any normal flow where Random Forest or both unsupervised models had a false positive. |
| **LEAK-02** | `scripts/evaluate_cohort_e_benchmark.js` (`runCohortEBenchmark`, initial line `883`) + `data/tri_model_dashboard_telemetry_v2.json` | **Curated 55-Flow Subset Selection Bias** | Loaded `triTelemetry.detections` (the 55-flow curated UI display list) instead of the full 384-flow held-out `test_set` in `data/autoencoder_flow_dataset_v2.json`. In the 55-flow subset, all normal outlier flows happened to be single-detector (`AE_ONLY` or `IF_ONLY`, `modelsAgreeCount = 1`), omitting `flow-collision-norm-01` (`MULTI_MODEL_CONFIRMED_THREAT`, `modelsAgreeCount = 2` with `RF=0.5133` and `AE=0.4703 >= P95`). |
| **LEAK-03** | `scripts/evaluate_cohort_e_benchmark.js` (`buildCohortEDatasetWithTriModelTelemetry`, initial lines `125–127` & `evaluateCohortE`, initial lines `578–598`) | **Generator-Only Variable + Post-Hoc Rule Tailoring** | Used the generator-only variable `isBurstyBenign = (i % 6 === 0)` to assign `normalBurstyFlows` (`modelsAgreeCount = 1`) vs. `normalCleanFlows` (`modelsAgreeCount = 0`), and then replaced the frozen `weighted_consensus` policy (`triDecision.is_anomaly`) in `evaluateCohortE` with an ad-hoc rule (`modelsAgreeCount >= 2 \|\| rfProb >= 0.80`). Because `S01_NORMAL_TRAFFIC` only contained flows with `modelsAgreeCount <= 1` and `rfProb <= 0.26`, `FP = 0` (`100%` specificity) was guaranteed by construction. |
| **LEAK-04** | `scripts/evaluate_cohort_e_benchmark.js` (initial line `170` & line `629`) + `playbook-decision-engine/index.js` (`deriveRiskMetadata`, lines `174–178`) | **Ground-Truth Label String Leakage into SOAR `/decide`** | In `S01_NORMAL_TRAFFIC`, events with `isBurstyBenign === false` set `ml_metadata.attack_type = 'BENIGN'`. When `evaluateCohortE` called `POST /decide` (`line 629`), it passed `context.attack_type = ml.attack_type` (`'BENIGN'`). Inside `playbook-decision-engine/index.js` (`deriveRiskMetadata`, lines `174–178`), `if (attackType === 'normal_traffic' \|\| attackType === 'benign')` forced `recommendedAction = 'monitor'` even when `prediction === 1` (`anomalous`)! |
| **SHORTCUT-05** | `scripts/evaluate_research_cohorts.js` (`generateLabeledBenchmarkDataset`, lines `150–442`) + `threat-intelligence-service/providers/intelProviders.js` (`KNOWN_IOC_CATALOG`, lines `28–90` & `isPrivateOrInternalIp`, lines `169–179`) | **Deterministic Sensor & IOC Coverage Shortcut on `S02–S10`** | In the Stage 7 500-event generator, `100%` (`360/360`) of malicious events across `S02–S10` are generated with either a non-null `nids_metadata.signature_id` (`180` events: `S02, S07, S08, S09` + half of `S10`) or a non-null `honeypot_metadata.honeypot_id` (`180` events: `S03, S04, S05, S06` + half of `S10`), and all `360` malicious events use 5 external IPs hardcoded in `KNOWN_IOC_CATALOG.ips` (`reputation_score: 78–98`), while all `140` benign events in `S01` use RFC1918 `10.20.x.x` IPs (`reputation_score: 0`). Consequently, `nidsHit \|\| honeypotHit` is `true` for `360/360` (`100%`) of malicious events before any ML model is consulted. |

### 1.2 Audit Inspection of Remaining Modules (Clean vs. Shortcut Verification)
- **[shared/lib/eventContract.js](file:///d:/ShadowGuard-main/ShadowGuard-main/shared/lib/eventContract.js) (`createEvent`, lines `14–68`; `createNormalizedEvent`, lines `124–156`)**: Does **not** contain or expose `ground_truth`, `binary_label`, or `scenario` fields. Normalized events only carry `source_domain`, `source_service`, `event_type`, `severity`, `confidence`, `telemetry`, `nids_metadata`, `honeypot_metadata`, and `ml_metadata`.
- **[event-correlation-service/engine/correlationEngine.js](file:///d:/ShadowGuard-main/ShadowGuard-main/event-correlation-service/engine/correlationEngine.js) (`correlateEvent`, lines `129–183`; `_evaluateRules`, lines `188–295`)**: Evaluates rules `CORR-01` through `CORR-06` using `event_type`, `source_category`, `nids_metadata`, `honeypot_metadata`, `ml_metadata`, and `threatIntel.reputation_score`. Does **not** read `ground_truth` or `scenario`. However, note that `this.dedupWindowMs = options.dedupWindowMs || 2000` (line `42`) defaults to `2000 ms` when `dedupWindowMs: 0` is passed (because `0` is falsy in JS), causing `120` consecutive events spaced `1500 ms` apart to be deduplicated prior to rule correlation.
- **[playbook-decision-engine/engine/soarPlaybookEngine.js](file:///d:/ShadowGuard-main/ShadowGuard-main/playbook-decision-engine/engine/soarPlaybookEngine.js) (`evaluateContext`, lines `121–227`)**: Evaluates `PB-SOAR-01` through `PB-SOAR-05` strictly on `attacker_risk_score`, `incident_severity`, `honeypot_interaction_count`, `classification_confidence`, `repeated_offense_count`, and `threat_intelligence_reputation`. Does **not** read ground-truth labels.

### 1.3 Remedies Applied Before Recalculating Cohort E
1. Exported all **384 held-out test flows** from `data/autoencoder_flow_dataset_v2.json` (`splits.test_set`) evaluated directly through the frozen Python `TriModelDetectionEngine` (`shared/ml/tri_model_fusion.py`) to [held_out_384_tri_model_predictions.json](file:///d:/ShadowGuard-main/ShadowGuard-main/data/held_out_384_tri_model_predictions.json).
2. Replaced `buildCohortEDatasetWithTriModelTelemetry` in [evaluate_cohort_e_benchmark.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_cohort_e_benchmark.js) (`lines 97–419`) with `buildLeakFreeCohortEDataset`, which assigns the unfiltered `182` held-out normal test flows and `202` held-out attack test flows sequentially in their fixed `seed=42` order **without inspecting any model predictions (`models.*`) or `isBurstyBenign`**.
3. Replaced the ad-hoc `modelsAgreeCount >= 2` rule in `evaluateCohortE` ([evaluate_cohort_e_benchmark.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_cohort_e_benchmark.js#L510-L519)) with the **frozen `weighted_consensus` policy (`Boolean(triDecision.is_anomaly)`)**.
4. Fixed the `attack_type: 'BENIGN'` leak when calling `POST /decide` ([evaluate_cohort_e_benchmark.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_cohort_e_benchmark.js#L576-L585)) so any flow flagged as an anomaly by Tri-Model ML passes `attack_type: 'FLOW_ANOMALY'` instead of leaking `'BENIGN'`.

---

## 2. Experimental Independence Findings

1. **How Training, Validation, and Test Events Are Separated**:
   - **Track 2 (69-Feature Network Flow Dataset — `1,524` Clean Flows in [prepare_autoencoder_dataset.py](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/prepare_autoencoder_dataset.py#L513-L590))**:
     - Enforces strict, leak-free split separation verified by full-record SHA-256 identity hashes (`zero_hash_overlap_verified = true`, lines `558–567`):
       - `train_normal`: `840` unambiguous normal flows (`70%` of normal) — used **exclusively** to fit `FeaturePreprocessor` (`RobustScaler`), train `FlowAutoencoder`, fit `IsolationForest`, and provide the normal class for `RandomForestClassifier`.
       - `val_normal`: `180` unambiguous normal flows (`15%` of normal) — used **exclusively** for Autoencoder early-stopping checkpoint selection (`best_epoch = 114`, `val_mse = 0.141353`) and `P95 / P97 / P99` threshold calibration.
       - `supervised_attack_train`: `120` attack flows (`15` per category across 8 categories) — used **only** for supervised `RandomForestClassifier` training; never seen by the Autoencoder or Isolation Forest.
       - `test_set`: `384` untouched held-out flows (`182` normal + `202` attack, including all `4` preserved cross-label feature-collision flows) — strictly unseen during training and threshold calibration.
   - **Track 1 (500-Event Multi-Source System Benchmark — `S01–S10` in [evaluate_research_cohorts.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_research_cohorts.js#L103-L447) and [evaluate_cohort_e_benchmark.js](file:///d:/ShadowGuard-main/ShadowGuard-main/scripts/evaluate_cohort_e_benchmark.js#L97-L419))**:
     - **Explicit Disclosure**: The 500-event multi-source system benchmark (`140` benign events in `S01` + `360` malicious events in `S02–S10`) is a **rule, sensor, correlation, and SOAR evaluation stream**; it does **not** have separate training/validation/test splits for Suricata NIDS signatures, Honeypot adapters, Threat Intelligence IOC catalogs, or Correlation rules (`CORR-01..CORR-06`), which are deterministic domain rules. In Cohort E, its network flow layer is paired sequentially with the **unseen held-out `test_set` flows** (`384` flows) from Track 2.
2. **Whether Fusion and Correlation Policies Were Frozen Before Test Evaluation**:
   - The PyTorch Autoencoder threshold ($P_{97} = 0.503670$) was frozen on `val_normal` in Stage 2 (`models/autoencoder_metadata.json`).
   - The three Tri-Model fusion policies (`weighted_consensus`, `unsupervised_ensemble`, `majority_vote`) in [tri_model_fusion.py](file:///d:/ShadowGuard-main/ShadowGuard-main/shared/ml/tri_model_fusion.py#L404-L536) and the correlation rules (`CORR-01..CORR-06`) in [correlationEngine.js](file:///d:/ShadowGuard-main/ShadowGuard-main/event-correlation-service/engine/correlationEngine.js#L188-L295) were defined prior to Stage 5.
   - **Audit Finding**: In the initial Stage 5 draft of `evaluate_cohort_e_benchmark.js`, an un-frozen ad-hoc rule (`modelsAgreeCount >= 2`) had been introduced inside the benchmark script specifically to suppress false positives on `S01_NORMAL_TRAFFIC`. In the corrected audit, that post-hoc rule was removed and replaced with the frozen Stage 3 `weighted_consensus` policy (`triDecision.is_anomaly`).
3. **Whether All Five Cohorts (`A, B, C, D, E`) Use Comparable Evaluation Conditions**:
   - Cohorts A, B, C, and D evaluate the scalar `ev.ml_metadata` generated by `Mulberry32(20261113)` on the 500 events, whereas Cohort E replaces scalar `ev.ml_metadata` with the 69-feature `TriModelDetectionEngine` evaluated on the held-out `test_set` flows (`seed = 42`). All five cohorts share the exact same 500-event scenario structure (`140` benign in `S01`, `360` malicious in `S02–S10`), the same NIDS and Honeypot metadata on `S02–S10`, and the same Correlation and SOAR engines in Cohorts D and E.
4. **Whether the Same Parametric Attack Patterns Appear in Training and Testing**:
   - **Yes (Parametric Family Overlap)**: Although `test_set` (`384` flows) has zero record overlap (`zero_hash_overlap_verified = true`) with `train_normal` (`840`), `val_normal` (`180`), and `supervised_attack_train` (`120`), all splits are generated by the same parametric generator (`scripts/prepare_autoencoder_dataset.py` with `seed = 42`). Therefore, `test_set` evaluates generalization to **unseen samples drawn from the same synthetic parametric distributions**, NOT genuinely novel real-world exploit families.
5. **Reproducibility via Documented Random Seeds**:
   - Running `python scripts/prepare_autoencoder_dataset.py` (`seed = 42`) and `node scripts/evaluate_cohort_e_benchmark.js` (`seed = 20261113` & `seed = 42`) reproduces the exact same confusion matrices and metrics on every execution.

---

## 3. Recalculated Benchmark Results (Before vs. After Leak Fix)

### 3.1 Track 1: 500-Event System Benchmark (Preserved Cohorts A–D vs. Invalidated Initial Cohort E vs. Audited Leak-Free Cohort E)

| Cohort | TP | FP | TN | FN | Accuracy | Precision | Recall | F1-Score | FPR | FNR | Raw Alerts | Consolidated Incidents | Alert Consolidation |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cohort A (`SG 1.0 ML Only`, Preserved)** | 216 | 24 | 116 | 144 | 66.40% | 90.00% | 60.00% | 72.00% | 17.14% | 40.00% | 240 | 240 | 0.00% |
| **Cohort B (`+Suricata NIDS`, Preserved)** | 276 | 13 | 127 | 84 | 80.60% | 95.50% | 76.67% | 85.05% | 9.29% | 23.33% | 289 | 289 | 0.00% |
| **Cohort C (`+Honeypots`, Preserved)** | 326 | 13 | 127 | 34 | 90.60% | 96.17% | 90.56% | 93.28% | 9.29% | 9.44% | 339 | 339 | 0.00% |
| **Cohort D (`Complete SG 2.0`, Preserved)** | 360 | 6 | 134 | 0 | 98.80% | 98.36% | 100.00% | 99.17% | 4.29% | 0.00% | 366 | 5 | 98.63% |
| *Cohort E (Initial Stage 5 — Invalidated by LEAK-01..03)* | *360* | *0* | *140* | *0* | *100.00%* | *100.00%* | *100.00%* | *100.00%* | *0.00%* | *0.00%* | *360* | *5* | *98.61%* |
| **Cohort E (Audited Leak-Free, Frozen `weighted_consensus`)** | **360** | **3** | **137** | **0** | **99.40%** | **99.17%** | **100.00%** | **99.59%** | **2.14%** | **0.00%** | **363** | **5** | **98.62%** |

### 3.2 Per-Attack-Category Precision, Recall, and F1 on Track 2 (`384` Held-Out Flows: `182` Normal + `202` Attack, Frozen `weighted_consensus`)
Across the `182` held-out normal flows in `test_set`, `weighted_consensus` produces **`TN = 175, FP = 7` (`FPR = 3.85%`)**. Across the `202` held-out attack flows, `weighted_consensus` produces **`TP = 194, FN = 8` (`Recall = 96.04%, FNR = 3.96%`)**. The table below reports each attack category's exact `TP`, `FN`, `Recall`, `FNR`, **One-vs-182-Normal Precision & F1** (evaluating category $c$ against all $182$ held-out normal flows where $FP = 7$), and **Apportioned-FP Precision & F1** (where the $7$ normal FPs are apportioned by category size $7 \times N_c / 202$):

| Attack Category (`test_set`) | Total Flows ($N_c$) | TP | FN | Recall (%) | FNR (%) | Precision (vs. All 7 Normal FPs) | F1 (vs. All 7 Normal FPs) | Precision (Apportioned FP) | F1 (Apportioned FP) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`ddos_flood`** | 34 | 34 | 0 | **100.00%** | 0.00% | 82.93% (`34/41`) | 0.9067 | 96.65% | 0.9830 |
| **`port_scan`** | 30 | 30 | 0 | **100.00%** | 0.00% | 81.08% (`30/37`) | 0.8955 | 96.65% | 0.9830 |
| **`data_exfiltration`** | 25 | 25 | 0 | **100.00%** | 0.00% | 78.13% (`25/32`) | 0.8772 | 96.65% | 0.9830 |
| **`c2_beaconing`** | 25 | 25 | 0 | **100.00%** | 0.00% | 78.13% (`25/32`) | 0.8772 | 96.65% | 0.9830 |
| **`multi_vector`** | 18 | 18 | 0 | **100.00%** | 0.00% | 72.00% (`18/25`) | 0.8372 | 96.65% | 0.9830 |
| **`novel_stealth_anomaly`** | 24 | 23 | 1 | **95.83%** | 4.17% | 76.67% (`23/30`) | 0.8519 | 96.51% | 0.9617 |
| **`ssh_brute_force`** | 22 | 21 | 1 | **95.45%** | 4.55% | 75.00% (`21/28`) | 0.8400 | 96.50% | 0.9597 |
| **`service_enum`** | 24 | 18 | 6 | **75.00%** | 25.00% | 72.00% (`18/25`) | 0.7347 | 95.58% | 0.8405 |
| **All Attack Categories Combined** | **202** | **194** | **8** | **96.04%** | **3.96%** | **96.52% (`194/201`)** | **0.9628** | **96.52%** | **0.9628** |

### 3.3 Per-Scenario Precision, Recall, and F1 on Track 1 (`500` System Events: Baseline Cohort E vs. Ablation 5 Pure Tri-Model ML Only)
On the 500-event Track 1 benchmark (`140` benign in `S01` with `FP = 3, TN = 137`; `40` malicious per scenario in `S02–S10`):

| Scenario ID | Events | Baseline Cohort E (`TP / FN`) | Baseline Recall (%) | Baseline Precision (vs. 3 `S01` FPs) | Baseline F1 | Pure Tri-Model ML Only (`TP / FN`) | Pure Tri-Model ML Recall (%) | Pure Tri-Model ML Precision (vs. 3 `S01` FPs) | Pure Tri-Model ML F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`S01_NORMAL_TRAFFIC`** | 140 | `TN=137, FP=3` | `97.86%` (Spec.) | `FPR = 2.14%` | — | `TN=137, FP=3` | `97.86%` (Spec.) | `FPR = 2.14%` | — |
| **`S02_PORT_SCANNING`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | `40 / 0` | 100.00% | 93.02% | 96.39% |
| **`S03_SSH_BRUTE_FORCE`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | **`38 / 2`** | **95.00%** | 92.68% (`38/41`) | **93.83%** |
| **`S04_HTTP_FTP_SMB_RECON`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | **`30 / 10`** | **75.00%** | 90.91% (`30/33`) | **82.19%** |
| **`S05_HONEYPOT_COMMAND_EXEC`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | **`39 / 1`** | **97.50%** | 92.86% (`39/42`) | **95.12%** |
| **`S06_MALWARE_SAMPLE_DOWNLOAD`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | `40 / 0` | 100.00% | 93.02% | 96.39% |
| **`S07_DDOS_VOLUMETRIC`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | `40 / 0` | 100.00% | 93.02% | 96.39% |
| **`S08_DATA_EXFILTRATION`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | `40 / 0` | 100.00% | 93.02% | 96.39% |
| **`S09_C2_BEACONING`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | `40 / 0` | 100.00% | 93.02% | 96.39% |
| **`S10_MULTI_STAGE_PROGRESSION`** | 40 | `40 / 0` | 100.00% | 93.02% (`40/43`) | 96.39% | `40 / 0` | 100.00% | 93.02% | 96.39% |

### 3.4 Per-Sensor Contribution Breakdown Across the 500 Events (`Track 1`)
- **Total Events**: `500` (`360` malicious across `S02–S10`, `140` benign in `S01_NORMAL_TRAFFIC`)
- **Suricata NIDS (`nidsHit`)**: Detects **`180 / 360` (`50.00%`)** of malicious events (`S02, S07, S08, S09` + steps 0 & 3 of `S10`); `0 / 140` false positives on `S01`.
- **Multi-Type Honeypots (`honeypotHit`: Cowrie, OpenCanary, Dionaea)**: Detects **`180 / 360` (`50.00%`)** of malicious events (`S03, S04, S05, S06` + steps 1 & 2 of `S10`); `0 / 140` false positives on `S01`.
- **Threat Intelligence IOC Lookup (`intel.is_malicious`)**: Matches **`360 / 360` (`100.00%`)** of malicious events (via the 5 external attacker IPs in `KNOWN_IOC_CATALOG.ips`), but in `evaluateCohortE` (`line 523`), Threat Intel is only permitted to corroborate an event when an ML detector flags the flow as anomalous/suspicious (`intelCorroboratedMl`).
- **Tri-Model ML Engine (`triModelHit`: RF + IF + PyTorch AE under `weighted_consensus`)**:
  - Independently detects **`347 / 360` (`96.39%`)** of malicious events (`180 / 180` NIDS-targeted events + `167 / 180` Honeypot-targeted events).
  - Misses **`13 / 360` (`3.61%`)** low-volume stealth events (`2` in `S03_SSH_BRUTE_FORCE`, `10` in `S04_HTTP_FTP_SMB_RECON`, `1` in `S05_HONEYPOT_COMMAND_EXEC`), which are **rescued solely by Cowrie and OpenCanary honeypots (`honeypot_only_rescues_missed_by_ml_and_nids = 13`)**.
  - Generates **`3 / 140` (`2.14%` FPR)** false-positive alerts on `S01_NORMAL_TRAFFIC` (`EV-0005`, `EV-0006`, `EV-0131`), all 3 of which have automatic IP blocking inhibited by the SOAR guardrail (`auto_block_permitted = false`).

### 3.5 Concrete False-Positive and False-Negative Examples

#### Concrete False Positives (`Track 1` 500-Event Stream: `3` FPs; `Track 2` 384-Flow `test_set`: `7` FPs)
| Sample / Flow ID | Profile / Scenario | `(packets, bytes, duration)` | RF $P(\text{attack})$ | IF Score | AE MSE ($P_{97}=0.5037$) | Decision Rule | Action & Auto-Block Guardrail |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **`EV-0005` / `flow-norm-00258`** | `normal_web_https` (`S01`) | `(85, 70368, 0.9986s)` | `0.0400` | `0.2480` | **`0.7409`** ($> P_{99}$) | `AUTOENCODER_HIGH_CONFIDENCE_ANOMALY_P99_NO_AUTOBLOCK` | `alert` (`auto_block: false`) |
| **`EV-0006` / `flow-norm-01179`** | `normal_backup_burst` (`S01`) | `(377, 510213, 3.0854s)` | `0.2200` | **`0.7418`** | `0.1137` | `ISOLATION_FOREST_ONLY_ANOMALY_MANUAL_REVIEW` | `manual-review` (`auto_block: false`) |
| **`EV-0131` / `flow-norm-00366`** | `normal_web_http` (`S01`) | `(22, 17193, 0.1578s)` | `0.1533` | `0.1070` | **`0.5725`** ($> P_{97}$) | `AUTOENCODER_ONLY_ANOMALY_P97_MANUAL_REVIEW` | `manual-review` (`auto_block: false`) |
| **`flow-norm-00639`** (`Track 2` idx 152) | `normal_dns_lookup` | `(6, 506, 0.0224s)` | `0.2067` | `0.0752` | **`0.5749`** ($> P_{97}$) | `AUTOENCODER_ONLY_ANOMALY_P97_MANUAL_REVIEW` | `manual-review` (`auto_block: false`) |
| **`flow-norm-00286`** (`Track 2` idx 167) | `normal_web_https` | `(80, 67140, 0.3039s)` | `0.2600` | `0.4964` | **`0.5226`** ($> P_{97}$) | `AUTOENCODER_ONLY_ANOMALY_P97_MANUAL_REVIEW` | `manual-review` (`auto_block: false`) |
| **`flow-norm-01156`** (`Track 2` idx 172) | `normal_backup_burst` | `(340, 408321, 2.4525s)` | `0.0333` | **`0.8151`** | `0.2162` | `ISOLATION_FOREST_ONLY_ANOMALY_MANUAL_REVIEW` | `manual-review` (`auto_block: false`) |
| **`flow-collision-norm-01`** (`Track 2` idx 174) | `normal_sysadmin_check` (Collision) | `(7, 490, 0.0190s)` | **`0.5133`** | `0.0767` | **`0.4703`** ($> P_{95}$) | `MULTI_MODEL_CONFIRMED_THREAT` | `alert` (`auto_block: false`) |

#### Concrete False Negatives (`Track 2` 384-Flow `test_set`: `8` FNs; `Track 1` Ablation 2/5 without Honeypots: `13` FNs)
| Flow ID (`Track 2` & `Track 1` Sample IDs) | Attack Category | `(packets, bytes, duration)` | RF $P(\text{attack})$ | IF Score | AE MSE ($P_{97}=0.5037$) | Why Missed by Flow-Only ML |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **`flow-atk-01272`** (`EV-0194`, `EV-0216` in `S03`) | `ssh_brute_force` | `(32, 2405, 0.4422s)` | `0.4733` ($<0.50$) | `0.0815` | `0.1999` | Short SSH auth flow overlaps normal SSH interactive `(p,b,d)` manifold; rescued in Baseline Cohort E by `cowrie-ssh-01`. |
| **`flow-atk-01481`** (`EV-0278` in `S05`) | `novel_stealth_anomaly` | `(48, 30422, 0.3639s)` | `0.0267` | `0.2488` | `0.2676` | Stealth anomaly sampled inside normal HTTPS volume/duration bounds; rescued in Baseline Cohort E by `cowrie-ssh-01`. |
| **`flow-atk-01318`** (`EV-0225`, `EV-0249` in `S04`) | `service_enum` | `(43, 31064, 2.0789s)` | `0.0000` | `0.0335` | `0.0763` | Low-rate service probe indistinguishable from normal HTTP in 3-scalar space; rescued in Baseline Cohort E by `opencanary-01`. |
| **`flow-atk-01294`** (`EV-0233`, `EV-0257` in `S04`) | `service_enum` | `(47, 20562, 0.3905s)` | `0.0933` | `0.1542` | `0.2358` | Overlaps normal HTTP transfer volume; rescued in Baseline Cohort E by `opencanary-01`. |
| **`flow-atk-01302`** (`EV-0234`, `EV-0258` in `S04`) | `service_enum` | `(18, 9198, 0.7346s)` | `0.1400` | `0.0460` | `0.0933` | Overlaps normal HTTP/SSH flow; rescued in Baseline Cohort E by `opencanary-01`. |
| **`flow-atk-01320`** (`EV-0240` in `S04`) | `service_enum` | `(6, 436, 0.0299s)` | `0.3333` | `0.0829` | `0.2512` | Short probe overlaps DNS/keepalive flow; rescued in Baseline Cohort E by `opencanary-01`. |
| **`flow-atk-01286`** (`EV-0241` in `S04`) | `service_enum` | `(35, 26928, 0.6872s)` | `0.0067` | `0.0764` | `0.1037` | Overlaps normal web flow; rescued in Baseline Cohort E by `opencanary-01`. |
| **`flow-collision-atk-00`** (`EV-0242` in `S04`) | `service_enum` (Collision) | `(33, 19800, 0.7770s)` | `0.0933` | `0.0646` | `0.1159` | Exact `(p,b,d)` collision with `flow-collision-norm-00`; rescued in Baseline Cohort E by `opencanary-01`. |

---

## 4. Cohort E Subsystem Ablation Findings (Executed in Code)

All five subsystem ablations below were executed directly by `node scripts/evaluate_cohort_e_benchmark.js` and persisted in [cohort_e_benchmark_results.json](file:///d:/ShadowGuard-main/ShadowGuard-main/evaluation/results/cohort_e_benchmark_results.json) (`track_1b_cohort_e_subsystem_ablations`):

| Ablation Experiment | TP | FP | TN | FN | Accuracy | Precision | Recall | F1-Score | FPR | FNR | Consolidated Incidents | Benign IPs Auto-Blocked | Key Scientific Finding |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`BASELINE_COHORT_E_COMPLETE`** | 360 | 3 | 137 | 0 | **99.40%** | **99.17%** | **100.00%** | **99.59%** | **2.14%** | **0.00%** | **5** (`98.62%` red.) | **0** | Full multi-sensor + Tri-Model + SOAR guardrail baseline. |
| **`ABLATION_1_THREAT_INTEL_DISABLED`** | 360 | 3 | 137 | 0 | 99.40% | 99.17% | 100.00% | 99.59% | 2.14% | 0.00% | 5 (`98.62%` red.) | 0 | Threat Intel does not inflate binary detection recall because `intelCorroboratedMl` requires ML anomaly/suspicion; disabling it removes `CORR-05` enrichment and lowers profiler risk scores. |
| **`ABLATION_2A_HONEYPOTS_DISABLED`** | **347** | 3 | 137 | **13** | **96.80%** | 99.14% | **96.39%** | **97.75%** | 2.14% | **3.61%** | 5 (`98.57%` red.) | 0 | Disabling Cowrie/OpenCanary/Dionaea causes **13 False Negatives** (`2` in `S03`, `10` in `S04`, `1` in `S05`) where stealth probes mimic normal `(p,b,d)` triples. |
| **`ABLATION_2B_HONEYPOTS_AND_INTEL_DISABLED`** | **347** | 3 | 137 | **13** | **96.80%** | 99.14% | **96.39%** | **97.75%** | 2.14% | **3.61%** | 5 (`98.57%` red.) | 0 | Confirms that the 13 missed stealth events are genuinely undetected by flow ML (`ALL_MODELS_NORMAL`) and cannot be rescued without deception sensors. |
| **`ABLATION_3_WITHOUT_INCIDENT_CORRELATION`** | 360 | 3 | 137 | 0 | 99.40% | 99.17% | 100.00% | 99.59% | 2.14% | 0.00% | **363 (`0.00%` red.)** | 0 | Proves correlation is an incident-grouping layer, not a classifier: `TP/FP/TN/FN` are unchanged, but incidents jump from **`5` to `363`** and kill chains drop from `5` to `0`. |
| **`ABLATION_4_WITHOUT_SOAR_POLICY_FILTERING`** | 360 | 3 | 137 | 0 | 99.40% | 99.17% | 100.00% | 99.59% | 2.14% | 0.00% | 5 (`98.62%` red.) | **3 (`100%` of FPs blocked!)** | Proves SOAR guardrails do not alter detection metrics, but removing `auto_block_permitted = false` causes **3 erroneous automatic IP blocks on benign internal hosts**. |
| **`ABLATION_5_PURE_TRI_MODEL_ML_ONLY`** (No NIDS, No Honeypots, No Intel) | **347** | 3 | 137 | **13** | **96.80%** | **99.14%** | **96.39%** | **97.75%** | **2.14%** | **3.61%** | 5 | 0 | Standalone 69-feature Tri-Model ML on the 500 events improves over Cohort A (`SG 1.0 ML Only`: `66.40%` Acc, `17.14%` FPR) by **`+30.40%` accuracy** and **`-15.00%` FPR**. |

---

## 5. Audit of the Alert Consolidation Claim (`98.62%`)

In `COHORT_E_SG_2_0_TRI_MODEL_AUTOENCODER_INTEGRATED`, the exact alert and response lifecycle counts across the `500` evaluated events are:
1. **`raw_alerts_generated` = `363`**: Every event where `predictedMalicious === true` (`360` true-positive malicious events + `3` false-positive internal benign events `EV-0005`, `EV-0006`, `EV-0131`).
2. **`correlated_alerts_grouped_into_incidents` = `240`**: `240` non-duplicate malicious alerts from the 5 external attacker IPs that matched correlation rules `CORR-01..CORR-06` and were merged into active incidents.
3. **`deduplicated_burst_alerts_within_2s_window` = `120`**: `120` consecutive malicious burst alerts (`1500 ms` apart $< 2000\text{ ms}$ `dedupWindowMs` in `correlationEngine.js` line `42`) suppressed as exact signature/honeypot burst duplicates.
4. **`uncorrelated_single_detector_manual_review_alerts` = `3`**: The `3` false-positive internal alerts (`10.20.1.14`, `10.20.2.15`, `10.20.3.40`), which had `severity = LOW`, `reputation_score = 0`, and `< 5` events per IP, and therefore did not trigger `CORR-01..CORR-06` (`240 + 120 + 3 = 363` raw alerts).
5. **`consolidated_incidents` = `5`**: One open multi-stage incident per distinct external attacker IP (`45.33.32.156`, `185.220.101.42`, `203.0.113.50`, `91.240.118.172`, `198.51.100.77`).
6. **`confirmed_attacks_tp` = `360`** vs. **`false_positive_alerts_fp` = `3`**.
7. **`soar_manual_reviews_routed` = `74`** (`71` medium/low-confidence alerts + `3` inhibited single-detector benign false positives).
8. **`soar_block_leases_executed` = `289`** (`BLOCK_IP_TEMPORARY` executed strictly against the 5 external attacker IPs; **`benign_ip_auto_blocks_executed = 0`**).
9. **Mathematical Formula & Scientific Distinction**:
   $$\text{Alert Consolidation Rate} = 1 - \frac{\text{Consolidated Incidents}}{\text{Raw Alerts Generated}} = 1 - \frac{5}{363} = 98.62\%$$
   **Critical Scientific Clarification**: Alert consolidation (`363` raw alerts $\to$ `5` incidents grouped by `source_ip`) measures **SOC alert-queue compression**, **NOT** a reduction in false-positive rate (which is `3 / 140 = 2.14%`).

---

## 6. Thesis & Viva Defense Guide Accuracy and Citation Audit

1. **Architecture & Code Parity**: Verified that all file paths, service ports (`:7000`, `:8000`, `:3001–:3010`), PyTorch layer dimensions (`69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69`), preprocessing steps (`signed_log1p` + `RobustScaler(25, 75)` + `clip[-10, 10]`), and threshold values ($P_{95}=0.409105, P_{97}=0.503670, P_{99}=0.645935$) in [SHADOW_GUARD_2_0_COMPLETE_BTECH_THESIS.md](file:///d:/ShadowGuard-main/ShadowGuard-main/docs/SHADOW_GUARD_2_0_COMPLETE_BTECH_THESIS.md) and [SHADOW_GUARD_2_0_VIVA_AND_DEFENSE_GUIDE.md](file:///d:/ShadowGuard-main/ShadowGuard-main/docs/SHADOW_GUARD_2_0_VIVA_AND_DEFENSE_GUIDE.md) match the implemented codebase.
2. **Correction of Cohort E Benchmark Numbers**: Updated Chapters 1, 20, 21, 23, and 25 of the thesis, the Viva Guide (`Q26, Q37, Q46–Q50`), and `docs/COHORT_E_BENCHMARK_AND_SCIENTIFIC_VALIDITY.md` to replace the invalidated `100.00%` (`TP=360, FP=0, TN=140, FN=0`) Cohort E table with the audited, leak-free results (`TP=360, FP=3, TN=137, FN=0`, `Acc = 99.40%, Prec = 99.17%, Rec = 100.00%, F1 = 99.59%, FPR = 2.14%, FNR = 0.00%`) and the 5 Cohort E subsystem ablations (`TP=347, FN=13` when Honeypots are disabled).
3. **Academic Citation Verification**: All 16 references in Chapter 26 of the thesis were audited and verified to be real, peer-reviewed foundational works (Denning 1987; Axelsson 2000; Breiman 2001; Provos 2004; Hinton & Salakhutdinov 2006; Liu et al. 2008; Sommer & Paxson 2010; Pedregosa et al. 2011; Sakurada & Yairi 2014; Kingma & Ba 2015; Moustafa & Slay 2015; Mirsky et al. 2018; Sharafaldin et al. 2018; Paszke et al. 2019; MITRE 2023; OISF Suricata 2024). Zero fabricated citations exist.
4. **Zero-Day & Synthetic Labeling Compliance**: Every benchmark table is explicitly labeled `SYNTHETIC BENCHMARK ONLY`, and no claim of real-world zero-day detection is made.

---

## 7. Docker Deployment Verification Status (`NOT VERIFIED`)

- **Commands Executed on Host**:
  1. `docker --version; docker compose version` $\to$ Exit code `1` (`CommandNotFoundException: The term 'docker' is not recognized`).
  2. `Test-Path "C:\Program Files\Docker\Docker\resources\bin\docker.exe"; Get-Command docker -ErrorAction SilentlyContinue` $\to$ `False` (Exit code `1`).
- **Verification Status**: **`NOT VERIFIED` (Host machine does not have Docker Desktop / Docker CLI installed)**.
- **Disclosure Enforcement**: All thesis chapters and verification reports explicitly distinguish **Static Configuration & Volume/Dependency Audit (`VERIFIED` via file inspection of `docker-compose.yml`, `ml-detection-service/Dockerfile`, and `requirements.txt`)** from **Live Docker Container Build & Runtime Deployment (`NOT VERIFIED` on this host; all runtime tests were executed natively via local Node.js and Python processes)**.

---

## 8. Exact Tests & Commands Executed and Remaining Limitations

### 8.1 Commands Executed During This Audit
1. `Test-Path "C:\Program Files\Docker\Docker\resources\bin\docker.exe"; Get-Command docker -ErrorAction SilentlyContinue` (Confirmed Docker CLI is absent on host $\to$ `NOT VERIFIED`).
2. `python -c "... TriModelDetectionEngine evaluate_tri_model_fusion on all 384 splits.test_set flows ..."` (Exported `data/held_out_384_tri_model_predictions.json` and verified `7` FPs and `8` FNs on `test_set`).
3. `node scripts/evaluate_cohort_e_benchmark.js` (Executed leak-free Cohort E + 6 subsystem ablations on the 500-event dataset and 384-flow held-out test set).
4. `node scripts/verify_autoencoder_stage5.js` & `node scripts/run_all_verifications.js` (Master verification suite across all platform and Autoencoder stages).

### 8.2 Remaining Technical & Methodological Limitations
1. **100% Synthetic Parametric Provenance**: Both the 500-event Track 1 benchmark (`seed = 20261113`) and the 1,524-flow Track 2 dataset (`seed = 42`) are synthetically generated.
2. **3-Scalar Informational Bottleneck in 69-Feature Extractor**: All 69 features in `flow-feature-extraction-service` are deterministic functions of `(packets, bytes, duration)`, with 13 duplicate polynomial columns (`f_25..f_39`) and 14 rank-1 collinear harmonic columns (`f_55..f_68`).
3. **Cross-Label Feature Collisions**: Because the 69 features depend only on `(packets, bytes, duration)`, `4` preserved collision records (`flow-collision-norm-00/01` and `flow-collision-atk-00/01`) produce identical feature vectors across opposite labels (`flow-collision-norm-01` causes `1` of the `7` false positives on `test_set`, and `flow-collision-atk-00` causes `1` of the `8` false negatives).
4. **Deterministic Sensor Coverage on `S02–S10` in Track 1**: In the preserved Stage 7 500-event generator, `100%` of malicious events in `S02–S10` carry either a Suricata `signature_id` (`180` events) or a Honeypot `honeypot_id` (`180` events), plus one of 5 known external attacker IPs in `KNOWN_IOC_CATALOG`. Only when Honeypot/NIDS sensors are ablated (`ABLATION_2A`, `ABLATION_2B`, `ABLATION_5`) do the `13` flow-level false negatives on stealth SSH/service-enumeration probes manifest in Track 1 (`Recall = 96.39%, FN = 13`).
5. **Docker Container Runtime Unverified on Host**: Live container orchestration via `docker compose up` could not be executed because Docker is not installed on the Windows host (`NOT VERIFIED`).
