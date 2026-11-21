# Shadow Guard 2.0: An Intelligent Cyber Defence, Cyber Deception and Automated Incident Response Platform with Explainable Artificial Intelligence

**B.Tech CSE Major Project Research Paper — Chandigarh University**  
**Evaluation Classification:** `SYNTHETIC BENCHMARK ONLY`

---

## Abstract
Enterprise Security Operations Centers (SOCs) face multi-stage cyber campaigns that blend volumetric floods, low-and-slow Command-and-Control (C2) beaconing, and interactive credential abuse. Standalone flow-based anomaly detectors suffer from high false-positive rates (`2%–5%`) and black-box opacity, making automated firewall containment unsafe. This paper presents **Shadow Guard 2.0**, a 22-container, event-driven cyber defense, cyber deception, tri-model machine learning, and safety-gated SOAR platform enhanced with an **Explainable Artificial Intelligence (XAI)** subsystem. Shadow Guard 2.0 fuses a supervised **Random Forest** (`150` trees), an unsupervised **Isolation Forest** (`150` iTrees), and an authoritative **PyTorch Deep Reconstruction Autoencoder** ($\mathbb{R}^{69} \to 32 \to 16 \to 8 \to 16 \to 32 \to \mathbb{R}^{69}$, frozen validation threshold $P_{97} = 0.503670$) with **Suricata NIDS**, isolated **Cowrie/OpenCanary/Dionaea honeypots**, **Threat Intelligence**, **Sliding-Window Correlation (`CORR-01..06`)**, and **MITRE ATT&CK kill-chain reconstruction**. On a strictly held-out 384-flow synthetic test set (`SYNTHETIC BENCHMARK ONLY`), the PyTorch Autoencoder increases label-free unsupervised recall from `49.50%` (IF alone) to `69.31%` (`IF + AE`), recovering `76.00%` of `c2_beaconing` and `56.67%` of `port_scan` where Isolation Forest achieved `0.00%`. At the 500-event multi-sensor system level (**Cohort E**), Shadow Guard 2.0 achieves `99.40%` accuracy (`100.00%` recall, `99.17%` precision, `2.14%` FPR, `98.62%` alert consolidation) with `0` erroneous benign IP auto-blocks. Finally, our read-only XAI subsystem integrates official `shap.TreeExplainer` (`shap==0.54.1`, max additivity error `8.88e-16`), reference-population perturbation (`840` normal flows, bootstrap $\rho = 0.9878$), and Autoencoder MSE decomposition into **Module 11** of the RBAC-protected SOC Dashboard, demonstrating that grouping 69 collinear features into `(packets, bytes, duration)` reduces $\pm 5\%$ perturbation L1 shift to `0.54%` (RF), `2.00%` (IF), and `2.16%` (AE) while preserving `0/384` detection mismatches across `517/517` automated verification assertions.

**Keywords:** *Cyber Deception, PyTorch Autoencoder, Tri-Model Fusion, Explainable AI (XAI), TreeSHAP, SOAR, MITRE ATT&CK, Honeypots, Suricata NIDS.*

---

## 1. Introduction & Motivation
Traditional signature-based Intrusion Detection Systems (NIDS) fail to detect novel or encrypted volumetric anomalies, whereas standalone unsupervised ML detectors trigger false alarms on legitimate enterprise bursts (the base-rate fallacy). Furthermore, analysts distrust black-box ensemble alerts and require transparent, paradigm-faithful explanations before authorizing containment. Shadow Guard 2.0 addresses these gaps by decoupling **Detection**, **Explanation**, **Correlation**, and **Safety-Gated Response** across five isolated network zones (`sg_ingress_net`, `sg_core_net`, `sg_deception_dmz`, `sg_storage_net`, `sg_frontend_net`).

## 2. System Architecture & Multi-Sensor Pipeline
- **Ingestion & Deception**: Suricata EVE JSON + Cowrie (zero-password retention) + OpenCanary + Dionaea (`noexec` quarantine + SHA-256) publishing Event Contract v2 messages over RabbitMQ (`shadowguard.events`).
- **Tri-Model ML Engine (`v2.0-69dim`)**: Resolves legacy 7-vs-69 schema skew (`max_abs_diff = 0.0` JS/Python parity) and fuses Random Forest (`P(attack)`), Isolation Forest (`best_threshold = -0.024499`), and PyTorch Autoencoder (`FeaturePreprocessor`: `signed_log1p` + `RobustScaler(25,75)` + `clip[-10,10]`, frozen $P_{97} = 0.503670$) under `weighted_consensus` with mandatory `AE_ONLY`/`IF_ONLY` non-auto-block guardrails.
- **Correlation, Profiling & SOAR**: 5-factor explainable attacker risk (`0–100`), `CORR-01..06` 15-minute sliding-window correlation, MITRE ATT&CK kill chains (`OBSERVED`, `INFERRED`, `SUSPECTED`), `DEC-01..04` adaptive deception, and `PB-SOAR-01..05` playbooks with timed leases and allowlists.
- **Read-Only XAI Subsystem**: `xai_explainer.py` + `unified_xai_engine.py` + PostgreSQL `004_xai_explanations.sql` + Node.js `/api/v2/xai/*` RBAC gateway + React **Module 11**.

## 3. Experimental Evaluation (`SYNTHETIC BENCHMARK ONLY`)
### 3.1 Track 2: 384 Held-Out Flows (`test_set`)
- **Random Forest**: `97.14%` acc, `99.48%` prec, `95.05%` rec, `0.9722` F1, `0.55%` FPR.
- **Isolation Forest**: `72.92%` acc, `98.04%` prec, `49.50%` rec, `0.6579` F1, `1.10%` FPR.
- **PyTorch AE @ P97 (`0.503670`)**: `76.30%` acc, `96.64%` prec, `56.93%` rec, `0.7165` F1, `2.20%` FPR (`ROC-AUC = 0.9652`).
- **IF + AE Unsupervised Ensemble**: `82.29%` acc, `95.89%` prec, `69.31%` rec, `0.8046` F1.
- **Tri-Model `weighted_consensus`**: `96.88%` acc, `97.98%` prec, `96.04%` rec, `0.9700` F1, `2.20%` FPR.

### 3.2 Track 1: 500-Event System Ablation (Cohorts A–E)
Progressing from **Cohort A** (SG 1.0 ML-only: `66.40%` acc, `17.14%` FPR) $\to$ **Cohort B** (+Suricata: `80.60%` acc) $\to$ **Cohort C** (+Honeypots: `90.60%` acc) $\to$ **Cohort D** (Complete RF+IF: `98.80%` acc, `4.29%` FPR) $\to$ **Cohort E** (+PyTorch AE + Tri-Model Fusion: **`99.40%` acc, `100.00%` recall, `99.17%` prec, `2.14%` FPR, `98.62%` alert consolidation, `0` benign IP auto-blocks**).

### 3.3 XAI Stage 5 Evaluation (`30` Perturbation Flows, `384` Held-Out Flows, `100` Latency Samples)
- **Repeatability & Stability**: `0/30` identical mismatches. Decision-preserving ($N=89$) Top-5 Jaccard / Spearman $\rho$ / 3-Scalar L1: RF `0.8482 / 0.9574 / 0.0054`, IF `0.6096 / 0.8595 / 0.0200`, AE `0.5728 / 0.7431 / 0.0216`.
- **Collinearity Attribution Bias (`60` flows)**: Duplicate/collinear columns (`f_25..f_39` + `f_55..f_68`) absorbed `42.79%` (RF) and `51.28%` (IF) vs. `8.63%` (AE), validating the necessity of 3-scalar grouped explanations.
- **Latency & Memory**: Median per-flow latency = `19.25 ms` (RF), `37.93 ms` (IF), `1.74 ms` (AE), `94.19 ms` (Unified); 20-flow batch peak traced memory = `0.911 MB`.

## 4. Conclusion & Scientific Limitations
Shadow Guard 2.0 demonstrates that combining multi-sensor cyber deception with tri-model anomaly detection, safety-gated SOAR, and model-faithful XAI achieves high detection recall with low false-positive containment risk across controlled synthetic benchmarks (`517/517` assertions passing). Future work will validate the pipeline on real-world PCAP datasets (CIC-IDS2017, UNSW-NB15) and upgrade the 69-feature extractor to true bidirectional L3/L4/L7 flow statistics.
