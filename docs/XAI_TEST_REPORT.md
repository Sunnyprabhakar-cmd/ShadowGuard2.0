# Shadow Guard 2.0 — Complete XAI & Platform Test Report

## 1. Master Verification Suite (`node scripts/run_all_verifications.js`)

| Suite | Scope | Passed | Failed |
| :--- | :--- | :---: | :---: |
| Stage 2 | Foundation (Migrations, Event Contract v2 & RabbitMQ) | 57 | 0 |
| Stage 3 | Suricata NIDS & Multi-Type Honeypot Infrastructure | 57 | 0 |
| Stage 4 | Threat Intel, Attacker Profiling, Correlation & Attack Chains | 65 | 0 |
| Stage 5 | Dynamic Deception Manager & Advanced SOAR Engine | 40 | 0 |
| Stage 6 | 8-Page SOC Command Center, RBAC/JWT & Prometheus Metrics | 37 | 0 |
| Stage 7 | Reproducible 500-Event Research Ablation Benchmark (Cohorts A–D) | 11 | 0 |
| AE Stg 1 | Canonical 69-Feature Schema (`v2.0-69dim`), Provenance & Parity | 28 | 0 |
| AE Stg 2 | PyTorch Autoencoder Training, $P_{97}$ Calibration & Artifacts | 30 | 0 |
| AE Stg 3 | Autoencoder Inference, Tri-Model Fusion & Guardrails | 32 | 0 |
| AE Stg 4 | SOC Dashboard Tri-Model Integration, Safety, RBAC & Benchmark | 30 | 0 |
| AE Stg 5 | Cohort E Benchmark, Scientific Validity, Thesis & Viva Guide | 33 | 0 |
| XAI Stg 1 | Model-Specific XAI Core (Official TreeSHAP, IF Perturb, AE MSE) | 24 | 0 |
| XAI Stg 2 | Unified Tri-Model Explanation Engine & 384-Flow Invariance | 20 | 0 |
| XAI Stg 3 | XAI Backend API Gateway, RBAC, Audit & PostgreSQL Migration | 23 | 0 |
| XAI Stg 4 | SOC Dashboard Module 11 (Explainable AI & Threat Reasoning) | 16 | 0 |
| XAI Stg 5 | XAI Scientific Evaluation, Stability, Performance & Regression | 14 | 0 |
| **GRAND TOTAL** | **All 16 Verification Suites** | **517** | **0** |

## 2. Python Unit Test Suites
- `ml-detection-service/tests/test_xai_explainer.py`: **`12/12` PASSED** (`1.504s`).
- `ml-detection-service/tests/test_unified_xai_engine.py`: **`9/9` PASSED** (`14.957s`).
- `ml-detection-service/tests/test_xai_api.py`: **`6/6` PASSED**.
- **384 Held-Out Flow Decision Invariance**: **`0 / 384`** mismatches vs. `data/held_out_384_tri_model_predictions.json`.
