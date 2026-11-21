# Shadow Guard 2.0 — XAI Stage 5 Completion Report (Evaluation, Scientific Validation & Regression)

**Classification:** `SYNTHETIC BENCHMARK ONLY`

---

## 1. Executive Summary
**XAI Stage 5** conducted a complete quantitative evaluation of the Shadow Guard 2.0 Explainable AI subsystem across all `384` held-out test flows (`data/autoencoder_flow_dataset_v2.json`), `90` $\pm 5\%$ input perturbations, `30` bootstrap reference-population subsamples, `60` feature-correlation audits, and `100` latency benchmarks, without retraining any model or altering any threshold, fusion policy, Cohort A–E benchmark, or SOAR guardrail.

---

## 2. Key Verified Findings
1. **Stability & 3-Scalar Grouping ([XAI_STABILITY_ANALYSIS.md](file:///d:/ShadowGuard-main/ShadowGuard-main/docs/XAI_STABILITY_ANALYSIS.md))**:
   - Identical inputs are `100%` deterministic (`0/30` mismatches).
   - Under decision-preserving $\pm 5\%$ perturbations ($N=89$), Random Forest TreeSHAP achieved Top-5 Jaccard `0.8482` and Spearman $\rho = 0.9574$; Isolation Forest achieved `0.6096` / $\rho = 0.8595$; PyTorch Autoencoder achieved `0.5728` / $\rho = 0.7431$.
   - Aggregating to the 3 underlying raw measurements `(packets, bytes, duration)` reduced instability to a mean L1 shift of **`0.54%` (RF)**, **`2.00%` (IF)**, and **`2.16%` (AE)**.
2. **Model-Specific Validation ([XAI_EVALUATION_RESULTS.md](file:///d:/ShadowGuard-main/ShadowGuard-main/docs/XAI_EVALUATION_RESULTS.md))**:
   - **Random Forest (`shap.TreeExplainer` v0.54.1)**: Max additivity error across `384` flows = **`8.88e-16`**.
   - **Isolation Forest**: 50% bootstrap subsampling of `train_normal` (`840 -> 420`) yielded Spearman $\rho = 0.9878$ and Top-5 Jaccard `0.9889`.
   - **Autoencoder**: Frozen thresholds ($P_{95}=0.409105$, $P_{97}=0.503670$, $P_{99}=0.645935$) preserved; max per-feature MSE identity difference = `5.07e-7`.
   - **Correlation Bias (`60` flows)**: Redundant duplicate/padding columns (`f_25..f_39` + `f_55..f_68`) absorbed **`42.79%`** of RF attribution and **`51.28%`** of IF attribution, vs. **`8.63%`** for the Autoencoder.
3. **Computational Performance ([XAI_PERFORMANCE_REPORT.md](file:///d:/ShadowGuard-main/ShadowGuard-main/docs/XAI_PERFORMANCE_REPORT.md))**:
   - Median per-flow latencies (`n=100`): RF = `19.25 ms`, IF = `37.93 ms`, AE = `1.74 ms`, Unified = `94.19 ms` (`P95 = 111.01 ms`, `P99 = 113.16 ms`). Peak traced memory for a 20-flow batch = `0.911 MB`.
4. **384-Flow Invariance & Master Regression**:
   - **`0 / 384`** mismatches against `held_out_384_tri_model_predictions.json`.
   - Master verification suite (`node scripts/run_all_verifications.js`): **`517 PASSED, 0 FAILED`** across all 16 suites (`Stage 2–7`, `AE Stg 1–5`, `XAI Stg 1–5`).

---

## 3. Remaining Limitations & Disclosures
- All evaluations are **`SYNTHETIC BENCHMARK ONLY`**; no real-world enterprise PCAP generalization, causal proof, or live SOC analyst effectiveness is claimed.
- Live browser screenshot capture of Module 11 remains blocked by the Windows sandbox TCP bind boundary (`EACCES`); Module 11 was verified programmatically in Stage 4 (`16/16` assertions).
