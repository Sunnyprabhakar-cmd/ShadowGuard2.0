# Shadow Guard 2.0 — XAI Stage 5 Experimental Evaluation Plan

**Classification:** `SYNTHETIC BENCHMARK ONLY`  
**Stage:** XAI Stage 5 — Explainability Evaluation, Scientific Validation & Regression  
**Frozen Models & Thresholds Under Evaluation (Read-Only):**
- Random Forest (`models/random_forest_69_v2.pkl`, 150 trees, `StandardScaler`, threshold = `0.50`)
- Isolation Forest (`models/isolation_forest_69_v2.pkl`, 150 iTrees, `StandardScaler`, `best_threshold = -0.024499`)
- PyTorch FlowAutoencoder (`models/autoencoder_model.pt`, `69->32->16->8->16->32->69`, `FeaturePreprocessor`, frozen $P_{97} = 0.503670$, $P_{95} = 0.409105$, $P_{99} = 0.645935$)
- Tri-Model Fusion (`weighted_consensus` policy, `AE_ONLY` non-auto-block guardrail)

---

## 1. Research Questions & Experimental Design

| Experiment ID | Focus | Sample Scope | Metrics & Formulas |
| :--- | :--- | :--- | :--- |
| **EXP-01** | **Explanation Stability & Perturbation Sensitivity** | `30` stratified flows from `test_set` (`15` normal, `15` attack) perturbed by $\pm 5\%$ on `packets`, `bytes`, `duration` independently + identical repeat runs | Top-5 Jaccard similarity $J(A,B) = \frac{|A \cap B|}{|A \cup B|}$, Spearman rank correlation $\rho$, L1 grouped `(packets, bytes, duration)` shift, separated by decision-preserving vs. boundary-crossing perturbations |
| **EXP-02** | **Random Forest Official `shap.TreeExplainer` Validation** | All `384` held-out `test_set` flows + `50` batch timing | Additivity error $|P_{\text{RF}}(\text{attack}\mid x) - (E[f(X)] + \sum \phi_j)|$, repeated consistency, top-5 consistency, SHAP distribution, per-flow & batch runtime |
| **EXP-03** | **Isolation Forest Perturbation Evaluation** | `60` stratified `test_set` flows + `5` bootstrap subsamples ($n=420$) of `train_normal` | Attribution repeatability, sensitivity to reference-population subsampling ($\rho$, Jaccard), correlation between perturbation rescue delta and anomaly score change, runtime |
| **EXP-04** | **Autoencoder Reconstruction Error Evaluation** | All `384` held-out `test_set` flows + perturbation sensitivity | MSE repeatability, identity $|\text{mean}(\text{sq\_err}) - \text{MSE}|$, top-5 anomalous feature stability, frozen $P_{95}/P_{97}/P_{99}$ invariance, runtime |
| **EXP-05** | **Unified Tri-Model & Consensus/Dissent Evaluation** | All `384` `test_set` flows + synthetic availability faults (`RF down`, `IF down`, `AE down`, `2 down`, `all down`, `invalid`) | Consensus breakdown (`3/3` attack, `3/3` normal, `RF_ONLY`, `IF_ONLY`, `AE_ONLY`, `2/3`), availability rates, shared grouped measurement overlap, latency |
| **EXP-06** | **Feature Correlation & Attribution Bias (`69` vs. `3` Scalars)** | `60` stratified `test_set` flows (`RF`, `IF`, `AE`) | Fraction of attribution absorbed by `13` duplicate polynomial columns (`f_25..f_39`) and `14` collinear harmonic padding columns (`f_55..f_68`); comparison of 69-feature Jaccard/Spearman stability vs. 3-scalar grouped stability |
| **EXP-07** | **Computational Performance & Memory Benchmark** | `100` sequential `test_set` flows + `20`-flow batch (`RF`, `IF`, `AE`, `Unified`) | Mean, Median (P50), P95, P99, Max latency (`ms`), and `tracemalloc` peak memory (`MB`) on documented host hardware |
| **EXP-08** | **384-Flow Decision Invariance & Master Regression** | All `384` `test_set` flows + all `14` verification suites | Zero (`0/384`) mismatches vs. `held_out_384_tri_model_predictions.json` + `run_all_verifications.js` |

## 2. Scientific Validity Boundaries
All datasets are **`SYNTHETIC BENCHMARK ONLY`**. No claim of real-world zero-day detection, causal proof, or live enterprise SOC analyst efficacy will be made.
