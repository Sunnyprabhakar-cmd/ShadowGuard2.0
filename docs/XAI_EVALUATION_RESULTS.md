# Shadow Guard 2.0 — XAI Stage 5 Evaluation Results

**Classification:** `SYNTHETIC BENCHMARK ONLY`  
**Raw Results Artifact:** `evaluation/results/xai_stage5_evaluation_results.json`  
**Script:** `scripts/evaluate_xai_stage5.py`  

---

## 1. Random Forest SHAP Evaluation (`384` Held-Out Flows)
- **Backend**: Official `shap.TreeExplainer` (`shap == 0.54.1`, `is_exact_shap = True`) explaining `StandardScaler` + `RandomForestClassifier.predict_proba` (`classes_ = [0, 1]`).
- **Max Additivity Error**: **`8.8818e-16`** (mean = **`7.0079e-16`**) across all `384` held-out `test_set` flows, verifying $P_{\text{RF}}(\text{attack} \mid \mathbf{x}) = \mathbb{E}[P_{\text{RF}}(\text{attack})] + \sum_{j=0}^{68} \phi_j^{(1)}(\mathbf{x})$ to machine precision.
- **Attack Probability Distribution**: Mean = `0.4864`, Std = `0.4644`.
- *Scientific Note*: Exact additivity verifies mathematical consistency of the Shapley decomposition with respect to the model's output, **not** causal correctness in real-world network traffic.

## 2. Isolation Forest Explanation Evaluation
- **Method**: `reference_population_perturbation_and_quantile_deviation` against `840`-flow `train_normal` baseline (`UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY`).
- **Bootstrap Reference Sensitivity (`30` flows, `n=840` vs. `n=420` subsample)**:
  - Mean Spearman rank correlation $\rho$ = **`0.9878`**
  - Mean Top-5 Jaccard overlap = **`0.9889`**
  - Demonstrates high robustness of reference-population attributions to 50% subsampling of the normal baseline.

## 3. PyTorch Autoencoder Explanation Evaluation (`384` Held-Out Flows)
- **Frozen Thresholds Preserved**: $P_{95} = 0.409105$, **$P_{97} = 0.503670$**, $P_{99} = 0.645935$ (`RECONSTRUCTION_ERROR_MSE_NOT_PROBABILITY`).
- **Identity Verification**: $\max |\text{mean}(\text{sq\_err}_{0..68}) - \text{MSE}| = 5.07 \times 10^{-7}$ across all `384` flows.
- **Held-Out MSE Distribution**: Mean = `0.504112`, Median = `0.261111`, P95 = `1.814136`.

## 4. Unified Tri-Model Consensus & Dissent Breakdown (`384` Held-Out Flows)

| Consensus State | Flow Count | Share of `test_set` (`384`) |
| :--- | :---: | :---: |
| `UNANIMOUS_NORMAL_3_OF_3` | 182 | 47.40% |
| `UNANIMOUS_ANOMALY_3_OF_3` | 75 | 19.53% |
| `MAJORITY_ANOMALY_2_OF_3_DISSENT` | 63 | 16.41% |
| `SINGLE_MODEL_ANOMALY_DISSENT_RANDOM_FOREST` | 55 | 14.32% |
| `SINGLE_MODEL_ANOMALY_DISSENT_AUTOENCODER` (`AE_ONLY`) | 4 | 1.04% |
| `SINGLE_MODEL_ANOMALY_DISSENT_ISOLATION_FOREST` (`IF_ONLY`) | 4 | 1.04% |
| `NORMAL_WITH_AUTOENCODER_P95_SUSPICIOUS_WARNING` | 1 | 0.26% |

## 5. Feature Correlation & Attribution Bias (`60` Stratified Flows)
Because `v2.0-69dim` derives deterministically from `(packets, bytes, duration)` and includes `15` polynomial ratio columns (`f_25..f_39`, `13` exact duplicates) plus `14` collinear harmonic padding columns (`f_55..f_68`), individual models absorb substantial attribution inside redundant coordinates:

| Model | Mean Share in `f_25..f_39` (Polynomial Duplicates) | Mean Share in `f_55..f_68` (Harmonic Padding) | Combined Redundant Column Share |
| :--- | :---: | :---: | :---: |
| **Random Forest (SHAP)** | `16.48%` | `26.31%` | **`42.79%`** |
| **Isolation Forest (Perturbation)** | `27.19%` | `24.09%` | **`51.28%`** |
| **PyTorch Autoencoder (MSE)** | `5.25%` | `3.38%` | **`8.63%`** |

**Key Research Finding**: Tree-based models (`RF` `42.79%`, `IF` `51.28%`) distribute nearly half of their feature-level attribution across duplicate/collinear columns, whereas the `FeaturePreprocessor` + bottleneck Autoencoder concentrates `91.37%` of its MSE residual on non-duplicate base/rate/sinusoidal/cosine features. Grouping into `(packets, bytes, duration)` eliminates this split-dilution artifact.
