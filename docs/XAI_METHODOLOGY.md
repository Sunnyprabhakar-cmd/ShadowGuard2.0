# Shadow Guard 2.0 — Explainable AI (XAI) Methodology

## A. Explainable AI Overview
In operational Security Operations Centers (SOCs), tri-model ensembles combining supervised classifiers, unsupervised tree isolation, and deep neural autoencoders produce heterogeneous outputs. **Shadow Guard 2.0 XAI** provides post-hoc, local and global, read-only explanations that preserve each model's native mathematical semantics and explicitly disclose feature-schema collinearity and non-causality.

## B. Random Forest Explainability via Official `shap.TreeExplainer`
- **Shapley Value Foundation**: For a coalition game over feature set $F = \{0, \dots, 68\}$, the Shapley value $\phi_j(\mathbf{x})$ quantifies the marginal contribution of feature $j$ averaged over all feature subsets $S \subseteq F \setminus \{j\}$:
  $$\phi_j(\mathbf{x}) = \sum_{S \subseteq F \setminus \{j\}} \frac{|S|!(|F|-|S|-1)!}{|F|!} \left[ f_{S \cup \{j\}}(\mathbf{x}_{S \cup \{j\}}) - f_S(\mathbf{x}_S) \right]$$
- **TreeExplainer**: `RandomForestSHAPExplainer` uses official `shap.TreeExplainer` (`shap == 0.54.1`) on `models/random_forest_69_v2.pkl` (`150` trees, `StandardScaler`, `classes_ = [0, 1]`).
- **Base Value & Additivity**: Explains attack-class probability $P_{\text{RF}}(\text{attack}\mid \mathbf{x})$ with exact additivity ($\max|\text{err}| = 8.88 \times 10^{-16}$ across `384` flows):
  $$P_{\text{RF}}(\text{attack} \mid \mathbf{x}) = \mathbb{E}[P_{\text{RF}}(\text{attack})] + \sum_{j=0}^{68} \phi_j^{(1)}(\mathbf{x})$$
- **Positive vs. Negative Contributions**: $\phi_j^{(1)} > 0$ pushes prediction toward `attack`; $\phi_j^{(1)} < 0$ pushes toward `normal`.
- **Global & Local Explanations**: Local top-5 positive/negative drivers per flow + global `mean(|SHAP|)` ranking.
- **Limitations**: Additivity verifies mathematical consistency with the tree ensemble, **not** real-world causal proof; split dilution occurs across correlated features.

## C. Isolation Forest Explainability (Reference-Population Perturbation)
- **Anomaly Scoring**: `IsolationForest` (`best_threshold = -0.024499`) outputs `raw_decision_score` (path-length isolation depth) and monotonic severity `anomaly_score` in $[0, 1]$ (`UNSUPERVISED_ANOMALY_SCORE_NOT_PROBABILITY`).
- **Perturbation-Based Attribution (`reference_population_perturbation_and_quantile_deviation`)**: Replaces each feature $x_j$ (and correlated duplicate/collinear blocks `f_25..f_39`, `f_55..f_68`, plus raw `packets`/`bytes`/`duration`) with the `840`-flow `train_normal` median $Q_{50}(X_j)$, measuring raw decision rescue $\Delta d_j = d(\mathbf{x}^{(j \leftarrow Q_{50})}) - d(\mathbf{x})$.
- **Reference Deviation**: Flags `UNUSUALLY_HIGH` ($> P_{95}, Z_{\text{rob}} > 2$) and `UNUSUALLY_LOW` ($< P_{05}, Z_{\text{rob}} < -2$).
- **Limitations**: Perturbation attributions are **not** exact Shapley values and depend on the reference population (50% bootstrap subsampling yielded $\rho = 0.9878$).

## D. PyTorch Autoencoder Explainability (MSE Decomposition)
- **Reconstruction-Based Detection**: `FlowAutoencoder` ($\mathbb{R}^{69} \to 32 \to 16 \to 8 \to 16 \to 32 \to \mathbb{R}^{69}$) reconstructs `FeaturePreprocessor`-scaled inputs $\mathbf{z} \in [-10, 10]^{69}$ (`signed_log1p` + `RobustScaler(25,75)`).
- **Per-Feature Squared Errors**: $\text{MSE}(\mathbf{z}) = \frac{1}{69}\sum_{j=0}^{68} (z_j - \hat{z}_j)^2$, with relative error share $s_j = (z_j - \hat{z}_j)^2 / \sum_k (z_k - \hat{z}_k)^2$.
- **Frozen Thresholds**: $P_{95} = 0.409105$ (warning), **$P_{97} = 0.503670$** (frozen primary anomaly threshold, `3.33%` val FPR), $P_{99} = 0.645935$ (critical).
- **Limitations**: MSE is an unsupervised reconstruction residual, **not** a probability, and cannot disambiguate cross-label 3-scalar collisions.

## E. Unified Tri-Model Explanation Engine (`UnifiedTriModelExplainer`)
- Orchestrates all 3 explainers without averaging SHAP, IF scores, and AE MSE.
- Reports `consensus_state` (`UNANIMOUS_ANOMALY_3_OF_3`, `UNANIMOUS_NORMAL_3_OF_3`, `MAJORITY_ANOMALY_2_OF_3_DISSENT`, `SINGLE_MODEL_ANOMALY_DISSENT_*`), handles partial/complete unavailability (`healthy`, `partially_degraded`, `degraded`), and generates evidence-grounded SOC narratives.

## F. Feature Correlation & 3-Scalar Grouping Transparency
- All `69` features in `v2.0-69dim` derive deterministically from `(packets, bytes, duration)`, with `13` exact duplicate polynomial columns (`f_25..f_39`) and `14` collinear harmonic padding columns (`f_55..f_68`).
- Stage 5 proved redundant columns absorb **`42.79%`** of RF attribution and **`51.28%`** of IF attribution (`8.63%` AE), whereas grouping into `(packets, bytes, duration)` reduces $\pm 5\%$ perturbation L1 shift to **`0.54%` (RF), `2.00%` (IF), and `2.16%` (AE)**.
