# Shadow Guard 2.0 — XAI Stage 5 Stability & Perturbation Analysis

**Classification:** `SYNTHETIC BENCHMARK ONLY`  
**Experiment ID:** `EXP-01` (`30` stratified flows $\times$ `3` `+5%` perturbations = `90` perturbed flows + `30` identical repeats)

---

## 1. Repeatability on Identical Inputs
- **Identical Input Mismatches**: **`0 / 30`** (bit-exact deterministic explanations across `RandomForestSHAPExplainer`, `IsolationForestAnomalyExplainer`, and `AutoencoderReconstructionExplainer`).

## 2. Decision-Preserving vs. Boundary-Crossing Perturbations ($\pm 5\%$ on `packets`, `bytes`, `duration`)
Across `90` perturbed variants, **`89`** preserved the original `final_decision` and **`1`** crossed the decision boundary:

| Model | Decision-Preserving Top-5 Jaccard ($N=89$) | Decision-Preserving Spearman $\rho$ ($N=89$) | Grouped 3-Scalar L1 Shift ($N=89$) | Boundary-Crossing Top-5 Jaccard ($N=1$) |
| :--- | :---: | :---: | :---: | :---: |
| **Random Forest (TreeSHAP)** | **`0.8482`** | **`0.9574`** | **`0.0054`** (`0.54%`) | `0.6667` |
| **Isolation Forest (Perturb)** | **`0.6096`** | **`0.8595`** | **`0.0200`** (`2.00%`) | `0.4286` |
| **PyTorch Autoencoder (MSE)** | **`0.5728`** | **`0.7431`** | **`0.0216`** (`2.16%`) | `0.0000` |

## 3. Key Stability Findings
1. **Why 69-Feature Top-5 Jaccard Is Lower Than Spearman $\rho$**: In `IF` (`0.6096`) and `AE` (`0.5728`), small `+5%` changes in `duration` shift high-frequency sinusoidal/damped-cosine phases (`f_40..f_54`), swapping individual feature ranks near the Top-5 cutoff, while global ranking ($\rho = 0.8595$ / $0.7431$) remains strong.
2. **Superior Stability of Grouped 3-Scalar Attributions**: When aggregated to `(packets, bytes, duration)` shares, the mean L1 shift is only **`0.54%` (RF)**, **`2.00%` (IF)**, and **`2.16%` (AE)**—proving that grouping 69 correlated features into 3 physical measurements yields dramatically more stable SOC explanations.
3. **Boundary-Crossing Separation**: On the single boundary-crossing case (`1/90`), Top-5 Jaccard drops as expected (`AE = 0.0000`) because crossing the anomaly manifold threshold activates different residual coordinates.
