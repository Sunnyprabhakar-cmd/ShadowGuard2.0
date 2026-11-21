# Shadow Guard 2.0 — XAI Stage 5 Computational Performance Report

**Classification:** `SYNTHETIC BENCHMARK ONLY`  
**Hardware / Software Environment:** Windows 11 (`10.0.26300`), Intel64 Family 6 Model 186 (`12` logical CPUs), `Python 3.14.7`, `PyTorch 2.15.0+cpu`, `scikit-learn 1.9.1`, `shap 0.54.1`.

---

## 1. Per-Flow Explanation Latency (`n = 100` Held-Out Flows, Single-Threaded CPU)

| Component | Mean (ms) | Median P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (`shap.TreeExplainer`)** | `18.3563` | `19.2495` | `23.7321` | `24.9925` | `25.7627` |
| **Isolation Forest (75-Row Perturbation Batch)** | `36.4449` | `37.9289` | `45.8062` | `47.9067` | `48.5941` |
| **PyTorch Autoencoder (MSE Decomposition)** | `1.6561` | `1.7352` | `2.4647` | `2.6898` | `2.9068` |
| **Unified Tri-Model Orchestrator (`UnifiedTriModelExplainer`)** | **`91.1541`** | **`94.1927`** | **`111.0056`** | **`113.1648`** | **`114.7064`** |

## 2. Batch Performance & Memory Footprint
- **20-Flow Batch (`POST /xai/explain/batch` equivalent)**: `4197.58 ms` total (**`209.88 ms`** per flow including JSON serialization/catalog lookup).
- **Traced Peak Python Memory (`tracemalloc`)**: **`0.911 MB`** incremental allocation during a 20-flow unified explanation batch.
- **Architectural Implication**: Real-time inline detection (`POST /detect` ~`1.4 ms`) remains completely decoupled from on-demand XAI (`~78.8 ms` median), ensuring XAI never throttles network flow ingestion.
