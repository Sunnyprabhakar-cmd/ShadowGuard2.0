# Shadow Guard 2.0 — Complete Viva-Voce & Defense Preparation Guide

**Includes:**
1. **50 Technical Viva Questions with Rigorous Answers** (`20` ML & Autoencoder + `20` Cybersecurity, IDS, Honeypots & SOAR + `10` Experimental Validity & Limitations)
2. **A 5-Minute Project Presentation Script**
3. **A 10-Minute Detailed Technical Walkthrough**
4. **Challenging External Examiner Questions & Scientifically Honest Defenses**

---

## PART A: 20 Challenging Questions on Machine Learning & the PyTorch Autoencoder

### Q1. Why did you integrate an Autoencoder when Shadow Guard already had a Random Forest and an Isolation Forest?
**Answer:** Each model represents a distinct mathematical paradigm:
1. **Random Forest (`random_forest_69_v2`)** is a *supervised* classifier ($P(\text{attack}\mid \mathbf{x})$) that requires labeled attack training data and excels on known attack profiles (`97.14%` accuracy on our synthetic test set), but cannot detect unmodeled anomaly patterns outside its training classes.
2. **Isolation Forest (`isolation_forest_69_v2`)** is an *unsupervised* recursive tree-partitioning model that isolates global coordinate outliers, achieving `100%` recall on volumetric `ddos_flood` and `data_exfiltration`, but **`0.00%` recall** on `c2_beaconing` and `port_scan` whose packet/byte counts lie inside normal marginal bounds.
3. **PyTorch Autoencoder (`ae-pytorch-v2.0.0`)** is an *unsupervised* neural manifold learner ($\mathbb{R}^{69} \to 32 \to 16 \to 8 \to 16 \to 32 \to \mathbb{R}^{69}$) trained strictly on normal traffic (`840` flows). It learns nonlinear inter-feature relationships across packet rates, durations, and trigonometric/cosine projections, detecting **`76.00%` of `c2_beaconing`** and **`56.67%` of `port_scan`** without any attack labels and raising label-free unsupervised recall (`IF + AE`) from **`49.50%` to `69.31%`** ($\text{F1} = 0.8046$).

### Q2. Why must an Autoencoder for anomaly detection be trained strictly on normal traffic (`train_normal`) rather than both normal and attack traffic?
**Answer:** Anomaly detection by reconstruction relies on the manifold hypothesis: if the Autoencoder parameters $(\phi, \psi)$ minimize reconstruction MSE exclusively over the normal distribution $\mathcal{D}_{\text{normal}}$, the bottleneck $\mathbb{R}^8$ learns a compressed coordinate chart only for normal traffic patterns. When an anomalous flow $\mathbf{z}_{\text{attack}} \notin \mathcal{D}_{\text{normal}}$ is passed through $D_\psi(E_\phi(\mathbf{z}))$, the network projects it onto the nearest normal manifold point, yielding a high reconstruction error $e(\mathbf{z}) > \theta$. If attack flows were included during training, the Autoencoder would allocate bottleneck capacity to reconstruct attacks accurately, destroying its anomaly separation power.

### Q3. Explain the exact layer-by-layer architecture of your PyTorch `FlowAutoencoder` and why an 8-dimensional bottleneck was chosen.
**Answer:** In `shared/ml/autoencoder_model.py`, `FlowAutoencoder` is a symmetric 6-layer MLP:
- **Encoder**: `Linear(69, 32) -> ReLU -> Linear(32, 16) -> ReLU -> Linear(16, 8) -> ReLU`.
- **Decoder**: `Linear(8, 16) -> ReLU -> Linear(16, 32) -> ReLU -> Linear(32, 69)` (linear output layer).
The output layer is strictly linear (no ReLU or Sigmoid) because `RobustScaler`-preprocessed inputs span negative and positive real values in $[-10, 10]$. The 8-dimensional bottleneck compresses the 69-dimensional vector by $8.6\times$, preventing the identity-mapping pathology while preserving enough capacity to represent the 6 normal enterprise protocol profiles (`val_mse = 0.141353`).

### Q4. Why did you apply `signed_log1p`, `RobustScaler(Q25, Q75)`, and clipping to `[-10, 10]` before feeding features into the Autoencoder?
**Answer:** In the 69-feature schema, polynomial ratio features (`f_25..f_39`) and volume products (`f_06`) reach $5.06 \times 10^6$, whereas trigonometric features (`f_10..f_24`) lie in $[-1, 1]$. Without log compression and robust scaling, Mean Squared Error $\frac{1}{69}\sum_{j=0}^{68}(z_j - \hat{z}_j)^2$ would be $99.99\%$ dominated by `f_06` and `f_25..f_39`. `signed_log1p` ($\operatorname{sign}(x)\ln(1+|x|)$) tames heavy-tailed orders of magnitude, `RobustScaler` centers by the median and scales by the interquartile range ($Q_{75}-Q_{25}$) on `train_normal` so outlier tails do not skew scaling, and clipping to $[-10, 10]$ prevents extreme test-time volumetric floods from causing exploding hidden activations.

### Q5. How did you prevent data leakage during preprocessing and threshold calibration?
**Answer:** Three strict anti-leakage controls are enforced and verified in `AE Stg 1` and `AE Stg 2`:
1. `FeaturePreprocessor` (`RobustScaler`) is fitted **exclusively on `train_normal` (`840` flows)** and persisted to `models/autoencoder_preprocessor.pkl`.
2. Candidate thresholds ($P_{95} = 0.409105, P_{97} = 0.503670, P_{99} = 0.645935$) and early-stopping epoch selection (`best_epoch = 114`) are computed **exclusively on `val_normal` (`180` normal flows)**.
3. Full-record SHA-256 identity hashing verifies `zero_hash_overlap_verified = true` across `train_normal`, `val_normal`, `supervised_attack_train`, and `test_set` (`384` flows).

### Q6. On the held-out test set, $P_{95}$ achieved a higher F1-score (`0.7977`) than $P_{97}$ (`0.7165`). Why did you select and freeze $P_{97}$ instead of $P_{95}$?
**Answer:** Two fundamental reasons:
1. **No Test-Set Tuning**: Selecting a threshold because it maximizes F1 on the held-out `test_set` is methodological data leakage. The threshold must be chosen using `val_normal` *before* inspecting `test_set`.
2. **Base-Rate Fallacy & SOC False-Positive Budget**: Our operational requirement specifies a validation false-positive rate $\le 3.5\%$ on normal traffic so SOC analysts are not flooded with false alarms. On `val_normal` (`180` flows), $P_{95}$ yields a `5.00%` FPR (`9/180`), violating the $\le 3.5\%$ primary alert budget; therefore $P_{95}$ is used only as a non-alerting `suspicious` warning tier. $P_{97}$ (`0.503670`) yields a **`3.33%` validation FPR (`6/180`)**, satisfying the $\le 3.5\%$ budget while avoiding the steep sensitivity loss of $P_{99}$ (`0.645935`). Note also that `test_set` has a `52.6%` synthetic attack base rate, which artificially rewards looser thresholds on F1 compared to real enterprise traffic where benign traffic is $>99\%$.

### Q7. How does per-feature explainability work in the PyTorch Autoencoder?
**Answer:** Unlike a black-box classifier that outputs a single scalar, the Autoencoder reconstructs each of the 69 scaled coordinates $\hat{z}_0, \dots, \hat{z}_{68}$. For each coordinate $j \in \{0, \dots, 68\}$, we compute its squared reconstruction error $e_j = (z_j - \hat{z}_j)^2$ and its relative contribution share $s_j = e_j / \sum_{k=0}^{68} e_k$. We sort $\{e_j\}$ descending and return the top 5 contributing features (`feature_index`, `feature_name`, `squared_error`, `error_share`), allowing a SOC analyst to see whether an anomaly was driven by packet rate (`f_04_packets_per_sec`), log duration (`f_09_log_duration`), or damped cosine timing (`f_47_cos_damp_7`).

### Q8. What is the mathematical difference between a Random Forest probability, an Isolation Forest anomaly score, and an Autoencoder reconstruction error?
**Answer:**
- **Random Forest Attack Probability ($p_{\text{RF}} \in [0, 1]$)**: A frequentist/calibrated posterior class probability estimate $P(Y = \text{attack} \mid \mathbf{x})$ computed as the fraction of 200 decision trees voting for class 1.
- **Isolation Forest Score ($d_{\text{IF}} \in \mathbb{R}$)**: A shifted function of average path length $\mathbb{E}[h(\mathbf{x})]$ in random isolation trees ($d_{\text{IF}} < 0$ indicates an outlier isolated in fewer splits). It is **not** a probability.
- **Autoencoder Reconstruction Error ($e_{\text{AE}} \in [0, \infty)$)**: Unbounded Mean Squared Error $\frac{1}{69}\|\mathbf{z} - \hat{\mathbf{z}}\|_2^2$ measuring Euclidean distance from the learned normal manifold in scaled feature space. It is **not** a probability.

### Q9. How do you combine these three incompatible score scales in the `weighted_consensus` fusion policy?
**Answer:** Before linear weighting, each unsupervised metric is monotonically mapped onto a bounded severity index in $[0, 1]$ anchored at its validation threshold:
- $p_{\text{RF}} \in [0, 1]$ is already a bounded probability.
- Isolation Forest raw score $d_{\text{IF}}$ is mapped via a calibrated sigmoid $a_{\text{IF}} = \sigma(-12.0 \cdot (d_{\text{IF}} - \tau_{\text{IF}})) \in [0, 1]$.
- Autoencoder MSE $e_{\text{AE}}$ is mapped relative to $\theta_{P_{97}}$ onto $a_{\text{AE}} \in [0, 1]$.
We then compute $S = 0.55 p_{\text{RF}} + 0.20 a_{\text{IF}} + 0.25 a_{\text{AE}}$ alongside explicit multi-tier agreement rules (`ALL_3_MODELS_AGREE`, `RF_AND_AE_AGREE`, `AE_ONLY`, etc.).

### Q10. Why did the Autoencoder detect `4` `AE_ONLY` flows on `test_set`, yet `weighted_consensus` gained `+2` true positives (`194` vs `192`) over Random Forest?
**Answer:** We audited every individual flow in `test_set`:
- All `115` true attack flows detected by the Autoencoder at $P_{97}$ were *also* detected by Random Forest (`75` where all 3 models agreed + `40` where RF and AE agreed). Thus, there were `0` true-positive `AE_ONLY` flows on this synthetic dataset.
- The `4` `AE_ONLY` detections (`flow-norm-00258`, `flow-norm-00366`, `flow-norm-00639`, `flow-norm-00286`) were normal flows in the upper tail of the normal MSE distribution (`4 / 182 = 2.20%` test FPR, matching the `P97` calibration expectation).
- Meanwhile, `weighted_consensus` gained `+2` true positives over Random Forest (`194` vs `192`) because `2` `novel_stealth_anomaly` attack flows (`flow-atk-01518` and `flow-atk-01507`) missed by Random Forest were caught by Isolation Forest (`IF_ONLY`).

### Q11. Why does Isolation Forest get `0.00%` recall on `c2_beaconing` and `port_scan` while the PyTorch Autoencoder gets `76.00%` and `56.67%`?
**Answer:** Isolation Forest partitions features one coordinate at a time using random axis-parallel cuts. `c2_beaconing` and `port_scan` flows have moderate packet and byte counts that fall well inside the marginal min–max range of normal web/DNS traffic, so random single-feature splits require many cuts to isolate them ($\mathbb{E}[h(\mathbf{x})]$ is large, $d_{\text{IF}} > 0$). In contrast, the PyTorch Autoencoder projects all 69 features jointly through an 8-dimensional nonlinear bottleneck; even when $p, b, d$ are individually moderate, their joint ratio and trigonometric phase combinations (`f_10..f_24`, `f_40..f_54`) violate the normal manifold, producing MSE $> 0.503670$.

### Q12. Why did the PyTorch Autoencoder have low recall on `service_enum` (`4.17%`) and `ssh_brute_force` (`13.64%`)?
**Answer:** Because the 69 features depend solely on `(packets, bytes, duration)`. In our synthetic dataset, `service_enum` (short banner grabs) and `ssh_brute_force` flows have packet counts, byte volumes, and durations that overlap the dense core of `normal_ssh_interactive` and `normal_web_http` flows (and `service_enum` includes `2` exact cross-label feature collisions). When an attack flow's `(packets, bytes, duration)` triple lies directly on the normal manifold, its reconstruction error is low ($\text{MSE} \approx 0.11–0.47 < P_{97}$). This proves why flow-only unsupervised ML must be paired with **Cowrie** and **OpenCanary** honeypots, which catch `100%` of `ssh_brute_force` (`S03`) and `service_enum` (`S04`).

### Q13. What was the legacy bug in `playbook-decision-engine/index.js` regarding Random Forest probabilities, and how did you fix it?
**Answer:** Previously, `decideAction(prediction, probabilities)` computed `threatProbability = Math.max(...probabilities)`. When `prediction` was `0` (benign) with `probabilities = [0.95, 0.05]`, `Math.max` returned `0.95`—the *benign* probability—and treated it as a `0.95` *threat* confidence whenever `deriveRiskMetadata` was invoked. We fixed `computeThreatProbability(prediction, probabilities)` so that when `prediction === benignPrediction (0)`, threat probability is computed as $1 - P(\text{benign}) = 0.05$.

### Q14. What happens during training if weight decay or early stopping is omitted?
**Answer:** Without `weight_decay = 1e-5` and validation-monitored checkpointing (`best_epoch = 114`), the Autoencoder can overfit to noisy boundary points in `train_normal`, shrinking `train_mse` while `val_mse` on `val_normal` begins to rise (as seen in Epochs 119–120 where `val_mse` rose to `0.1802` while Epoch 114 achieved `0.141353`). Saving the best validation state dict at Epoch 114 prevents overfitting.

### Q15. How do you verify that the saved PyTorch checkpoint (`autoencoder_model.pt`) and preprocessor (`autoencoder_preprocessor.pkl`) have not been tampered with or mismatched?
**Answer:** `models/autoencoder_metadata.json` records the SHA-256 cryptographic checksums of both `autoencoder_model.pt` (`7b8baf32c504de77...`) and `autoencoder_preprocessor.pkl` (`1407ec5e01b8a0cf...`), along with `schema_version: "v2.0-69dim"` and the exact layer dimensions (`69 -> 32 -> 16 -> 8`). Both `ml-detection-service` and `verify_autoencoder_stage2.js` validate these artifacts on load.

### Q16. What is the CPU inference latency of the PyTorch Autoencoder, and is it fast enough for real-time SOC flow inspection?
**Answer:** On CPU (`PyTorch 2.15.0+cpu`), a single-flow Autoencoder inference (including 69-feature validation, `FeaturePreprocessor` transform, forward pass, and top-5 feature attribution sorting) takes **`P50 = 0.28 ms` (`P95 = 0.54 ms`)**, and full Tri-Model evaluation (`RF + IF + AE`) takes **`P50 = 1.42 ms` (`P95 = 2.65 ms`)**, supporting hundreds of flows per second per worker process.

### Q17. When should a SOC operator switch the active fusion policy from `weighted_consensus` to `majority_vote` or `unsupervised_ensemble`?
**Answer:**
- **`weighted_consensus` (Default)**: Best overall balance (`96.04%` recall, `96.52%` precision) with `AE_ONLY` routed safely to `manual-review`.
- **`majority_vote` (`2-of-3`)**: Best during high-traffic maintenance windows where false alarms must be zero (`100.00%` precision, `0.00%` FPR on `test_set`).
- **`unsupervised_ensemble` (`IF + AE`)**: Best when evaluating traffic from a new subnet or environment where historical supervised attack labels are untrusted or unavailable (`69.31%` recall using zero attack labels).

### Q18. Why did you use PyTorch (`torch.nn.Module`) as the single authoritative implementation rather than writing a duplicate JavaScript neural network?
**Answer:** Maintaining two separate neural network implementations across Python and JavaScript introduces floating-point drift, weight serialization mismatches, and maintenance divergence. Instead, PyTorch in `shared/ml/autoencoder_model.py` and `ml-detection-service` is the single authoritative engine, and Node.js services consume its verified REST endpoints (`/detect/autoencoder`, `/detect/tri-model`) and exported telemetry artifacts.

### Q19. Why does the Autoencoder achieve a high ROC-AUC (`0.9652`) and PR-AUC (`0.9670`) on `test_set` even though its point recall at $P_{97}$ is `56.93%`?
**Answer:** ROC-AUC and PR-AUC integrate ranking quality across *all* thresholds from $0$ to $\infty$. Almost all `202` attack flows have higher reconstruction errors than the median normal flow (`0.0945`), giving an excellent rank ordering (`ROC-AUC = 0.9652`). However, because we freeze a strict threshold at the 97th percentile of normal validation errors ($P_{97} = 0.503670$) to keep validation FPR $\le 3.33\%$, lower-error stealth attacks falling between $P_{50}$ and $P_{97}$ (`0.0945` to `0.5037`) are not flagged at that conservative operating point.

### Q20. How does the system behave if a malformed flow vector (e.g., 12 features instead of 69, or containing `NaN` / `Inf`) is sent to `/detect/tri-model`?
**Answer:** `FeaturePreprocessor` and `TriModelFusionEngine` explicitly validate `len(features) == 69` and `np.all(np.isfinite(features))`. If validation fails, the engine **never** crashes and **never** returns `"normal"`; it returns `status: "degraded"`, `final_decision: "degraded"`, `recommended_action: "manual-review"`, `auto_block_permitted: false`, and a detailed warning explaining the schema/finite check failure.

---

## PART B: 20 Questions on Cybersecurity, Suricata NIDS, Honeypots & SOAR

### Q21. How are the 5 Docker network zones architected in Shadow Guard 2.0, and why is network segmentation critical?
**Answer:** `docker-compose.yml` defines five isolated bridge networks:
1. `sg_ingress_net` (`172.28.1.0/24`): Suricata NIDS and `traffic-capture-service`.
2. `sg_deception_dmz` (`172.29.0.0/24`, `internal: true`): Cowrie, OpenCanary, and Dionaea honeypots.
3. `sg_core_net` (`172.28.2.0/24`): RabbitMQ, ML services, Correlation, Profiling, Attack Chains, and SOAR.
4. `sg_storage_net` (`172.28.3.0/24`): PostgreSQL 15 and `threat-log-database-service`.
5. `sg_frontend_net` (`172.28.4.0/24`): `threat-dashboard-service` (`:7000`).
Segmentation ensures that even if an attacker compromises a decoy container in `sg_deception_dmz`, they cannot reach PostgreSQL in `sg_storage_net` or the internet.

### Q22. How do you prevent a compromised honeypot from being used as a pivot point (lateral movement) by an attacker?
**Answer:** Three defense layers: (1) `sg_deception_dmz` is configured with `internal: true`, blocking outbound internet C2 callbacks and isolating decoys from production subnets; (2) `honeypot-event-collector-service` ingests logs via read-only (`:ro`) volume mounts rather than accepting inbound network connections from honeypots; and (3) Dionaea malware drops are written to a `noexec,nosuid,nodev` quarantine directory and hashed via SHA-256 without ever executing the binary.

### Q23. Why do your honeypot collectors strip all plaintext passwords and password hashes before storing telemetry?
**Answer:** In enterprise environments, human administrators occasionally mistype a production hostname and accidentally enter a real corporate password into an internal SSH or SMB honeypot. Storing plaintext passwords or crackable hashes in SOC logs creates a severe credential-leakage liability. Therefore, `cowrieAdapter.js` and `honeypot-event-collector-service` enforce a strict zero-password policy: only `username_attempted`, `attempt_count`, and `auth_outcome` (`FAILED` / `SUCCESS`) are stored.

### Q24. Which Suricata EVE JSON event types does Shadow Guard 2.0 ingest, and why is `alert` alone insufficient?
**Answer:** `suricata-event-collector-service` ingests five EVE record types: `alert`, `dns`, `http`, `tls`, and `flow`. `alert` alone is insufficient because high-entropy DNS exfiltration queries (`dns`), suspicious HTTP user-agents/URIs (`http`), and self-signed or botnet JA3 TLS fingerprints (`tls`) provide critical enrichment context for correlation and threat intelligence lookups even before a signature alert fires.

### Q25. Why did you choose RabbitMQ over Redis for asynchronous event streaming, and how are failed messages handled?
**Answer:** Per Architectural Modification #2, Redis was excluded to minimize infrastructure complexity. RabbitMQ (`3.13-management-alpine`) provides a durable topic exchange (`sg.events`) with routing-key subscriptions (`nids.*`, `deception.*`, `network.*`, `soar.*`) and a dedicated Dead-Letter Exchange (`sg.dlx` -> `q.dlq.events`) with exponential backoff retries so transient consumer failures never drop security telemetry.

### Q26. How does the sliding-window `EventCorrelationEngine` achieve a `98.62%–98.63%` reduction in alert fatigue without Redis, and is alert consolidation a reduction in false positives?
**Answer:** `EventCorrelationEngine` (`event-correlation-service/engine/correlationEngine.js`) maintains an in-memory map keyed by `source_ip` over a configurable 30-minute sliding window (`windowMs = 1,800,000 ms`) with a 2-second burst deduplication filter. In Cohort E (`363` raw alerts: `360` true-positive malicious alerts + `3` single-detector internal false positives), `240` non-duplicate malicious alerts match `CORR-01..CORR-06` and merge into **`5` structured multi-stage incidents** (one per external attacker IP), `120` consecutive burst alerts within 2 seconds are deduplicated, and `3` low-severity internal single-detector alerts remain uncorrelated manual-review items (`1 - 5/363 = 98.62%` alert consolidation). Crucially, **alert consolidation is NOT a reduction in false-positive rate**—it groups multi-event attacks by `source_ip` to prevent SOC alert storms while the system FPR is independently measured (`3/140 = 2.14%`).

### Q27. Explain the difference between `OBSERVED`, `INFERRED`, and `SUSPECTED` stages in your MITRE ATT&CK kill-chain reconstruction.
**Answer:** In `AttackChainBuilder` (`attack-chain-service/engine/attackChainBuilder.js`):
- **`OBSERVED`**: Directly proven by deterministic packet signature (`Suricata SID`) or interactive decoy session (`Cowrie` command execution, `Dionaea` file capture).
- **`INFERRED`**: Derived from statistical/ML flow classification (`Random Forest`, `Isolation Forest`, or `PyTorch Autoencoder` flow anomaly).
- **`SUSPECTED`**: An intermediate kill-chain bridge stage (e.g., inferring `TA0001 Initial Access` when `TA0043 Reconnaissance` is followed directly by `TA0002 Execution`) with a decayed confidence score ($\times 0.70$) so analysts never confuse gap-filling hypotheses with hard forensic evidence.

### Q28. How does the 5-Factor Attacker Risk Score work in `attacker-profiling-service`?
**Answer:** For every `source_ip`, the profiler computes a weighted score $R \in [0, 100]$:
$$R = 0.25 S_{\text{severity}} + 0.25 S_{\text{honeypot}} + 0.20 S_{\text{intel}} + 0.15 S_{\text{progression}} + 0.15 S_{\text{frequency}}$$
Each factor is explicitly logged alongside the list of `event_id`s that triggered it, making every risk score 100% auditable.

### Q29. What is Closed-Loop Adaptive Deception (`DEC-01` to `DEC-04`)?
**Answer:** `AdaptiveDeceptionEngine` (`deception-manager-service`) dynamically adapts the deception posture based on live attacker behavior:
- `DEC-01`: Expands high-interaction Cowrie SSH decoy listeners when repeated reconnaissance (`TA0043`) is detected.
- `DEC-02`: Deploys honey-credential breadcrumbs when credential stuffing (`TA0006`) is observed.
- `DEC-03`: Elevates OpenCanary SMB/MySQL decoy logging during lateral discovery (`TA0007`).
- `DEC-04`: Isolates and snapshots Dionaea malware quarantine volumes upon payload delivery (`TA0002`).
All directives support instant rollback.

### Q30. Why must an Autoencoder-only (`AE_ONLY`) anomaly NEVER execute an automatic IP block in SOAR?
**Answer:** An Autoencoder measures statistical deviation from the training normal manifold ($\text{MSE} > P_{97}$), not malicious intent. Even with a validation-calibrated threshold at $P_{97}$, approximately $2\%–3.3\%$ of legitimate normal traffic (such as an unusual backup burst or large HTTPS transfer) will exceed $P_{97}$. In fact, on our held-out `test_set`, all `4` `AE_ONLY` detections (`flow-norm-00258`, `flow-norm-00366`, `flow-norm-00639`, `flow-norm-00286`) were legitimate normal flows! Because our guardrail sets `auto_block_permitted = false` and `recommended_action = manual-review` for `AE_ONLY`, **zero (`0/4`) normal flows were erroneously blocked**.

### Q31. What happens in SOAR if an attacker spoofs the IP address of the internal DNS server or default gateway (`10.0.0.1` or `127.0.0.1`)?
**Answer:** `ResponseExecutionEngine` (`automated-response-service/engine/responseExecutionEngine.js`) checks every target IP against an immutable critical-infrastructure allowlist (`127.0.0.1`, `10.0.0.1`, gateway/DNS IPs) before executing any block. If an allowlisted IP is targeted, the block is rejected (`status: rejected_allowlist`) and logged for analyst review, preventing self-inflicted denial of service via IP spoofing.

### Q32. Why does Shadow Guard 2.0 use 30-minute timed IP block leases (`BLOCK_IP_TEMPORARY`) by default instead of permanent firewall bans?
**Answer:** Dynamic IP reassignment (DHCP, NAT gateways, cloud egress IPs) means blocking an IP permanently can block legitimate users hours or days later. Shadow Guard 2.0 issues 30-minute expiring leases (`lease_minutes: 30`) for automated containment and places permanent block requests (`BLOCK_IP_PERMANENT`) into a manual analyst approval queue (`pending_approvals`), with one-click rollback (`POST /api/soar/actions/:id/rollback`) available at any time.

### Q33. How does the platform handle degraded mode when one of the three ML models fails or is offline?
**Answer:** If any model (`random_forest`, `isolation_forest`, or `autoencoder`) is unavailable, `TriModelFusionEngine` and `/decide` set `status: "degraded"`, list the unavailable model in `degraded_models`, evaluate the remaining healthy models so detection visibility is not lost, and enforce `auto_block_permitted = false` (`action: "manual-review"`). It **never** silently classifies traffic as normal and **never** executes an uncorroborated auto-block.

### Q34. How is Role-Based Access Control (RBAC) enforced across the SOC Command Center (`:7000`)?
**Answer:** `securityAndObservability.js` implements JWT token verification and role enforcement across three tiers:
- **`VIEWER`**: Read-only access to dashboards, Tri-Model telemetry, and Cohort A–E research benchmarks (`GET` endpoints).
- **`ANALYST`**: Can trigger SOAR evaluations, approve/reject pending blocks, and switch Tri-Model fusion policies (`POST /api/soc/ml/tri-model/policy`).
- **`ADMIN`**: Full administrative control including playbook rule modification, deception directive rollback, and model reloads.

### Q35. How does Threat Intelligence caching work, and what happens when external API keys (AbuseIPDB, VirusTotal, OTX) are not configured?
**Answer:** `ThreatIntelEngine` checks its local TTL cache first, queries configured external providers if keys are present, and falls back deterministically to a curated local IOC intelligence database (`localIocStore`) so offline lab environments and reproducible benchmarks (`Cohorts D & E`) run with zero external network dependency.

### Q36. How do Cohort B (`+Suricata`) and Cohort C (`+Honeypots`) complement each other across the 10 benchmark scenarios?
**Answer:**
- **Cohort B (`+Suricata`)** achieves `100%` recall on external network-layer attacks where attackers do not touch decoy hosts: `S02_PORT_SCANNING` (`100%`), `S08_DATA_EXFILTRATION` DNS tunnels (`100%`), and `S09_C2_BEACONING` (`100%`), where Cohort C (`+Honeypots`) only achieves `65%–75%`.
- **Cohort C (`+Honeypots`)** achieves `100%` recall on interactive deception scenarios where payloads are encrypted or low-volume: `S03_SSH_BRUTE_FORCE` (`100%`), `S04_HTTP_FTP_SMB_RECON` (`100%`), `S05_HONEYPOT_COMMAND_EXEC` (`100%`), and `S06_MALWARE_SAMPLE_DOWNLOAD` (`100%`), where Cohort B (`+Suricata`) only achieves `25%–82.5%`.
Combining both in **Cohorts D & E** achieves **`100.00%` recall across all 9 attack scenarios**.

### Q37. How does Cohort E reduce the system False Positive Rate on `S01_NORMAL_TRAFFIC` from `4.29%` (Cohort D) to `2.14%` (Cohort E) while achieving `0` erroneous IP blocks?
**Answer:** In `S01_NORMAL_TRAFFIC` (`140` normal enterprise events), Cohort D generated `6` false positives (`FPR = 4.29%`) on internal backup bursts. In our audited, leak-free **Cohort E** (where `S01_NORMAL_TRAFFIC` is paired sequentially with the first `140` unfiltered held-out normal test flows `norm_flows[0..139]` from `test_set` and evaluated under the frozen `weighted_consensus` policy), only **`3` normal flows** (`EV-0005 / flow-norm-00258` [`AE_ONLY P99`], `EV-0006 / flow-norm-01179` [`IF_ONLY`], and `EV-0131 / flow-norm-00366` [`AE_ONLY P97`]) trigger single-detector unsupervised alerts, halving the system FPR to **`2.14%` (`TN = 137, FP = 3`)**. Even more importantly, because all `3` false positives are single-detector unsupervised anomalies (`AE_ONLY` or `IF_ONLY`), the Stage 3/4 Tri-Model SOAR Guardrail sets `auto_block_permitted = false`, resulting in **`0` benign internal IPs blocked** (whereas removing the SOAR guardrail in `Ablation 4` causes all `3` benign hosts to be erroneously blocked!).

### Q38. How does the SOC Dashboard prevent Cross-Site Scripting (XSS) when displaying attacker-controlled fields like SSH usernames, shell commands, or URLs?
**Answer:** In `threat-dashboard-service/public/app.js`, every dynamic string rendered into the DOM passes through `escapeHtml(val)` (converting `&`, `<`, `>`, `"`, `'` to HTML entities), and the HTTP server sets strict security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).

### Q39. How is observability implemented across the microservices?
**Answer:** Every service exposes `/health`, `/health/live`, and `/health/ready` endpoints plus a Prometheus-compatible `/metrics` endpoint (`securityAndObservability.js`) tracking request counts, latency histograms, active SOAR block leases, and Tri-Model inference counters.

### Q40. How did you ensure that synthetic research benchmark data never pollutes live operational SOC incident tables?
**Answer:** Research benchmark telemetry (`data/tri_model_dashboard_telemetry_v2.json` and `evaluation/results/cohort_e_benchmark_results.json`) is tagged with `"benchmark_classification": "SYNTHETIC BENCHMARK ONLY"` and served through dedicated read-only evaluation structures (`tri_model_detection`, `research_evaluation`), keeping live operational incidents (`normalized_security_events`, `security_incidents`) strictly separated.

---

## PART C: 10 Questions on Experimental Validity, Feature Collisions & Limitations

### Q41. What is the exact origin of the 1,524 network flow records used to train and evaluate the Autoencoder? Are they from a real PCAP?
**Answer:** No. We state explicitly throughout the codebase, dashboard, and thesis that the dataset is **100% synthetic parametric generation (`SYNTHETIC BENCHMARK ONLY`)**, created by `scripts/prepare_autoencoder_dataset.py` with `seed = 42` across 6 normal enterprise profiles and 8 attack profiles. They are not from a live network capture or public PCAP dataset.

### Q42. Why is it scientifically invalid to claim "real-world zero-day detection" from your held-out `test_set` results?
**Answer:** Although the `384` flows in `test_set` (`182` normal + `202` attack) have zero record overlap with the training/validation splits (`zero_hash_overlap_verified = true`), they were sampled from the **same parametric distributions** (`prepare_autoencoder_dataset.py`) used to generate the benchmark. True zero-day validation requires evaluating on genuinely novel exploit traffic captured from real network environments (such as CIC-IDS2017, UNSW-NB15, or live enterprise taps).

### Q43. Your feature vector has 69 dimensions. Does it actually contain 69 independent network flow measurements?
**Answer:** No. Our Stage 1 mathematical audit (`shared/ml/feature_schema.py` and `data/autoencoder_dataset_audit_report.json`) proved that all 69 features in `flow-feature-extraction-service` are deterministic transformations $\mathbf{x} = \Phi(p, b, d)$ of only **three scalar inputs**: `packets`, `bytes`, and `duration`. Therefore, the intrinsic informational dimensionality of the 69-feature space is bounded above by $3$.

### Q44. Which specific feature indices in the 69-feature schema are redundant or collinear, and why did you keep them?
**Answer:**
1. **Features `f_25`–`f_39` (15 polynomial ratio features)** contain **13 exact duplicate columns**: all 8 even-index columns (`f_25, f_27, f_29, f_31, f_33, f_35, f_37, f_39`) equal $p^2/(1+p)$, and all 7 odd-index columns (`f_26, f_28, f_30, f_32, f_34, f_36, f_38`) equal $p/(1+d)$.
2. **Features `f_55`–`f_68` (14 padding features)** are $(0.1 + 0.01k)\frac{p+b}{1+d}$, which are exact scalar multiples of a single ratio (`rank = 1`).
We preserved the 69-feature schema to maintain **100% backward compatibility** with existing Shadow Guard services and model contracts (Requirement #2), while documenting these exact mathematical limitations.

### Q45. What are the 4 cross-label feature-collision flows in `test_set`, and why weren't they deleted as "corrupted data"?
**Answer:** In real networks, two distinct flows (different IPs, ports, and payloads) can have the exact same `(packets, bytes, duration)` measurements—for example, a 7-packet, 490-byte, 19ms SSH session (`flow-collision-norm-01`) and a 7-packet, 490-byte, 19ms service enumeration probe (`flow-collision-atk-01`). Because $\Phi(p, b, d)$ depends only on $(p, b, d)$, both produce the **exact same 69-feature vector** and the exact same reconstruction error ($\text{MSE} = 0.470278$). Deleting them would artificially hide a real limitation of 3-scalar flow features. Per Stage 1 Requirement #1, we preserved all 4 collision flows in `test_set` and quarantined only genuinely corrupted source records (`NaN`, negative values, or same-`flow_id` label contradictions).

### Q46. Why did you not run the 69-feature Autoencoder directly on the original 500 events in `scripts/evaluate_research_cohorts.js` by inventing packet and byte counts?
**Answer:** In `scripts/evaluate_research_cohorts.js`, the 500 events were created as high-level normalized NIDS/Honeypot events where `packets`, `bytes`, and `duration` were omitted (`0, 0, 0`). Fabricating or randomly guessing `(packets, bytes, duration)` on those 500 events would violate scientific integrity (Stage 1 Requirement #3). Instead, we preserved `evaluate_research_cohorts.js` untouched and linked authentic held-out flows from the 384-flow 69-feature `test_set` in `scripts/evaluate_cohort_e_benchmark.js` while reporting Track 1 (500-event system ablation) and Track 2 (384-flow 69-feature ablation) transparently.

### Q47. Why does supervised Random Forest outperform the PyTorch Autoencoder on overall F1 (`0.9722` vs `0.7165`) on the 384-flow test set?
**Answer:** Because the synthetic dataset generator creates attacks using 8 bounded parametric rules in $(p, b, d)$, and `RandomForestClassifier` is given `120` labeled attack flows (`supervised_attack_train`) drawn from those exact 8 parametric rules. Decision trees carve axis-aligned boxes that match the synthetic generator's boundaries. The PyTorch Autoencoder is given **zero attack labels** (`train_normal` only), solving a harder open-world problem.

### Q48. Why did you fix the Unsupervised Ensemble accuracy from `82.81%` to `82.29%` in the Stage 3 audit?
**Answer:** On the `384`-flow held-out `test_set`, the `IF + AE Unsupervised Ensemble` confusion matrix is `TN = 176, FP = 6, FN = 62, TP = 140`. Computing accuracy directly from the confusion matrix gives:
$$\text{Accuracy} = \frac{\text{TN} + \text{TP}}{N} = \frac{176 + 140}{384} = \frac{316}{384} = 0.822916\dots \approx 82.29\%$$
We verified in `AE Stg 3`, `AE Stg 4`, and `AE Stg 5` that every metric in the codebase and UI is derived directly from its confusion matrix with zero rounding or transcription discrepancies.

### Q49. Why is Detection Performance reported separately from SOAR Response Performance in Track 3?
**Answer:** Because a detection alert and an automated firewall block have different operational risk tolerances. In `weighted_consensus`, the detection layer flags `201` flows (`194` TP + `7` FP) so analysts have `96.04%` visibility into attacks. However, the SOAR response layer only permits automatic blocking on high-confidence multi-model consensus (`75` flows, `100%` true attacks) and routes all single-detector outliers (`22` flows, including all `4` `AE_ONLY` and `2` `IF_ONLY` false positives) to `manual-review`, achieving **`0` erroneous IP blocks (`0.00%` operational block FPR)**.

### Q50. What concrete upgrades are required before deploying Shadow Guard 2.0 on a live production campus or enterprise network?
**Answer:**
1. Replace the 3-scalar `(packets, bytes, duration)` feature extractor (`f_25..f_39` duplicates and `f_55..f_68` collinear padding) with a real **CICFlowMeter / NFStream** extractor computing 69 genuinely independent bidirectional L3/L4/L7 flow features from live packet taps.
2. Retrain and benchmark the PyTorch Autoencoder on real enterprise PCAPs and public datasets (**CIC-IDS2017**, **CSE-CIC-IDS2018**, **UNSW-NB15**).
3. Persist sliding-window correlation state to PostgreSQL / TimescaleDB for crash-resilient state recovery across container restarts.

---

## PART D: 5-Minute Project Presentation Script

> **Slide 1 — Title & Core Problem (0:00 – 0:45)**
> "Good morning/afternoon to the examination panel. I am presenting **Shadow Guard 2.0**, an Intelligent Cyber Defence, Cyber Deception, Explainable Tri-Model Anomaly Detection, and Automated Incident Response Platform.
> Modern enterprise SOCs face a critical dilemma: signature-based NIDS like Suricata miss novel traffic patterns, flow-only machine learning misses encrypted post-auth commands and suffers from feature collisions, and standalone unsupervised anomaly detectors generate false positives that cannot safely trigger automated IP blocking. Shadow Guard 2.0 solves this by uniting a **PyTorch Deep Reconstruction Autoencoder**, **Tri-Model Detection Fusion**, **Suricata NIDS**, **isolated Multi-Type Honeypots**, **Sliding-Window Correlation**, and **Safety-Gated SOAR** across a 22-container segmented architecture."

> **Slide 2 — 69-Feature Audit & PyTorch Autoencoder Architecture (0:45 – 2:00)**
> "In Stage 1, we audited the legacy pipeline and resolved a mismatch between the 7-column training script and the 69-feature runtime extractor, establishing bit-exact parity (`max_abs_diff = 0.0`) between Node.js and Python. We also proved mathematically that all 69 legacy features derive from 3 raw scalars (`packets, bytes, duration`), containing 13 duplicate polynomial columns and 14 collinear padding columns—which can cause cross-label feature collisions when distinct normal and attack flows share identical volume and duration.
> In Stage 2, we built our authoritative **PyTorch Flow Autoencoder (`69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69`)** with `signed_log1p` and `RobustScaler(Q25, Q75)` preprocessing fitted strictly on **840 normal flows (`train_normal`)** with zero attack leakage. On our 180-flow normal validation split (`val_normal`), we calibrated $P_{95}$, $P_{97}$, and $P_{99}$, selecting and freezing **$P_{97} = 0.503670$** (`3.33%` validation FPR) to satisfy the $\le 3.5\%$ SOC false-positive budget."

> **Slide 3 — Tri-Model Fusion & Safety-Gated SOAR Guardrails (2:00 – 3:15)**
> "In Stages 3 and 4, we integrated the PyTorch Autoencoder with **Random Forest** (supervised probability) and **Isolation Forest** (unsupervised outlier score) inside `ml-detection-service` under three selectable fusion policies: `weighted_consensus`, `unsupervised_ensemble`, and `majority_vote`.
> Crucially, we separated **Detection Visibility** from **Automated SOAR Containment**: whenever a flow is flagged solely by the Autoencoder (`AE_ONLY`) or when any model is degraded, our guardrail sets `auto_block_permitted = false` and routes the alert to analyst `manual-review` in our 8-page SOC Command Center on port 7000—showing per-flow MSE, top-5 contributing features, and model agreement."

> **Slide 4 — Cohort E Ablation Results & Scientific Validity (3:15 – 4:30)**
> "In Stage 5, we evaluated the complete architecture on our reproducible synthetic benchmarks (**`SYNTHETIC BENCHMARK ONLY`**):
> 1. On the **384-flow held-out test set**, adding the PyTorch Autoencoder lifts label-free unsupervised recall from **49.50%** (Isolation Forest alone) to **69.31%** in the **IF + AE Unsupervised Ensemble** ($\text{F1} = 0.8046$), detecting **76.00%** of `c2_beaconing` and **56.67%** of `port_scan` flows where Isolation Forest alone detected **0.00%**.
> 2. Across the **500-event multi-source system benchmark (`Cohorts A–E`)**, our audited leak-free **Cohort E** achieves **99.40% accuracy** (`TP=360, FP=3, TN=137, FN=0`, **99.17% precision**, **100.00% recall**, **99.59% F1**), halves the system false-positive rate from **4.29%** (Cohort D) to **2.14%**, consolidates **363 raw alerts into 5 correlated incidents (98.62% alert queue consolidation)**, and prevents **100% (`3/3` in Track 1; `4/4` `AE_ONLY` in Track 2) of single-detector normal outliers** from executing automatic IP blocks (`0` benign IPs blocked)."

> **Slide 5 — Conclusion & Verification (4:30 – 5:00)**
> "Every subsystem, guardrail, and mathematical claim is verified by **11 automated verification suites totaling 419 assertions (`419 PASSED, 0 FAILED`)**. Thank you—I welcome your questions."

---

## PART E: 10-Minute Detailed Technical Walkthrough

### Minute 0:00 – 1:30 | System Architecture & 5-Zone Isolation
- Walk through the 5 segmented Docker networks: `sg_ingress_net` (Suricata + Traffic Capture), `sg_deception_dmz` (`internal: true` isolating Cowrie SSH/Telnet, OpenCanary HTTP/FTP/SMB/MySQL, and Dionaea malware traps with `:ro` log mounts and `noexec` quarantine), `sg_core_net` (RabbitMQ `sg.events` + `sg.dlx`, Tri-Model ML, Threat Intel, Attacker Profiling, Correlation, Attack Chain Builder, Deception Manager, SOAR), `sg_storage_net` (PostgreSQL 15 with 17 tables), and `sg_frontend_net` (8-page SOC Dashboard on `:7000`).

### Minute 1:30 – 3:30 | Canonical 69-Feature Mathematics & Leak-Free Dataset Pipeline
- Explain how `shared/ml/feature_schema.py` and `flow-feature-extraction-service/index.js` compute the exact same 69 features ($\text{max\_abs\_diff} = 0.0$).
- Present the mathematical audit: 10 base/rate/log features (`f_00..f_09`), 15 trig/log features (`f_10..f_24`), 15 polynomial ratio features (`f_25..f_39`, containing 13 duplicate columns), 15 damped cosine features (`f_40..f_54`), and 14 collinear padding features (`f_55..f_68`).
- Show the 4 preserved cross-label collision records (`flow-collision-norm-00/01` and `flow-collision-atk-00/01`) and explain why 3-scalar flow collisions create a non-zero Bayes error floor that requires NIDS and Honeypot fusion.

### Minute 3:30 – 5:30 | PyTorch Autoencoder Training & Validation Threshold Calibration
- Detail `FeaturePreprocessor` (`signed_log1p` + `RobustScaler(Q25, Q75)` + `clip[-10, 10]`) fitted strictly on `train_normal` (`840` flows).
- Detail `FlowAutoencoder` (`69 -> 32 -> 16 -> 8 -> 16 -> 32 -> 69`, ReLU hidden activations, Linear output, Adam $\text{lr}=0.002$, 120 epochs, `best_epoch=114`, `val_mse=0.141353`).
- Contrast $P_{95} = 0.409105$ (`5.00%` val FPR), **$P_{97} = 0.503670$ (`3.33%` val FPR — frozen primary threshold)**, and $P_{99} = 0.645935$ (`1.11%` val FPR), explaining why tuning on `test_set` is forbidden.

### Minute 5:30 – 7:30 | Tri-Model Fusion, Explainability & SOAR Safety Guardrails
- Walk through `TriModelFusionEngine` (`shared/ml/tri_model_fusion.py`) and the three policies (`weighted_consensus`, `unsupervised_ensemble`, `majority_vote`).
- Show how `ml-detection-service` computes top-5 MSE feature attributions ($e_j = (z_j - \hat{z}_j)^2$) and clearly distinguishes **Attack Probability** (`PROBABILITY`) from **Isolation Score** (`ANOMALY_SCORE`) and **Reconstruction MSE** (`RECONSTRUCTION_ERROR_MSE`).
- Trace an `AE_ONLY` flow (`flow-norm-00258`, $\text{MSE} = 0.7409 > P_{97}$, $\text{RF} = 0.04$) through `playbook-decision-engine/index.js` (`/decide`), showing how `auto_block_permitted = false` routes it to `manual-review` instead of blocking a legitimate normal flow.

### Minute 7:30 – 10:00 | Cohort E Ablation Results, SOC Dashboard Demo & Future Scope
- Present the Track 1 (`500` events across `Cohorts A–E`), Track 2 (`384` held-out flows across 8 attack categories), and Track 3 (Detection vs. SOAR separation) tables.
- Highlight the SOC Command Center (`http://localhost:7000`): Tri-Model Overview cards, Model Health & Degraded-State banner, Per-Flow Explainable Drawer, False-Positive/False-Negative Evaluator (`FP=7, FN=8, AE_ONLY=4, Collisions=4`), and RBAC policy selector.
- Conclude with scientific limitations (`SYNTHETIC BENCHMARK ONLY`, 3-scalar feature bottleneck) and future work (CIC-IDS2017/UNSW-NB15 PCAP validation, bidirectional L3/L4/L7 features, and Temporal Sequence Autoencoders).

---

## PART F: Difficult Questions an External Examiner Might Ask (With Model Defenses)

### Examiner Trap 1: *"Your Random Forest achieves 97.14% accuracy while your new PyTorch Autoencoder achieves 76.30% accuracy. Doesn't that mean the Autoencoder failed and made your system worse?"*
**Your Defense:**
"No, Professor—comparing a supervised classifier against an unsupervised anomaly detector on overall accuracy in a synthetic closed-world split is an apples-to-oranges comparison:
1. Random Forest was given **120 labeled attack flows** drawn from the exact same 8 parametric equations used to generate the test attacks. In a closed-world synthetic benchmark, a tree ensemble will naturally fit those known parametric boxes (`97.14%`).
2. The PyTorch Autoencoder was trained on **zero attack labels (`840` normal flows only)**. Its proper baseline is our other unsupervised model, **Isolation Forest (`72.92%` accuracy, `49.50%` recall, `0.6579` F1)**.
3. Against Isolation Forest, the PyTorch Autoencoder improves unsupervised accuracy from `72.92%` to `76.30%` (and `81.77%` at $P_{95}$), achieves a **`0.9652` ROC-AUC**, detects **`76.00%` of `c2_beaconing`** and **`56.67%` of `port_scan`** where Isolation Forest achieved **`0.00%`**, and lifts the label-free **`IF + AE Unsupervised Ensemble` to `82.29%` accuracy and `69.31%` recall (`0.8046` F1)**."

### Examiner Trap 2: *"Why did you keep 13 duplicate columns (`f_25..f_39`) and 14 collinear columns (`f_55..f_68`) in the 69-feature vector instead of deleting them and training a 42-feature Autoencoder?"*
**Your Defense:**
"That was an explicit architectural constraint for backward compatibility: `flow-feature-extraction-service`, `ml-detection-service`, `threat-classification-service`, and all historical verification tests (`Stages 2–7`) enforce a strict 69-float contract. Deleting features would have broken backward compatibility across the microservice pipeline. Instead, we:
1. Mathematically proved and documented the exact duplicate and collinear indices in `shared/ml/feature_schema.py` and `data/autoencoder_dataset_audit_report.json`.
2. Applied `RobustScaler` and an 8-dimensional bottleneck (`69 -> 32 -> 16 -> 8`) which projects out collinear redundancy into an 8-dimensional latent space.
3. Documented replacing those 27 redundant coordinates with genuine bidirectional L3/L4/L7 features (TCP flags, IAT variance, payload entropy) as our primary v3 schema upgrade."

### Examiner Trap 3: *"In Track 1 (`Cohort E`), you report 100.00% Recall (`TP=360, FN=0`) and 99.40% Accuracy (`FP=3, TN=137`). Why is Recall 100.00% in Track 1 when Weighted Consensus gets 96.04% Recall (`FN=8`) in Track 2?"*
**Your Defense:**
"That is why we report **Track 1 (500-event multi-sensor system benchmark)**, **Track 1B (5 Cohort E Subsystem Ablations)**, and **Track 2 (384-flow ML-only benchmark)** separately and label all of them **`SYNTHETIC BENCHMARK ONLY`**:
- On the **ML-only flow benchmark (Track 2)**, the models do *not* get 100% recall: Random Forest gets `95.05%` (`FN = 10`), Autoencoder at $P_{97}$ gets `56.93%` (`FN = 87`), and Weighted Consensus gets `96.04%` (`TP = 194, FP = 7, TN = 175, FN = 8`, `Accuracy = 96.09%`), because stealth SSH/service-enumeration probes overlap normal `(packets, bytes, duration)` distributions and include `4` cross-label feature collisions.
- In **Track 1 (`Baseline Cohort E`)**, each of the 360 malicious events in scenarios `S02–S10` is a multi-modal security event generated with either a Suricata NIDS signature (`180` events) or an isolated Honeypot interaction (`180` events). Specifically, Tri-Model ML independently detects `347/360` (`96.39%`) of the malicious events, while the `13` low-volume stealth probes missed by flow ML (`2` in `S03`, `10` in `S04`, `1` in `S05`) are rescued by `Cowrie` and `OpenCanary` honeypots (`honeypot_only_rescues = 13`). When we disable Honeypots in **`Ablation 2A/2B`** or evaluate pure Tri-Model ML in **`Ablation 5`**, system recall drops from **`100.00%` to `96.39%` (`TP = 347, FN = 13`)**, proving that `100%` recall requires multi-sensor deception coverage."

---

## PART D: 10 Challenging Questions on Explainable AI (XAI)

### Q51. Why did you use official `shap.TreeExplainer` for Random Forest, perturbation attribution for Isolation Forest, and MSE decomposition for the Autoencoder instead of one single method?
**Answer:** Each model has a distinct mathematical structure: `RandomForestClassifier` is a tree ensemble whose exact Shapley values over $P(\text{attack}\mid \mathbf{x})$ can be computed in polynomial time via `shap.TreeExplainer` (`shap == 0.54.1`, max additivity error `8.88e-16`). Isolation Forest outputs unsupervised tree-isolation path-length scores (`NOT a probability`), which we explain via reference-population median-replacement perturbation (`840` normal flows, bootstrap $\rho = 0.9878$). The PyTorch Autoencoder minimizes 69-dimensional MSE, so per-feature squared reconstruction errors $(z_j - \hat{z}_j)^2$ directly decompose its decision metric against frozen $P_{97} = 0.503670$.

### Q52. Does exact SHAP additivity ($8.88 \times 10^{-16}$) prove that the Random Forest found the real-world cause of a cyberattack?
**Answer:** **No.** Additivity only proves that $\mathbb{E}[P_{\text{RF}}(\text{attack})] + \sum_{j=0}^{68} \phi_j = P_{\text{RF}}(\text{attack} \mid \mathbf{x})$ accurately decomposes the *model's* prediction. Feature attributions reflect statistical correlations learned from `(packets, bytes, duration)`—never real-world causal proof.

### Q53. What did your Stage 5 attribution bias experiment reveal about the 69-feature schema?
**Answer:** Across `60` stratified flows, the `15` polynomial ratio columns (`f_25..f_39`, `13` exact duplicates) and `14` collinear harmonic padding columns (`f_55..f_68`) absorbed **`42.79%`** of Random Forest SHAP weight and **`51.28%`** of Isolation Forest perturbation weight (versus **`8.63%`** for the Autoencoder). Grouping into `(packets, bytes, duration)` eliminates this split-dilution artifact and reduces $\pm 5\%$ perturbation L1 shift to **`0.54%` (RF), `2.00%` (IF), and `2.16%` (AE)**.

### Q54. How does `UnifiedTriModelExplainer` handle model disagreement and partial model unavailability?
**Answer:** It never averages SHAP values, IF scores, and AE MSE. Instead, it reports `consensus_state` (`UNANIMOUS_ANOMALY_3_OF_3`, `MAJORITY_ANOMALY_2_OF_3_DISSENT`, `SINGLE_MODEL_ANOMALY_DISSENT_AUTOENCODER`, etc.), isolates any failed/unavailable model into `partially_degraded` or `degraded`, preserves `auto_block_permitted = false` on `AE_ONLY`/degraded states, and achieved **`0/384`** detection mismatches.

### Q55. How are XAI endpoints secured and persisted?
**Answer:** PostgreSQL migration `004_xai_explanations.sql` stores structured JSONB attributions with SHA-256 duplicate prevention (`uq_xai_flow_policy_signature`). Node.js `/api/v2/xai/*` routes enforce JWT/RBAC (`VIEWER` read-only with `src_ip`/`dst_ip` redacted, `SOC_ANALYST` explanation generation, `ADMIN` diagnostics) and record every request/denial in `securityAuditLog`. All `16` verification suites pass with **`517 PASSED, 0 FAILED`**.
