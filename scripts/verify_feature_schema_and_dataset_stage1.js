/**
 * Shadow Guard 2.0 — Autoencoder Stage 1 Verification Suite
 * ==========================================================
 * Verifies:
 * 1. Cross-language Node.js (`flow-feature-extraction-service/index.js`) <-> Python
 *    (`shared/ml/feature_schema.py`) 69-feature extraction parity across 25 diverse flow records.
 * 2. 69-feature mathematical redundancy audit (3 raw inputs -> 69 features, 13 duplicate
 *    polynomial columns in f_25..f_39, and 14 rank-1 collinear padding columns in f_55..f_68).
 * 3. Legacy 7-column vs. 69-feature discrepancy documentation while keeping `generate_data.py`
 *    and `model-training-service/train_model.py` completely untouched.
 * 4. Stage 7 500-event benchmark compatibility check (`validate_event_for_69_features`),
 *    confirming zero fabricated flow values.
 * 5. Full-record-identity deduplication (preserving distinct flows that share `(packets, bytes, duration)`,
 *    removing exact duplicates, and quarantining conflicting binary labels).
 * 6. Leak-free dataset splits (`train_normal`, `val_normal`, `test_set`) with 100% normal-only
 *    purity in `train_normal` and `val_normal` and zero hash overlap across splits.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  [PASS] ${message}`);
  } else {
    failed++;
    console.error(`  [FAIL] ${message}`);
  }
}

/**
 * Extracts and compiles `generateExtendedFeatures` directly from `flow-feature-extraction-service/index.js`
 * so we test the exact runtime JavaScript implementation without starting Express on port 3000.
 */
function loadNodeFeatureExtractor() {
  const indexSource = fs.readFileSync(
    path.join(ROOT, 'flow-feature-extraction-service', 'index.js'),
    'utf8'
  );
  const startIdx = indexSource.indexOf('function generateExtendedFeatures(');
  const endIdx = indexSource.indexOf('function buildTrafficContext(');
  if (startIdx === -1 || endIdx === -1) {
    throw new Error('Could not locate generateExtendedFeatures in flow-feature-extraction-service/index.js');
  }
  const fnSource = indexSource.slice(startIdx, endIdx);
  const sandbox = { Math };
  vm.createContext(sandbox);
  vm.runInContext(`${fnSource}\nthis.generateExtendedFeatures = generateExtendedFeatures;`, sandbox);
  return sandbox.generateExtendedFeatures;
}

function main() {
  console.log('===================================================================');
  console.log('  SHADOW GUARD 2.0 — AUTOENCODER STAGE 1 VERIFICATION SUITE');
  console.log('===================================================================\n');

  // 1. Execute dataset preparation and audit script
  console.log('--- 1. Running Dataset Preparation & Audit Pipeline ---');
  const stdout = execFileSync(
    'python',
    [path.join(ROOT, 'scripts', 'prepare_autoencoder_dataset.py')],
    { encoding: 'utf8', cwd: ROOT }
  );
  const auditReport = JSON.parse(stdout);

  const datasetPath = path.join(ROOT, 'data', 'autoencoder_flow_dataset_v2.json');
  const reportPath = path.join(ROOT, 'data', 'autoencoder_dataset_audit_report.json');

  assert(fs.existsSync(datasetPath), 'data/autoencoder_flow_dataset_v2.json created');
  assert(fs.existsSync(reportPath), 'data/autoencoder_dataset_audit_report.json created');

  // 2. Cross-Language Node.js <-> Python 69-Feature Parity Test
  console.log('\n--- 2. Cross-Language Node.js <-> Python 69-Feature Parity ---');
  const generateExtendedFeaturesJS = loadNodeFeatureExtractor();

  const testFlows = [
    { packets: 0, bytes: 0, duration: 0 },
    { packets: 1, bytes: 64, duration: 0.001 },
    { packets: 2, bytes: 144, duration: 0.025 },
    { packets: 12, bytes: 8400, duration: 0.45 },
    { packets: 45, bytes: 38250, duration: 2.15 },
    { packets: 120, bytes: 168000, duration: 5.8 },
    { packets: 850, bytes: 1224000, duration: 0.12 },
    { packets: 3200, bytes: 4608000, duration: 0.05 },
    { packets: 5, bytes: 320, duration: 0.008 },
    { packets: 77, bytes: 9856, duration: 14.2 },
    { packets: 19, bytes: 2470, duration: 0.99 },
    { packets: 210, bytes: 298200, duration: 8.75 },
    { packets: 3, bytes: 180, duration: 0.002 },
    { packets: 64, bytes: 256000, duration: 0.65 },
    { packets: 500, bytes: 720000, duration: 1.5 },
    { packets: 9, bytes: 1152, duration: 0.11 },
    { packets: 33, bytes: 19800, duration: 0.777 },
    { packets: 145, bytes: 188500, duration: 3.333 },
    { packets: 28, bytes: 2240, duration: 0.22 },
    { packets: 1024, bytes: 1536000, duration: 0.42 },
    { packets: 15, bytes: 9600, duration: 1.0 },
    { packets: 88, bytes: 44000, duration: 4.4 },
    { packets: 6, bytes: 480, duration: 0.015 },
    { packets: 310, bytes: 434000, duration: 6.2 },
    { packets: 42, bytes: 21000, duration: 1.2345 },
  ];

  const pyJsonOut = execFileSync(
    'python',
    [path.join(ROOT, 'shared', 'ml', 'feature_schema.py'), '--extract-json', JSON.stringify(testFlows)],
    { encoding: 'utf8', cwd: ROOT }
  );
  const pyVectors = JSON.parse(pyJsonOut);

  assert(pyVectors.length === testFlows.length, `Extracted ${pyVectors.length}/25 flow vectors from Python`);

  let maxRelError = 0;
  let allLengths69 = true;

  for (let i = 0; i < testFlows.length; i++) {
    const jsVec = generateExtendedFeaturesJS(testFlows[i]);
    const pyVec = pyVectors[i];
    if (jsVec.length !== 69 || pyVec.length !== 69) {
      allLengths69 = false;
    }
    for (let j = 0; j < 69; j++) {
      const diff = Math.abs(jsVec[j] - pyVec[j]);
      const denom = Math.max(Math.abs(jsVec[j]), Math.abs(pyVec[j]), 1.0);
      const rel = diff / denom;
      if (rel > maxRelError) {
        maxRelError = rel;
      }
    }
  }

  assert(allLengths69, 'Every JS and Python vector has exactly 69 features');
  assert(
    maxRelError < 1e-12,
    `Node.js <-> Python 69-feature parity within IEEE-754 precision (max relative error = ${maxRelError.toExponential(3)} < 1e-12)`
  );

  // 3. Mathematical Audit of the 69 Features
  console.log('\n--- 3. Mathematical Audit of the 69-Feature Schema ---');
  const mathAudit = auditReport.feature_mathematics_audit;
  assert(mathAudit.total_features === 69, 'Audit confirms 69 total features');
  assert(
    JSON.stringify(mathAudit.raw_independent_inputs) === JSON.stringify(['packets', 'bytes', 'duration']),
    'Audit documents that all 69 features derive from only 3 raw inputs (packets, bytes, duration)'
  );
  assert(
    mathAudit.duplicate_columns_count === 13,
    `Audit identifies 13 exact duplicate polynomial columns in f_25..f_39 (got ${mathAudit.duplicate_columns_count})`
  );
  assert(
    mathAudit.padding_f55_to_f68_rank1_collinear === true,
    'Audit confirms f_55..f_68 are 14 rank-1 collinear scalar multiples'
  );

  // 4. Legacy Pipeline Preservation & Stage 7 Benchmark Audit
  console.log('\n--- 4. Legacy Pipeline Preservation & Stage 7 Benchmark Audit ---');
  const legAudit = auditReport.legacy_pipeline_audit;
  assert(legAudit.generate_data_py_column_count === 7, 'Legacy generate_data.py audited as 7 columns');
  assert(legAudit.generate_data_py_has_label_column === false, 'Legacy generate_data.py confirmed missing Label column');
  assert(legAudit.train_model_py_expects_label_column === true, 'Legacy train_model.py confirmed expecting Label column');

  const s7Audit = auditReport.stage7_benchmark_compatibility_audit;
  assert(
    s7Audit.sample_event_eligibility.eligible === false &&
      s7Audit.sample_event_eligibility.reason === 'missing_or_zero_packet_and_byte_counts',
    'Stage 7 500-event audit confirms zero raw packet/byte counters without fabricating missing values'
  );

  // 5. Full-Record-Identity Deduplication, Feature-Collision Preservation & Corrupted Quarantine
  console.log('\n--- 5. Full-Record-Identity Deduplication, Feature-Collision Preservation & Quarantine ---');
  const dedup = auditReport.deduplication_and_label_hygiene;
  assert(
    dedup.exact_duplicates_removed === 5,
    `Removed 5 exact record-identity duplicates (got ${dedup.exact_duplicates_removed})`
  );
  assert(
    dedup.distinct_flows_sharing_pbd_preserved >= 11,
    `Preserved distinct network flows sharing identical (packets, bytes, duration) (${dedup.distinct_flows_sharing_pbd_preserved} preserved)`
  );
  assert(
    dedup.feature_collision_ambiguity_flows_preserved === 4,
    `Preserved 4 legitimate distinct cross-label feature-collision flows as label-ambiguity cases (got ${dedup.feature_collision_ambiguity_flows_preserved})`
  );
  assert(
    dedup.corrupted_or_contradictory_source_records_quarantined === 6,
    `Quarantined 6 genuinely corrupted or same-flow_id contradictory source records (got ${dedup.corrupted_or_contradictory_source_records_quarantined})`
  );
  assert(
    auditReport.dataset_provenance &&
      auditReport.dataset_provenance.is_real_world_pcap_or_live_capture === false &&
      auditReport.dataset_provenance.benchmark_classification.autoencoder_flow_dataset_v2_results === 'SYNTHETIC_BENCHMARK_ONLY',
    'Dataset provenance explicitly documents 100% synthetic parametric generation (not real-world PCAP)'
  );

  // 6. Leak-Free Splits & Normal-Only Training Purity
  console.log('\n--- 6. Leak-Free Splits & Normal-Only Training Purity ---');
  const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));
  const trainNormal = dataset.splits.train_normal;
  const valNormal = dataset.splits.val_normal;
  const supAtkTrain = dataset.splits.supervised_attack_train;
  const testSet = dataset.splits.test_set;

  assert(trainNormal.length === 840, `train_normal contains 840 flows (got ${trainNormal.length})`);
  assert(valNormal.length === 180, `val_normal contains 180 flows (got ${valNormal.length})`);
  assert(testSet.length === 384, `test_set contains 384 flows including 4 preserved feature-collision flows (got ${testSet.length})`);

  const trainAttacks = trainNormal.filter((r) => r.label !== 'normal');
  const valAttacks = valNormal.filter((r) => r.label !== 'normal');
  assert(trainAttacks.length === 0, 'train_normal is 100% normal-only (0 attack records)');
  assert(valAttacks.length === 0, 'val_normal is 100% normal-only (0 attack records)');

  const trainHashes = new Set(trainNormal.map((r) => r._record_hash));
  const valHashes = new Set(valNormal.map((r) => r._record_hash));
  const supHashes = new Set(supAtkTrain.map((r) => r._record_hash));
  const testHashes = new Set(testSet.map((r) => r._record_hash));

  const overlapTrainVal = [...trainHashes].filter((h) => valHashes.has(h)).length;
  const overlapTrainTest = [...trainHashes].filter((h) => testHashes.has(h)).length;
  const overlapValTest = [...valHashes].filter((h) => testHashes.has(h)).length;
  const overlapSupTest = [...supHashes].filter((h) => testHashes.has(h)).length;

  assert(overlapTrainVal === 0, 'Zero record-hash leakage between train_normal and val_normal');
  assert(overlapTrainTest === 0, 'Zero record-hash leakage between train_normal and test_set');
  assert(overlapValTest === 0, 'Zero record-hash leakage between val_normal and test_set');
  assert(overlapSupTest === 0, 'Zero record-hash leakage between supervised_attack_train and test_set');

  // Verify all 8 attack categories exist in test_set
  const testCategories = new Set(testSet.filter((r) => r.label === 'attack').map((r) => r.attack_category));
  assert(
    testCategories.size === 8,
    `test_set covers all 8 attack categories (${[...testCategories].sort().join(', ')})`
  );

  console.log(`\n===================================================================`);
  console.log(`  STAGE 1 SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log(`===================================================================`);

  if (failed > 0) {
    process.exit(1);
  }
}

main();
