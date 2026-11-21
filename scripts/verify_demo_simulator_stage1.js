/**
 * Demo Simulator Stage 1 Verification Wrapper
 * Runs tests/test_demo_simulator_stage1.py and reports RESULTS for run_all_verifications.js
 */
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const root = path.resolve(__dirname, '..');
const res = spawnSync('python', ['-m', 'unittest', 'tests/test_demo_simulator_stage1.py', '-v'], {
  cwd: root,
  encoding: 'utf8'
});

const combined = `${res.stdout || ''}\n${res.stderr || ''}`.trim();
const ranMatch = combined.match(/Ran\s+(\d+)\s+tests?/i);
const count = ranMatch ? Number(ranMatch[1]) : 4;

if (res.status === 0) {
  console.log(combined);
  console.log(`RESULTS: ${count} PASSED, 0 FAILED`);
  process.exit(0);
} else {
  console.error(combined || (res.error && res.error.message) || 'Stage 1 tests failed');
  console.log(`RESULTS: 0 PASSED, ${count} FAILED`);
  process.exit(1);
}
