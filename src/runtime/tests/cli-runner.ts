/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - CLI Test Runner
 * Produces structured regression test reports with timing, pass/fail counts, and non-zero exit on failure.
 */

import { runAllRuntimeTests } from './runtime-tests';

async function main() {
  console.log('====================================================');
  console.log('APK RUNTIME ENGINE — AUTOMATED REGRESSION TEST SUITE');
  console.log('====================================================\n');

  const startTime = performance.now();

  const results = await runAllRuntimeTests((res) => {
    const statusTag = res.passed ? '✓ PASS' : '✗ FAIL';
    console.log(`[${statusTag}] [${res.module}] ${res.name} (${res.durationMs.toFixed(2)} ms)`);
    if (res.error) {
      console.error(`       ↳ Error Details: ${res.error}`);
    }
  });

  const totalTime = (performance.now() - startTime).toFixed(2);
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;
  const skipped = 0; // All implemented tests execute

  console.log('\n====================================================');
  console.log('TEST EXECUTION REPORT');
  console.log('====================================================');
  console.log(`Total Test Suites : ${results.length}`);
  console.log(`Passed Suites     : ${passed}`);
  console.log(`Failed Suites     : ${failed}`);
  console.log(`Skipped Suites    : ${skipped}`);
  console.log(`Execution Duration: ${totalTime} ms`);
  console.log('====================================================');

  if (failed > 0) {
    console.error(`\n❌ REGRESSION DETECTED: ${failed} test suite(s) failed.`);
    process.exit(1);
  } else {
    console.log(`\n✅ ALL ${passed} TEST SUITES VERIFIED.`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Fatal test runner crash:', err);
  process.exit(1);
});
