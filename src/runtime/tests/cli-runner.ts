/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - CLI Test Runner
 */

import { runAllRuntimeTests } from './runtime-tests';

async function main() {
  console.log('----------------------------------------------------');
  console.log('APK RUNTIME ENGINE - CLI TEST RUNNER');
  console.log('----------------------------------------------------');

  const results = await runAllRuntimeTests((res) => {
    const status = res.passed ? '✓ PASS' : '✗ FAIL';
    console.log(`[${status}] [${res.module}] ${res.name} (${res.durationMs}ms)`);
    if (res.error) {
      console.error(`       Error: ${res.error}`);
    }
  });

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  console.log('----------------------------------------------------');
  console.log(`Summary: ${passed} passed, ${failed} failed out of ${results.length} tests.`);
  console.log('----------------------------------------------------');

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal test runner error:', err);
  process.exit(1);
});
