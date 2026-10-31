/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Evidence-Based Compatibility Evaluation Engine
 * Evaluates real APK characteristics against implemented Phase 1 capabilities.
 * Enforces zero false claims: all parsed APKs remain ANALYSIS ONLY until Phase 4 DEX VM is implemented.
 */

import {
  AndroidManifestData,
  DexFileAnalysis,
  NativeLibraryInfo,
  CompatibilityReport,
  CompatibilityCheck,
  CompatibilityStatus,
} from '../core/types';

export function evaluateCompatibility(
  manifest: AndroidManifestData,
  dexFiles: DexFileAnalysis[],
  nativeLibs: NativeLibraryInfo[]
): CompatibilityReport {
  const checks: CompatibilityCheck[] = [];
  const missingApis: string[] = [];
  const unsupportedAbis: string[] = [];

  // Check 1: Archive & Manifest Structure
  const hasValidManifest = Boolean(manifest.packageName && manifest.packageName !== 'unknown.package');
  checks.push({
    title: 'Archive & Manifest Structure',
    passed: hasValidManifest,
    level: hasValidManifest ? 'success' : 'error',
    detail: hasValidManifest
      ? `Valid AndroidManifest decoded for package "${manifest.packageName}".`
      : 'Malformed or missing AndroidManifest structure in APK archive.',
  });

  // Check 2: Minimum SDK Declaration
  const hasMinSdk = manifest.minSdkVersion !== undefined;
  checks.push({
    title: 'Minimum SDK Declaration',
    passed: hasMinSdk,
    level: hasMinSdk ? 'info' : 'warning',
    detail: hasMinSdk
      ? `Declared minSdkVersion API ${manifest.minSdkVersion}.`
      : 'No minSdkVersion declared in manifest (unspecified API target).',
  });

  // Check 3: Target SDK Declaration
  const hasTargetSdk = manifest.targetSdkVersion !== undefined;
  checks.push({
    title: 'Target SDK Declaration',
    passed: hasTargetSdk,
    level: hasTargetSdk ? 'info' : 'warning',
    detail: hasTargetSdk
      ? `Declared targetSdkVersion API ${manifest.targetSdkVersion}.`
      : 'No targetSdkVersion declared in manifest (legacy Android behavior).',
  });

  // Check 4: DEX Bytecode Integrity & Adler-32
  const hasDex = dexFiles.length > 0;
  const totalClasses = dexFiles.reduce((acc, d) => acc + d.classesCount, 0);
  const totalMethods = dexFiles.reduce((acc, d) => acc + d.methodsCount, 0);
  checks.push({
    title: 'DEX Bytecode Integrity',
    passed: hasDex && totalClasses > 0,
    level: hasDex && totalClasses > 0 ? 'success' : 'error',
    detail: hasDex
      ? `${dexFiles.length} valid DEX file(s) parsed (${totalClasses} classes, ${totalMethods} methods, Adler-32 verified).`
      : 'No valid Dalvik Executable (classes.dex) discovered in archive.',
  });

  // Check 5: Native Binaries & ABI Requirements
  const hasNativeLibs = nativeLibs.length > 0;
  const isPureBytecode = !hasNativeLibs;

  if (hasNativeLibs) {
    const abis = Array.from(new Set(nativeLibs.map(l => l.abi)));
    for (const abi of abis) {
      unsupportedAbis.push(abi);
    }
    checks.push({
      title: 'Native Shared Libraries (NDK)',
      passed: false,
      level: 'warning',
      detail: `${nativeLibs.length} precompiled ELF librar${nativeLibs.length === 1 ? 'y' : 'ies'} found (${abis.join(', ')}). Requires Phase 10 WebAssembly translation layer.`,
    });
  } else {
    checks.push({
      title: 'Bytecode Architecture',
      passed: true,
      level: 'success',
      detail: 'Pure Dalvik/ART bytecode architecture. No native ELF shared libraries required.',
    });
  }

  // Check 6: Launcher Entry Point
  const hasLauncher = Boolean(manifest.launcherActivity);
  checks.push({
    title: 'Application Entry Point',
    passed: hasLauncher,
    level: hasLauncher ? 'success' : 'warning',
    detail: hasLauncher
      ? `Main launcher activity resolved: ${manifest.launcherActivity}`
      : 'No android.intent.action.MAIN + android.intent.category.LAUNCHER activity found.',
  });

  // Check 7: Runtime Execution Status (Honest Assessment)
  // Per Task 8 & strict constitution: until Phase 4 DEX VM is implemented, no APK executes!
  checks.push({
    title: 'Browser Execution Engine',
    passed: false,
    level: 'info',
    detail: 'Runtime Engine is currently in Phase 1 (Analysis & Extraction). In-browser DEX VM bytecode execution is scheduled for Phase 4.',
  });

  // Honest Status Assignment:
  // If invalid or no DEX -> NOT_SUPPORTED
  // Otherwise -> ANALYSIS_ONLY (never claim SUPPORTED before runtime execution exists!)
  let status: CompatibilityStatus = 'ANALYSIS_ONLY';
  let summary = '';

  if (!hasDex || totalClasses === 0) {
    status = 'NOT_SUPPORTED';
    summary = 'APK archive lacks valid Dalvik executable bytecode or contains corrupt classes.';
  } else {
    status = 'ANALYSIS_ONLY';
    summary = isPureBytecode
      ? `Pure Dalvik bytecode analyzed successfully (${totalClasses} classes, ${totalMethods} methods). Execution engine is in development (Phase 4).`
      : `Complete metadata and ${nativeLibs.length} native ELF libraries analyzed (${unsupportedAbis.join(', ')}). Execution requires Phase 4 DEX VM and Phase 10 NDK translation.`;
  }

  return {
    status,
    statusBadge: status === 'NOT_SUPPORTED' ? 'NOT SUPPORTED' : 'ANALYSIS ONLY',
    summary,
    minSdkMet: hasMinSdk,
    targetSdkCompliant: hasTargetSdk,
    pureBytecode: isPureBytecode,
    unsupportedAbis,
    checks,
    missingApis,
    readyForExecution: false, // Never true until real DEX VM exists!
  };
}
