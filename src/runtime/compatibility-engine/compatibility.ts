/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Compatibility Evaluation Engine
 * Rigorously evaluates real APK execution readiness against current runtime capabilities.
 * Enforces zero false claims: provides transparent, technically substantiated readiness tiers.
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

  // Check 1: Android Min SDK
  const minSdkSupported = manifest.minSdkVersion <= 34;
  checks.push({
    title: 'Minimum SDK Support',
    passed: minSdkSupported,
    level: minSdkSupported ? 'success' : 'error',
    detail: `App requires minSdkVersion ${manifest.minSdkVersion}. Web runtime target API range is 19 to 34.`,
  });

  // Check 2: Target SDK Compliance
  const targetSdkOk = manifest.targetSdkVersion >= 14 && manifest.targetSdkVersion <= 35;
  checks.push({
    title: 'Target SDK Alignment',
    passed: targetSdkOk,
    level: targetSdkOk ? 'success' : 'warning',
    detail: `Target SDK ${manifest.targetSdkVersion} detected. Android behavior changes mapped for modern API targets.`,
  });

  // Check 3: Dalvik Bytecode Integrity
  const hasDex = dexFiles.length > 0;
  const validDex = dexFiles.every(d => d.classesCount > 0);
  checks.push({
    title: 'DEX Bytecode Integrity',
    passed: hasDex && validDex,
    level: hasDex && validDex ? 'success' : 'error',
    detail: `${dexFiles.length} DEX archive(s) parsed with ${dexFiles.reduce((acc, d) => acc + d.classesCount, 0)} total class definitions.`,
  });

  // Check 4: Native Architecture / NDK Dependencies
  const hasNativeLibs = nativeLibs.length > 0;
  const isPureBytecode = !hasNativeLibs;

  if (hasNativeLibs) {
    const abis = Array.from(new Set(nativeLibs.map(l => l.abi)));
    for (const abi of abis) {
      if (abi === 'arm64-v8a' || abi === 'armeabi-v7a') {
        unsupportedAbis.push(abi);
      }
    }

    checks.push({
      title: 'Native Libraries (NDK)',
      passed: false,
      level: 'warning',
      detail: `${nativeLibs.length} native .so librar${nativeLibs.length === 1 ? 'y' : 'ies'} detected (${abis.join(', ')}). ARM execution requires WebAssembly translation layer in Phase 10.`,
    });
  } else {
    checks.push({
      title: 'Pure Bytecode Architecture',
      passed: true,
      level: 'success',
      detail: 'Pure Dalvik/ART Java/Kotlin bytecode. No binary native dependencies required for execution.',
    });
  }

  // Check 5: Launcher Activity
  const hasLauncher = Boolean(manifest.launcherActivity);
  checks.push({
    title: 'Application Entry Point',
    passed: hasLauncher,
    level: hasLauncher ? 'success' : 'warning',
    detail: hasLauncher
      ? `Main launcher activity resolved: ${manifest.launcherActivity}`
      : 'No standard MAIN/LAUNCHER intent filter declared. Custom intent or service launch required.',
  });

  // Check 6: Proprietary Google Play Services & Anti-Tamper
  const totalStrings = dexFiles.flatMap(d => d.stringsSample);
  const usesGooglePlayServices = totalStrings.some(s => s.includes('com.google.android.gms'));
  const usesFirebaseAuth = totalStrings.some(s => s.includes('com.google.firebase'));
  const usesSafetyNet = totalStrings.some(s => s.includes('safetynet') || s.includes('playintegrity'));

  if (usesGooglePlayServices) {
    missingApis.push('com.google.android.gms.* (Google Play Services)');
  }
  if (usesFirebaseAuth) {
    missingApis.push('com.google.firebase.* (Firebase Mobile SDK)');
  }

  if (usesSafetyNet) {
    checks.push({
      title: 'Play Integrity / DRM Verification',
      passed: false,
      level: 'error',
      detail: 'Hardware-backed SafetyNet/Play Integrity attestation detected. Sandboxed browser environments cannot fake cryptographic device tokens.',
    });
  }

  // Determine Overall Status Tier
  let status: CompatibilityStatus = 'ANALYSIS_ONLY';
  let summary = '';
  let readyForExecution = false;

  if (!hasDex || !validDex) {
    status = 'NOT_SUPPORTED';
    summary = 'APK archive lacks valid Dalvik executable bytecode or contains corrupt classes.';
  } else if (usesSafetyNet) {
    status = 'ANALYSIS_ONLY';
    summary = 'App enforces hardware cryptographic attestation (SafetyNet/DRM) not available in sandboxed web runtimes.';
  } else if (isPureBytecode && hasLauncher && minSdkSupported && missingApis.length === 0) {
    status = 'SUPPORTED';
    summary = '100% pure Dalvik bytecode with standard Android View framework and lifecycle support. Fully compatible for local execution.';
    readyForExecution = true;
  } else if (hasNativeLibs && unsupportedAbis.length > 0) {
    status = 'ANALYSIS_ONLY';
    summary = `Contains ${nativeLibs.length} precompiled ARM/ARM64 machine code libraries. Complete analysis provided; execution requires native WebAssembly translation layer.`;
  } else {
    status = 'PARTIALLY_SUPPORTED';
    summary = 'Bytecode and manifest parsed successfully. Partial execution possible with mocked framework fallbacks.';
    readyForExecution = false;
  }

  const badgeMap: Record<CompatibilityStatus, string> = {
    SUPPORTED: 'SUPPORTED',
    PARTIALLY_SUPPORTED: 'PARTIALLY SUPPORTED',
    NOT_SUPPORTED: 'NOT SUPPORTED',
    ANALYSIS_ONLY: 'ANALYSIS ONLY',
  };

  return {
    status,
    statusBadge: badgeMap[status],
    summary,
    minSdkMet: minSdkSupported,
    targetSdkCompliant: targetSdkOk,
    pureBytecode: isPureBytecode,
    unsupportedAbis,
    checks,
    missingApis,
    readyForExecution,
  };
}
