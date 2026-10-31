/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Automated Test Suite
 * Executes real technical assertions against ZIP, AXML, DEX, ELF, and Compatibility modules.
 */

import { TestCaseResult } from '../core/types';
import { calculateSha256 } from '../apk-extractor/sha256';
import { parseApkArchive, extractZipEntryData, sanitizePath, ZipSecurityError } from '../apk-extractor/zip-parser';
import { parseBinaryAndroidManifest } from '../manifest-engine/axml-parser';
import { parseDexFile, adler32 } from '../dex-parser/dex-parser';
import { inspectNativeLibraries } from '../native-inspector/elf-inspector';
import { evaluateCompatibility } from '../compatibility-engine/compatibility';
import { SAMPLE_APKS, createSampleAndroidManifest, createSampleDex, createSampleElf64 } from '../apk-loader/sample-apks';

export async function runAllRuntimeTests(onProgress?: (result: TestCaseResult) => void): Promise<TestCaseResult[]> {
  const results: TestCaseResult[] = [];

  const runTest = async (
    id: string,
    name: string,
    module: string,
    testFn: () => Promise<void> | void
  ) => {
    const start = performance.now();
    try {
      await testFn();
      const res: TestCaseResult = {
        id,
        name,
        module,
        passed: true,
        durationMs: Math.round((performance.now() - start) * 100) / 100,
      };
      results.push(res);
      onProgress?.(res);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const res: TestCaseResult = {
        id,
        name,
        module,
        passed: false,
        durationMs: Math.round((performance.now() - start) * 100) / 100,
        error: errorMsg,
      };
      results.push(res);
      onProgress?.(res);
    }
  };

  // Test 1: Cryptographic SHA-256 Digest
  await runTest('t1-sha256', 'Cryptographic SHA-256 Digest Calculation', 'APK Extractor', async () => {
    const data = new TextEncoder().encode('APK_RUNTIME_ENGINE_TEST_VECTOR_2026');
    const digest = await calculateSha256(data);
    if (typeof digest !== 'string' || digest.length !== 64) {
      throw new Error(`Invalid SHA-256 digest format: ${digest}`);
    }
  });

  // Test 2: Path Traversal & Zip Bomb Security
  await runTest('t2-zip-security', 'Directory Traversal Sanitization Defense', 'Security Engine', () => {
    const safe = sanitizePath('assets/images/icon.png');
    if (safe !== 'assets/images/icon.png') {
      throw new Error(`Sanitization failed on valid path: ${safe}`);
    }

    let caught = false;
    try {
      sanitizePath('../../etc/passwd');
    } catch (e) {
      if (e instanceof ZipSecurityError) caught = true;
    }
    if (!caught) {
      throw new Error('Directory traversal segment (../) was not blocked.');
    }
  });

  // Test 3: ZIP Archive Header & EOCD Parsing
  await runTest('t3-zip-parsing', 'ZIP Archive Header & EOCD Extraction', 'APK Extractor', async () => {
    const sample = SAMPLE_APKS[0].generate();
    const archive = await parseApkArchive(sample, 'HelloAndroid.apk');
    if (archive.entries.length < 2) {
      throw new Error(`Expected at least 2 entries in test APK, found ${archive.entries.length}`);
    }
    if (!archive.manifestEntry) {
      throw new Error('AndroidManifest.xml not indexed in archive.');
    }
    if (archive.dexEntries.length === 0) {
      throw new Error('classes.dex not detected.');
    }

    // Verify raw file extraction
    const manifestBytes = await extractZipEntryData(sample, archive.manifestEntry);
    if (!manifestBytes || manifestBytes.byteLength === 0) {
      throw new Error('Failed to decompress AndroidManifest.xml from archive.');
    }
  });

  // Test 4: Binary Android XML (AXML) Parser
  await runTest('t4-axml-parser', 'Binary XML (AXML) Chunk Decoding & Hierarchy', 'Manifest Engine', () => {
    const rawAxml = createSampleAndroidManifest(
      'com.test.runtime',
      'com.test.runtime.MainActivity',
      'Test Suite App',
      21,
      34
    );
    const manifest = parseBinaryAndroidManifest(rawAxml);
    if (manifest.packageName !== 'com.test.runtime') {
      throw new Error(`Package mismatch: expected "com.test.runtime", got "${manifest.packageName}"`);
    }
    if (manifest.minSdkVersion !== 21) {
      throw new Error(`Min SDK mismatch: expected 21, got ${manifest.minSdkVersion}`);
    }
    if (manifest.targetSdkVersion !== 34) {
      throw new Error(`Target SDK mismatch: expected 34, got ${manifest.targetSdkVersion}`);
    }
    if (!manifest.launcherActivity || !manifest.launcherActivity.includes('MainActivity')) {
      throw new Error(`Launcher activity not resolved properly: ${manifest.launcherActivity}`);
    }
    if (!manifest.permissions.includes('android.permission.INTERNET')) {
      throw new Error('Declared permission android.permission.INTERNET was not parsed.');
    }
  });

  // Test 5: Dalvik DEX Header & Adler-32 Checksum
  await runTest('t5-dex-header', 'Dalvik DEX Header Validation & Adler-32 Checksum', 'DEX Parser', () => {
    const rawDex = createSampleDex('Lcom/test/runtime/MainActivity;', 'onCreate', 'Test Bytecode');
    const dex = parseDexFile(rawDex, 'classes.dex');
    if (dex.header.magic !== 'dex\n') {
      throw new Error(`Invalid DEX magic: ${dex.header.magic}`);
    }
    if (dex.header.version !== '035') {
      throw new Error(`Expected DEX version 035, got ${dex.header.version}`);
    }
    if (dex.header.endianTag !== 0x12345678) {
      throw new Error(`Endian constant invalid: 0x${dex.header.endianTag.toString(16)}`);
    }
    // Verify Adler32
    const calc = adler32(rawDex.subarray(12));
    if (calc !== dex.header.checksum) {
      throw new Error(`Adler32 checksum mismatch: calculated 0x${calc.toString(16)}, header 0x${dex.header.checksum.toString(16)}`);
    }
  });

  // Test 6: DEX Class Definition & Bytecode Disassembler
  await runTest('t6-dex-disasm', 'DEX Class Definition & Dalvik Bytecode Disassembly', 'DEX Parser', () => {
    const rawDex = createSampleDex('Lcom/test/runtime/MainActivity;', 'onCreate', 'Sample Instruction Payload');
    const dex = parseDexFile(rawDex, 'classes.dex');
    if (dex.classes.length === 0) {
      throw new Error('No class definitions extracted from DEX.');
    }
    const cls = dex.classes[0];
    if (cls.className !== 'com.test.runtime.MainActivity') {
      throw new Error(`Class name formatting failed: got "${cls.className}"`);
    }
    if (cls.directMethods.length === 0) {
      throw new Error('Expected at least 1 direct method in class.');
    }
    const m = cls.directMethods[0];
    if (!m.instructions || m.instructions.length === 0) {
      throw new Error('Bytecode instructions were not disassembled.');
    }
    const hasConstString = m.instructions.some(ins => ins.includes('const-string'));
    if (!hasConstString) {
      throw new Error('Expected const-string opcode in disassembled stream.');
    }
  });

  // Test 7: Native ELF Binary Header Inspection
  await runTest('t7-elf-inspector', 'Native ELF Architecture & ABI Inspection', 'Native Inspector', () => {
    const elfAarch64 = createSampleElf64(0xb7); // AArch64
    const entries = [{
      filename: 'lib/arm64-v8a/libnative.so',
      compressedSize: 64,
      uncompressedSize: 64,
      compressionMethod: 0,
      crc32: 0,
      offset: 0,
    }];
    const dataMap = new Map<string, Uint8Array>([
      ['lib/arm64-v8a/libnative.so', elfAarch64],
    ]);

    const results = inspectNativeLibraries(entries, dataMap);
    if (results.length === 0) {
      throw new Error('Native library entry not detected.');
    }
    const lib = results[0];
    if (!lib.isElf) {
      throw new Error('ELF magic verification failed.');
    }
    if (lib.bitness !== '64-bit') {
      throw new Error(`Expected 64-bit ELF class, got ${lib.bitness}`);
    }
    if (lib.abi !== 'arm64-v8a') {
      throw new Error(`ABI folder mismatch: ${lib.abi}`);
    }
  });

  // Test 8: Compatibility Evaluation Heuristics
  await runTest('t8-compat-eval', 'Compatibility Evaluation & Readiness Heuristics', 'Compatibility Engine', () => {
    const rawManifest = createSampleAndroidManifest();
    const manifest = parseBinaryAndroidManifest(rawManifest);
    const rawDex = createSampleDex();
    const dex = parseDexFile(rawDex);

    // Pure bytecode app -> SUPPORTED
    const pureReport = evaluateCompatibility(manifest, [dex], []);
    if (pureReport.status !== 'SUPPORTED') {
      throw new Error(`Expected pure Dalvik app to be SUPPORTED, got ${pureReport.status}`);
    }

    // App with ARM64 native library -> ANALYSIS_ONLY (transparent engineering)
    const nativeLibEntry = {
      filename: 'libgame.so',
      path: 'lib/arm64-v8a/libgame.so',
      size: 1024,
      abi: 'arm64-v8a',
      isElf: true,
      bitness: '64-bit' as const,
      endianness: 'little' as const,
      machine: 'AArch64',
    };
    const nativeReport = evaluateCompatibility(manifest, [dex], [nativeLibEntry]);
    if (nativeReport.status !== 'ANALYSIS_ONLY') {
      throw new Error(`Expected ARM64 app to be ANALYSIS_ONLY, got ${nativeReport.status}`);
    }
  });

  return results;
}
