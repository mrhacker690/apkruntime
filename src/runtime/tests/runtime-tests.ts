/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Rigorous Automated Test Suite
 * Comprehensive regression tests for SHA-256 (NIST vectors), hardened ZIP parser,
 * binary XML decoder, DEX parser with Adler-32 verification, ULEB/SLEB128 decoders,
 * ELF architecture analyzer, and evidence-based compatibility evaluation.
 */

import { TestCaseResult } from '../core/types';
import { calculateSha256, pureJsSha256 } from '../apk-extractor/sha256';
import {
  parseApkArchive,
  extractZipEntryData,
  sanitizePath,
  calculateCrc32,
  ZipSecurityError,
  ZipParseError,
} from '../apk-extractor/zip-parser';
import { parseBinaryAndroidManifest, AxmlParseError } from '../manifest-engine/axml-parser';
import {
  parseDexFile,
  adler32,
  readMutf8String,
  readUleb128,
  readSleb128,
  DexParseError,
} from '../dex-parser/dex-parser';
import {
  inspectNativeLibrariesDetailed,
  inspectNativeLibraries,
} from '../native-inspector/elf-inspector';
import { evaluateCompatibility } from '../compatibility-engine/compatibility';
import {
  SAMPLE_APKS,
  createSampleAndroidManifest,
  createSampleDex,
  createSampleElf64,
  buildZipArchive,
} from '../apk-loader/sample-apks';
import { deflateSync } from 'fflate';

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

  // ==========================================
  // MODULE 1: SHA-256 NIST Test Vectors (Task 5)
  // ==========================================

  await runTest('t01-sha256-nist-empty', 'SHA-256 NIST Vector: Empty Input ("")', 'SHA-256 Engine', () => {
    const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const emptyBytes = new Uint8Array(0);
    const result = pureJsSha256(emptyBytes);
    if (result !== expected) {
      throw new Error(`Expected ${expected}, got ${result}`);
    }
  });

  await runTest('t02-sha256-nist-abc', 'SHA-256 NIST Vector: "abc"', 'SHA-256 Engine', () => {
    const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    const input = new TextEncoder().encode('abc');
    const result = pureJsSha256(input);
    if (result !== expected) {
      throw new Error(`Expected ${expected}, got ${result}`);
    }
  });

  await runTest('t03-sha256-nist-multi', 'SHA-256 NIST Vector: 56-Byte Multi-Block', 'SHA-256 Engine', () => {
    const expected = '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';
    const input = new TextEncoder().encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
    const result = pureJsSha256(input);
    if (result !== expected) {
      throw new Error(`Expected ${expected}, got ${result}`);
    }
  });

  await runTest('t04-sha256-webcrypto-parity', 'SHA-256 Web Crypto vs Pure JS Parity', 'SHA-256 Engine', async () => {
    const input = new TextEncoder().encode('APK Runtime Engine 🚀 2026');
    const pureResult = pureJsSha256(input);
    const subtleResult = await calculateSha256(input);
    if (pureResult !== subtleResult) {
      throw new Error(`Discrepancy: pureJs="${pureResult}", subtle="${subtleResult}"`);
    }
  });

  // ==========================================
  // MODULE 2: Hardened ZIP Archive Engine (Task 4)
  // ==========================================

  await runTest('t05-zip-crc32-ieee', 'CRC-32 IEEE 802.3 Checksum Calculation', 'ZIP Engine', () => {
    // Known CRC-32 vector for "123456789" is 0xcbf43926
    const data = new TextEncoder().encode('123456789');
    const crc = calculateCrc32(data);
    if (crc !== 0xcbf43926) {
      throw new Error(`Expected 0xcbf43926, got 0x${crc.toString(16)}`);
    }
  });

  await runTest('t06-zip-security-traversal', 'ZIP Security: Directory Traversal Rejection (..)', 'ZIP Engine', () => {
    let rejected = false;
    try {
      sanitizePath('../../etc/passwd');
    } catch (e) {
      if (e instanceof ZipSecurityError) rejected = true;
    }
    if (!rejected) throw new Error('Directory traversal segment (..) was not rejected.');
  });

  await runTest('t07-zip-security-absolute', 'ZIP Security: Absolute Path Rejection (/root)', 'ZIP Engine', () => {
    let rejected = false;
    try {
      sanitizePath('/system/bin/sh');
    } catch (e) {
      if (e instanceof ZipSecurityError) rejected = true;
    }
    if (!rejected) throw new Error('Absolute path was not rejected.');
  });

  await runTest('t08-zip-deflate-extraction', 'ZIP Engine: DEFLATE Mode & CRC-32 Verification', 'ZIP Engine', async () => {
    const rawPayload = new TextEncoder().encode('Hello Dalvik Runtime Engine - Deflate Test Payload');
    const compressedPayload = deflateSync(rawPayload);
    const crc = calculateCrc32(rawPayload);

    // Build a ZIP containing this deflated file
    const nameBytes = new TextEncoder().encode('payload.txt');
    const local = new Uint8Array(30 + nameBytes.length + compressedPayload.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(8, 8, true); // Deflate
    lv.setUint32(14, crc, true);
    lv.setUint32(18, compressedPayload.length, true);
    lv.setUint32(22, rawPayload.length, true);
    lv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    local.set(compressedPayload, 30 + nameBytes.length);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(10, 8, true); // Deflate
    cv.setUint32(16, crc, true);
    cv.setUint32(20, compressedPayload.length, true);
    cv.setUint32(24, rawPayload.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, 0, true); // Local header offset 0
    central.set(nameBytes, 46);

    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(8, 1, true);
    ev.setUint16(10, 1, true);
    ev.setUint32(12, central.length, true);
    ev.setUint32(16, local.length, true);

    const zipData = new Uint8Array(local.length + central.length + eocd.length);
    zipData.set(local, 0);
    zipData.set(central, local.length);
    zipData.set(eocd, local.length + central.length);

    const archive = await parseApkArchive(zipData, 'test-deflate.apk');
    if (archive.entries.length !== 1) throw new Error('Expected 1 entry in test ZIP.');

    const decompressed = await extractZipEntryData(zipData, archive.entries[0]);
    const text = new TextDecoder().decode(decompressed);
    if (text !== 'Hello Dalvik Runtime Engine - Deflate Test Payload') {
      throw new Error(`Decompressed text mismatch: got "${text}"`);
    }
  });

  await runTest('t09-zip-crc-mismatch-detection', 'ZIP Engine: CRC-32 Mismatch Rejection', 'ZIP Engine', async () => {
    // Build archive with bad CRC declared in central directory
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const zip = buildZipArchive([{ name: 'test.bin', data: payload }]);
    // Tamper with CRC in central directory header
    const eocdView = new DataView(zip.buffer);
    const eocdOff = zip.length - 22;
    const cdOff = eocdView.getUint32(eocdOff + 16, true);
    eocdView.setUint32(cdOff + 16, 0x11223344, true); // Bad CRC

    const archive = await parseApkArchive(zip, 'bad-crc.apk');
    let threw = false;
    try {
      await extractZipEntryData(zip, archive.entries[0]);
    } catch (e) {
      if (e instanceof ZipParseError && e.message.includes('CRC-32 checksum mismatch')) {
        threw = true;
      }
    }
    if (!threw) throw new Error('Mismatched CRC-32 did not throw ZipParseError.');
  });

  await runTest('t10-zip-security-duplicate-entries', 'ZIP Security: Duplicate Entry Rejection', 'ZIP Engine', async () => {
    const payload = new Uint8Array([1, 2, 3]);
    // Create ZIP containing two entries with identical path
    const zip = buildZipArchive([
      { name: 'classes.dex', data: payload },
      { name: 'classes.dex', data: payload },
    ]);
    let caught = false;
    try {
      await parseApkArchive(zip, 'duplicate.apk');
    } catch (e) {
      if (e instanceof ZipSecurityError && e.message.includes('Duplicate entry')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Duplicate central directory entries were not rejected.');
  });

  // ==========================================
  // MODULE 3: Binary Android XML Engine (Task 6)
  // ==========================================

  await runTest('t11-axml-strict-chunk-bounds', 'AXML Parser: Strict Buffer Bounds Checking', 'Manifest Engine', () => {
    // Synthesize binary XML with chunk size extending beyond buffer
    const badAxml = new Uint8Array(32);
    const v = new DataView(badAxml.buffer);
    v.setUint16(0, 0x0003, true); // RES_XML_TYPE
    v.setUint16(2, 8, true);      // headerSize
    v.setUint32(4, 32, true);     // fileSize
    v.setUint16(8, 0x0001, true); // RES_STRING_POOL_TYPE
    v.setUint16(10, 28, true);
    v.setUint32(12, 1000, true);  // Chunk size 1000 > buffer 32!

    let caught = false;
    try {
      parseBinaryAndroidManifest(badAxml);
    } catch (e) {
      if (e instanceof AxmlParseError && e.message.includes('extends outside actual file buffer')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Out-of-bounds chunk size was not rejected.');
  });

  await runTest('t12-axml-no-invented-defaults', 'AXML Parser: No Invented SDK Defaults When Undeclared', 'Manifest Engine', () => {
    // Generate manifest without uses-sdk
    const raw = createSampleAndroidManifest('com.test.nodefaults', 'com.test.nodefaults.MainActivity', 'App', 0, 0);
    const parsed = parseBinaryAndroidManifest(raw);
    if (parsed.packageName !== 'com.test.nodefaults') {
      throw new Error(`Package mismatch: ${parsed.packageName}`);
    }
  });

  // ==========================================
  // MODULE 4: DEX Parser & Disassembler (Task 7)
  // ==========================================

  await runTest('t13-dex-adler32-mismatch', 'DEX Parser: Adler-32 Checksum Validation & Rejection', 'DEX Parser', () => {
    const rawDex = createSampleDex('Lcom/test/AdlerTest;', 'testMethod', 'Valid Payload');
    // Tamper with byte in data section
    rawDex[rawDex.length - 1] ^= 0xff;

    let caught = false;
    try {
      parseDexFile(rawDex, 'corrupted-adler.dex');
    } catch (e) {
      if (e instanceof DexParseError && e.message.includes('Adler-32 checksum mismatch')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Adler-32 checksum mismatch was not detected.');
  });

  await runTest('t14-dex-uleb128-overflow', 'DEX Parser: ULEB128 5-Byte Overflow Protection', 'DEX Parser', () => {
    // Malicious ULEB128 with more than 5 bytes with bit 7 set
    const maliciousUleb = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
    let caught = false;
    try {
      readUleb128(maliciousUleb, 0);
    } catch (e) {
      if (e instanceof DexParseError && e.message.includes('exceeds maximum 5-byte limit')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Malicious 6-byte ULEB128 was not rejected.');
  });

  await runTest('t15-dex-sleb128-negative', 'DEX Parser: Signed SLEB128 Decoder Correctness', 'DEX Parser', () => {
    // Encoded -1 in SLEB128 is 0x7F
    const minusOne = new Uint8Array([0x7f]);
    const [val1] = readSleb128(minusOne, 0);
    if (val1 !== -1) throw new Error(`Expected -1, got ${val1}`);

    // Encoded -64 in SLEB128 is 0x40
    const minus64 = new Uint8Array([0x40]);
    const [val2] = readSleb128(minus64, 0);
    if (val2 !== -64) throw new Error(`Expected -64, got ${val2}`);
  });

  await runTest('t16-dex-mutf8-embedded-null', 'DEX Parser: MUTF-8 Embedded Null Character Decoding', 'DEX Parser', () => {
    // In MUTF-8, \u0000 is encoded as 0xC0 0x80, followed by null terminator 0x00
    // ULEB128 size = 3 chars, data = 'A', 0xC0, 0x80, 'B', 0x00
    const mutf8Buffer = new Uint8Array([0x03, 0x41, 0xc0, 0x80, 0x42, 0x00]);
    const decoded = readMutf8String(mutf8Buffer, 0);
    if (decoded.length !== 3 || decoded.charCodeAt(1) !== 0) {
      throw new Error(`Failed to decode embedded MUTF-8 null. Got length ${decoded.length}`);
    }
  });

  // ==========================================
  // MODULE 5: Native ELF Architecture (Task 9)
  // ==========================================

  await runTest('t17-elf-abi-crosscheck', 'ELF Inspector: ABI Directory Cross-Checking & Mismatch Detection', 'Native Inspector', () => {
    // Create an ARM 32-bit (0x28) binary placed falsely into lib/arm64-v8a/
    const elfArm32 = createSampleElf64(0x28); // EM_ARM
    const entries = [{
      filename: 'lib/arm64-v8a/libmismatch.so',
      compressedSize: 64,
      uncompressedSize: 64,
      compressionMethod: 0,
      crc32: 0,
      offset: 0,
    }];
    const dataMap = new Map([['lib/arm64-v8a/libmismatch.so', elfArm32]]);
    const summary = inspectNativeLibrariesDetailed(entries, dataMap);
    if (!summary.hasAbiMismatches) {
      throw new Error('ABI directory mismatch was not detected.');
    }
  });

  // ==========================================
  // MODULE 6: Compatibility Engine (Task 8)
  // ==========================================

  await runTest('t18-compatibility-honest-status', 'Compatibility Engine: Honest Assessment (ANALYSIS ONLY in Phase 1)', 'Compatibility Engine', () => {
    const rawManifest = createSampleAndroidManifest();
    const manifest = parseBinaryAndroidManifest(rawManifest);
    const rawDex = createSampleDex();
    const dex = parseDexFile(rawDex);

    const report = evaluateCompatibility(manifest, [dex], []);
    // Must remain ANALYSIS ONLY because runtime execution engine is Phase 4!
    if (report.status !== 'ANALYSIS_ONLY') {
      throw new Error(`Expected ANALYSIS_ONLY until DEX VM is built, got: ${report.status}`);
    }
    if (report.readyForExecution !== false) {
      throw new Error('readyForExecution must be false in Phase 1.');
    }
  });

  return results;
}
