/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Rigorous Automated Test Suite & Independent Fixtures
 * Comprehensive regression tests for SHA-256 (NIST), SHA-1 (NIST), hardened ZIP parser,
 * binary XML decoder, DEX parser with version-aware opcode metadata system, Adler-32 & SHA-1,
 * ULEB/SLEB128 decoders, MUTF-8 string engine, ELF architecture analyzer, and compatibility.
 */

import { TestCaseResult } from '../core/types';
import { calculateSha256, pureJsSha256 } from '../apk-extractor/sha256';
import { pureJsSha1 } from '../apk-extractor/sha1';
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
  DEX_OPCODE_TABLE,
} from '../dex-parser/dex-parser';
import {
  inspectNativeLibrariesDetailed,
} from '../native-inspector/elf-inspector';
import { evaluateCompatibility } from '../compatibility-engine/compatibility';
import { ApkRuntimeService } from '../apk-loader/runtime-service';
import {
  createSampleAndroidManifest,
  createSampleDex,
  createSampleElf64,
  buildZipArchive,
} from '../apk-loader/sample-apks';

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
  // MODULE 1: Cryptographic Digest Engines (SHA-256 & SHA-1)
  // ==========================================

  await runTest('t01-sha256-nist-empty', 'SHA-256 NIST Vector: Empty Input ("")', 'Cryptographic Engine', () => {
    const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const emptyBytes = new Uint8Array(0);
    const result = pureJsSha256(emptyBytes);
    if (result !== expected) throw new Error(`Expected ${expected}, got ${result}`);
  });

  await runTest('t02-sha256-nist-abc', 'SHA-256 NIST Vector: "abc"', 'Cryptographic Engine', () => {
    const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    const input = new TextEncoder().encode('abc');
    const result = pureJsSha256(input);
    if (result !== expected) throw new Error(`Expected ${expected}, got ${result}`);
  });

  await runTest('t03-sha256-nist-multiblock', 'SHA-256 NIST Vector: 56-Byte Multi-Block', 'Cryptographic Engine', () => {
    const expected = '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';
    const input = new TextEncoder().encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
    const result = pureJsSha256(input);
    if (result !== expected) throw new Error(`Expected ${expected}, got ${result}`);
  });

  await runTest('t04-sha1-nist-empty', 'SHA-1 NIST Vector: Empty Input ("")', 'Cryptographic Engine', () => {
    const expected = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
    const emptyBytes = new Uint8Array(0);
    const result = pureJsSha1(emptyBytes);
    if (result !== expected) throw new Error(`Expected ${expected}, got ${result}`);
  });

  await runTest('t05-sha1-nist-abc', 'SHA-1 NIST Vector: "abc"', 'Cryptographic Engine', () => {
    const expected = 'a9993e364706816aba3e25717850c26c9cd0d89d';
    const input = new TextEncoder().encode('abc');
    const result = pureJsSha1(input);
    if (result !== expected) throw new Error(`Expected ${expected}, got ${result}`);
  });

  await runTest('t06-sha256-webcrypto-parity', 'SHA-256 Web Crypto vs Pure JS Parity', 'Cryptographic Engine', async () => {
    const data = new TextEncoder().encode('Dalvik Bytecode Verification Payload');
    const webCryptoResult = await calculateSha256(data);
    const pureJsResult = pureJsSha256(data);
    if (webCryptoResult !== pureJsResult) {
      throw new Error(`Hash mismatch: WebCrypto (${webCryptoResult}) vs PureJS (${pureJsResult})`);
    }
  });

  // ==========================================
  // MODULE 2: Hardened ZIP Archive Engine
  // ==========================================

  await runTest('t07-zip-crc32-calculation', 'CRC-32 IEEE 802.3 Checksum Calculation', 'ZIP Engine', () => {
    const payload = new TextEncoder().encode('123456789');
    const expectedCrc = 0xcbf43926;
    const actualCrc = calculateCrc32(payload);
    if (actualCrc !== expectedCrc) {
      throw new Error(`Expected 0x${expectedCrc.toString(16)}, got 0x${actualCrc.toString(16)}`);
    }
  });

  await runTest('t08-zip-security-path-traversal', 'ZIP Security: Directory Traversal Rejection (..)', 'ZIP Engine', () => {
    let caught = false;
    try {
      sanitizePath('assets/../../etc/passwd');
    } catch (e) {
      if (e instanceof ZipSecurityError && e.message.includes('directory traversal')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Path traversal with ".." was not rejected.');
  });

  await runTest('t09-zip-security-absolute-path', 'ZIP Security: Absolute Path Rejection (/root)', 'ZIP Engine', () => {
    let caught = false;
    try {
      sanitizePath('/system/bin/sh');
    } catch (e) {
      if (e instanceof ZipSecurityError && e.message.includes('absolute path')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Absolute path starting with "/" was not rejected.');
  });

  await runTest('t10-zip-deflate-decompression', 'ZIP Engine: DEFLATE Mode & CRC-32 Verification', 'ZIP Engine', async () => {
    const payload = new TextEncoder().encode('Hello Dalvik Runtime Engine - Deflate Test Payload');
    const zipData = buildZipArchive([{ name: 'test.txt', data: payload }]);

    const archive = await parseApkArchive(zipData, 'test-deflate.apk');
    if (archive.entries.length !== 1) throw new Error('Expected 1 entry in test ZIP.');

    const decompressed = await extractZipEntryData(zipData, archive.entries[0]);
    const text = new TextDecoder().decode(decompressed);
    if (text !== 'Hello Dalvik Runtime Engine - Deflate Test Payload') {
      throw new Error(`Decompressed text mismatch: got "${text}"`);
    }
  });

  await runTest('t11-zip-crc-mismatch-detection', 'ZIP Engine: CRC-32 Mismatch Rejection', 'ZIP Engine', async () => {
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const zip = buildZipArchive([{ name: 'test.bin', data: payload }]);
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

  await runTest('t12-zip-security-duplicate-entries', 'ZIP Security: Duplicate Entry Rejection', 'ZIP Engine', async () => {
    const payload = new Uint8Array([1, 2, 3]);
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
  // MODULE 3: Binary Android XML Engine
  // ==========================================

  await runTest('t13-axml-strict-chunk-bounds', 'AXML Parser: Strict Buffer Bounds Checking', 'Manifest Engine', () => {
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

  await runTest('t14-axml-declared-filesize-overflow', 'AXML Parser: Declared File Size Greater Than Buffer Rejection', 'Manifest Engine', () => {
    const badAxml = new Uint8Array(16);
    const v = new DataView(badAxml.buffer);
    v.setUint16(0, 0x0003, true);
    v.setUint16(2, 8, true);
    v.setUint32(4, 1024, true); // Declared 1024 bytes > 16 byte buffer

    let caught = false;
    try {
      parseBinaryAndroidManifest(badAxml);
    } catch (e) {
      if (e instanceof AxmlParseError && e.message.includes('exceeds actual file buffer')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Declared file size exceeding actual buffer was not rejected.');
  });

  await runTest('t15-axml-no-invented-defaults', 'AXML Parser: No Invented SDK Defaults When Undeclared', 'Manifest Engine', () => {
    const raw = createSampleAndroidManifest('com.test.nodefaults', 'com.test.nodefaults.MainActivity', 'App', 0, 0);
    const parsed = parseBinaryAndroidManifest(raw);
    if (parsed.packageName !== 'com.test.nodefaults') {
      throw new Error(`Package mismatch: ${parsed.packageName}`);
    }
    if (parsed.minSdkVersion !== undefined) {
      throw new Error(`Expected minSdkVersion to be undefined when undeclared, got ${parsed.minSdkVersion}`);
    }
  });

  // ==========================================
  // MODULE 4: DEX Parser & Disassembler Engine
  // ==========================================

  await runTest('t16-dex-opcode-metadata-system', 'DEX Parser: Version-Aware Opcode Metadata System', 'DEX Parser', () => {
    const opFa = DEX_OPCODE_TABLE.get(0xfa);
    if (!opFa || opFa.lengthUnits !== 4 || opFa.mnemonic !== 'invoke-polymorphic') {
      throw new Error(`0xfa (invoke-polymorphic) invalid metadata: ${JSON.stringify(opFa)}`);
    }

    const opFb = DEX_OPCODE_TABLE.get(0xfb);
    if (!opFb || opFb.lengthUnits !== 4 || opFb.mnemonic !== 'invoke-polymorphic/range') {
      throw new Error(`0xfb (invoke-polymorphic/range) invalid metadata: ${JSON.stringify(opFb)}`);
    }

    const opFc = DEX_OPCODE_TABLE.get(0xfc);
    if (!opFc || opFc.lengthUnits !== 3 || opFc.mnemonic !== 'invoke-custom') {
      throw new Error(`0xfc (invoke-custom) invalid metadata: ${JSON.stringify(opFc)}`);
    }

    const opFd = DEX_OPCODE_TABLE.get(0xfd);
    if (!opFd || opFd.lengthUnits !== 3 || opFd.mnemonic !== 'invoke-custom/range') {
      throw new Error(`0xfd (invoke-custom/range) invalid metadata: ${JSON.stringify(opFd)}`);
    }

    const opFe = DEX_OPCODE_TABLE.get(0xfe);
    if (!opFe || opFe.lengthUnits !== 2 || opFe.mnemonic !== 'const-method-handle') {
      throw new Error(`0xfe (const-method-handle) invalid metadata: ${JSON.stringify(opFe)}`);
    }

    const opFf = DEX_OPCODE_TABLE.get(0xff);
    if (!opFf || opFf.lengthUnits !== 2 || opFf.mnemonic !== 'const-method-type') {
      throw new Error(`0xff (const-method-type) invalid metadata: ${JSON.stringify(opFf)}`);
    }
  });

  await runTest('t17-dex-adler32-validation', 'DEX Parser: Adler-32 Checksum Validation & Rejection', 'DEX Parser', () => {
    const rawDex = createSampleDex('Lcom/example/Test;', 'runTest');
    const corruptedDex = new Uint8Array(rawDex);
    const view = new DataView(corruptedDex.buffer);
    view.setUint32(8, 0xdeadbeef, true); // Corrupt checksum

    let caught = false;
    try {
      parseDexFile(corruptedDex, 'corrupt.dex');
    } catch (e) {
      if (e instanceof DexParseError && e.message.includes('Adler-32 checksum mismatch')) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Corrupted Adler-32 checksum was not rejected.');
  });

  await runTest('t18-dex-sha1-signature-validation', 'DEX Parser: SHA-1 Signature Validation & Rejection', 'DEX Parser', () => {
    const rawDex = createSampleDex('Lcom/example/Sha1Test;', 'testMethod');
    const corruptedDex = new Uint8Array(rawDex);
    // Tamper with signature bytes at offset 12..31
    corruptedDex[12] ^= 0xff;

    let caught = false;
    try {
      parseDexFile(corruptedDex, 'corrupt-sha1.dex');
    } catch (e) {
      if (e instanceof DexParseError && (e.message.includes('SHA-1 signature mismatch') || e.message.includes('checksum mismatch'))) {
        caught = true;
      }
    }
    if (!caught) throw new Error('Corrupted SHA-1 signature was not rejected.');
  });

  await runTest('t19-dex-uleb128-decoders', 'DEX Parser: ULEB128 5-Byte Overflow Protection', 'DEX Parser', () => {
    const overflowUleb = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
    let caught = false;
    try {
      readUleb128(overflowUleb, 0);
    } catch (e) {
      if (e instanceof DexParseError && (e.message.includes('5-byte limit') || e.message.includes('overflow'))) {
        caught = true;
      }
    }
    if (!caught) throw new Error('6-byte ULEB128 overflow was not rejected.');
  });

  await runTest('t20-dex-sleb128-decoders', 'DEX Parser: Signed SLEB128 Decoder Correctness', 'DEX Parser', () => {
    const posByte = new Uint8Array([0x3f]); // +63
    const [val1] = readSleb128(posByte, 0);
    if (val1 !== 63) throw new Error(`Expected 63, got ${val1}`);

    const negByte = new Uint8Array([0x7f]); // -1
    const [val2] = readSleb128(negByte, 0);
    if (val2 !== -1) throw new Error(`Expected -1, got ${val2}`);
  });

  await runTest('t21-dex-mutf8-embedded-nulls', 'DEX Parser: MUTF-8 Embedded Null Character Decoding', 'DEX Parser', () => {
    // 0xc0 0x80 represents embedded null character \u0000 in MUTF-8
    const mutf8Data = new Uint8Array([
      0x0b, // declared UTF-16 length = 11 code units ("Hello\u0000World")
      0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello"
      0xc0, 0x80, // embedded \u0000
      0x57, 0x6f, 0x72, 0x6c, 0x64, // "World"
      0x00, // null terminator
    ]);
    const decoded = readMutf8String(mutf8Data, 0);
    if (!decoded.startsWith('Hello')) {
      throw new Error(`Decoded MUTF-8 string does not begin with "Hello": "${decoded}"`);
    }
  });

  // ==========================================
  // MODULE 5: Native Library (ELF) Inspector
  // ==========================================

  await runTest('t22-elf-abi-crosschecking', 'Native Inspector: ABI Directory Cross-Checking & Mismatch Detection', 'Native Inspector', () => {
    const arm64Elf = createSampleElf64(0xb7); // 0xb7 = EM_AARCH64
    const zipEntries = [
      {
        filename: 'lib/x86/libnative.so', // Intentionally mismatched folder (x86 vs arm64)
        compressedSize: arm64Elf.length,
        uncompressedSize: arm64Elf.length,
        compressionMethod: 0,
        crc32: 0,
        offset: 0,
      },
    ];

    const dataMap = new Map<string, Uint8Array>();
    dataMap.set('lib/x86/libnative.so', arm64Elf);

    const summary = inspectNativeLibrariesDetailed(zipEntries, dataMap);
    if (!summary.hasAbiMismatches) {
      throw new Error('ABI mismatch (x86 folder containing arm64 ELF) was not detected.');
    }
  });

  // ==========================================
  // MODULE 6: Compatibility Assessment
  // ==========================================

  await runTest('t23-compatibility-honest-assessment', 'Compatibility Engine: Honest Assessment (ANALYSIS ONLY in Phase 1)', 'Compatibility Engine', () => {
    const manifest = parseBinaryAndroidManifest(
      createSampleAndroidManifest('com.example.app', 'com.example.app.MainActivity', 'Test App')
    );
    const dex = parseDexFile(createSampleDex('Lcom/example/app/MainActivity;', 'onCreate'));

    const result = evaluateCompatibility(manifest, [dex], []);
    if (result.status !== 'ANALYSIS_ONLY') {
      throw new Error(`Expected compatibility status ANALYSIS_ONLY, got ${result.status}`);
    }
    if (result.readyForExecution !== false) {
      throw new Error('Expected readyForExecution to be false in Phase 1 release.');
    }
  });

  // ==========================================
  // MODULE 7: Remote Import & GitHub URL Security
  // ==========================================

  await runTest('t24-github-url-parser-security', 'Remote Importer: Strict GitHub URL Hostname & Security Validation', 'Remote Importer', () => {
    // 1. Valid repository URL
    const res1 = ApkRuntimeService.parseGitHubUrl('https://github.com/mrhacker690/apkruntime');
    if (!res1 || res1.owner !== 'mrhacker690' || res1.repo !== 'apkruntime' || res1.isDirectAsset !== false) {
      throw new Error(`Failed to parse valid repository URL: ${JSON.stringify(res1)}`);
    }

    // 2. Valid direct release asset URL
    const res2 = ApkRuntimeService.parseGitHubUrl('https://github.com/owner/repo/releases/download/v1.0.0/app.apk');
    if (!res2 || res2.owner !== 'owner' || res2.repo !== 'repo' || res2.tag !== 'v1.0.0' || res2.isDirectAsset !== true) {
      throw new Error(`Failed to parse valid direct release asset URL: ${JSON.stringify(res2)}`);
    }

    // 3. Reject lookalike domain (evilgithub.com)
    const res3 = ApkRuntimeService.parseGitHubUrl('https://evilgithub.com/owner/repo');
    if (res3 !== null) {
      throw new Error('Lookalike domain evilgithub.com was not rejected.');
    }

    // 4. Reject lookalike subdomain (github.com.attacker.org)
    const res4 = ApkRuntimeService.parseGitHubUrl('https://github.com.attacker.org/owner/repo');
    if (res4 !== null) {
      throw new Error('Subdomain trick github.com.attacker.org was not rejected.');
    }

    // 5. Reject URL with embedded credentials (user:pass@github.com)
    const res5 = ApkRuntimeService.parseGitHubUrl('https://user:pass@github.com/owner/repo');
    if (res5 !== null) {
      throw new Error('URL with embedded credentials was not rejected.');
    }
  });

  return results;
}
