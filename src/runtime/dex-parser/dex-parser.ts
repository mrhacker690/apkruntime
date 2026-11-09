/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Hardened Dalvik Executable (DEX) Parser & Disassembler
 * Strictly validates DEX headers, SHA-1 signatures, Adler-32 checksums, section bounds,
 * MUTF-8 strings, ULEB128/SLEB128 integer decoders, class definitions, and Dalvik instruction formats.
 */

import { DexFileAnalysis, DexHeader, DexClass, DexMethod } from '../core/types';
import { pureJsSha1Bytes } from '../apk-extractor/sha1';

export class DexParseError extends Error {
  constructor(message: string) {
    super(`DEX Parse Error: ${message}`);
    this.name = 'DexParseError';
  }
}

const SUPPORTED_DEX_VERSIONS = new Set(['035', '037', '038', '039']);
const ENDIAN_CONSTANT = 0x12345678;
const NO_INDEX = 0xffffffff;

export interface DexOpcodeMetadata {
  opcode: number;
  mnemonic: string;
  format: string;
  lengthUnits: number;
  dexVersions: string[];
  operandLayout: string;
  hasRegisterOperands: boolean;
  hasLiteralOperands: boolean;
  hasReferenceIndex: boolean;
  referenceType?: 'string' | 'type' | 'field' | 'method' | 'proto' | 'method_handle' | 'call_site';
}

/**
 * Version-Aware Master Dalvik Opcode Metadata Table (0x00 - 0xFF)
 */
export const DEX_OPCODE_TABLE: Map<number, DexOpcodeMetadata> = new Map();

function registerOpcode(
  opcode: number,
  mnemonic: string,
  format: string,
  lengthUnits: number,
  operandLayout: string,
  hasReg: boolean,
  hasLit: boolean,
  refType?: 'string' | 'type' | 'field' | 'method' | 'proto' | 'method_handle' | 'call_site',
  versions: string[] = ['035', '037', '038', '039']
) {
  DEX_OPCODE_TABLE.set(opcode, {
    opcode,
    mnemonic,
    format,
    lengthUnits,
    dexVersions: versions,
    operandLayout,
    hasRegisterOperands: hasReg,
    hasLiteralOperands: hasLit,
    hasReferenceIndex: refType !== undefined,
    referenceType: refType,
  });
}

// 0x00 - 0x0e: Basic moves & returns
registerOpcode(0x00, 'nop', '10x', 1, 'none', false, false);
registerOpcode(0x01, 'move', '12x', 1, 'vA, vB', true, false);
registerOpcode(0x02, 'move/from16', '22x', 2, 'vAA, vBBBB', true, false);
registerOpcode(0x03, 'move/16', '32x', 3, 'vAAAA, vBBBB', true, false);
registerOpcode(0x04, 'move-wide', '12x', 1, 'vA, vB', true, false);
registerOpcode(0x05, 'move-wide/from16', '22x', 2, 'vAA, vBBBB', true, false);
registerOpcode(0x06, 'move-wide/16', '32x', 3, 'vAAAA, vBBBB', true, false);
registerOpcode(0x07, 'move-object', '12x', 1, 'vA, vB', true, false);
registerOpcode(0x08, 'move-object/from16', '22x', 2, 'vAA, vBBBB', true, false);
registerOpcode(0x09, 'move-object/16', '32x', 3, 'vAAAA, vBBBB', true, false);
registerOpcode(0x0a, 'move-result', '11x', 1, 'vAA', true, false);
registerOpcode(0x0b, 'move-result-wide', '11x', 1, 'vAA', true, false);
registerOpcode(0x0c, 'move-result-object', '11x', 1, 'vAA', true, false);
registerOpcode(0x0d, 'move-result-exception', '11x', 1, 'vAA', true, false);
registerOpcode(0x0e, 'return-void', '10x', 1, 'none', false, false);
registerOpcode(0x0f, 'return', '11x', 1, 'vAA', true, false);
registerOpcode(0x10, 'return-wide', '11x', 1, 'vAA', true, false);
registerOpcode(0x11, 'return-object', '11x', 1, 'vAA', true, false);

// 0x12 - 0x1c: Constants & Type casts
registerOpcode(0x12, 'const/4', '11n', 1, 'vA, #+B', true, true);
registerOpcode(0x13, 'const/16', '21s', 2, 'vAA, #+BBBB', true, true);
registerOpcode(0x14, 'const', '31i', 3, 'vAA, #+BBBBBBBB', true, true);
registerOpcode(0x15, 'const/high16', '21h', 2, 'vAA, #+BBBB0000', true, true);
registerOpcode(0x16, 'const-wide/16', '21s', 2, 'vAA, #+BBBB', true, true);
registerOpcode(0x17, 'const-wide/32', '31i', 3, 'vAA, #+BBBBBBBB', true, true);
registerOpcode(0x18, 'const-wide', '51l', 5, 'vAA, #+BBBBBBBBBBBBBBBB', true, true);
registerOpcode(0x19, 'const-wide/high16', '21h', 2, 'vAA, #+BBBB000000000000', true, true);
registerOpcode(0x1a, 'const-string', '21c', 2, 'vAA, string@BBBB', true, false, 'string');
registerOpcode(0x1b, 'const-string/jumbo', '31c', 3, 'vAA, string@BBBBBBBB', true, false, 'string');
registerOpcode(0x1c, 'const-class', '21c', 2, 'vAA, type@BBBB', true, false, 'type');
registerOpcode(0x1d, 'monitor-enter', '11x', 1, 'vAA', true, false);
registerOpcode(0x1e, 'monitor-exit', '11x', 1, 'vAA', true, false);
registerOpcode(0x1f, 'check-cast', '21c', 2, 'vAA, type@BBBB', true, false, 'type');
registerOpcode(0x20, 'instance-of', '22c', 2, 'vA, vB, type@CCCC', true, false, 'type');
registerOpcode(0x21, 'array-length', '12x', 1, 'vA, vB', true, false);
registerOpcode(0x22, 'new-instance', '21c', 2, 'vAA, type@BBBB', true, false, 'type');
registerOpcode(0x23, 'new-array', '22c', 2, 'vA, vB, type@CCCC', true, false, 'type');
registerOpcode(0x24, 'filled-new-array', '35c', 3, '{vC..vG}, type@BBBB', true, false, 'type');
registerOpcode(0x25, 'filled-new-array/range', '3rc', 3, '{vCCCC..vNNNN}, type@BBBB', true, false, 'type');
registerOpcode(0x26, 'fill-array-data', '31t', 3, 'vAA, +BBBBBBBB', true, true);
registerOpcode(0x27, 'throw', '11x', 1, 'vAA', true, false);

// 0x28 - 0x3d: Jumps & Branches
registerOpcode(0x28, 'goto', '10t', 1, '+AA', false, true);
registerOpcode(0x29, 'goto/16', '20t', 2, '+AAAA', false, true);
registerOpcode(0x2a, 'goto/32', '30t', 3, '+AAAAAAAA', false, true);
registerOpcode(0x2b, 'packed-switch', '31t', 3, 'vAA, +BBBBBBBB', true, true);
registerOpcode(0x2c, 'sparse-switch', '31t', 3, 'vAA, +BBBBBBBB', true, true);
registerOpcode(0x2d, 'cmpl-float', '23x', 2, 'vAA, vBB, vCC', true, false);
registerOpcode(0x2e, 'cmpg-float', '23x', 2, 'vAA, vBB, vCC', true, false);
registerOpcode(0x2f, 'cmpl-double', '23x', 2, 'vAA, vBB, vCC', true, false);
registerOpcode(0x30, 'cmpg-double', '23x', 2, 'vAA, vBB, vCC', true, false);
registerOpcode(0x31, 'cmp-long', '23x', 2, 'vAA, vBB, vCC', true, false);
registerOpcode(0x32, 'if-eq', '22t', 2, 'vA, vB, +CCCC', true, true);
registerOpcode(0x33, 'if-ne', '22t', 2, 'vA, vB, +CCCC', true, true);
registerOpcode(0x34, 'if-lt', '22t', 2, 'vA, vB, +CCCC', true, true);
registerOpcode(0x35, 'if-ge', '22t', 2, 'vA, vB, +CCCC', true, true);
registerOpcode(0x36, 'if-gt', '22t', 2, 'vA, vB, +CCCC', true, true);
registerOpcode(0x37, 'if-le', '22t', 2, 'vA, vB, +CCCC', true, true);
registerOpcode(0x38, 'if-eqz', '21t', 2, 'vAA, +BBBB', true, true);
registerOpcode(0x39, 'if-nez', '21t', 2, 'vAA, +BBBB', true, true);
registerOpcode(0x3a, 'if-ltz', '21t', 2, 'vAA, +BBBB', true, true);
registerOpcode(0x3b, 'if-gez', '21t', 2, 'vAA, +BBBB', true, true);
registerOpcode(0x3c, 'if-gtz', '21t', 2, 'vAA, +BBBB', true, true);
registerOpcode(0x3d, 'if-lez', '21t', 2, 'vAA, +BBBB', true, true);

// 0x44 - 0x51: Array getters & putters
for (let op = 0x44; op <= 0x51; op++) {
  const m = [
    'aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short',
    'aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short',
  ][op - 0x44];
  registerOpcode(op, m, '23x', 2, 'vAA, vBB, vCC', true, false);
}

// 0x52 - 0x5f: Instance field get/put
for (let op = 0x52; op <= 0x5f; op++) {
  const m = [
    'iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short',
    'iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short',
  ][op - 0x52];
  registerOpcode(op, m, '22c', 2, 'vA, vB, field@CCCC', true, false, 'field');
}

// 0x60 - 0x6d: Static field get/put
for (let op = 0x60; op <= 0x6d; op++) {
  const m = [
    'sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short',
    'sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short',
  ][op - 0x60];
  registerOpcode(op, m, '21c', 2, 'vAA, field@BBBB', true, false, 'field');
}

// 0x6e - 0x78: Method Invocation
registerOpcode(0x6e, 'invoke-virtual', '35c', 3, '{vC..vG}, method@BBBB', true, false, 'method');
registerOpcode(0x6f, 'invoke-super', '35c', 3, '{vC..vG}, method@BBBB', true, false, 'method');
registerOpcode(0x70, 'invoke-direct', '35c', 3, '{vC..vG}, method@BBBB', true, false, 'method');
registerOpcode(0x71, 'invoke-static', '35c', 3, '{vC..vG}, method@BBBB', true, false, 'method');
registerOpcode(0x72, 'invoke-interface', '35c', 3, '{vC..vG}, method@BBBB', true, false, 'method');
registerOpcode(0x74, 'invoke-virtual/range', '3rc', 3, '{vCCCC..vNNNN}, method@BBBB', true, false, 'method');
registerOpcode(0x75, 'invoke-super/range', '3rc', 3, '{vCCCC..vNNNN}, method@BBBB', true, false, 'method');
registerOpcode(0x76, 'invoke-direct/range', '3rc', 3, '{vCCCC..vNNNN}, method@BBBB', true, false, 'method');
registerOpcode(0x77, 'invoke-static/range', '3rc', 3, '{vCCCC..vNNNN}, method@BBBB', true, false, 'method');
registerOpcode(0x78, 'invoke-interface/range', '3rc', 3, '{vCCCC..vNNNN}, method@BBBB', true, false, 'method');

// 0x7b - 0x8f: Unary operators & Primitive conversions
for (let op = 0x7b; op <= 0x8f; op++) {
  const m = [
    'neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double',
    'int-to-long', 'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float', 'long-to-double',
    'float-to-int', 'float-to-long', 'float-to-double', 'double-to-int', 'double-to-long', 'double-to-float',
    'int-to-byte', 'int-to-char', 'int-to-short'
  ][op - 0x7b];
  if (m) registerOpcode(op, m, '12x', 1, 'vA, vB', true, false);
}

// 0x90 - 0xaf: Binary arithmetic
for (let op = 0x90; op <= 0xaf; op++) {
  const m = [
    'add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int',
    'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long',
    'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float', 'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double'
  ][op - 0x90];
  registerOpcode(op, m, '23x', 2, 'vAA, vBB, vCC', true, false);
}

// 0xb0 - 0xcf: Binary arithmetic / 2addr
for (let op = 0xb0; op <= 0xcf; op++) {
  const m = [
    'add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr', 'rem-int/2addr', 'and-int/2addr', 'or-int/2addr', 'xor-int/2addr', 'shl-int/2addr', 'shr-int/2addr', 'ushr-int/2addr',
    'add-long/2addr', 'sub-long/2addr', 'mul-long/2addr', 'div-long/2addr', 'rem-long/2addr', 'and-long/2addr', 'or-long/2addr', 'xor-long/2addr', 'shl-long/2addr', 'shr-long/2addr', 'ushr-long/2addr',
    'add-float/2addr', 'sub-float/2addr', 'mul-float/2addr', 'div-float/2addr', 'rem-float/2addr', 'add-double/2addr', 'sub-double/2addr', 'mul-double/2addr', 'div-double/2addr', 'rem-double/2addr'
  ][op - 0xb0];
  registerOpcode(op, m, '12x', 1, 'vA, vB', true, false);
}

// 0xd0 - 0xd7: Binary arithmetic / lit16
for (let op = 0xd0; op <= 0xd7; op++) {
  const m = ['add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16', 'and-int/lit16', 'or-int/lit16', 'xor-int/lit16'][op - 0xd0];
  registerOpcode(op, m, '22s', 2, 'vA, vB, #+CCCC', true, true);
}

// 0xd8 - 0xe2: Binary arithmetic / lit8
for (let op = 0xd8; op <= 0xe2; op++) {
  const m = ['add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8', 'and-int/lit8', 'or-int/lit8', 'xor-int/lit8', 'shl-int/lit8', 'shr-int/lit8', 'ushr-int/lit8'][op - 0xd8];
  registerOpcode(op, m, '22b', 2, 'vAA, vBB, #+CC', true, true);
}

// Task 1 mandatory specific opcode metadata:
// 0xfa: invoke-polymorphic (4 code units = 8 bytes)
registerOpcode(0xfa, 'invoke-polymorphic', '45cc', 4, '{vC..vG}, method@BBBB, proto@HHHH', true, false, 'method', ['038', '039']);
// 0xfb: invoke-polymorphic/range (4 code units = 8 bytes)
registerOpcode(0xfb, 'invoke-polymorphic/range', '4rcc', 4, '{vCCCC..vNNNN}, method@BBBB, proto@HHHH', true, false, 'method', ['038', '039']);
// 0xfc: invoke-custom (3 code units = 6 bytes)
registerOpcode(0xfc, 'invoke-custom', '35c', 3, '{vC..vG}, call_site@BBBB', true, false, 'call_site', ['038', '039']);
// 0xfd: invoke-custom/range (3 code units = 6 bytes)
registerOpcode(0xfd, 'invoke-custom/range', '3rc', 3, '{vCCCC..vNNNN}, call_site@BBBB', true, false, 'call_site', ['038', '039']);
// 0xfe: const-method-handle (2 code units = 4 bytes)
registerOpcode(0xfe, 'const-method-handle', '21c', 2, 'vAA, method_handle@BBBB', true, false, 'method_handle', ['039']);
// 0xff: const-method-type (2 code units = 4 bytes)
registerOpcode(0xff, 'const-method-type', '21c', 2, 'vAA, proto@BBBB', true, false, 'proto', ['039']);

/**
 * Complete Dalvik Executable (DEX) parser with strict boundaries, SHA-1, Adler-32, section checks.
 */
export function parseDexFile(buffer: Uint8Array, fileName: string = 'classes.dex'): DexFileAnalysis {
  if (!buffer || buffer.byteLength < 0x70) {
    throw new DexParseError(
      `File size (${buffer?.byteLength || 0} bytes) is smaller than minimum DEX header size (112 bytes).`
    );
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  // 1. Magic & Version Check
  const magicBytes = Array.from(buffer.subarray(0, 8));
  const magicStr = String.fromCharCode(...magicBytes.slice(0, 4));
  if (magicStr !== 'dex\n') {
    throw new DexParseError(`Invalid DEX magic header: expected "dex\\n", got "${escapeBytes(magicBytes)}"`);
  }

  const version = String.fromCharCode(...magicBytes.slice(4, 7));
  const nul = magicBytes[7];
  if (nul !== 0) {
    throw new DexParseError('Malformed DEX version: expected null terminator at byte offset 7.');
  }

  if (!SUPPORTED_DEX_VERSIONS.has(version)) {
    throw new DexParseError(`Unsupported DEX version "${version}". Supported versions: 035, 037, 038, 039.`);
  }

  // Header sizes and boundaries
  const fileSize = view.getUint32(32, true);
  const headerSize = view.getUint32(36, true);
  const endianTag = view.getUint32(40, true);

  if (endianTag !== ENDIAN_CONSTANT) {
    throw new DexParseError(
      `Unsupported endianness tag: 0x${endianTag.toString(16)} (expected little-endian 0x12345678).`
    );
  }

  if (headerSize !== 0x70) {
    throw new DexParseError(`Invalid DEX header size: expected 112 (0x70) bytes, got ${headerSize}.`);
  }

  if (fileSize > buffer.byteLength) {
    throw new DexParseError(`DEX file truncated: header declares ${fileSize} bytes, actual buffer is ${buffer.byteLength} bytes.`);
  }

  // Strict DEX file boundary
  const maxDexSize = fileSize;

  // 2. SHA-1 Signature Verification (bytes 12-31 calculated over bytes 32 to maxDexSize)
  const storedSigBytes = buffer.subarray(12, 32);
  const storedSigHex = Array.from(storedSigBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const calculatedSigBytes = pureJsSha1Bytes(buffer.subarray(32, maxDexSize));
  const calculatedSigHex = Array.from(calculatedSigBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  if (storedSigHex !== calculatedSigHex) {
    throw new DexParseError(
      `DEX SHA-1 signature mismatch: header declares ${storedSigHex}, but calculated ${calculatedSigHex}.`
    );
  }

  // 3. Adler-32 Checksum Verification (bytes 8-11 calculated over bytes 12 to maxDexSize)
  const storedChecksum = view.getUint32(8, true);
  const calculatedChecksum = adler32(buffer.subarray(12, maxDexSize));
  if (storedChecksum !== calculatedChecksum) {
    throw new DexParseError(
      `DEX Adler-32 checksum mismatch: header declares 0x${storedChecksum.toString(16).padStart(8, '0')}, but calculated 0x${calculatedChecksum.toString(16).padStart(8, '0')}.`
    );
  }

  const header: DexHeader = {
    magic: 'dex\n',
    version,
    checksum: storedChecksum,
    signature: storedSigHex,
    fileSize,
    headerSize,
    endianTag,
    linkSize: view.getUint32(44, true),
    linkOff: view.getUint32(48, true),
    mapOff: view.getUint32(52, true),
    stringIdsSize: view.getUint32(56, true),
    stringIdsOff: view.getUint32(60, true),
    typeIdsSize: view.getUint32(64, true),
    typeIdsOff: view.getUint32(68, true),
    protoIdsSize: view.getUint32(72, true),
    protoIdsOff: view.getUint32(76, true),
    fieldIdsSize: view.getUint32(80, true),
    fieldIdsOff: view.getUint32(84, true),
    methodIdsSize: view.getUint32(88, true),
    methodIdsOff: view.getUint32(92, true),
    classDefsSize: view.getUint32(96, true),
    classDefsOff: view.getUint32(100, true),
    dataSize: view.getUint32(104, true),
    dataOff: view.getUint32(108, true),
  };

  // 4. Section Boundary & Offset Validation
  validateSection('string_ids', header.stringIdsOff, header.stringIdsSize, 4, maxDexSize);
  validateSection('type_ids', header.typeIdsOff, header.typeIdsSize, 4, maxDexSize);
  validateSection('proto_ids', header.protoIdsOff, header.protoIdsSize, 12, maxDexSize);
  validateSection('field_ids', header.fieldIdsOff, header.fieldIdsSize, 8, maxDexSize);
  validateSection('method_ids', header.methodIdsOff, header.methodIdsSize, 8, maxDexSize);
  validateSection('class_defs', header.classDefsOff, header.classDefsSize, 32, maxDexSize);

  // 5. Parse String Table
  const strings: string[] = [];
  for (let i = 0; i < header.stringIdsSize; i++) {
    const stringDataOff = view.getUint32(header.stringIdsOff + i * 4, true);
    if (stringDataOff < headerSize || stringDataOff >= maxDexSize) {
      throw new DexParseError(`String ID #${i} points to invalid data offset 0x${stringDataOff.toString(16)} outside boundary (0x${headerSize.toString(16)}..0x${maxDexSize.toString(16)}).`);
    }
    strings.push(readMutf8String(buffer, stringDataOff, maxDexSize));
  }

  // 6. Parse Type IDs
  const types: string[] = [];
  for (let i = 0; i < header.typeIdsSize; i++) {
    const descriptorIdx = view.getUint32(header.typeIdsOff + i * 4, true);
    if (descriptorIdx >= strings.length) {
      throw new DexParseError(`Type ID #${i} references invalid string index ${descriptorIdx} (table size ${strings.length}).`);
    }
    types.push(strings[descriptorIdx] ?? '');
  }

  // 7. Parse Method IDs
  interface MethodIdRecord {
    classIdx: number;
    protoIdx: number;
    nameIdx: number;
  }
  const methodIds: MethodIdRecord[] = [];
  for (let i = 0; i < header.methodIdsSize; i++) {
    const off = header.methodIdsOff + i * 8;
    const classIdx = view.getUint16(off, true);
    const protoIdx = view.getUint16(off + 2, true);
    const nameIdx = view.getUint32(off + 4, true);

    if (classIdx >= types.length) {
      throw new DexParseError(`Method ID #${i} references out-of-bounds class index ${classIdx}.`);
    }
    if (protoIdx >= header.protoIdsSize && protoIdx !== NO_INDEX) {
      throw new DexParseError(`Method ID #${i} references out-of-bounds proto index ${protoIdx}.`);
    }
    if (nameIdx >= strings.length) {
      throw new DexParseError(`Method ID #${i} references out-of-bounds name index ${nameIdx}.`);
    }

    methodIds.push({ classIdx, protoIdx, nameIdx });
  }

  // 8. Parse Class Definitions
  const classes: DexClass[] = [];
  for (let i = 0; i < header.classDefsSize; i++) {
    const classDefOff = header.classDefsOff + i * 32;
    const classIdx = view.getUint32(classDefOff, true);
    const accessFlags = view.getUint32(classDefOff + 4, true);
    const superclassIdx = view.getUint32(classDefOff + 8, true);
    const sourceFileIdx = view.getUint32(classDefOff + 16, true);
    const classDataOff = view.getUint32(classDefOff + 24, true);

    if (classIdx >= types.length) {
      throw new DexParseError(`Class definition #${i} has out-of-bounds class index ${classIdx}.`);
    }
    if (superclassIdx !== NO_INDEX && superclassIdx >= types.length) {
      throw new DexParseError(`Class definition #${i} has out-of-bounds superclass index ${superclassIdx}.`);
    }
    if (sourceFileIdx !== NO_INDEX && sourceFileIdx >= strings.length) {
      throw new DexParseError(`Class definition #${i} has out-of-bounds source file index ${sourceFileIdx}.`);
    }

    const className = formatJavaTypeName(types[classIdx]);
    const superclassName = superclassIdx === NO_INDEX ? '' : formatJavaTypeName(types[superclassIdx] || '');
    const sourceFile = sourceFileIdx === NO_INDEX ? undefined : strings[sourceFileIdx];

    const directMethods: DexMethod[] = [];
    const virtualMethods: DexMethod[] = [];
    let staticFieldsCount = 0;
    let instanceFieldsCount = 0;

    if (classDataOff > 0) {
      if (classDataOff < headerSize || classDataOff >= maxDexSize) {
        throw new DexParseError(`Class data offset 0x${classDataOff.toString(16)} for ${className} is outside boundary.`);
      }

      let cursor = classDataOff;
      const [numStaticFields, next1] = readUleb128(buffer, cursor, maxDexSize);
      cursor = next1;
      const [numInstanceFields, next2] = readUleb128(buffer, cursor, maxDexSize);
      cursor = next2;
      const [numDirectMethods, next3] = readUleb128(buffer, cursor, maxDexSize);
      cursor = next3;
      const [numVirtualMethods, next4] = readUleb128(buffer, cursor, maxDexSize);
      cursor = next4;

      staticFieldsCount = numStaticFields;
      instanceFieldsCount = numInstanceFields;

      // Skip fields
      for (let f = 0; f < numStaticFields; f++) {
        const [, nA] = readUleb128(buffer, cursor, maxDexSize);
        const [, nB] = readUleb128(buffer, nA, maxDexSize);
        cursor = nB;
      }
      for (let f = 0; f < numInstanceFields; f++) {
        const [, nA] = readUleb128(buffer, cursor, maxDexSize);
        const [, nB] = readUleb128(buffer, nA, maxDexSize);
        cursor = nB;
      }

      // Read direct methods
      let lastMethodIndex = 0;
      for (let m = 0; m < numDirectMethods; m++) {
        const [methodIdxDiff, nA] = readUleb128(buffer, cursor, maxDexSize);
        const [methodFlags, nB] = readUleb128(buffer, nA, maxDexSize);
        const [codeOff, nC] = readUleb128(buffer, nB, maxDexSize);
        cursor = nC;

        lastMethodIndex += methodIdxDiff;
        if (lastMethodIndex >= methodIds.length) {
          throw new DexParseError(`Accumulated direct method index ${lastMethodIndex} exceeds method table size ${methodIds.length}.`);
        }

        const methodObj = decodeDexMethod(
          buffer,
          lastMethodIndex,
          methodFlags,
          codeOff,
          methodIds,
          strings,
          types,
          maxDexSize,
          version
        );
        directMethods.push(methodObj);
      }

      // Read virtual methods
      lastMethodIndex = 0;
      for (let m = 0; m < numVirtualMethods; m++) {
        const [methodIdxDiff, nA] = readUleb128(buffer, cursor, maxDexSize);
        const [methodFlags, nB] = readUleb128(buffer, nA, maxDexSize);
        const [codeOff, nC] = readUleb128(buffer, nB, maxDexSize);
        cursor = nC;

        lastMethodIndex += methodIdxDiff;
        if (lastMethodIndex >= methodIds.length) {
          throw new DexParseError(`Accumulated virtual method index ${lastMethodIndex} exceeds method table size ${methodIds.length}.`);
        }

        const methodObj = decodeDexMethod(
          buffer,
          lastMethodIndex,
          methodFlags,
          codeOff,
          methodIds,
          strings,
          types,
          maxDexSize,
          version
        );
        virtualMethods.push(methodObj);
      }
    }

    classes.push({
      classIndex: classIdx,
      className,
      accessFlags,
      superclassName,
      sourceFile,
      directMethods,
      virtualMethods,
      staticFieldsCount,
      instanceFieldsCount,
    });
  }

  return {
    name: fileName,
    size: fileSize,
    header,
    stringsCount: header.stringIdsSize,
    typesCount: header.typeIdsSize,
    protoCount: header.protoIdsSize,
    fieldsCount: header.fieldIdsSize,
    methodsCount: header.methodIdsSize,
    classesCount: header.classDefsSize,
    stringsSample: strings.slice(0, 100),
    classes,
  };
}

function validateSection(
  name: string,
  offset: number,
  count: number,
  itemSize: number,
  maxBoundary: number
): void {
  if (count === 0) return;
  if (offset % 4 !== 0) {
    throw new DexParseError(`DEX section "${name}" offset 0x${offset.toString(16)} violates 4-byte alignment requirement.`);
  }
  const totalBytes = count * itemSize;
  if (offset + totalBytes > maxBoundary) {
    throw new DexParseError(`DEX section "${name}" (offset 0x${offset.toString(16)}, size ${totalBytes}) exceeds file size (${maxBoundary}).`);
  }
}

function decodeDexMethod(
  buffer: Uint8Array,
  methodIndex: number,
  accessFlags: number,
  codeOff: number,
  methodIds: { classIdx: number; protoIdx: number; nameIdx: number }[],
  strings: string[],
  types: string[],
  maxDexSize: number,
  dexVersion: string
): DexMethod {
  const mId = methodIds[methodIndex];
  const className = mId ? formatJavaTypeName(types[mId.classIdx] || '') : 'UnknownClass';
  const name = mId ? (strings[mId.nameIdx] || `method_${methodIndex}`) : `method_${methodIndex}`;

  let registersSize: number | undefined;
  let insSize: number | undefined;
  let outsSize: number | undefined;
  let insnsSize: number | undefined;
  const instructions: string[] = [];

  if (codeOff > 0) {
    if (codeOff + 16 > maxDexSize) {
      throw new DexParseError(`Code item offset 0x${codeOff.toString(16)} for ${className}.${name} exceeds boundary ${maxDexSize}.`);
    }

    const view = new DataView(buffer.buffer, buffer.byteOffset, maxDexSize);
    registersSize = view.getUint16(codeOff, true);
    insSize = view.getUint16(codeOff + 2, true);
    outsSize = view.getUint16(codeOff + 4, true);
    const triesSize = view.getUint16(codeOff + 6, true);
    const debugInfoOff = view.getUint32(codeOff + 8, true);
    insnsSize = view.getUint32(codeOff + 12, true);

    const insnsStart = codeOff + 16;
    const insnsEnd = insnsStart + insnsSize * 2;

    if (insnsEnd > maxDexSize) {
      throw new DexParseError(`Declared instructions for ${className}.${name} (size ${insnsSize} code units) extend beyond boundary ${maxDexSize}.`);
    }

    let insnOffset = 0;
    while (insnOffset < insnsSize) {
      const currentBytePos = insnsStart + insnOffset * 2;
      if (currentBytePos + 2 > maxDexSize) {
        throw new DexParseError(`Instruction stream decoding past DEX file boundary at code unit ${insnOffset}.`);
      }

      const codeUnit = view.getUint16(currentBytePos, true);

      // Check for special payload format markers
      if (codeUnit === 0x0100) { // packed-switch payload
        if (currentBytePos + 4 > maxDexSize) throw new DexParseError('Truncated packed-switch payload header.');
        const size = view.getUint16(currentBytePos + 2, true);
        const payloadUnits = (size * 2) + 4;
        instructions.push(`0x${(insnOffset * 2).toString(16).padStart(4, '0')}: packed-switch-payload (size: ${size}, units: ${payloadUnits})`);
        insnOffset += payloadUnits;
        continue;
      } else if (codeUnit === 0x0200) { // sparse-switch payload
        if (currentBytePos + 4 > maxDexSize) throw new DexParseError('Truncated sparse-switch payload header.');
        const size = view.getUint16(currentBytePos + 2, true);
        const payloadUnits = (size * 4) + 2;
        instructions.push(`0x${(insnOffset * 2).toString(16).padStart(4, '0')}: sparse-switch-payload (size: ${size}, units: ${payloadUnits})`);
        insnOffset += payloadUnits;
        continue;
      } else if (codeUnit === 0x0300) { // fill-array-data payload
        if (currentBytePos + 8 > maxDexSize) throw new DexParseError('Truncated fill-array-data payload header.');
        const elementWidth = view.getUint16(currentBytePos + 2, true);
        const elementCount = view.getUint32(currentBytePos + 4, true);
        const payloadUnits = Math.ceil((elementWidth * elementCount) / 2) + 4;
        instructions.push(`0x${(insnOffset * 2).toString(16).padStart(4, '0')}: fill-array-data-payload (width: ${elementWidth}, count: ${elementCount}, units: ${payloadUnits})`);
        insnOffset += payloadUnits;
        continue;
      }

      const opcode = codeUnit & 0xff;
      const argA = (codeUnit >> 8) & 0xff;

      const meta = DEX_OPCODE_TABLE.get(opcode);
      if (!meta) {
        throw new DexParseError(`Unsupported or reserved DEX opcode 0x${opcode.toString(16).padStart(2, '0')} at code unit offset ${insnOffset}.`);
      }

      if (meta.dexVersions.length > 0 && !meta.dexVersions.includes(dexVersion)) {
        throw new DexParseError(`Opcode 0x${opcode.toString(16)} (${meta.mnemonic}) is not supported in DEX version ${dexVersion}.`);
      }

      const unitsRequired = meta.lengthUnits;
      if (insnOffset + unitsRequired > insnsSize) {
        throw new DexParseError(`Instruction ${meta.mnemonic} (size ${unitsRequired} units) extends beyond method insnsSize (${insnsSize} units).`);
      }

      const [disasm, consumedUnits] = disassembleOpcode(
        opcode,
        argA,
        view,
        currentBytePos,
        strings,
        types,
        meta
      );

      const hexAddr = (insnOffset * 2).toString(16).padStart(4, '0');
      instructions.push(`0x${hexAddr}: ${disasm}`);

      insnOffset += consumedUnits;
    }
  }

  return {
    classIndex: mId ? mId.classIdx : -1,
    className,
    protoIndex: mId ? mId.protoIdx : -1,
    nameIndex: mId ? mId.nameIdx : -1,
    name,
    accessFlags,
    codeOffset: codeOff,
    registersSize,
    insSize,
    outsSize,
    insnsSize,
    instructions: instructions.length > 0 ? instructions : undefined,
  };
}

function disassembleOpcode(
  opcode: number,
  argA: number,
  view: DataView,
  bytePos: number,
  strings: string[],
  types: string[],
  meta: DexOpcodeMetadata
): [string, number] {
  const len = meta.lengthUnits;

  switch (opcode) {
    case 0x00:
      return ['nop', 1];

    case 0x01: {
      const vA = argA & 0x0f;
      const vB = (argA >> 4) & 0x0f;
      return [`move v${vA}, v${vB}`, 1];
    }

    case 0x07: {
      const vA = argA & 0x0f;
      const vB = (argA >> 4) & 0x0f;
      return [`move-object v${vA}, v${vB}`, 1];
    }

    case 0x0e:
      return ['return-void', 1];

    case 0x0f:
      return [`return v${argA}`, 1];

    case 0x11:
      return [`return-object v${argA}`, 1];

    case 0x12: {
      const vA = argA & 0x0f;
      let lit = (argA >> 4) & 0x0f;
      if (lit & 0x08) lit |= ~0x0f;
      return [`const/4 v${vA}, #${lit}`, 1];
    }

    case 0x13: {
      const lit16 = view.getInt16(bytePos + 2, true);
      return [`const/16 v${argA}, #${lit16}`, 2];
    }

    case 0x14: {
      const lit32 = view.getInt32(bytePos + 2, true);
      return [`const v${argA}, #${lit32}`, 3];
    }

    case 0x18: {
      const low = view.getUint32(bytePos + 2, true);
      const high = view.getInt32(bytePos + 6, true);
      return [`const-wide v${argA}, #0x${high.toString(16)}${low.toString(16).padStart(8, '0')}`, 5];
    }

    case 0x1a: {
      const stringIdx = view.getUint16(bytePos + 2, true);
      const strVal = strings[stringIdx] !== undefined ? JSON.stringify(strings[stringIdx]) : `string@${stringIdx}`;
      return [`const-string v${argA}, ${strVal}`, 2];
    }

    case 0x1b: {
      const stringIdx = view.getUint32(bytePos + 2, true);
      const strVal = strings[stringIdx] !== undefined ? JSON.stringify(strings[stringIdx]) : `string@${stringIdx}`;
      return [`const-string/jumbo v${argA}, ${strVal}`, 3];
    }

    case 0x1c: {
      const typeIdx = view.getUint16(bytePos + 2, true);
      const tName = types[typeIdx] ? formatJavaTypeName(types[typeIdx]) : `type@${typeIdx}`;
      return [`const-class v${argA}, ${tName}`, 2];
    }

    case 0x1f: {
      const typeIdx = view.getUint16(bytePos + 2, true);
      const tName = types[typeIdx] ? formatJavaTypeName(types[typeIdx]) : `type@${typeIdx}`;
      return [`check-cast v${argA}, ${tName}`, 2];
    }

    case 0x22: {
      const typeIdx = view.getUint16(bytePos + 2, true);
      const tName = types[typeIdx] ? formatJavaTypeName(types[typeIdx]) : `type@${typeIdx}`;
      return [`new-instance v${argA}, ${tName}`, 2];
    }

    case 0x28: {
      const offset = (argA << 24) >> 24;
      return [`goto ${offset >= 0 ? '+' : ''}${offset}`, 1];
    }

    case 0x29: {
      const offset16 = view.getInt16(bytePos + 2, true);
      return [`goto/16 ${offset16 >= 0 ? '+' : ''}${offset16}`, 2];
    }

    case 0x2a: {
      const offset32 = view.getInt32(bytePos + 2, true);
      return [`goto/32 ${offset32 >= 0 ? '+' : ''}${offset32}`, 3];
    }

    case 0x38: {
      const offset16 = view.getInt16(bytePos + 2, true);
      return [`if-eqz v${argA}, ${offset16 >= 0 ? '+' : ''}${offset16}`, 2];
    }

    case 0x39: {
      const offset16 = view.getInt16(bytePos + 2, true);
      return [`if-nez v${argA}, ${offset16 >= 0 ? '+' : ''}${offset16}`, 2];
    }

    case 0x6e:
    case 0x6f:
    case 0x70:
    case 0x71:
    case 0x72: {
      const methodIdx = view.getUint16(bytePos + 2, true);
      const argCount = (argA >> 4) & 0x0f;
      return [`${meta.mnemonic} {args: ${argCount}}, method@0x${methodIdx.toString(16)}`, 3];
    }

    case 0xfa: {
      const methodIdx = view.getUint16(bytePos + 2, true);
      const protoIdx = view.getUint16(bytePos + 6, true);
      return [`invoke-polymorphic method@0x${methodIdx.toString(16)}, proto@0x${protoIdx.toString(16)}`, 4];
    }

    case 0xfb: {
      const methodIdx = view.getUint16(bytePos + 2, true);
      const protoIdx = view.getUint16(bytePos + 6, true);
      return [`invoke-polymorphic/range method@0x${methodIdx.toString(16)}, proto@0x${protoIdx.toString(16)}`, 4];
    }

    case 0xfc: {
      const callSiteIdx = view.getUint16(bytePos + 2, true);
      return [`invoke-custom call_site@0x${callSiteIdx.toString(16)}`, 3];
    }

    case 0xfd: {
      const callSiteIdx = view.getUint16(bytePos + 2, true);
      return [`invoke-custom/range call_site@0x${callSiteIdx.toString(16)}`, 3];
    }

    case 0xfe: {
      const methodHandleIdx = view.getUint16(bytePos + 2, true);
      return [`const-method-handle v${argA}, handle@0x${methodHandleIdx.toString(16)}`, 2];
    }

    case 0xff: {
      const protoIdx = view.getUint16(bytePos + 2, true);
      return [`const-method-type v${argA}, proto@0x${protoIdx.toString(16)}`, 2];
    }

    default:
      return [`${meta.mnemonic} (format ${meta.format}, size ${len} units)`, len];
  }
}

/**
 * Reads DEX Modified UTF-8 String (MUTF-8) with boundary protection and chunked decoding.
 */
export function readMutf8String(buffer: Uint8Array, offset: number, maxBoundary: number = buffer.byteLength): string {
  const [declaredUtf16Size, dataStart] = readUleb128(buffer, offset, maxBoundary);
  let cur = dataStart;
  const chars: number[] = [];

  while (cur < maxBoundary) {
    const a = buffer[cur++];
    if (a === 0) break;

    if ((a & 0x80) === 0x00) {
      // 1-byte ASCII
      chars.push(a);
    } else if ((a & 0xe0) === 0xc0) {
      // 2-byte sequence
      if (cur >= maxBoundary) throw new DexParseError('Truncated 2-byte MUTF-8 sequence.');
      const b = buffer[cur++];
      if ((b & 0xc0) !== 0x80) throw new DexParseError('Invalid second byte in 2-byte MUTF-8 character.');
      chars.push(((a & 0x1f) << 6) | (b & 0x3f));
    } else if ((a & 0xf0) === 0xe0) {
      // 3-byte sequence
      if (cur + 1 >= maxBoundary) throw new DexParseError('Truncated 3-byte MUTF-8 sequence.');
      const b = buffer[cur++];
      const c = buffer[cur++];
      if ((b & 0xc0) !== 0x80 || (c & 0xc0) !== 0x80) {
        throw new DexParseError('Invalid continuation bytes in 3-byte MUTF-8 character.');
      }
      chars.push(((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f));
    } else {
      throw new DexParseError(`Invalid MUTF-8 leading byte 0x${a.toString(16)} at offset 0x${(cur - 1).toString(16)}.`);
    }
  }

  // Chunked string construction to prevent call stack overflow for large strings
  const CHUNK_SIZE = 1024;
  let result = '';
  for (let i = 0; i < chars.length; i += CHUNK_SIZE) {
    result += String.fromCharCode(...chars.slice(i, i + CHUNK_SIZE));
  }

  // Verify decoded UTF-16 code units length matches declared utf16 size
  if (declaredUtf16Size > 0 && chars.length !== declaredUtf16Size) {
    // Note: surrogate pairs count as 2 UTF-16 units
    const utf16Length = chars.reduce((acc, code) => acc + (code > 0xffff ? 2 : 1), 0);
    if (utf16Length !== declaredUtf16Size && chars.length !== declaredUtf16Size) {
      throw new DexParseError(`MUTF-8 length mismatch: declared ${declaredUtf16Size} code units, decoded ${chars.length}.`);
    }
  }

  return result;
}

/**
 * Reads unsigned LEB128 integer with 5-byte overflow and buffer boundary protection.
 */
export function readUleb128(buffer: Uint8Array, offset: number, maxBoundary: number = buffer.byteLength): [number, number] {
  let result = 0;
  let shift = 0;
  let cur = offset;
  let bytesRead = 0;

  while (cur < maxBoundary) {
    const byte = buffer[cur++];
    bytesRead++;
    if (bytesRead > 5) {
      throw new DexParseError(`ULEB128 integer exceeds maximum 5-byte limit at offset 0x${offset.toString(16)}.`);
    }

    if (bytesRead === 5 && (byte & 0xf0) !== 0) {
      throw new DexParseError(`ULEB128 integer overflow (> 32-bit uint) at offset 0x${offset.toString(16)}.`);
    }

    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return [result >>> 0, cur];
    }
    shift += 7;
  }

  throw new DexParseError(`Unexpected EOF while reading ULEB128 at offset 0x${offset.toString(16)}.`);
}

/**
 * Reads signed LEB128 integer with sign extension and bounds checking.
 */
export function readSleb128(buffer: Uint8Array, offset: number, maxBoundary: number = buffer.byteLength): [number, number] {
  let result = 0;
  let shift = 0;
  let cur = offset;
  let bytesRead = 0;
  let byte = 0;

  while (cur < maxBoundary) {
    byte = buffer[cur++];
    bytesRead++;
    if (bytesRead > 5) {
      throw new DexParseError(`SLEB128 integer exceeds maximum 5-byte limit at offset 0x${offset.toString(16)}.`);
    }

    result |= (byte & 0x7f) << shift;
    shift += 7;

    if ((byte & 0x80) === 0) {
      if (shift < 32 && (byte & 0x40) !== 0) {
        result |= -(1 << shift);
      }
      return [result | 0, cur];
    }
  }

  throw new DexParseError(`Unexpected EOF while reading SLEB128 at offset 0x${offset.toString(16)}.`);
}

/**
 * Adler-32 checksum calculation (RFC 1950)
 */
export function adler32(data: Uint8Array): number {
  const MOD_ADLER = 65521;
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; i++) {
    a = (a + data[i]) % MOD_ADLER;
    b = (b + a) % MOD_ADLER;
  }
  return ((b << 16) | a) >>> 0;
}

export function formatJavaTypeName(rawDescriptor: string): string {
  if (!rawDescriptor) return '';
  if (rawDescriptor.startsWith('L') && rawDescriptor.endsWith(';')) {
    return rawDescriptor.substring(1, rawDescriptor.length - 1).replace(/\//g, '.');
  }
  if (rawDescriptor.startsWith('[')) {
    return formatJavaTypeName(rawDescriptor.substring(1)) + '[]';
  }
  switch (rawDescriptor) {
    case 'V': return 'void';
    case 'Z': return 'boolean';
    case 'B': return 'byte';
    case 'S': return 'short';
    case 'C': return 'char';
    case 'I': return 'int';
    case 'J': return 'long';
    case 'F': return 'float';
    case 'D': return 'double';
    default: return rawDescriptor;
  }
}

function escapeBytes(bytes: number[]): string {
  return bytes.map(b => '\\x' + b.toString(16).padStart(2, '0')).join('');
}
