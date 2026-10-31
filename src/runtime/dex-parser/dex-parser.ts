/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Hardened Dalvik Executable (DEX) Parser & Disassembler
 * Strictly validates DEX headers, Adler-32 checksums, section bounds, MUTF-8 strings,
 * ULEB128/SLEB128 integer decoders, class definitions, and Dalvik instruction formats.
 */

import { DexFileAnalysis, DexHeader, DexClass, DexMethod } from '../core/types';

export class DexParseError extends Error {
  constructor(message: string) {
    super(`DEX Parse Error: ${message}`);
    this.name = 'DexParseError';
  }
}

const SUPPORTED_DEX_VERSIONS = new Set(['035', '037', '038', '039']);
const ENDIAN_CONSTANT = 0x12345678;
const NO_INDEX = 0xffffffff;

/**
 * Standard Dalvik Opcode Instruction Size Table (in 16-bit code units)
 * Indexed by opcode (0x00 to 0xff). 0 indicates special payload or invalid/reserved.
 */
const OPCODE_LENGTH_TABLE: number[] = new Array(256).fill(1);

// Configure well-known standard multi-word instruction sizes (Dalvik Bytecode Format Spec)
// Format 10x, 12x, 11n, 11x: 1 unit (default)
// Format 20t, 21t, 21s, 21h, 21c, 23x, 22b, 22t, 22s, 22c, 22x: 2 units
const OPCODES_2_UNITS = [
  0x02, 0x03, 0x05, 0x06, 0x08, 0x09, // move/from16, move-wide/from16, move-object/from16
  0x13, 0x15, 0x16, 0x19, 0x1a, 0x1b, 0x1c, 0x1f, 0x20, 0x21, // const/16, const-high16, const-string, check-cast, new-instance
  0x22, 0x23, // new-instance, new-array
  0x29, 0x2d, 0x2e, 0x2f, 0x30, 0x31, // goto/16, cmpl-float, cmpg-float, cmpl-double, cmpg-double, cmp-long
  0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // if-test
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, // if-testz
  0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, // aget, aput
  0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, // iget, iput
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, // sget, sput
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, // add-int, etc.
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];
for (const op of OPCODES_2_UNITS) OPCODE_LENGTH_TABLE[op] = 2;

// Format 30t, 32x, 31i, 31t, 31c, 35c, 3rc: 3 units
const OPCODES_3_UNITS = [
  0x04, 0x07, 0x0a, 0x14, 0x17, 0x18, 0x1b, // move/16, const, const-wide/32, const-string/jumbo
  0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c, // filled-new-array, filled-new-array/range, fill-array-data, goto/32, packed-switch, sparse-switch
  0x6e, 0x6f, 0x70, 0x71, 0x72, // invoke-virtual, invoke-super, invoke-direct, invoke-static, invoke-interface
  0x74, 0x75, 0x76, 0x77, 0x78, // invoke-virtual/range, etc.
  0xfc, 0xfd, 0xfe, // invoke-polymorphic, invoke-custom
];
for (const op of OPCODES_3_UNITS) OPCODE_LENGTH_TABLE[op] = 3;

// Format 51l: 5 units (const-wide)
OPCODE_LENGTH_TABLE[0x18] = 5;

/**
 * Parses Dalvik Executable (DEX) file completely with strict header, Adler-32, section,
 * and instruction stream validation.
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

  // 2. Adler-32 Checksum Verification
  const storedChecksum = view.getUint32(8, true);
  const calculatedChecksum = adler32(buffer.subarray(12));
  if (storedChecksum !== calculatedChecksum) {
    throw new DexParseError(
      `DEX Adler-32 checksum mismatch: header declares 0x${storedChecksum.toString(16).padStart(8, '0')}, but calculated 0x${calculatedChecksum.toString(16).padStart(8, '0')}.`
    );
  }

  // 3. Signature (20-byte SHA-1)
  const sigBytes = Array.from(buffer.subarray(12, 32));
  const signature = sigBytes.map(b => b.toString(16).padStart(2, '0')).join('');

  // 4. Header Fields & Endianness
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

  const header: DexHeader = {
    magic: 'dex\n',
    version,
    checksum: storedChecksum,
    signature,
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

  // 5. Section Boundary Validation
  validateSection('string_ids', header.stringIdsOff, header.stringIdsSize, 4, buffer.byteLength);
  validateSection('type_ids', header.typeIdsOff, header.typeIdsSize, 4, buffer.byteLength);
  validateSection('proto_ids', header.protoIdsOff, header.protoIdsSize, 12, buffer.byteLength);
  validateSection('field_ids', header.fieldIdsOff, header.fieldIdsSize, 8, buffer.byteLength);
  validateSection('method_ids', header.methodIdsOff, header.methodIdsSize, 8, buffer.byteLength);
  validateSection('class_defs', header.classDefsOff, header.classDefsSize, 32, buffer.byteLength);

  // 6. Parse String Table
  const strings: string[] = [];
  for (let i = 0; i < header.stringIdsSize; i++) {
    const stringDataOff = view.getUint32(header.stringIdsOff + i * 4, true);
    if (stringDataOff >= buffer.byteLength) {
      throw new DexParseError(`String ID #${i} points to invalid data offset 0x${stringDataOff.toString(16)} outside buffer.`);
    }
    strings.push(readMutf8String(buffer, stringDataOff));
  }

  // 7. Parse Type IDs
  const types: string[] = [];
  for (let i = 0; i < header.typeIdsSize; i++) {
    const descriptorIdx = view.getUint32(header.typeIdsOff + i * 4, true);
    if (descriptorIdx >= strings.length) {
      throw new DexParseError(`Type ID #${i} references invalid string index ${descriptorIdx} (table size ${strings.length}).`);
    }
    types.push(strings[descriptorIdx] ?? '');
  }

  // 8. Parse Method IDs
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
    if (nameIdx >= strings.length) {
      throw new DexParseError(`Method ID #${i} references out-of-bounds name index ${nameIdx}.`);
    }

    methodIds.push({ classIdx, protoIdx, nameIdx });
  }

  // 9. Parse Class Definitions
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

    const className = formatJavaTypeName(types[classIdx]);
    const superclassName = superclassIdx === NO_INDEX ? '' : formatJavaTypeName(types[superclassIdx] || '');
    const sourceFile = sourceFileIdx === NO_INDEX ? undefined : strings[sourceFileIdx];

    const directMethods: DexMethod[] = [];
    const virtualMethods: DexMethod[] = [];
    let staticFieldsCount = 0;
    let instanceFieldsCount = 0;

    if (classDataOff > 0) {
      if (classDataOff >= buffer.byteLength) {
        throw new DexParseError(`Class data offset 0x${classDataOff.toString(16)} for ${className} is outside buffer.`);
      }

      let cursor = classDataOff;
      const [numStaticFields, next1] = readUleb128(buffer, cursor);
      cursor = next1;
      const [numInstanceFields, next2] = readUleb128(buffer, cursor);
      cursor = next2;
      const [numDirectMethods, next3] = readUleb128(buffer, cursor);
      cursor = next3;
      const [numVirtualMethods, next4] = readUleb128(buffer, cursor);
      cursor = next4;

      staticFieldsCount = numStaticFields;
      instanceFieldsCount = numInstanceFields;

      // Skip fields
      for (let f = 0; f < numStaticFields; f++) {
        const [, nA] = readUleb128(buffer, cursor);
        const [, nB] = readUleb128(buffer, nA);
        cursor = nB;
      }
      for (let f = 0; f < numInstanceFields; f++) {
        const [, nA] = readUleb128(buffer, cursor);
        const [, nB] = readUleb128(buffer, nA);
        cursor = nB;
      }

      // Read direct methods
      let lastMethodIndex = 0;
      for (let m = 0; m < numDirectMethods; m++) {
        const [methodIdxDiff, nA] = readUleb128(buffer, cursor);
        const [methodFlags, nB] = readUleb128(buffer, nA);
        const [codeOff, nC] = readUleb128(buffer, nB);
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
          types
        );
        directMethods.push(methodObj);
      }

      // Read virtual methods
      lastMethodIndex = 0;
      for (let m = 0; m < numVirtualMethods; m++) {
        const [methodIdxDiff, nA] = readUleb128(buffer, cursor);
        const [methodFlags, nB] = readUleb128(buffer, nA);
        const [codeOff, nC] = readUleb128(buffer, nB);
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
          types
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
    size: buffer.byteLength,
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
  bufferSize: number
): void {
  if (count === 0) return;
  if (offset % 4 !== 0) {
    throw new DexParseError(`DEX section "${name}" offset 0x${offset.toString(16)} violates 4-byte alignment requirement.`);
  }
  const totalBytes = count * itemSize;
  if (offset + totalBytes > bufferSize) {
    throw new DexParseError(`DEX section "${name}" (offset 0x${offset.toString(16)}, size ${totalBytes}) exceeds file size (${bufferSize}).`);
  }
}

function decodeDexMethod(
  buffer: Uint8Array,
  methodIndex: number,
  accessFlags: number,
  codeOff: number,
  methodIds: { classIdx: number; protoIdx: number; nameIdx: number }[],
  strings: string[],
  types: string[]
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
    if (codeOff + 16 > buffer.byteLength) {
      throw new DexParseError(`Code item offset 0x${codeOff.toString(16)} for ${className}.${name} exceeds buffer.`);
    }

    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    registersSize = view.getUint16(codeOff, true);
    insSize = view.getUint16(codeOff + 2, true);
    outsSize = view.getUint16(codeOff + 4, true);
    const triesSize = view.getUint16(codeOff + 6, true);
    const debugInfoOff = view.getUint32(codeOff + 8, true);
    insnsSize = view.getUint32(codeOff + 12, true);

    const insnsStart = codeOff + 16;
    const insnsEnd = insnsStart + insnsSize * 2;

    if (insnsEnd > buffer.byteLength) {
      throw new DexParseError(`Declared instructions for ${className}.${name} (size ${insnsSize} words) extend beyond buffer.`);
    }

    let insnOffset = 0;
    while (insnOffset < insnsSize && (insnsStart + insnOffset * 2 + 2) <= buffer.byteLength) {
      const codeUnit = view.getUint16(insnsStart + insnOffset * 2, true);
      const opcode = codeUnit & 0xff;
      const argA = (codeUnit >> 8) & 0xff;

      const [disasm, consumedUnits] = disassembleOpcode(
        opcode,
        argA,
        view,
        insnsStart + insnOffset * 2,
        strings,
        types
      );

      const hexAddr = (insnOffset * 2).toString(16).padStart(4, '0');
      instructions.push(`0x${hexAddr}: ${disasm}`);

      // Advances strictly by the verified instruction size, never guessing
      insnOffset += Math.max(1, consumedUnits);
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
  types: string[]
): [string, number] {
  const standardLen = OPCODE_LENGTH_TABLE[opcode] || 1;

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
      if (lit & 0x08) lit |= ~0x0f; // Sign extend 4-bit
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
      return [`const-wide v${argA}, #0x${high.toString(16)}${low.toString(16)}`, 5];
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
      const opNames: Record<number, string> = {
        0x6e: 'invoke-virtual',
        0x6f: 'invoke-super',
        0x70: 'invoke-direct',
        0x71: 'invoke-static',
        0x72: 'invoke-interface',
      };
      const opName = opNames[opcode] || 'invoke';
      const methodIdx = view.getUint16(bytePos + 2, true);
      const argCount = (argA >> 4) & 0x0f;
      return [`${opName} {args: ${argCount}}, method@0x${methodIdx.toString(16)}`, 3];
    }

    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93: {
      const names: Record<number, string> = {
        0x90: 'add-int',
        0x91: 'sub-int',
        0x92: 'mul-int',
        0x93: 'div-int',
      };
      const name = names[opcode] || 'arith-int';
      const secondWord = view.getUint16(bytePos + 2, true);
      const vB = secondWord & 0xff;
      const vC = (secondWord >> 8) & 0xff;
      return [`${name} v${argA}, v${vB}, v${vC}`, 2];
    }

    default:
      return [`op_0x${opcode.toString(16).padStart(2, '0')} (format size ${standardLen})`, standardLen];
  }
}

/**
 * Reads DEX Modified UTF-8 String (MUTF-8).
 * Correctly decodes 1-byte, 2-byte, 3-byte characters, embedded nulls (0xC0 0x80), and surrogate pairs.
 */
export function readMutf8String(buffer: Uint8Array, offset: number): string {
  const [declaredUtf16Size, dataStart] = readUleb128(buffer, offset);
  let cur = dataStart;
  const chars: number[] = [];

  while (cur < buffer.byteLength) {
    const a = buffer[cur++];
    if (a === 0) break; // Null-terminated

    if ((a & 0x80) === 0x00) {
      // 1-byte standard ASCII (0x01 .. 0x7f)
      chars.push(a);
    } else if ((a & 0xe0) === 0xc0) {
      // 2-byte sequence (includes 0xc0 0x80 representing embedded null \u0000)
      if (cur >= buffer.byteLength) throw new DexParseError('Truncated 2-byte MUTF-8 sequence.');
      const b = buffer[cur++];
      if ((b & 0xc0) !== 0x80) throw new DexParseError('Invalid second byte in 2-byte MUTF-8 character.');
      chars.push(((a & 0x1f) << 6) | (b & 0x3f));
    } else if ((a & 0xf0) === 0xe0) {
      // 3-byte sequence
      if (cur + 1 >= buffer.byteLength) throw new DexParseError('Truncated 3-byte MUTF-8 sequence.');
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

  return String.fromCharCode(...chars);
}

/**
 * Reads unsigned LEB128 integer with 5-byte overflow and buffer boundary protection.
 */
export function readUleb128(buffer: Uint8Array, offset: number): [number, number] {
  let result = 0;
  let shift = 0;
  let cur = offset;
  let bytesRead = 0;

  while (cur < buffer.byteLength) {
    const byte = buffer[cur++];
    bytesRead++;
    if (bytesRead > 5) {
      throw new DexParseError(`ULEB128 integer exceeds maximum 5-byte limit at offset 0x${offset.toString(16)}.`);
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
export function readSleb128(buffer: Uint8Array, offset: number): [number, number] {
  let result = 0;
  let shift = 0;
  let cur = offset;
  let bytesRead = 0;
  let byte = 0;

  while (cur < buffer.byteLength) {
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
