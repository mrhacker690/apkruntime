/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Dalvik Executable (DEX) Parser & Bytecode Disassembler
 * Validates DEX headers, resolves string/type/proto/field/method pools, decodes class definitions and bytecode.
 */

import { DexFileAnalysis, DexHeader, DexClass, DexMethod } from '../core/types';

export class DexParseError extends Error {
  constructor(message: string) {
    super(`DEX Parse Error: ${message}`);
    this.name = 'DexParseError';
  }
}

export function parseDexFile(buffer: Uint8Array, fileName: string = 'classes.dex'): DexFileAnalysis {
  if (buffer.byteLength < 0x70) {
    throw new DexParseError(`File size (${buffer.byteLength} bytes) is smaller than minimum DEX header (112 bytes).`);
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
    throw new DexParseError(`Malformed DEX version string: expected null terminator at index 7.`);
  }

  // 2. Checksum (Adler-32)
  const checksum = view.getUint32(8, true);
  const calculatedChecksum = adler32(buffer.subarray(12));

  // 3. Signature (20-byte SHA-1)
  const sigBytes = Array.from(buffer.subarray(12, 32));
  const signature = sigBytes.map(b => b.toString(16).padStart(2, '0')).join('');

  // 4. Header fields
  const fileSize = view.getUint32(32, true);
  const headerSize = view.getUint32(36, true);
  const endianTag = view.getUint32(40, true);

  if (endianTag !== 0x12345678) {
    throw new DexParseError(`Unsupported endianness: 0x${endianTag.toString(16)} (expected 0x12345678 little-endian).`);
  }

  const header: DexHeader = {
    magic: 'dex\n',
    version,
    checksum,
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

  // 5. Parse String Table
  const strings: string[] = [];
  for (let i = 0; i < header.stringIdsSize; i++) {
    const stringDataOff = view.getUint32(header.stringIdsOff + i * 4, true);
    if (stringDataOff < buffer.byteLength) {
      strings.push(readStringDataItem(buffer, stringDataOff));
    } else {
      strings.push(`<out-of-bounds offset: 0x${stringDataOff.toString(16)}>`);
    }
  }

  // 6. Parse Type IDs
  const types: string[] = [];
  for (let i = 0; i < header.typeIdsSize; i++) {
    const descriptorIdx = view.getUint32(header.typeIdsOff + i * 4, true);
    types.push(strings[descriptorIdx] ?? `Type#${descriptorIdx}`);
  }

  // 7. Parse Method IDs
  interface RawMethodId {
    classIdx: number;
    protoIdx: number;
    nameIdx: number;
  }
  const methodIds: RawMethodId[] = [];
  for (let i = 0; i < header.methodIdsSize; i++) {
    const off = header.methodIdsOff + i * 8;
    if (off + 8 <= buffer.byteLength) {
      methodIds.push({
        classIdx: view.getUint16(off, true),
        protoIdx: view.getUint16(off + 2, true),
        nameIdx: view.getUint32(off + 4, true),
      });
    }
  }

  // 8. Parse Class Definitions
  const classes: DexClass[] = [];
  for (let i = 0; i < header.classDefsSize; i++) {
    const classDefOff = header.classDefsOff + i * 32;
    if (classDefOff + 32 > buffer.byteLength) break;

    const classIdx = view.getUint32(classDefOff, true);
    const accessFlags = view.getUint32(classDefOff + 4, true);
    const superclassIdx = view.getUint32(classDefOff + 8, true);
    const sourceFileIdx = view.getUint32(classDefOff + 16, true);
    const classDataOff = view.getUint32(classDefOff + 24, true);

    const className = formatJavaTypeName(types[classIdx] || `Class#${classIdx}`);
    const superclassName = superclassIdx === 0xffffffff ? '' : formatJavaTypeName(types[superclassIdx] || '');
    const sourceFile = sourceFileIdx === 0xffffffff ? undefined : strings[sourceFileIdx];

    const directMethods: DexMethod[] = [];
    const virtualMethods: DexMethod[] = [];
    let staticFieldsCount = 0;
    let instanceFieldsCount = 0;

    if (classDataOff > 0 && classDataOff < buffer.byteLength) {
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

  if (codeOff > 0 && codeOff + 16 <= buffer.byteLength) {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    registersSize = view.getUint16(codeOff, true);
    insSize = view.getUint16(codeOff + 2, true);
    outsSize = view.getUint16(codeOff + 4, true);
    const triesSize = view.getUint16(codeOff + 6, true);
    const debugInfoOff = view.getUint32(codeOff + 8, true);
    insnsSize = view.getUint32(codeOff + 12, true);

    const insnsStart = codeOff + 16;
    let insnOffset = 0;

    // Disassemble instructions
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
      insnOffset += Math.max(1, consumedUnits);
      if (instructions.length >= 30) {
        instructions.push(`... (+${insnsSize - insnOffset} more instructions)`);
        break;
      }
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
      const lit = (argA >> 4) & 0x0f;
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
    case 0x1a: {
      const stringIdx = view.getUint16(bytePos + 2, true);
      const strVal = strings[stringIdx] ? JSON.stringify(strings[stringIdx]) : `string@${stringIdx}`;
      return [`const-string v${argA}, ${strVal}`, 2];
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
    case 0x38: {
      const offset16 = view.getInt16(bytePos + 2, true);
      return [`if-eqz v${argA}, ${offset16 >= 0 ? '+' : ''}${offset16}`, 2];
    }
    case 0x39: {
      const offset16 = view.getInt16(bytePos + 2, true);
      return [`if-nez v${argA}, ${offset16 >= 0 ? '+' : ''}${offset16}`, 2];
    }
    case 0x6e:
    case 0x70:
    case 0x71: {
      const opName = opcode === 0x6e ? 'invoke-virtual' : opcode === 0x70 ? 'invoke-direct' : 'invoke-static';
      const methodIdx = view.getUint16(bytePos + 2, true);
      const count = (argA >> 4) & 0x0f;
      return [`${opName} {v...}, method@0x${methodIdx.toString(16)} (args: ${count})`, 3];
    }
    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93: {
      const name = opcode === 0x90 ? 'add-int' : opcode === 0x91 ? 'sub-int' : opcode === 0x92 ? 'mul-int' : 'div-int';
      const secondWord = view.getUint16(bytePos + 2, true);
      const vB = secondWord & 0xff;
      const vC = (secondWord >> 8) & 0xff;
      return [`${name} v${argA}, v${vB}, v${vC}`, 2];
    }
    default:
      return [`op_0x${opcode.toString(16).padStart(2, '0')} (0x${argA.toString(16)})`, 1];
  }
}

function readStringDataItem(buffer: Uint8Array, offset: number): string {
  const [size, nextOff] = readUleb128(buffer, offset);
  let cur = nextOff;
  const chars: number[] = [];

  for (let i = 0; i < size; i++) {
    if (cur >= buffer.byteLength) break;
    const a = buffer[cur++];
    if (a === 0) break;
    if (a < 0x80) {
      chars.push(a);
    } else if ((a & 0xe0) === 0xc0) {
      const b = buffer[cur++];
      chars.push(((a & 0x1f) << 6) | (b & 0x3f));
    } else if ((a & 0xf0) === 0xe0) {
      const b = buffer[cur++];
      const c = buffer[cur++];
      chars.push(((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f));
    }
  }

  return String.fromCharCode(...chars);
}

function readUleb128(buffer: Uint8Array, offset: number): [number, number] {
  let result = 0;
  let shift = 0;
  let cur = offset;

  while (cur < buffer.byteLength) {
    const byte = buffer[cur++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7;
  }

  return [result >>> 0, cur];
}

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

function formatJavaTypeName(rawDescriptor: string): string {
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
