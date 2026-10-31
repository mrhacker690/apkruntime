/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Native Library (ELF) Inspector
 * Inspects native .so binaries inside APK archives, detects ABIs, ELF class, endianness, and target CPU.
 */

import { NativeLibraryInfo, ZipEntry } from '../core/types';

const ELF_MAGIC = 0x464c457f; // 0x7F 'E' 'L' 'F' in little-endian

const MACHINE_MAP: Record<number, string> = {
  0x03: 'x86 (Intel 80386)',
  0x28: 'ARM 32-bit (ARMv7-A)',
  0x3e: 'x86-64 (AMD64)',
  0xb7: 'AArch64 (ARMv8-A 64-bit)',
  0xf3: 'RISC-V',
};

export function inspectNativeLibraries(
  entries: ZipEntry[],
  extractedDataMap: Map<string, Uint8Array>
): NativeLibraryInfo[] {
  const nativeEntries = entries.filter(
    e => e.filename.startsWith('lib/') && e.filename.endsWith('.so')
  );

  return nativeEntries.map(entry => {
    // Determine ABI from folder path: lib/<abi>/libsomething.so
    const parts = entry.filename.split('/');
    const abiFolder = parts.length > 2 ? parts[1] : 'unknown';
    const fileName = parts[parts.length - 1];

    const data = extractedDataMap.get(entry.filename);
    let isElf = false;
    let bitness: '32-bit' | '64-bit' | 'unknown' = 'unknown';
    let endianness: 'little' | 'big' | 'unknown' = 'unknown';
    let machine = 'Unknown';

    if (data && data.byteLength >= 16) {
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const magic = view.getUint32(0, true);
      if (magic === ELF_MAGIC) {
        isElf = true;
        const elfClass = data[4];
        if (elfClass === 1) bitness = '32-bit';
        else if (elfClass === 2) bitness = '64-bit';

        const elfData = data[5];
        if (elfData === 1) endianness = 'little';
        else if (elfData === 2) endianness = 'big';

        if (data.byteLength >= 20) {
          const isLittle = endianness === 'little';
          const machineCode = view.getUint16(18, isLittle);
          machine = MACHINE_MAP[machineCode] || `Machine(0x${machineCode.toString(16)})`;
        }
      }
    } else {
      // Fast path heuristic based on folder name if data wasn't pre-decompressed
      if (abiFolder === 'arm64-v8a') {
        bitness = '64-bit';
        machine = 'AArch64 (ARMv8-A 64-bit)';
        isElf = true;
      } else if (abiFolder === 'armeabi-v7a') {
        bitness = '32-bit';
        machine = 'ARM 32-bit (ARMv7-A)';
        isElf = true;
      } else if (abiFolder === 'x86_64') {
        bitness = '64-bit';
        machine = 'x86-64';
        isElf = true;
      } else if (abiFolder === 'x86') {
        bitness = '32-bit';
        machine = 'x86';
        isElf = true;
      }
    }

    return {
      filename: fileName,
      path: entry.filename,
      size: entry.uncompressedSize,
      abi: abiFolder,
      isElf,
      bitness,
      endianness,
      machine,
    };
  });
}
