/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Hardened Native Library (ELF) Inspector
 * Dissects ELF binaries inside APK archives, verifies ELF magic, class, endianness,
 * compares ABI directory paths against actual declared machine code, and enforces resource budgets.
 */

import { NativeLibraryInfo, ZipEntry } from '../core/types';

const ELF_MAGIC = 0x464c457f; // 0x7F 'E' 'L' 'F' in little-endian uint32

// Standard ELF Machine Codes (e_machine)
const EM_386 = 0x03;
const EM_ARM = 0x28;
const EM_X86_64 = 0x3e;
const EM_AARCH64 = 0xb7;
const EM_RISCV = 0xf3;

const MACHINE_NAMES: Record<number, string> = {
  [EM_386]: 'x86 (Intel 80386)',
  [EM_ARM]: 'ARM 32-bit (ARMv7-A)',
  [EM_X86_64]: 'x86-64 (AMD64)',
  [EM_AARCH64]: 'AArch64 (ARMv8-A 64-bit)',
  [EM_RISCV]: 'RISC-V',
};

// Expected machine code for canonical Android ABI directory names
const ABI_EXPECTED_MACHINE: Record<string, number> = {
  'arm64-v8a': EM_AARCH64,
  'armeabi-v7a': EM_ARM,
  'armeabi': EM_ARM,
  'x86_64': EM_X86_64,
  'x86': EM_386,
  'riscv64': EM_RISCV,
};

export interface NativeInspectionSummary {
  libraries: NativeLibraryInfo[];
  totalLibrariesFound: number;
  totalLibrariesInspected: number;
  totalLibrariesSkipped: number;
  hasAbiMismatches: boolean;
  resourceBudgetExceeded: boolean;
}

// Resource budget for native inspection (Phase 1)
export const MAX_INSPECTABLE_NATIVE_FILES = 100;
export const MAX_INSPECTABLE_NATIVE_BYTES = 50 * 1024 * 1024; // 50 MB

export function inspectNativeLibraries(
  entries: ZipEntry[],
  extractedDataMap: Map<string, Uint8Array>
): NativeLibraryInfo[] {
  const summary = inspectNativeLibrariesDetailed(entries, extractedDataMap);
  return summary.libraries;
}

export function inspectNativeLibrariesDetailed(
  entries: ZipEntry[],
  extractedDataMap: Map<string, Uint8Array>
): NativeInspectionSummary {
  const nativeEntries = entries.filter(
    e => e.filename.startsWith('lib/') && e.filename.endsWith('.so')
  );

  let totalInspected = 0;
  let totalSkipped = 0;
  let totalBytesProcessed = 0;
  let hasAbiMismatches = false;
  const libraries: NativeLibraryInfo[] = [];

  for (const entry of nativeEntries) {
    if (totalInspected >= MAX_INSPECTABLE_NATIVE_FILES || totalBytesProcessed >= MAX_INSPECTABLE_NATIVE_BYTES) {
      totalSkipped++;
      continue;
    }

    const parts = entry.filename.split('/');
    const abiFolder = parts.length > 2 ? parts[1] : 'unknown';
    const fileName = parts[parts.length - 1];

    const data = extractedDataMap.get(entry.filename);
    let isElf = false;
    let bitness: '32-bit' | '64-bit' | 'unknown' = 'unknown';
    let endianness: 'little' | 'big' | 'unknown' = 'unknown';
    let machine = 'Unknown';
    let machineCode = 0;

    if (data && data.byteLength >= 16) {
      totalInspected++;
      totalBytesProcessed += data.byteLength;

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

        const elfVersion = data[6];
        if (elfVersion === 1 && data.byteLength >= 20) {
          const isLittle = endianness === 'little';
          machineCode = view.getUint16(18, isLittle);
          machine = MACHINE_NAMES[machineCode] || `Machine(0x${machineCode.toString(16)})`;

          // Verify whether ABI folder matches the actual ELF machine header
          const expected = ABI_EXPECTED_MACHINE[abiFolder];
          if (expected !== undefined && expected !== machineCode) {
            hasAbiMismatches = true;
            machine += ` [MISMATCH: folder declares ${abiFolder}]`;
          }
        }
      }
    } else {
      // Header data was not extracted
      totalSkipped++;
      machine = `Unextracted (${abiFolder})`;
    }

    libraries.push({
      filename: fileName,
      path: entry.filename,
      size: entry.uncompressedSize,
      abi: abiFolder,
      isElf,
      bitness,
      endianness,
      machine,
    });
  }

  return {
    libraries,
    totalLibrariesFound: nativeEntries.length,
    totalLibrariesInspected: totalInspected,
    totalLibrariesSkipped: totalSkipped,
    hasAbiMismatches,
    resourceBudgetExceeded: totalSkipped > 0,
  };
}
