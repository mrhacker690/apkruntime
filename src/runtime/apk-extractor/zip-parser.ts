/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Browser-Native Hardened ZIP Archive Parser
 * Supports Stored (0) and Deflate (8) with robust validation, CRC-32 verification,
 * and comprehensive Zip-Bomb, ZIP64, Encryption, and Path-Traversal Defenses.
 */

import { inflateSync } from 'fflate';
import { ZipEntry, ApkArchive } from '../core/types';
import { calculateSha256 } from './sha256';

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_DIR_SIGNATURE = 0x02014b50;
const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const ZIP64_EOCD_SIGNATURE = 0x06064b50;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;

// Security Limits
export const MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024; // 500 MB max archive total
export const MAX_ENTRY_UNCOMPRESSED_BYTES = 150 * 1024 * 1024; // 150 MB max per single entry
export const MAX_ENTRIES_COUNT = 5000;
export const MAX_COMPRESSION_RATIO = 100; // Uncompressed to compressed anomaly ratio threshold

export class ZipSecurityError extends Error {
  constructor(message: string) {
    super(`ZIP Security Violation: ${message}`);
    this.name = 'ZipSecurityError';
  }
}

export class ZipParseError extends Error {
  constructor(message: string) {
    super(`ZIP Parsing Error: ${message}`);
    this.name = 'ZipParseError';
  }
}

/**
 * IEEE 802.3 CRC-32 calculation table
 */
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32_TABLE[i] = c;
}

/**
 * Computes standard IEEE 802.3 CRC-32 checksum of a byte buffer
 */
export function calculateCrc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ data[i]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Sanitizes archive paths and rejects path traversal, drive letters, and absolute paths
 */
export function sanitizePath(rawPath: string): string {
  if (!rawPath || typeof rawPath !== 'string') {
    throw new ZipSecurityError('Empty or invalid filename in archive entry.');
  }

  // Reject absolute paths
  if (rawPath.startsWith('/') || rawPath.startsWith('\\') || /^[a-zA-Z]:/.test(rawPath)) {
    throw new ZipSecurityError(`Archive contains forbidden absolute path: "${rawPath}"`);
  }

  const normalized = rawPath.replace(/\\/g, '/');
  const segments = normalized.split('/');
  const safeSegments: string[] = [];

  for (const seg of segments) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      throw new ZipSecurityError(`Archive contains forbidden directory traversal segment (..): "${rawPath}"`);
    }
    // Block control characters or null bytes in path names
    if (/[\x00-\x1f\x7f]/.test(seg)) {
      throw new ZipSecurityError(`Archive contains invalid control characters in filename: "${rawPath}"`);
    }
    safeSegments.push(seg);
  }

  if (safeSegments.length === 0) {
    throw new ZipSecurityError(`Archive filename resolved to empty path: "${rawPath}"`);
  }

  return safeSegments.join('/');
}

/**
 * Parses and verifies an APK (ZIP) archive structure completely before returning.
 */
export async function parseApkArchive(
  data: Uint8Array,
  filename: string = 'app.apk'
): Promise<ApkArchive> {
  if (!data || data.byteLength < 22) {
    throw new ZipParseError('Buffer is too small to be a valid ZIP/APK archive (minimum 22 bytes required).');
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const sha256 = await calculateSha256(data);

  // 1. Locate End of Central Directory (EOCD)
  // EOCD record is minimum 22 bytes long and at most 65535 + 22 bytes from the end.
  const minEocdOffset = Math.max(0, data.byteLength - 65557);
  let eocdOffset = -1;

  for (let i = data.byteLength - 22; i >= minEocdOffset; i--) {
    if (view.getUint32(i, true) === EOCD_SIGNATURE) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    throw new ZipParseError('Invalid APK archive: End of Central Directory (EOCD) record not found.');
  }

  // 2. Reject ZIP64 explicitly
  // Check for ZIP64 locator or 0xFFFF / 0xFFFFFFFF placeholder counts
  const totalEntriesDisk = view.getUint16(eocdOffset + 8, true);
  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const centralDirSize = view.getUint32(eocdOffset + 12, true);
  const centralDirOffset = view.getUint32(eocdOffset + 16, true);

  if (
    totalEntries === 0xffff ||
    totalEntriesDisk === 0xffff ||
    centralDirSize === 0xffffffff ||
    centralDirOffset === 0xffffffff
  ) {
    throw new ZipSecurityError('ZIP64 archives are not supported in standard 32-bit Android APK format.');
  }

  // Check if a ZIP64 locator signature precedes the EOCD
  if (eocdOffset >= 20) {
    const possibleZip64Locator = view.getUint32(eocdOffset - 20, true);
    if (possibleZip64Locator === ZIP64_LOCATOR_SIGNATURE) {
      throw new ZipSecurityError('ZIP64 End of Central Directory Locator detected. ZIP64 APKs are not supported.');
    }
  }

  if (totalEntries > MAX_ENTRIES_COUNT) {
    throw new ZipSecurityError(
      `Archive entry count (${totalEntries}) exceeds maximum safe threshold (${MAX_ENTRIES_COUNT}).`
    );
  }

  if (centralDirOffset + centralDirSize > eocdOffset) {
    throw new ZipParseError('Malformed archive: Central directory extends beyond EOCD record.');
  }

  const entries: ZipEntry[] = [];
  const seenPaths = new Set<string>();
  const normalizedLowerPaths = new Set<string>();
  let currOffset = centralDirOffset;
  let totalUncompressedBytes = 0;

  for (let i = 0; i < totalEntries; i++) {
    if (currOffset + 46 > data.byteLength) {
      throw new ZipParseError(`Central directory header truncated at entry index ${i}.`);
    }

    const sig = view.getUint32(currOffset, true);
    if (sig !== CENTRAL_DIR_SIGNATURE) {
      throw new ZipParseError(`Expected Central Directory signature (0x02014b50) at offset 0x${currOffset.toString(16)}, got 0x${sig.toString(16)}.`);
    }

    const flags = view.getUint16(currOffset + 8, true);
    // Bit 0: Encryption
    if ((flags & 0x0001) !== 0) {
      throw new ZipSecurityError('Encrypted ZIP entries are not supported in standard APK packages.');
    }

    const compressionMethod = view.getUint16(currOffset + 10, true);
    if (compressionMethod !== 0 && compressionMethod !== 8) {
      throw new ZipParseError(`Unsupported compression method ${compressionMethod} in entry ${i}. Only Stored (0) and Deflate (8) are supported.`);
    }

    const crc32 = view.getUint32(currOffset + 16, true);
    const compressedSize = view.getUint32(currOffset + 20, true);
    const uncompressedSize = view.getUint32(currOffset + 24, true);
    const filenameLength = view.getUint16(currOffset + 28, true);
    const extraFieldLength = view.getUint16(currOffset + 30, true);
    const fileCommentLength = view.getUint16(currOffset + 32, true);
    const localHeaderOffset = view.getUint32(currOffset + 42, true);

    const nameOffset = currOffset + 46;
    if (nameOffset + filenameLength > data.byteLength) {
      throw new ZipParseError(`Filename field out of bounds in central directory entry ${i}.`);
    }

    const rawFilename = new TextDecoder('utf-8').decode(
      data.subarray(nameOffset, nameOffset + filenameLength)
    );

    const safeFilename = sanitizePath(rawFilename);

    // Duplicate path & normalized collision check
    if (seenPaths.has(safeFilename)) {
      throw new ZipSecurityError(`Duplicate entry detected in archive: "${safeFilename}"`);
    }
    seenPaths.add(safeFilename);

    const lower = safeFilename.toLowerCase();
    if (normalizedLowerPaths.has(lower)) {
      throw new ZipSecurityError(`Normalized filename collision detected in archive: "${safeFilename}"`);
    }
    normalizedLowerPaths.add(lower);

    // Zip bomb detection (Per-entry and total limits)
    if (uncompressedSize > MAX_ENTRY_UNCOMPRESSED_BYTES) {
      throw new ZipSecurityError(
        `Entry "${safeFilename}" declared size (${(uncompressedSize / 1024 / 1024).toFixed(1)} MB) exceeds per-entry limit (${MAX_ENTRY_UNCOMPRESSED_BYTES / 1024 / 1024} MB).`
      );
    }

    totalUncompressedBytes += uncompressedSize;
    if (totalUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
      throw new ZipSecurityError(
        `Total archive uncompressed size exceeds maximum safety limit (${MAX_TOTAL_UNCOMPRESSED_BYTES / 1024 / 1024} MB). Possible Zip Bomb.`
      );
    }

    if (
      compressedSize > 0 &&
      (uncompressedSize / compressedSize) > MAX_COMPRESSION_RATIO &&
      uncompressedSize > 5 * 1024 * 1024
    ) {
      throw new ZipSecurityError(
        `Suspicious compression ratio (${(uncompressedSize / compressedSize).toFixed(1)}x) for entry "${safeFilename}". Possible Zip Bomb.`
      );
    }

    // Verify local header offset boundary
    if (localHeaderOffset + 30 > centralDirOffset) {
      throw new ZipParseError(`Local file header offset for "${safeFilename}" extends past central directory start.`);
    }

    entries.push({
      filename: safeFilename,
      compressedSize,
      uncompressedSize,
      compressionMethod,
      crc32,
      offset: localHeaderOffset,
    });

    currOffset += 46 + filenameLength + extraFieldLength + fileCommentLength;
  }

  // Classify entries
  const dexEntries = entries.filter(e => /^classes\d*\.dex$/i.test(e.filename));
  const manifestEntry = entries.find(e => e.filename === 'AndroidManifest.xml');
  const resourcesEntry = entries.find(e => e.filename === 'resources.arsc');
  const nativeLibEntries = entries.filter(e => e.filename.startsWith('lib/') && e.filename.endsWith('.so'));

  return {
    filename,
    fileSize: data.byteLength,
    sha256,
    entries,
    dexEntries,
    manifestEntry,
    resourcesEntry,
    nativeLibEntries,
  };
}

/**
 * Extracts, decompresses, and strictly verifies the raw bytes of a single ZipEntry from archive data.
 * Validates local header signatures, decompressed output size, and CRC-32 checksum.
 */
export async function extractZipEntryData(
  archiveData: Uint8Array,
  entry: ZipEntry
): Promise<Uint8Array> {
  const view = new DataView(archiveData.buffer, archiveData.byteOffset, archiveData.byteLength);
  const localOffset = entry.offset;

  if (localOffset + 30 > archiveData.byteLength) {
    throw new ZipParseError(`Local file header out of bounds for "${entry.filename}".`);
  }

  const sig = view.getUint32(localOffset, true);
  if (sig !== LOCAL_HEADER_SIGNATURE) {
    throw new ZipParseError(`Invalid local header signature for "${entry.filename}": expected 0x04034b50, got 0x${sig.toString(16)}.`);
  }

  const localMethod = view.getUint16(localOffset + 8, true);
  if (localMethod !== entry.compressionMethod) {
    throw new ZipParseError(`Compression method mismatch between central directory (${entry.compressionMethod}) and local header (${localMethod}) for "${entry.filename}".`);
  }

  const filenameLength = view.getUint16(localOffset + 26, true);
  const extraLength = view.getUint16(localOffset + 28, true);
  const dataStart = localOffset + 30 + filenameLength + extraLength;
  const dataEnd = dataStart + entry.compressedSize;

  if (dataEnd > archiveData.byteLength) {
    throw new ZipParseError(`Compressed payload out of bounds for "${entry.filename}".`);
  }

  const rawCompressedData = archiveData.subarray(dataStart, dataEnd);
  let decompressed: Uint8Array;

  // Method 0: Stored (Uncompressed)
  if (entry.compressionMethod === 0) {
    if (entry.compressedSize !== entry.uncompressedSize) {
      throw new ZipParseError(`Stored entry "${entry.filename}" has mismatched compressed and uncompressed sizes.`);
    }
    decompressed = rawCompressedData;
  } else if (entry.compressionMethod === 8) {
    // Method 8: Deflated
    try {
      const out = new Uint8Array(entry.uncompressedSize);
      decompressed = inflateSync(rawCompressedData, { out });
    } catch (inflateErr) {
      throw new ZipParseError(`DEFLATE decompression failed for entry "${entry.filename}": ${inflateErr instanceof Error ? inflateErr.message : String(inflateErr)}`);
    }
  } else {
    throw new ZipParseError(`Unsupported compression method (${entry.compressionMethod}) for entry "${entry.filename}".`);
  }

  // 1. Verify actual decompressed size
  if (decompressed.byteLength !== entry.uncompressedSize) {
    throw new ZipParseError(
      `Decompressed size mismatch for entry "${entry.filename}": expected ${entry.uncompressedSize} bytes, got ${decompressed.byteLength} bytes.`
    );
  }

  // 2. Verify CRC-32 checksum against central directory
  const actualCrc = calculateCrc32(decompressed);
  if (actualCrc !== entry.crc32) {
    throw new ZipParseError(
      `CRC-32 checksum mismatch for entry "${entry.filename}": expected 0x${entry.crc32.toString(16).padStart(8, '0')}, got 0x${actualCrc.toString(16).padStart(8, '0')}.`
    );
  }

  return decompressed;
}
