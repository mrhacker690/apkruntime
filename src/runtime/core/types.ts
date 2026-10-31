/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Core Types & Interfaces
 */

export type CompatibilityStatus =
  | 'SUPPORTED'
  | 'PARTIALLY_SUPPORTED'
  | 'NOT_SUPPORTED'
  | 'ANALYSIS_ONLY';

export interface ZipEntry {
  filename: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number; // 0 = Stored, 8 = Deflated
  crc32: number;
  offset: number;
  data?: Uint8Array;
}

export interface ApkArchive {
  filename: string;
  fileSize: number;
  sha256: string;
  entries: ZipEntry[];
  dexEntries: ZipEntry[];
  manifestEntry?: ZipEntry;
  resourcesEntry?: ZipEntry;
  nativeLibEntries: ZipEntry[];
}

export interface AndroidActivity {
  name: string;
  isLauncher: boolean;
  exported?: boolean;
  label?: string;
  theme?: string;
}

export interface AndroidComponent {
  name: string;
  exported?: boolean;
  permission?: string;
}

export interface AndroidManifestData {
  packageName: string;
  versionCode?: number;
  versionName?: string;
  compileSdkVersion?: number;
  minSdkVersion?: number;
  targetSdkVersion?: number;
  maxSdkVersion?: number;
  appLabel?: string;
  appIcon?: string;
  theme?: string;
  launcherActivity?: string;
  activities: AndroidActivity[];
  services: AndroidComponent[];
  receivers: AndroidComponent[];
  providers: AndroidComponent[];
  permissions: string[];
  features: string[];
  rawXml: string;
}

export interface DexHeader {
  magic: string;
  version: string;
  checksum: number; // Adler32
  signature: string; // 20-byte SHA-1 in hex
  fileSize: number;
  headerSize: number;
  endianTag: number; // 0x12345678
  linkSize: number;
  linkOff: number;
  mapOff: number;
  stringIdsSize: number;
  stringIdsOff: number;
  typeIdsSize: number;
  typeIdsOff: number;
  protoIdsSize: number;
  protoIdsOff: number;
  fieldIdsSize: number;
  fieldIdsOff: number;
  methodIdsSize: number;
  methodIdsOff: number;
  classDefsSize: number;
  classDefsOff: number;
  dataSize: number;
  dataOff: number;
}

export interface DexMethod {
  classIndex: number;
  className: string;
  protoIndex: number;
  nameIndex: number;
  name: string;
  accessFlags?: number;
  codeOffset?: number;
  registersSize?: number;
  insSize?: number;
  outsSize?: number;
  insnsSize?: number;
  instructions?: string[];
}

export interface DexClass {
  classIndex: number;
  className: string;
  accessFlags: number;
  superclassName: string;
  sourceFile?: string;
  directMethods: DexMethod[];
  virtualMethods: DexMethod[];
  staticFieldsCount: number;
  instanceFieldsCount: number;
}

export interface DexFileAnalysis {
  name: string;
  size: number;
  header: DexHeader;
  stringsCount: number;
  typesCount: number;
  protoCount: number;
  fieldsCount: number;
  methodsCount: number;
  classesCount: number;
  stringsSample: string[];
  classes: DexClass[];
}

export interface NativeLibraryInfo {
  filename: string;
  path: string;
  size: number;
  abi: string; // 'arm64-v8a' | 'armeabi-v7a' | 'x86' | 'x86_64' | 'unknown'
  isElf: boolean;
  bitness: '32-bit' | '64-bit' | 'unknown';
  endianness: 'little' | 'big' | 'unknown';
  machine: string;
}

export interface CompatibilityCheck {
  title: string;
  passed: boolean;
  level: 'info' | 'warning' | 'error' | 'success';
  detail: string;
}

export interface CompatibilityReport {
  status: CompatibilityStatus;
  statusBadge: string;
  summary: string;
  minSdkMet: boolean;
  targetSdkCompliant: boolean;
  pureBytecode: boolean;
  unsupportedAbis: string[];
  checks: CompatibilityCheck[];
  missingApis: string[];
  readyForExecution: boolean;
}

export interface ApkAnalysisReport {
  archive: ApkArchive;
  manifest: AndroidManifestData;
  dexFiles: DexFileAnalysis[];
  nativeLibraries: NativeLibraryInfo[];
  compatibility: CompatibilityReport;
  analyzedAt: string;
}

export interface RuntimeLog {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success';
  source: string;
  message: string;
}

export interface TestCaseResult {
  id: string;
  name: string;
  module: string;
  passed: boolean;
  durationMs: number;
  error?: string;
  details?: string;
}
