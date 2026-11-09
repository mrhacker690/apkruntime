/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Runtime Orchestrator & APK Analysis Pipeline
 * Coordinates input validation, archive extraction, AXML decoding, DEX parsing,
 * ELF architecture inspection, and evidence-based compatibility evaluation.
 */

import {
  ApkArchive,
  ApkAnalysisReport,
  AndroidManifestData,
  DexFileAnalysis,
  NativeLibraryInfo,
  RuntimeLog,
} from '../core/types';
import { parseApkArchive, extractZipEntryData } from '../apk-extractor/zip-parser';
import { parseBinaryAndroidManifest } from '../manifest-engine/axml-parser';
import { parseDexFile } from '../dex-parser/dex-parser';
import {
  inspectNativeLibrariesDetailed,
  MAX_INSPECTABLE_NATIVE_FILES,
  MAX_INSPECTABLE_NATIVE_BYTES,
} from '../native-inspector/elf-inspector';
import { evaluateCompatibility } from '../compatibility-engine/compatibility';

export class PipelineError extends Error {
  public readonly stage: string;
  constructor(stage: string, message: string) {
    super(`[${stage}] ${message}`);
    this.name = 'PipelineError';
    this.stage = stage;
  }
}

export interface GitHubAssetItem {
  id: number;
  name: string;
  size: number;
  downloadUrl: string;
  contentType: string;
}

export class ApkRuntimeService {
  /**
   * Complete End-to-End Pipeline: Ingests raw APK buffer and performs deep analysis
   */
  public static async analyzeApk(
    buffer: Uint8Array,
    filename: string = 'application.apk',
    logCallback?: (log: RuntimeLog) => void
  ): Promise<ApkAnalysisReport> {
    const addLog = (level: RuntimeLog['level'], source: string, message: string) => {
      const log: RuntimeLog = {
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toLocaleTimeString(),
        level,
        source,
        message,
      };
      logCallback?.(log);
    };

    // 1. Input Validation
    if (!buffer || buffer.byteLength < 22) {
      throw new PipelineError('Input Validation', 'Supplied file is too small to be a valid Android APK archive.');
    }

    // Verify ZIP magic header: PK\x03\x04 (0x50 0x4B 0x03 0x04)
    const isZip = buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;
    if (!isZip) {
      throw new PipelineError(
        'Input Validation',
        `File magic header signature invalid. Expected standard ZIP header (PK\\x03\\x04), found: 0x${buffer[0].toString(16)} 0x${buffer[1].toString(16)}.`
      );
    }

    addLog('info', 'Loader', `Ingesting APK archive "${filename}" (${(buffer.byteLength / 1024).toFixed(1)} KB)...`);

    // 2. Extract and Validate ZIP Archive
    addLog('info', 'ZIP Parser', 'Scanning End of Central Directory (EOCD), validating entries & CRC-32...');
    const archive: ApkArchive = await parseApkArchive(buffer, filename);
    addLog('success', 'ZIP Parser', `Indexed ${archive.entries.length} archive entries. SHA-256: ${archive.sha256.substring(0, 16)}...`);

    // 3. Parse AndroidManifest.xml
    let manifest: AndroidManifestData;
    if (archive.manifestEntry) {
      addLog('info', 'Manifest Engine', 'Extracting binary AndroidManifest.xml...');
      const manifestBytes = await extractZipEntryData(buffer, archive.manifestEntry);
      addLog('info', 'Manifest Engine', 'Decoding ResXMLTree binary chunks, string pool, and components...');
      manifest = parseBinaryAndroidManifest(manifestBytes);
      addLog(
        'success',
        'Manifest Engine',
        `Parsed manifest: Package="${manifest.packageName}", Version="${manifest.versionName || 'unspecified'}" (Code: ${manifest.versionCode !== undefined ? manifest.versionCode : 'unspecified'}), MinSDK=${manifest.minSdkVersion !== undefined ? manifest.minSdkVersion : 'unspecified'}`
      );
    } else {
      addLog('warn', 'Manifest Engine', 'No AndroidManifest.xml found in root archive directory.');
      manifest = {
        packageName: 'unknown.package',
        activities: [],
        services: [],
        receivers: [],
        providers: [],
        permissions: [],
        features: [],
        rawXml: '<!-- No AndroidManifest.xml present in archive -->',
      };
    }

    // 4. Parse DEX Bytecode Files
    const dexFiles: DexFileAnalysis[] = [];
    if (archive.dexEntries.length > 0) {
      addLog('info', 'DEX Parser', `Discovered ${archive.dexEntries.length} Dalvik executable container(s)...`);
      for (const dexEntry of archive.dexEntries) {
        addLog('info', 'DEX Parser', `Extracting ${dexEntry.filename}...`);
        const dexBytes = await extractZipEntryData(buffer, dexEntry);
        addLog('info', 'DEX Parser', `Validating header, Adler-32 checksum, and symbol pools for ${dexEntry.filename}...`);
        const parsedDex = parseDexFile(dexBytes, dexEntry.filename);
        dexFiles.push(parsedDex);
        addLog(
          'success',
          'DEX Parser',
          `Parsed ${dexEntry.filename}: ${parsedDex.classesCount} classes, ${parsedDex.methodsCount} methods, ${parsedDex.stringsCount} strings (Adler-32 verified).`
        );
      }
    } else {
      addLog('warn', 'DEX Parser', 'No classes.dex found in APK archive.');
    }

    // 5. Inspect Native Shared Libraries (lib/*.so) within Resource Budget
    const extractedNativeMap = new Map<string, Uint8Array>();
    let nativeBytesAccumulated = 0;
    let nativeFilesAccumulated = 0;

    for (let i = 0; i < archive.nativeLibEntries.length; i++) {
      const entry = archive.nativeLibEntries[i];
      // Pre-flight check: check if adding this entry exceeds max files or byte budget
      if (
        nativeFilesAccumulated >= MAX_INSPECTABLE_NATIVE_FILES ||
        nativeBytesAccumulated + entry.uncompressedSize > MAX_INSPECTABLE_NATIVE_BYTES
      ) {
        addLog(
          'info',
          'Native Inspector',
          `Native inspection budget threshold reached (${nativeFilesAccumulated}/${MAX_INSPECTABLE_NATIVE_FILES} files, ${(nativeBytesAccumulated / 1024 / 1024).toFixed(1)} MB / 50 MB). Remaining native binaries skipped.`
        );
        break;
      }

      try {
        const soBytes = await extractZipEntryData(buffer, entry);
        if (nativeBytesAccumulated + soBytes.byteLength <= MAX_INSPECTABLE_NATIVE_BYTES) {
          extractedNativeMap.set(entry.filename, soBytes);
          nativeBytesAccumulated += soBytes.byteLength;
          nativeFilesAccumulated++;
        } else {
          break;
        }
      } catch (err: unknown) {
        addLog(
          'warn',
          'Native Inspector',
          `Failed to extract native binary "${entry.filename}": ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    const nativeInspection = inspectNativeLibrariesDetailed(archive.entries, extractedNativeMap);
    const nativeLibraries: NativeLibraryInfo[] = nativeInspection.libraries;

    if (nativeLibraries.length > 0) {
      const abis = Array.from(new Set(nativeLibraries.map(n => n.abi)));
      addLog(
        'info',
        'Native Inspector',
        `Discovered ${nativeInspection.totalLibrariesFound} native library files (${abis.join(', ')}). Inspected: ${nativeInspection.totalLibrariesInspected}, Skipped: ${nativeInspection.totalLibrariesSkipped}.`
      );
      if (nativeInspection.hasAbiMismatches) {
        addLog('warn', 'Native Inspector', 'ABI mismatch detected between directory name and ELF machine architecture.');
      }
    }

    // 6. Evaluate Compatibility (Honest Assessment)
    addLog('info', 'Compatibility', 'Evaluating runtime readiness heuristics and framework dependencies...');
    const compatibility = evaluateCompatibility(manifest, dexFiles, nativeLibraries);
    addLog(
      compatibility.status === 'NOT_SUPPORTED' ? 'error' : 'info',
      'Compatibility',
      `Assessment complete: [${compatibility.statusBadge}] — ${compatibility.summary}`
    );

    return {
      archive,
      manifest,
      dexFiles,
      nativeLibraries,
      compatibility,
      analyzedAt: new Date().toISOString(),
    };
  }

  /**
   * Discovers APK files inside a ZIP archive container
   */
  public static async discoverApksInZip(
    zipBuffer: Uint8Array
  ): Promise<{ name: string; size: number; entry: ApkArchive['entries'][0] }[]> {
    const archive = await parseApkArchive(zipBuffer, 'container.zip');
    const apks = archive.entries.filter(e => e.filename.toLowerCase().endsWith('.apk'));
    return apks.map(a => ({
      name: a.filename,
      size: a.uncompressedSize,
      entry: a,
    }));
  }

  /**
   * Extracts a specific APK file from inside a parent ZIP container
   */
  public static async extractApkFromZip(
    zipBuffer: Uint8Array,
    apkFilename: string
  ): Promise<Uint8Array> {
    const archive = await parseApkArchive(zipBuffer, 'container.zip');
    const targetEntry = archive.entries.find(e => e.filename === apkFilename);
    if (!targetEntry) {
      throw new PipelineError('ZIP Container', `APK "${apkFilename}" not found inside the ZIP archive.`);
    }
    return await extractZipEntryData(zipBuffer, targetEntry);
  }

  /**
   * Parses public GitHub URLs into structured release metadata components
   */
  public static parseGitHubUrl(rawUrl: string): {
    owner: string;
    repo: string;
    tag?: string;
    isDirectAsset: boolean;
  } | null {
    const clean = rawUrl.trim();
    // Example: https://github.com/owner/repo/releases/download/v1.0.0/app.apk
    const downloadMatch = clean.match(/github\.com\/([^/]+)\/([^/]+)\/releases\/download\/([^/]+)\/(.+)/i);
    if (downloadMatch) {
      return { owner: downloadMatch[1], repo: downloadMatch[2], tag: downloadMatch[3], isDirectAsset: true };
    }

    // Example: https://github.com/owner/repo/releases/tag/v1.0.0
    const tagMatch = clean.match(/github\.com\/([^/]+)\/([^/]+)\/releases\/tag\/([^/?#]+)/i);
    if (tagMatch) {
      return { owner: tagMatch[1], repo: tagMatch[2], tag: tagMatch[3], isDirectAsset: false };
    }

    // Example: https://github.com/owner/repo/releases or https://github.com/owner/repo
    const repoMatch = clean.match(/github\.com\/([^/]+)\/([^/?#]+)/i);
    if (repoMatch) {
      return { owner: repoMatch[1], repo: repoMatch[2], isDirectAsset: false };
    }

    return null;
  }

  /**
   * Queries public GitHub API for release assets without requiring private tokens
   */
  public static async fetchGitHubReleaseAssets(
    owner: string,
    repo: string,
    tag?: string
  ): Promise<GitHubAssetItem[]> {
    const endpoint = tag
      ? `https://api.github.com/repos/${owner}/${repo}/releases/tags/${encodeURIComponent(tag)}`
      : `https://api.github.com/repos/${owner}/${repo}/releases/latest`;

    const res = await fetch(endpoint, {
      headers: { Accept: 'application/vnd.github.v3+json' },
    });

    if (!res.ok) {
      if (res.status === 404) {
        throw new Error(`GitHub release not found for ${owner}/${repo}${tag ? ` (tag: ${tag})` : ''}.`);
      }
      if (res.status === 403) {
        throw new Error('GitHub API rate limit exceeded for public requests. Please download the APK locally and drop it in.');
      }
      throw new Error(`GitHub API returned HTTP ${res.status}: ${res.statusText}`);
    }

    const data = await res.json();
    if (!data.assets || !Array.isArray(data.assets)) {
      throw new Error('No release assets found in GitHub release metadata.');
    }

    const relevant = data.assets.filter((a: { name: string }) => {
      const lower = a.name.toLowerCase();
      return lower.endsWith('.apk') || lower.endsWith('.zip');
    });

    return relevant.map((a: { id: number; name: string; size: number; browser_download_url: string; content_type: string }) => ({
      id: a.id,
      name: a.name,
      size: a.size,
      downloadUrl: a.browser_download_url,
      contentType: a.content_type,
    }));
  }

  /**
   * Streams an APK from a remote URL with size caps, progress feedback, and AbortController
   */
  public static async fetchApkFromUrl(
    url: string,
    signal?: AbortSignal,
    onProgress?: (loaded: number, total: number) => void
  ): Promise<{ data: Uint8Array; filename: string }> {
    const cleanUrl = url.trim();
    const filenameMatch = cleanUrl.split('/').pop()?.split('?')[0] || 'remote_download.apk';
    const filename = filenameMatch.endsWith('.apk') || filenameMatch.endsWith('.zip')
      ? filenameMatch
      : `${filenameMatch}.apk`;

    try {
      const response = await fetch(cleanUrl, {
        method: 'GET',
        signal,
        headers: {
          Accept: 'application/vnd.android.package-archive,application/octet-stream,*/*',
        },
      });

      if (!response.ok) {
        throw new Error(`Remote server returned HTTP ${response.status} (${response.statusText})`);
      }

      const contentLengthHeader = response.headers.get('content-length');
      const total = contentLengthHeader ? parseInt(contentLengthHeader, 10) : 0;

      // Max download cap (250 MB)
      if (total > 250 * 1024 * 1024) {
        throw new Error(`Remote file size (${(total / 1024 / 1024).toFixed(1)} MB) exceeds maximum download limit of 250 MB.`);
      }

      if (!response.body) {
        const buffer = await response.arrayBuffer();
        const uint8 = new Uint8Array(buffer);
        // Verify ZIP header
        if (uint8.length < 4 || uint8[0] !== 0x50 || uint8[1] !== 0x4b || uint8[2] !== 0x03 || uint8[3] !== 0x04) {
          throw new Error('Downloaded file does not start with standard ZIP signature (PK\\x03\\x04). Remote URL may have returned HTML instead of an APK.');
        }
        return { data: uint8, filename };
      }

      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let loaded = 0;

      while (true) {
        if (signal?.aborted) {
          throw new Error('Download aborted by user.');
        }

        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          loaded += value.byteLength;
          if (loaded > 250 * 1024 * 1024) {
            reader.cancel();
            throw new Error('Download terminated: payload exceeded maximum limit of 250 MB.');
          }
          chunks.push(value);
          onProgress?.(loaded, total || loaded);
        }
      }

      const combined = new Uint8Array(loaded);
      let writeOffset = 0;
      for (const chunk of chunks) {
        combined.set(chunk, writeOffset);
        writeOffset += chunk.byteLength;
      }

      // Verify ZIP header
      if (combined.length < 4 || combined[0] !== 0x50 || combined[1] !== 0x4b || combined[2] !== 0x03 || combined[3] !== 0x04) {
        throw new Error('Downloaded file does not start with standard ZIP signature (PK\\x03\\x04). The remote host likely returned an HTML login or error page.');
      }

      return { data: combined, filename };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('CORS')) {
        throw new Error(
          `Browser CORS Restriction: Remote host at "${cleanUrl}" does not send 'Access-Control-Allow-Origin' headers. Please download the file to your computer and drag it into the upload box.`
        );
      }
      throw err;
    }
  }
}
