/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Runtime Orchestrator & APK Analysis Pipeline
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
import { inspectNativeLibraries } from '../native-inspector/elf-inspector';
import { evaluateCompatibility } from '../compatibility-engine/compatibility';

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

    addLog('info', 'Loader', `Ingesting APK archive "${filename}" (${(buffer.byteLength / 1024).toFixed(1)} KB)...`);

    // 1. Extract ZIP Archive
    addLog('info', 'ZIP Parser', 'Scanning End of Central Directory (EOCD) & validating integrity...');
    const archive: ApkArchive = await parseApkArchive(buffer, filename);
    addLog('success', 'ZIP Parser', `Indexed ${archive.entries.length} archive entries. SHA-256: ${archive.sha256.substring(0, 16)}...`);

    // 2. Parse AndroidManifest.xml
    let manifest: AndroidManifestData;
    if (archive.manifestEntry) {
      addLog('info', 'Manifest Engine', 'Extracting and decompressing binary AndroidManifest.xml...');
      const manifestBytes = await extractZipEntryData(buffer, archive.manifestEntry);
      addLog('info', 'Manifest Engine', 'Parsing ResXMLTree binary chunks, string pool, and component graph...');
      manifest = parseBinaryAndroidManifest(manifestBytes);
      addLog(
        'success',
        'Manifest Engine',
        `Parsed manifest: Package="${manifest.packageName}", Version="${manifest.versionName}" (${manifest.versionCode}), MinSDK=${manifest.minSdkVersion}`
      );
    } else {
      addLog('warn', 'Manifest Engine', 'No AndroidManifest.xml found in root archive directory.');
      manifest = {
        packageName: 'unknown.package',
        versionCode: 1,
        versionName: '1.0',
        minSdkVersion: 21,
        targetSdkVersion: 33,
        appLabel: filename.replace(/\.apk$/i, ''),
        activities: [],
        services: [],
        receivers: [],
        providers: [],
        permissions: [],
        features: [],
        rawXml: '<!-- No AndroidManifest.xml found -->',
      };
    }

    // 3. Parse DEX Files
    const dexFiles: DexFileAnalysis[] = [];
    if (archive.dexEntries.length > 0) {
      addLog('info', 'DEX Parser', `Discovered ${archive.dexEntries.length} Dalvik executable(s)...`);
      for (const dexEntry of archive.dexEntries) {
        addLog('info', 'DEX Parser', `Extracting ${dexEntry.filename}...`);
        const dexBytes = await extractZipEntryData(buffer, dexEntry);
        addLog('info', 'DEX Parser', `Validating header, Adler32, and symbols for ${dexEntry.filename}...`);
        const parsedDex = parseDexFile(dexBytes, dexEntry.filename);
        dexFiles.push(parsedDex);
        addLog(
          'success',
          'DEX Parser',
          `Parsed ${dexEntry.filename}: ${parsedDex.classesCount} classes, ${parsedDex.methodsCount} methods, ${parsedDex.stringsCount} strings.`
        );
      }
    } else {
      addLog('warn', 'DEX Parser', 'No classes.dex found in APK archive.');
    }

    // 4. Inspect Native Libraries (lib/*.so)
    const extractedNativeMap = new Map<string, Uint8Array>();
    if (archive.nativeLibEntries.length > 0) {
      addLog('info', 'Native Inspector', `Inspecting ${archive.nativeLibEntries.length} native .so files in lib/...`);
      // Extract first few native headers to check ELF magic
      for (const entry of archive.nativeLibEntries.slice(0, 10)) {
        try {
          const soBytes = await extractZipEntryData(buffer, entry);
          extractedNativeMap.set(entry.filename, soBytes);
        } catch {
          // Continue
        }
      }
    }
    const nativeLibraries: NativeLibraryInfo[] = inspectNativeLibraries(
      archive.entries,
      extractedNativeMap
    );
    if (nativeLibraries.length > 0) {
      const abis = Array.from(new Set(nativeLibraries.map(n => n.abi)));
      addLog('info', 'Native Inspector', `Detected native ABIs: ${abis.join(', ')} (${nativeLibraries.length} files).`);
    }

    // 5. Evaluate Compatibility
    addLog('info', 'Compatibility', 'Evaluating runtime readiness heuristics and framework dependencies...');
    const compatibility = evaluateCompatibility(manifest, dexFiles, nativeLibraries);
    addLog(
      compatibility.status === 'SUPPORTED' ? 'success' : 'warn',
      'Compatibility',
      `Evaluation complete: Tier [${compatibility.statusBadge}] - ${compatibility.summary}`
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
   * Discovers APK files inside a ZIP archive and extracts the chosen one
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
   * Extracts a specific APK file from inside a parent ZIP
   */
  public static async extractApkFromZip(
    zipBuffer: Uint8Array,
    apkFilename: string
  ): Promise<Uint8Array> {
    const archive = await parseApkArchive(zipBuffer, 'container.zip');
    const targetEntry = archive.entries.find(e => e.filename === apkFilename);
    if (!targetEntry) {
      throw new Error(`APK "${apkFilename}" not found inside the ZIP archive.`);
    }
    return await extractZipEntryData(zipBuffer, targetEntry);
  }

  /**
   * Fetches an APK from a public GitHub release URL or raw direct link
   * Handles CORS constraints with clear feedback
   */
  public static async fetchApkFromUrl(
    url: string,
    onProgress?: (loaded: number, total: number) => void
  ): Promise<{ data: Uint8Array; filename: string }> {
    // Clean URL
    const cleanUrl = url.trim();
    const filenameMatch = cleanUrl.split('/').pop() || 'downloaded.apk';
    const filename = filenameMatch.includes('?') ? filenameMatch.split('?')[0] : filenameMatch;

    try {
      const response = await fetch(cleanUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/vnd.android.package-archive,application/octet-stream,*/*',
        },
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status} (${response.statusText})`);
      }

      const contentLength = response.headers.get('content-length');
      const total = contentLength ? parseInt(contentLength, 10) : 0;

      if (!response.body) {
        const buffer = await response.arrayBuffer();
        return { data: new Uint8Array(buffer), filename };
      }

      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let loaded = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          chunks.push(value);
          loaded += value.byteLength;
          onProgress?.(loaded, total || loaded);
        }
      }

      const combined = new Uint8Array(loaded);
      let offset = 0;
      for (const chunk of chunks) {
        combined.set(chunk, offset);
        offset += chunk.byteLength;
      }

      return { data: combined, filename };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('CORS')) {
        throw new Error(
          `Browser CORS Restriction: The remote server at "${cleanUrl}" does not send 'Access-Control-Allow-Origin'. Please download the APK locally and drop it directly into the upload area.`
        );
      }
      throw err;
    }
  }
}
