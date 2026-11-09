/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Import Engine Component
 * Handles local APK/ZIP drag-and-drop with pre-flight signature checks,
 * public GitHub repository / release inspection via GitHub API, and synthetic test fixtures.
 */

import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  Link2,
  ArrowRight,
  Sparkles,
  AlertCircle,
  FolderArchive,
  Download,
  X,
} from 'lucide-react';
import { SAMPLE_APKS, SampleApkDefinition } from '../runtime/apk-loader/sample-apks';
import { ApkRuntimeService, GitHubAssetItem } from '../runtime/apk-loader/runtime-service';

interface ImportZoneProps {
  onLoadApkBuffer: (buffer: Uint8Array, filename: string) => void;
  onLoadZipBuffer: (buffer: Uint8Array, filename: string) => void;
  isLoading: boolean;
  loadingMessage?: string;
  loadProgress?: number;
}

export const ImportZone: React.FC<ImportZoneProps> = ({
  onLoadApkBuffer,
  onLoadZipBuffer,
  isLoading,
  loadingMessage,
  loadProgress,
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [remoteUrl, setRemoteUrl] = useState('');
  const [isFetchingUrl, setIsFetchingUrl] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [gitHubAssets, setGitHubAssets] = useState<GitHubAssetItem[]>([]);
  const [showAssetPicker, setShowAssetPicker] = useState(false);
  const [selectedRepoInfo, setSelectedRepoInfo] = useState('');
  const [downloadProgress, setDownloadProgress] = useState<{
    loaded: number;
    total: number;
    speedKbps?: number;
  } | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  /**
   * Pre-flight validation of local files: checks extension, size, and ZIP signature (PK\x03\x04)
   */
  const processFile = async (file: File) => {
    setUrlError(null);
    const filename = file.name;
    const lower = filename.toLowerCase();

    if (!lower.endsWith('.apk') && !lower.endsWith('.zip')) {
      setUrlError(`Invalid file type "${filename}". Expected an Android .apk package or .zip container.`);
      return;
    }

    if (file.size < 22) {
      setUrlError(`File "${filename}" is corrupted or empty (size ${file.size} bytes).`);
      return;
    }

    if (file.size > 500 * 1024 * 1024) {
      setUrlError(`File "${filename}" exceeds maximum allowable size of 500 MB.`);
      return;
    }

    // Pre-flight check: read first 4 bytes to verify ZIP signature
    const headerSlice = await file.slice(0, 4).arrayBuffer();
    const headerBytes = new Uint8Array(headerSlice);
    const isZip = headerBytes[0] === 0x50 && headerBytes[1] === 0x4b && headerBytes[2] === 0x03 && headerBytes[3] === 0x04;

    if (!isZip) {
      setUrlError(`Invalid file header for "${filename}". File does not begin with standard ZIP magic signature (PK\\x03\\x04).`);
      return;
    }

    const buffer = new Uint8Array(await file.arrayBuffer());

    if (lower.endsWith('.zip')) {
      onLoadZipBuffer(buffer, filename);
    } else {
      onLoadApkBuffer(buffer, filename);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      await processFile(file);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      await processFile(file);
    }
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleFetchUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!remoteUrl.trim()) return;

    setUrlError(null);
    setGitHubAssets([]);
    setShowAssetPicker(false);
    setIsFetchingUrl(true);
    setDownloadProgress(null);

    const targetUrl = remoteUrl.trim();
    const parsedGitHub = ApkRuntimeService.parseGitHubUrl(targetUrl);

    if (parsedGitHub && !parsedGitHub.isDirectAsset) {
      try {
        const repoStr = `${parsedGitHub.owner}/${parsedGitHub.repo}${parsedGitHub.tag ? ` (${parsedGitHub.tag})` : ' (latest)'}`;
        setSelectedRepoInfo(repoStr);

        const assets = await ApkRuntimeService.fetchGitHubReleaseAssets(
          parsedGitHub.owner,
          parsedGitHub.repo,
          parsedGitHub.tag
        );

        if (assets.length === 0) {
          throw new Error(`Release found for ${repoStr}, but it contains no .apk or .zip assets.`);
        }

        if (assets.length === 1) {
          await downloadAsset(assets[0].downloadUrl, assets[0].name);
        } else {
          setGitHubAssets(assets);
          setShowAssetPicker(true);
        }
      } catch (err: unknown) {
        setUrlError(err instanceof Error ? err.message : String(err));
      } finally {
        setIsFetchingUrl(false);
      }
      return;
    }

    await downloadAsset(targetUrl);
    setIsFetchingUrl(false);
  };

  const downloadAsset = async (downloadUrl: string, assetName?: string) => {
    setIsFetchingUrl(true);
    setUrlError(null);
    setDownloadProgress(null);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const startTime = Date.now();

    try {
      const result = await ApkRuntimeService.fetchApkFromUrl(
        downloadUrl,
        controller.signal,
        (loaded, total) => {
          const elapsedSec = (Date.now() - startTime) / 1000;
          const speedKbps = elapsedSec > 0 ? (loaded / 1024) / elapsedSec : 0;
          setDownloadProgress({ loaded, total, speedKbps });
        }
      );

      const filename = assetName || result.filename;
      if (filename.toLowerCase().endsWith('.zip')) {
        onLoadZipBuffer(result.data, filename);
      } else {
        onLoadApkBuffer(result.data, filename);
      }
      setRemoteUrl('');
      setShowAssetPicker(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setUrlError(msg);
    } finally {
      setIsFetchingUrl(false);
      setDownloadProgress(null);
      abortControllerRef.current = null;
    }
  };

  const cancelDownload = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      setIsFetchingUrl(false);
      setDownloadProgress(null);
    }
  };

  const loadSample = (sample: SampleApkDefinition) => {
    const bytes = sample.generate();
    onLoadApkBuffer(bytes, sample.name);
  };

  return (
    <div className="space-y-6">
      {/* Hero Title & Subtitle */}
      <div className="text-center max-w-3xl mx-auto pt-4 pb-2">
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 dark:text-white" style={{ textWrap: 'balance' }}>
          Android APK Analysis Engine
        </h1>
        <p className="mt-3 text-base text-slate-600 dark:text-slate-400 max-w-2xl mx-auto" style={{ textWrap: 'balance' }}>
          Independent, browser-based Android APK inspection software. Ingest real APK archives, decode binary XML manifests, disassemble Dalvik bytecode, and inspect ELF native libraries without cloud servers.
        </p>
      </div>

      {/* Main Drag-and-Drop Area */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative group cursor-pointer rounded-2xl border-2 border-dashed p-8 sm:p-12 text-center transition-all ${
          isDragOver
            ? 'border-indigo-500 bg-indigo-50/50 dark:bg-indigo-950/20 scale-[0.99]'
            : 'border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 hover:border-slate-400 dark:hover:border-slate-700'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".apk,.zip"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="max-w-md mx-auto space-y-4">
          <div className="w-14 h-14 mx-auto rounded-xl bg-indigo-100 dark:bg-indigo-950/60 flex items-center justify-center text-indigo-600 dark:text-indigo-400 group-hover:scale-110 transition-transform">
            <UploadCloud className="w-7 h-7" />
          </div>

          <div>
            <p className="text-base font-semibold text-slate-900 dark:text-white">
              Drop Android APK or ZIP archive here
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Supports <span className="font-mono text-slate-700 dark:text-slate-300">.apk</span> files and <span className="font-mono text-slate-700 dark:text-slate-300">.zip</span> archives up to 500 MB · Safe local client-side extraction
            </p>
          </div>

          <div className="flex items-center justify-center gap-2 pt-1">
            <button
              type="button"
              className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 dark:bg-indigo-600 hover:bg-slate-800 dark:hover:bg-indigo-500 rounded-lg shadow-sm transition-colors whitespace-nowrap"
            >
              Browse Local Files
            </button>
          </div>
        </div>

        {/* Loading & Progress Overlay */}
        {(isLoading || isFetchingUrl) && (
          <div className="absolute inset-0 bg-white/95 dark:bg-slate-900/95 backdrop-blur-sm rounded-2xl flex flex-col items-center justify-center p-6 z-10">
            <div className="w-10 h-10 border-3 border-indigo-600 border-t-transparent rounded-full animate-spin mb-4" />
            <p className="text-sm font-semibold text-slate-900 dark:text-white">
              {loadingMessage || (isFetchingUrl ? 'Downloading remote APK asset...' : 'Processing Android archive...')}
            </p>

            {/* Real Progress Feedback */}
            {downloadProgress && (
              <div className="w-72 mt-3 space-y-2">
                <div className="flex justify-between text-xs font-mono text-slate-600 dark:text-slate-400">
                  <span>{(downloadProgress.loaded / 1024 / 1024).toFixed(2)} MB</span>
                  <span>
                    {downloadProgress.total > 0 && downloadProgress.total !== downloadProgress.loaded
                      ? `${(downloadProgress.total / 1024 / 1024).toFixed(2)} MB (${Math.round((downloadProgress.loaded / downloadProgress.total) * 100)}%)`
                      : downloadProgress.speedKbps
                      ? `${(downloadProgress.speedKbps / 1024).toFixed(1)} MB/s`
                      : 'Downloading...'}
                  </span>
                </div>
                {downloadProgress.total > 0 && downloadProgress.total !== downloadProgress.loaded && (
                  <div className="w-full bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-indigo-600 h-full transition-all duration-150"
                      style={{ width: `${Math.min(100, Math.round((downloadProgress.loaded / downloadProgress.total) * 100))}%` }}
                    />
                  </div>
                )}
              </div>
            )}

            {loadProgress !== undefined && loadProgress > 0 && !downloadProgress && (
              <div className="w-64 bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
                <div
                  className="bg-indigo-600 h-full transition-all duration-200"
                  style={{ width: `${Math.min(100, Math.round(loadProgress * 100))}%` }}
                />
              </div>
            )}

            {isFetchingUrl && (
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); cancelDownload(); }}
                className="mt-4 px-3 py-1.5 text-xs text-rose-600 dark:text-rose-400 border border-rose-300 dark:border-rose-800 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/30 font-semibold"
              >
                Cancel Download
              </button>
            )}
          </div>
        )}
      </div>

      {/* GitHub Asset Selector Modal */}
      {showAssetPicker && gitHubAssets.length > 0 && (
        <div className="p-5 rounded-2xl border border-indigo-200 dark:border-indigo-900 bg-indigo-50/40 dark:bg-indigo-950/30 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-900 dark:text-white">
              <FolderArchive className="w-4 h-4 text-indigo-500" />
              <span>Select APK Asset from Release ({selectedRepoInfo})</span>
            </div>
            <button
              onClick={() => setShowAssetPicker(false)}
              className="text-slate-400 hover:text-slate-600 dark:hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="space-y-2">
            {gitHubAssets.map(asset => (
              <div
                key={asset.id}
                className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between gap-4"
              >
                <div>
                  <div className="text-xs font-mono font-bold text-slate-900 dark:text-white">
                    {asset.name}
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono tabular-nums">
                    {(asset.size / 1024 / 1024).toFixed(2)} MB
                  </div>
                </div>

                <button
                  onClick={() => downloadAsset(asset.downloadUrl, asset.name)}
                  className="px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download & Inspect</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Secondary Import Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* GitHub / Remote APK URL */}
        <div className="lg:col-span-5 p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white mb-2">
            <Link2 className="w-4 h-4 text-indigo-500" />
            <span>Import from Public GitHub Release</span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
            Enter repository (e.g. <span className="font-mono">owner/repo</span>) or release asset link
          </p>

          <form onSubmit={handleFetchUrl} className="flex gap-2">
            <input
              type="text"
              placeholder="https://github.com/owner/repo/releases/..."
              value={remoteUrl}
              onChange={e => setRemoteUrl(e.target.value)}
              disabled={isFetchingUrl}
              className="flex-1 px-3 py-2 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
            />
            <button
              type="submit"
              disabled={isFetchingUrl || !remoteUrl.trim()}
              className="px-3.5 py-2 text-xs font-semibold text-white bg-slate-900 dark:bg-slate-800 hover:bg-slate-800 dark:hover:bg-slate-700 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
            >
              <span>Inspect</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>

          {urlError && (
            <div className="mt-3 p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/50 flex gap-2 text-xs text-amber-800 dark:text-amber-300">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
              <span className="leading-relaxed">{urlError}</span>
            </div>
          )}
        </div>

        {/* Synthetic Test Fixtures */}
        <div className="lg:col-span-7 p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Sparkles className="w-4 h-4 text-cyan-500" />
              <span>Synthetic Test Fixtures (For Parser Verification)</span>
            </div>
            <span className="text-[10px] text-slate-500 font-mono">Optional</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {SAMPLE_APKS.map(sample => (
              <button
                key={sample.id}
                type="button"
                onClick={() => loadSample(sample)}
                className="p-3 text-left rounded-lg border border-slate-200 dark:border-slate-800 hover:border-indigo-400 dark:hover:border-indigo-500 hover:bg-indigo-50/30 dark:hover:bg-indigo-950/20 transition-all group"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 font-mono">
                    {sample.name}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono tabular-nums">
                    {sample.sizeDescription}
                  </span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 line-clamp-2 leading-relaxed">
                  {sample.description}
                </p>
                <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500">
                  <span>{sample.category}</span>
                  <span className="text-sky-600 dark:text-sky-400 font-semibold font-mono">
                    SYNTHETIC FIXTURE
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
