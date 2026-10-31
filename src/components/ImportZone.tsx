/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Import Engine Component
 * Handles local APK/ZIP drag-and-drop, public GitHub release URL fetching, and sample fixtures.
 */

import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileCode,
  Link2,
  FolderArchive,
  ArrowRight,
  Sparkles,
  AlertCircle,
  CheckCircle2,
  Cpu,
} from 'lucide-react';
import { SAMPLE_APKS, SampleApkDefinition } from '../runtime/apk-loader/sample-apks';

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
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const processFile = async (file: File) => {
    const filename = file.name;
    const buffer = new Uint8Array(await file.arrayBuffer());

    if (filename.toLowerCase().endsWith('.zip')) {
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
  };

  const handleFetchUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!remoteUrl.trim()) return;

    setUrlError(null);
    setIsFetchingUrl(true);

    try {
      let targetUrl = remoteUrl.trim();
      // Auto-convert standard github release page URLs to raw asset download if possible
      if (targetUrl.includes('github.com') && targetUrl.includes('/releases/tag/')) {
        targetUrl = targetUrl.replace('/releases/tag/', '/releases/download/');
      }

      const res = await fetch(targetUrl, {
        method: 'GET',
        headers: { Accept: 'application/vnd.android.package-archive,application/octet-stream,*/*' },
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }

      const buf = await res.arrayBuffer();
      const filenameMatch = targetUrl.split('/').pop()?.split('?')[0] || 'remote_app.apk';
      const cleanFilename = filenameMatch.endsWith('.apk') || filenameMatch.endsWith('.zip')
        ? filenameMatch
        : `${filenameMatch}.apk`;

      const uint8 = new Uint8Array(buf);
      if (cleanFilename.toLowerCase().endsWith('.zip')) {
        onLoadZipBuffer(uint8, cleanFilename);
      } else {
        onLoadApkBuffer(uint8, cleanFilename);
      }
      setRemoteUrl('');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('Failed to fetch') || msg.includes('CORS') || msg.includes('NetworkError')) {
        setUrlError(
          'Browser CORS restriction prevented fetching directly. GitHub raw release URLs usually require direct download. Please download the file to your computer and drag it into the box below.'
        );
      } else {
        setUrlError(`Download failed: ${msg}`);
      }
    } finally {
      setIsFetchingUrl(false);
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
          Run Android Apps in Your Browser
        </h1>
        <p className="mt-3 text-base text-slate-600 dark:text-slate-400 max-w-2xl mx-auto" style={{ textWrap: 'balance' }}>
          Independent, browser-based Android execution environment. Ingest real APK files, inspect binary manifests, disassemble Dalvik bytecode, and evaluate compatibility without cloud servers.
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

        {/* Loading Overlay */}
        {(isLoading || isFetchingUrl) && (
          <div className="absolute inset-0 bg-white/90 dark:bg-slate-900/90 backdrop-blur-sm rounded-2xl flex flex-col items-center justify-center p-6 z-10">
            <div className="w-10 h-10 border-3 border-indigo-600 border-t-transparent rounded-full animate-spin mb-4" />
            <p className="text-sm font-semibold text-slate-900 dark:text-white">
              {loadingMessage || 'Processing Android archive...'}
            </p>
            {loadProgress !== undefined && loadProgress > 0 && (
              <div className="w-64 bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
                <div
                  className="bg-indigo-600 h-full transition-all duration-200"
                  style={{ width: `${Math.min(100, Math.round(loadProgress * 100))}%` }}
                />
              </div>
            )}
          </div>
        )}
      </div>

      {/* Secondary Import Row: Remote GitHub Release URL & Pre-packaged Samples */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* GitHub / Remote APK URL */}
        <div className="lg:col-span-5 p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white mb-2">
            <Link2 className="w-4 h-4 text-indigo-500" />
            <span>Import from Public GitHub Release</span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
            Enter direct link to a public <span className="font-mono">.apk</span> release asset
          </p>

          <form onSubmit={handleFetchUrl} className="flex gap-2">
            <input
              type="url"
              placeholder="https://github.com/.../release.apk"
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
              <span>Fetch</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>

          {urlError && (
            <div className="mt-3 p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/50 flex gap-2 text-xs text-amber-800 dark:text-amber-300">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
              <span>{urlError}</span>
            </div>
          )}
        </div>

        {/* 1-Click Built-In Sample Test APKs */}
        <div className="lg:col-span-7 p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Sparkles className="w-4 h-4 text-cyan-500" />
              <span>Instant Test APK Fixtures</span>
            </div>
            <span className="text-xs text-slate-500 dark:text-slate-400">1-click validation</span>
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
                  <span
                    className={
                      sample.expectedStatus === 'SUPPORTED'
                        ? 'text-emerald-600 dark:text-emerald-400 font-semibold'
                        : 'text-amber-600 dark:text-amber-400 font-semibold'
                    }
                  >
                    {sample.expectedStatus}
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
