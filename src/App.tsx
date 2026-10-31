/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Master Application Shell
 */

import React, { useState, useEffect } from 'react';
import {
  ApkAnalysisReport,
  RuntimeLog,
} from './runtime/core/types';
import { ApkRuntimeService } from './runtime/apk-loader/runtime-service';
import { SAMPLE_APKS } from './runtime/apk-loader/sample-apks';
import { Header, ActiveTab } from './components/Header';
import { ImportZone } from './components/ImportZone';
import { OverviewCard } from './components/OverviewCard';
import { ManifestView } from './components/ManifestView';
import { DexExplorer } from './components/DexExplorer';
import { NativeLibsView } from './components/NativeLibsView';
import { ArchiveFilesView } from './components/ArchiveFilesView';
import { CompatibilityView } from './components/CompatibilityView';
import { TestSuiteView } from './components/TestSuiteView';
import { DocumentationView } from './components/DocumentationView';
import { RuntimeConsole } from './components/RuntimeConsole';
import { ZipApkModal } from './components/ZipApkModal';
import { AlertCircle, RotateCcw } from 'lucide-react';

export default function App() {
  const [report, setReport] = useState<ApkAnalysisReport | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [isLoading, setIsLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState('Parsing APK archive...');
  const [loadProgress, setLoadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<RuntimeLog[]>([]);

  // Dark/Light Theme state
  const [isDark, setIsDark] = useState<boolean>(() => {
    return document.documentElement.classList.contains('dark') || true;
  });

  // ZIP modal state
  const [zipModalOpen, setZipModalOpen] = useState(false);
  const [discoveredApks, setDiscoveredApks] = useState<{ name: string; size: number }[]>([]);
  const [pendingZipBuffer, setPendingZipBuffer] = useState<Uint8Array | null>(null);
  const [pendingZipName, setPendingZipName] = useState('');

  const toggleTheme = () => {
    const nextDark = !isDark;
    setIsDark(nextDark);
    if (nextDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  const addLog = (level: RuntimeLog['level'], source: string, message: string) => {
    const log: RuntimeLog = {
      id: Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toLocaleTimeString(),
      level,
      source,
      message,
    };
    setLogs(prev => [log, ...prev].slice(0, 100));
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const handleProcessApkBuffer = async (buffer: Uint8Array, filename: string) => {
    setError(null);
    setIsLoading(true);
    setLoadingMessage(`Analyzing "${filename}"...`);
    setLoadProgress(0.2);

    try {
      const result = await ApkRuntimeService.analyzeApk(buffer, filename, (log) => {
        addLog(log.level, log.source, log.message);
      });
      setReport(result);
      setActiveTab('overview');
      setLoadProgress(1.0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      addLog('error', 'Pipeline', `Analysis failed: ${msg}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleProcessZipBuffer = async (zipBuffer: Uint8Array, filename: string) => {
    setError(null);
    setIsLoading(true);
    setLoadingMessage(`Inspecting ZIP container "${filename}"...`);

    try {
      const apks = await ApkRuntimeService.discoverApksInZip(zipBuffer);
      if (apks.length === 0) {
        throw new Error(`No .apk files found inside ZIP archive "${filename}".`);
      }

      if (apks.length === 1) {
        // Automatically extract the single APK
        addLog('info', 'ZIP Container', `Found single APK "${apks[0].name}", extracting...`);
        const apkBytes = await ApkRuntimeService.extractApkFromZip(zipBuffer, apks[0].name);
        await handleProcessApkBuffer(apkBytes, apks[0].name);
      } else {
        // Multiple APKs: show modal selector
        setDiscoveredApks(apks);
        setPendingZipBuffer(zipBuffer);
        setPendingZipName(filename);
        setZipModalOpen(true);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      addLog('error', 'ZIP Container', msg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectApkFromZip = async (apkName: string) => {
    if (!pendingZipBuffer) return;
    setZipModalOpen(false);
    setIsLoading(true);
    setLoadingMessage(`Extracting "${apkName}" from ZIP...`);

    try {
      const apkBytes = await ApkRuntimeService.extractApkFromZip(pendingZipBuffer, apkName);
      await handleProcessApkBuffer(apkBytes, apkName);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // Pre-load default fixture on initial boot so dashboard is never empty
  useEffect(() => {
    const defaultSample = SAMPLE_APKS[0];
    const bytes = defaultSample.generate();
    handleProcessApkBuffer(bytes, defaultSample.name);
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col selection:bg-indigo-500 selection:text-white">
      {/* Strict 3-Zone Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isDark={isDark}
        toggleTheme={toggleTheme}
        hasLoadedApk={Boolean(report)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Error Banner */}
        {error && (
          <div className="p-4 rounded-xl border border-rose-300 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 text-xs text-rose-800 dark:text-rose-200 flex items-start gap-3">
            <AlertCircle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="font-bold">Error Analyzing APK Archive</p>
              <p className="mt-0.5 leading-relaxed font-mono">{error}</p>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-slate-400 hover:text-slate-600 dark:hover:text-white"
            >
              ✕
            </button>
          </div>
        )}

        {/* View Routing */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            <ImportZone
              onLoadApkBuffer={handleProcessApkBuffer}
              onLoadZipBuffer={handleProcessZipBuffer}
              isLoading={isLoading}
              loadingMessage={loadingMessage}
              loadProgress={loadProgress}
            />

            {report && (
              <OverviewCard
                report={report}
                onAddLog={addLog}
              />
            )}
          </div>
        )}

        {activeTab === 'manifest' && report && (
          <ManifestView manifest={report.manifest} />
        )}

        {activeTab === 'dex' && report && (
          <DexExplorer dexFiles={report.dexFiles} />
        )}

        {activeTab === 'native' && report && (
          <NativeLibsView nativeLibs={report.nativeLibraries} />
        )}

        {activeTab === 'files' && report && (
          <ArchiveFilesView archive={report.archive} />
        )}

        {activeTab === 'compatibility' && report && (
          <CompatibilityView compatibility={report.compatibility} />
        )}

        {activeTab === 'tests' && (
          <TestSuiteView />
        )}

        {activeTab === 'docs' && (
          <DocumentationView />
        )}

        {/* Runtime Diagnostics Console (Always accessible at bottom) */}
        <RuntimeConsole
          logs={logs}
          onClearLogs={clearLogs}
        />
      </main>

      {/* ZIP Multi-APK Selector Modal */}
      <ZipApkModal
        isOpen={zipModalOpen}
        onClose={() => setZipModalOpen(false)}
        apks={discoveredApks}
        onSelectApk={handleSelectApkFromZip}
        zipName={pendingZipName}
      />

      {/* Editorial Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-950 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-700 dark:text-slate-300">
              APK Runtime Engine
            </span>
            <span aria-hidden="true">·</span>
            <span>Independent Browser-Based Android Execution</span>
            <span aria-hidden="true">·</span>
            <span>Phase 1 Milestone</span>
          </div>

          <div className="flex items-center gap-4 text-slate-500">
            <span>Client-side WebAssembly & TS Runtime</span>
            <span aria-hidden="true">·</span>
            <span>MIT License</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
