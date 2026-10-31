/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Master Application Shell
 */

import React, { useState } from 'react';
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
import { AlertCircle, Smartphone, Sparkles } from 'lucide-react';

export default function App() {
  // Start with clean dashboard (no auto-loaded samples) as mandated by Task 3
  const [report, setReport] = useState<ApkAnalysisReport | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [isLoading, setIsLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState('Parsing APK archive...');
  const [loadProgress, setLoadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<RuntimeLog[]>([]);

  // Fixed theme initialization: checks localStorage and class, no unconditional "|| true"
  const [isDark, setIsDark] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('apk_theme');
      if (stored !== null) return stored === 'dark';
      return document.documentElement.classList.contains('dark');
    }
    return true;
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
      localStorage.setItem('apk_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('apk_theme', 'light');
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

  const handleLoadSampleFixture = (fixtureIndex: number = 0) => {
    const fixture = SAMPLE_APKS[fixtureIndex] || SAMPLE_APKS[0];
    const bytes = fixture.generate();
    handleProcessApkBuffer(bytes, fixture.name);
  };

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

            {report ? (
              <OverviewCard
                report={report}
                onAddLog={addLog}
              />
            ) : (
              /* Clean Empty State as mandated by Task 3 */
              <div className="p-8 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-center space-y-3">
                <div className="w-12 h-12 mx-auto rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-400 flex items-center justify-center">
                  <Smartphone className="w-6 h-6" />
                </div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white">
                  No APK Archive Loaded
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
                  Upload an Android <span className="font-mono">.apk</span> package above, fetch from a public GitHub release, or run a synthetic test fixture to verify parser outputs.
                </p>
                <div className="pt-2">
                  <button
                    onClick={() => handleLoadSampleFixture(0)}
                    className="px-3.5 py-2 text-xs font-semibold text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/50 hover:bg-indigo-100 dark:hover:bg-indigo-900/60 rounded-lg transition-colors inline-flex items-center gap-1.5"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Analyze Synthetic Test Fixture (HelloAndroid.apk)</span>
                  </button>
                </div>
              </div>
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

        {/* Runtime Diagnostics Console */}
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

      {/* Editorial Footer (Strict Apache-2.0 Notice) */}
      <footer className="border-t border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-950 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-700 dark:text-slate-300">
              APK Runtime Engine
            </span>
            <span aria-hidden="true">·</span>
            <span>Independent Browser-Based Android Execution</span>
            <span aria-hidden="true">·</span>
            <span>Phase 1 Analysis Foundation</span>
          </div>

          <div className="flex items-center gap-4 text-slate-500">
            <span>Client-side WebAssembly & TS Engine</span>
            <span aria-hidden="true">·</span>
            <span>Apache-2.0 License</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
