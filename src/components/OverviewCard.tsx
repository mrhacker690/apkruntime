/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Overview & Honest Runtime Status Card
 * Displays APK metadata, honest compatibility badge, and transparent Phase 1 status panel.
 * Strictly adheres to QA constitution: zero fake execution, zero simulated registers or lifecycles.
 */

import React, { useState } from 'react';
import {
  ApkAnalysisReport,
  RuntimeLog,
} from '../runtime/core/types';
import {
  Play,
  Info,
  XCircle,
  Copy,
  Check,
  Smartphone,
  Cpu,
  Layers,
  AlertCircle,
  Clock,
  Terminal,
} from 'lucide-react';

interface OverviewCardProps {
  report: ApkAnalysisReport;
  onAddLog: (level: RuntimeLog['level'], source: string, message: string) => void;
}

export const OverviewCard: React.FC<OverviewCardProps> = ({ report, onAddLog }) => {
  const [copiedHash, setCopiedHash] = useState(false);

  const { manifest, archive, dexFiles, nativeLibraries, compatibility } = report;

  const copySha256 = () => {
    navigator.clipboard.writeText(archive.sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Status Badge Colors & Icons (Task 2 & 8: Transparent status)
  const isInvalid = compatibility.status === 'NOT_SUPPORTED';

  return (
    <div className="space-y-6">
      {/* Top Banner: Main Identity, Stats, and Honest Status Badge */}
      <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-100 dark:border-slate-800">
          <div className="flex items-start gap-4">
            {/* App Icon Representation */}
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-indigo-500 to-cyan-500 p-0.5 shadow-md shrink-0 flex items-center justify-center">
              <div className="w-full h-full bg-slate-950 rounded-[14px] flex items-center justify-center">
                <Smartphone className="w-8 h-8 text-cyan-400" />
              </div>
            </div>

            <div>
              <div className="flex items-center gap-3 flex-wrap">
                <h2 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
                  {manifest.appLabel || archive.filename}
                </h2>

                {/* Compatibility Badge: Transparent, never claims executable */}
                <div
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-semibold ${
                    isInvalid
                      ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-800'
                      : 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400 border-sky-300 dark:border-sky-800'
                  }`}
                >
                  {isInvalid ? <XCircle className="w-3.5 h-3.5" /> : <Info className="w-3.5 h-3.5" />}
                  <span>{compatibility.statusBadge}</span>
                </div>
              </div>

              <div className="mt-1 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono flex-wrap">
                <span className="text-slate-800 dark:text-slate-200 font-medium">
                  {manifest.packageName}
                </span>
                <span aria-hidden="true">·</span>
                <span>{manifest.versionName ? `v${manifest.versionName}` : 'Version: unspecified'}</span>
                <span aria-hidden="true">·</span>
                <span className="tabular-nums">
                  {manifest.versionCode !== undefined ? `(Code ${manifest.versionCode})` : '(Code unspecified)'}
                </span>
                <span aria-hidden="true">·</span>
                <span>{(archive.fileSize / 1024).toFixed(1)} KB</span>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 lg:gap-6 border-t lg:border-t-0 pt-4 lg:pt-0 border-slate-100 dark:border-slate-800">
            <div>
              <div className="text-[11px] font-medium text-slate-500 dark:text-slate-400">Min SDK</div>
              <div className="text-lg font-bold text-slate-900 dark:text-white font-mono tabular-nums">
                {manifest.minSdkVersion !== undefined ? `API ${manifest.minSdkVersion}` : 'Unspecified'}
              </div>
            </div>
            <div>
              <div className="text-[11px] font-medium text-slate-500 dark:text-slate-400">Target SDK</div>
              <div className="text-lg font-bold text-slate-900 dark:text-white font-mono tabular-nums">
                {manifest.targetSdkVersion !== undefined ? `API ${manifest.targetSdkVersion}` : 'Unspecified'}
              </div>
            </div>
            <div>
              <div className="text-[11px] font-medium text-slate-500 dark:text-slate-400">DEX Files</div>
              <div className="text-lg font-bold text-slate-900 dark:text-white font-mono tabular-nums">
                {dexFiles.length}
              </div>
            </div>
            <div>
              <div className="text-[11px] font-medium text-slate-500 dark:text-slate-400">Native ABIs</div>
              <div className="text-lg font-bold text-slate-900 dark:text-white font-mono">
                {nativeLibraries.length === 0 ? 'None (Bytecode)' : `${nativeLibraries.length} .so`}
              </div>
            </div>
          </div>
        </div>

        {/* Technical Identification Strip */}
        <div className="pt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 overflow-hidden text-slate-600 dark:text-slate-400 font-mono">
            <span className="font-semibold text-slate-500 shrink-0">SHA-256:</span>
            <span className="truncate tabular-nums text-slate-800 dark:text-slate-300">
              {archive.sha256}
            </span>
            <button
              onClick={copySha256}
              className="p-1 text-slate-400 hover:text-slate-900 dark:hover:text-white shrink-0"
              title="Copy SHA-256"
            >
              {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          <div className="text-slate-500 dark:text-slate-400 shrink-0">
            Launcher Activity:{' '}
            <span className="font-mono text-slate-900 dark:text-white font-medium">
              {manifest.launcherActivity || 'Unspecified (No MAIN/LAUNCHER filter)'}
            </span>
          </div>
        </div>
      </div>

      {/* Honest Runtime Status Panel (Mandated by Task 2) */}
      <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white">
              Application Runtime Engine
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Browser-side execution environment status
            </p>
          </div>

          {/* Run button must remain disabled as mandated by Task 2 */}
          <div className="flex items-center gap-2">
            <button
              disabled={true}
              title="Execution is unavailable in Phase 1 (DEX VM is scheduled for Phase 4)"
              className="px-4 py-2 text-xs font-semibold text-slate-400 bg-slate-100 dark:bg-slate-800 cursor-not-allowed rounded-lg transition-all flex items-center gap-2 whitespace-nowrap opacity-60"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run Application (Disabled)</span>
            </button>
          </div>
        </div>

        {/* Explicit Status Grid: Exact Strings Mandated by Task 2 */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 font-mono text-xs">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">Engine State</div>
            <div className="font-bold text-amber-600 dark:text-amber-400 mt-1">
              RUNTIME ENGINE: NOT IMPLEMENTED
            </div>
          </div>

          <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 font-mono text-xs">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">Application Status</div>
            <div className="font-bold text-sky-600 dark:text-sky-400 mt-1">
              APPLICATION STATUS: ANALYSIS ONLY
            </div>
          </div>

          <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 font-mono text-xs">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">Execution Availability</div>
            <div className="font-bold text-slate-600 dark:text-slate-300 mt-1">
              EXECUTION: UNAVAILABLE
            </div>
          </div>
        </div>

        {/* Clear Technical Explanation */}
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-950/40 text-xs text-slate-600 dark:text-slate-400 space-y-1.5 leading-relaxed">
          <div className="flex items-center gap-1.5 font-semibold text-slate-800 dark:text-slate-200">
            <Info className="w-4 h-4 text-indigo-500" />
            <span>Phase 1 Verification Policy</span>
          </div>
          <p>
            This software strictly avoids simulated execution. The APK archive, binary XML manifest, Dalvik DEX bytecode, Adler-32 checksums, and native ELF libraries have been parsed and verified using client-side algorithms.
          </p>
          <p className="text-[11px] text-slate-500">
            Actual bytecode execution requires the register-based Dalvik Virtual Machine (Phase 4) and Android Framework compatibility layer (Phase 5). See the Roadmap tab for milestone details.
          </p>
        </div>
      </div>
    </div>
  );
};
