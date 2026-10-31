/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Native Library (ELF) Inspector
 * Dissects native shared libraries, machine architectures, and ABI requirements.
 */

import React from 'react';
import { NativeLibraryInfo } from '../runtime/core/types';
import { Cpu, FileCode, CheckCircle2, AlertTriangle, Layers, Info } from 'lucide-react';

interface NativeLibsViewProps {
  nativeLibs: NativeLibraryInfo[];
}

export const NativeLibsView: React.FC<NativeLibsViewProps> = ({ nativeLibs }) => {
  if (nativeLibs.length === 0) {
    return (
      <div className="p-8 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-center space-y-3">
        <div className="w-12 h-12 mx-auto rounded-xl bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
          <CheckCircle2 className="w-6 h-6" />
        </div>
        <h3 className="text-base font-bold text-slate-900 dark:text-white">
          Pure Bytecode Application
        </h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
          No native ELF compiled shared libraries (<span className="font-mono">.so</span>) found in the <span className="font-mono">lib/</span> directory. This application runs entirely through Dalvik/ART bytecode.
        </p>
      </div>
    );
  }

  const abis = Array.from(new Set(nativeLibs.map(n => n.abi)));

  return (
    <div className="space-y-6">
      {/* Top Banner Notice */}
      <div className="p-5 rounded-2xl border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20 text-xs text-amber-800 dark:text-amber-300 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-bold text-sm">
            Native Machine Code Binaries Detected ({nativeLibs.length} files, ABIs: {abis.join(', ')})
          </p>
          <p className="leading-relaxed">
            These precompiled binary libraries target physical CPU architectures (e.g., ARM64, x86). In accordance with the Phase 10 Roadmap, executing ARM binary instructions in modern web browsers requires a specialized WebAssembly binary translator or JNI emulation layer.
          </p>
        </div>
      </div>

      {/* Libraries Table */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm">
        <div className="p-5 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-indigo-500" />
            <span>Indexed ELF Shared Libraries ({nativeLibs.length})</span>
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            {abis.length} Target ABI{abis.length > 1 ? 's' : ''}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-50 dark:bg-slate-950/60 border-b border-slate-200 dark:border-slate-800 text-slate-500">
              <tr>
                <th className="py-3 px-4 font-semibold">Library File</th>
                <th className="py-3 px-4 font-semibold">ABI Directory</th>
                <th className="py-3 px-4 font-semibold">Target Machine</th>
                <th className="py-3 px-4 font-semibold">Bitness</th>
                <th className="py-3 px-4 font-semibold text-right">Size</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {nativeLibs.map((lib, idx) => (
                <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-950/40">
                  <td className="py-3 px-4 font-bold text-slate-900 dark:text-white">
                    {lib.filename}
                  </td>
                  <td className="py-3 px-4 text-indigo-600 dark:text-indigo-400">
                    {lib.abi}
                  </td>
                  <td className="py-3 px-4 text-slate-600 dark:text-slate-300">
                    {lib.machine}
                  </td>
                  <td className="py-3 px-4 text-slate-500">
                    {lib.bitness} ({lib.endianness})
                  </td>
                  <td className="py-3 px-4 text-right tabular-nums text-slate-700 dark:text-slate-300">
                    {(lib.size / 1024).toFixed(1)} KB
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
