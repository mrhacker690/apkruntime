/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Compatibility Matrix View
 * Transparent, technically grounded breakdown of APK execution capabilities.
 */

import React from 'react';
import { CompatibilityReport } from '../runtime/core/types';
import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Info,
  Check,
  ArrowRight,
} from 'lucide-react';

interface CompatibilityViewProps {
  compatibility: CompatibilityReport;
}

export const CompatibilityView: React.FC<CompatibilityViewProps> = ({ compatibility }) => {
  return (
    <div className="space-y-6">
      {/* Tier Explanation Card */}
      <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold text-indigo-600 dark:text-indigo-400">
              Evaluation Result
            </span>
            <h3 className="text-xl font-bold text-slate-900 dark:text-white mt-0.5">
              Compatibility Tier: {compatibility.statusBadge}
            </h3>
          </div>

          <div
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 ${
              compatibility.status === 'SUPPORTED'
                ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800'
                : compatibility.status === 'PARTIALLY_SUPPORTED'
                ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800'
                : 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400 border border-sky-200 dark:border-sky-800'
            }`}
          >
            {compatibility.status === 'SUPPORTED' ? (
              <CheckCircle2 className="w-4 h-4" />
            ) : (
              <Info className="w-4 h-4" />
            )}
            <span>{compatibility.readyForExecution ? 'Ready for Execution' : 'Analysis Mode'}</span>
          </div>
        </div>

        <p className="mt-4 text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
          {compatibility.summary}
        </p>
      </div>

      {/* Heuristic Checks List */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-100 dark:border-slate-800">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-indigo-500" />
            <span>Compatibility & Environment Verification ({compatibility.checks.length} checks)</span>
          </h3>
        </div>

        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {compatibility.checks.map((check, idx) => (
            <div key={idx} className="p-4 flex items-start gap-3">
              <div className="mt-0.5 shrink-0">
                {check.level === 'success' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                ) : check.level === 'warning' ? (
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-500" />
                )}
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-900 dark:text-white">
                    {check.title}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium ${
                      check.passed
                        ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    {check.passed ? 'PASSED' : 'REQUIRES PHASE EXPANSION'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  {check.detail}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Missing APIs Box if any */}
      {compatibility.missingApis.length > 0 && (
        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            External Proprietary Dependencies ({compatibility.missingApis.length})
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            These services require Google Play proprietary packages not bundled in standard open-source Android:
          </p>
          <ul className="space-y-1.5 font-mono text-xs">
            {compatibility.missingApis.map((api, i) => (
              <li key={i} className="p-2 rounded bg-slate-50 dark:bg-slate-950/60 text-slate-700 dark:text-slate-300">
                {api}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
