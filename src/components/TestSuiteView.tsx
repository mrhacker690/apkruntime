/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - In-Browser Automated Test Suite
 * Executes live technical assertions against ZIP, AXML, DEX, ELF, and Compatibility modules.
 */

import React, { useState, useEffect } from 'react';
import { TestCaseResult } from '../runtime/core/types';
import { runAllRuntimeTests } from '../runtime/tests/runtime-tests';
import { ShieldCheck, Play, CheckCircle2, XCircle, RotateCcw, Clock } from 'lucide-react';

export const TestSuiteView: React.FC = () => {
  const [results, setResults] = useState<TestCaseResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [completedCount, setCompletedCount] = useState(0);

  const runTests = async () => {
    setIsRunning(true);
    setResults([]);
    setCompletedCount(0);

    const testResults = await runAllRuntimeTests((res) => {
      setResults(prev => [...prev, res]);
      setCompletedCount(c => c + 1);
    });

    setIsRunning(false);
  };

  useEffect(() => {
    // Automatically execute tests on mount so user sees instant live results
    runTests();
  }, []);

  const totalPassed = results.filter(r => r.passed).length;
  const totalFailed = results.filter(r => !r.passed).length;
  const totalDuration = results.reduce((acc, r) => acc + r.durationMs, 0);

  return (
    <div className="space-y-6">
      {/* Test Suite Hero Bar */}
      <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-500" />
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                Core Runtime Automated Test Suite
              </h2>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Real cryptographic, binary XML, Dalvik instruction, and ZIP archive validation tests.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={runTests}
              disabled={isRunning}
              className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg shadow-sm transition-all flex items-center gap-2 whitespace-nowrap"
            >
              {isRunning ? (
                <>
                  <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                  <span>Running Tests ({completedCount}/8)...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Re-run All Tests</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="pt-4 grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
          <div>
            <span className="text-slate-500 text-[11px]">Total Tests</span>
            <div className="text-lg font-bold text-slate-900 dark:text-white tabular-nums">
              8 Suites
            </div>
          </div>
          <div>
            <span className="text-slate-500 text-[11px]">Passed</span>
            <div className="text-lg font-bold text-emerald-600 dark:text-emerald-400 tabular-nums">
              {totalPassed}
            </div>
          </div>
          <div>
            <span className="text-slate-500 text-[11px]">Failed</span>
            <div className="text-lg font-bold text-rose-600 dark:text-rose-400 tabular-nums">
              {totalFailed}
            </div>
          </div>
          <div>
            <span className="text-slate-500 text-[11px]">Duration</span>
            <div className="text-lg font-bold text-slate-900 dark:text-white tabular-nums">
              {totalDuration.toFixed(2)} ms
            </div>
          </div>
        </div>
      </div>

      {/* Tests Results List */}
      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-100 dark:border-slate-800 text-xs font-bold text-slate-500 uppercase tracking-wider">
          Individual Test Assertions
        </div>

        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {results.map((res) => (
            <div key={res.id} className="p-4 flex items-start justify-between gap-4 hover:bg-slate-50 dark:hover:bg-slate-950/40">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 shrink-0">
                  {res.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-500" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-slate-900 dark:text-white">
                      {res.name}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                      {res.module}
                    </span>
                  </div>

                  {res.error && (
                    <div className="mt-2 p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-xs font-mono text-rose-700 dark:text-rose-300">
                      {res.error}
                    </div>
                  )}
                </div>
              </div>

              <div className="text-right shrink-0 font-mono text-xs text-slate-400 tabular-nums">
                {res.durationMs.toFixed(2)} ms
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
