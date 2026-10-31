/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Real-Time Runtime Console
 * Displays live pipeline logs, lifecycle events, and bytecode trace outputs.
 */

import React, { useState } from 'react';
import { RuntimeLog } from '../runtime/core/types';
import { Terminal, Trash2, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react';

interface RuntimeConsoleProps {
  logs: RuntimeLog[];
  onClearLogs: () => void;
}

export const RuntimeConsole: React.FC<RuntimeConsoleProps> = ({ logs, onClearLogs }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyLogs = () => {
    const text = logs.map(l => `[${l.timestamp}] [${l.level.toUpperCase()}] [${l.source}] ${l.message}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">
      <div className="p-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-indigo-500" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            Runtime Diagnostics & Pipeline Trace
          </h3>
          <span className="text-xs text-slate-400 font-mono tabular-nums">
            ({logs.length} events)
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={copyLogs}
            className="p-1.5 text-slate-400 hover:text-slate-900 dark:hover:text-white rounded transition-colors"
            title="Copy Logs"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={onClearLogs}
            className="p-1.5 text-slate-400 hover:text-rose-500 rounded transition-colors"
            title="Clear Logs"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1.5 text-slate-400 hover:text-slate-900 dark:hover:text-white rounded transition-colors"
          >
            {isCollapsed ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {!isCollapsed && (
        <div className="p-4 bg-slate-950 font-mono text-xs text-slate-300 max-h-56 overflow-y-auto space-y-1.5 leading-relaxed">
          {logs.length === 0 ? (
            <div className="text-slate-600 italic">No logs recorded yet.</div>
          ) : (
            logs.map((log) => (
              <div key={log.id} className="flex items-start gap-2.5">
                <span className="text-slate-600 text-[10px] tabular-nums shrink-0 select-none">
                  {log.timestamp}
                </span>
                <span
                  className={`text-[10px] font-semibold uppercase px-1 rounded shrink-0 ${
                    log.level === 'success'
                      ? 'bg-emerald-950 text-emerald-400'
                      : log.level === 'warn'
                      ? 'bg-amber-950 text-amber-400'
                      : log.level === 'error'
                      ? 'bg-rose-950 text-rose-400'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {log.level}
                </span>
                <span className="text-indigo-400 text-[11px] shrink-0 font-medium">
                  [{log.source}]
                </span>
                <span className="text-slate-200 break-all">{log.message}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};
