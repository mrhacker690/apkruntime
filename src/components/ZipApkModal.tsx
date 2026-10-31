/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - ZIP Multi-APK Discovery & Selection Modal
 */

import React from 'react';
import { FolderArchive, Smartphone, X, ArrowRight } from 'lucide-react';

interface DiscoveredApk {
  name: string;
  size: number;
}

interface ZipApkModalProps {
  isOpen: boolean;
  onClose: () => void;
  apks: DiscoveredApk[];
  onSelectApk: (apkName: string) => void;
  zipName: string;
}

export const ZipApkModal: React.FC<ZipApkModalProps> = ({
  isOpen,
  onClose,
  apks,
  onSelectApk,
  zipName,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="p-5 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <FolderArchive className="w-5 h-5 text-indigo-500" />
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                Discovered APKs in ZIP
              </h3>
              <p className="text-xs text-slate-500 font-mono truncate max-w-xs">
                {zipName}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
            Found {apks.length} Android application package{apks.length > 1 ? 's' : ''} inside this archive. Select which APK to extract and inspect:
          </p>

          <div className="space-y-2 max-h-72 overflow-y-auto">
            {apks.map((apk, idx) => (
              <button
                key={idx}
                onClick={() => onSelectApk(apk.name)}
                className="w-full p-3 text-left rounded-xl border border-slate-200 dark:border-slate-800 hover:border-indigo-500 dark:hover:border-indigo-500 hover:bg-indigo-50/40 dark:hover:bg-indigo-950/20 transition-all flex items-center justify-between group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 flex items-center justify-center text-indigo-600 dark:text-indigo-400 group-hover:scale-105 transition-transform">
                    <Smartphone className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-mono font-bold text-slate-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400">
                      {apk.name}
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono tabular-nums">
                      {(apk.size / 1024).toFixed(1)} KB
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1 text-xs font-semibold text-indigo-600 dark:text-indigo-400 group-hover:translate-x-1 transition-transform">
                  <span>Extract</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="p-4 bg-slate-50 dark:bg-slate-950/60 border-t border-slate-100 dark:border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};
