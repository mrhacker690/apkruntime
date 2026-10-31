/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Manifest Inspector Component
 * Renders decoded AndroidManifest.xml components, permissions, features, and reconstructed XML.
 */

import React, { useState } from 'react';
import { AndroidManifestData } from '../runtime/core/types';
import {
  ShieldAlert,
  Radio,
  FileCode2,
  Copy,
  Check,
  Zap,
  Boxes,
  Compass,
} from 'lucide-react';

interface ManifestViewProps {
  manifest: AndroidManifestData;
}

export const ManifestView: React.FC<ManifestViewProps> = ({ manifest }) => {
  const [copied, setCopied] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'components' | 'permissions' | 'xml'>('components');

  const copyXml = () => {
    navigator.clipboard.writeText(manifest.rawXml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Sub-navigation */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveSubTab('components')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeSubTab === 'components'
                ? 'bg-slate-900 text-white dark:bg-slate-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Components ({manifest.activities.length + manifest.services.length + manifest.receivers.length})
          </button>
          <button
            onClick={() => setActiveSubTab('permissions')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeSubTab === 'permissions'
                ? 'bg-slate-900 text-white dark:bg-slate-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Permissions ({manifest.permissions.length})
          </button>
          <button
            onClick={() => setActiveSubTab('xml')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeSubTab === 'xml'
                ? 'bg-slate-900 text-white dark:bg-slate-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Reconstructed XML
          </button>
        </div>

        {activeSubTab === 'xml' && (
          <button
            onClick={copyXml}
            className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors flex items-center gap-1.5"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy XML'}</span>
          </button>
        )}
      </div>

      {/* 1. Components Tab */}
      {activeSubTab === 'components' && (
        <div className="space-y-6">
          {/* Activities */}
          <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
              <Compass className="w-4 h-4 text-indigo-500" />
              <span>Activities ({manifest.activities.length})</span>
            </h3>

            {manifest.activities.length === 0 ? (
              <p className="text-xs text-slate-500">No activities declared in manifest.</p>
            ) : (
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {manifest.activities.map((act, idx) => (
                  <div key={idx} className="py-3 flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-semibold text-slate-900 dark:text-white">
                          {act.name}
                        </span>
                        {act.isLauncher && (
                          <span className="px-2 py-0.5 text-[10px] font-semibold text-indigo-700 dark:text-indigo-300 bg-indigo-50 dark:bg-indigo-950/60 rounded">
                            LAUNCHER ENTRY
                          </span>
                        )}
                        {act.exported && (
                          <span className="px-2 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 rounded">
                            exported
                          </span>
                        )}
                      </div>
                      {act.label && (
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          Label: {act.label}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Services, Receivers & Providers */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Services */}
            <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-500" />
                <span>Services ({manifest.services.length})</span>
              </h3>
              {manifest.services.length === 0 ? (
                <p className="text-xs text-slate-500">No background services declared.</p>
              ) : (
                <ul className="space-y-2 text-xs font-mono text-slate-800 dark:text-slate-300">
                  {manifest.services.map((svc, i) => (
                    <li key={i} className="p-2 rounded bg-slate-50 dark:bg-slate-950/60 truncate">
                      {svc.name}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Broadcast Receivers */}
            <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-500" />
                <span>Broadcast Receivers ({manifest.receivers.length})</span>
              </h3>
              {manifest.receivers.length === 0 ? (
                <p className="text-xs text-slate-500">No broadcast receivers declared.</p>
              ) : (
                <ul className="space-y-2 text-xs font-mono text-slate-800 dark:text-slate-300">
                  {manifest.receivers.map((rec, i) => (
                    <li key={i} className="p-2 rounded bg-slate-50 dark:bg-slate-950/60 truncate">
                      {rec.name}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 2. Permissions Tab */}
      {activeSubTab === 'permissions' && (
        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>Requested Android Permissions ({manifest.permissions.length})</span>
            </h3>
          </div>

          {manifest.permissions.length === 0 ? (
            <p className="text-xs text-slate-500">No special permissions requested by this application.</p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800 font-mono text-xs">
              {manifest.permissions.map((perm, idx) => {
                const shortName = perm.replace('android.permission.', '');
                const isDangerous = perm.includes('CAMERA') || perm.includes('LOCATION') || perm.includes('STORAGE') || perm.includes('CONTACTS') || perm.includes('AUDIO');
                return (
                  <div key={idx} className="py-2.5 flex items-center justify-between gap-4">
                    <span className="text-slate-900 dark:text-slate-200 font-medium truncate">
                      {perm}
                    </span>
                    <span
                      className={`text-[10px] font-sans font-semibold px-2 py-0.5 rounded ${
                        isDangerous
                          ? 'bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400'
                          : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      {isDangerous ? 'Dangerous / Runtime' : 'Normal'}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* 3. Reconstructed XML Tab */}
      {activeSubTab === 'xml' && (
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-950 text-slate-200 p-5 font-mono text-xs overflow-x-auto leading-relaxed max-h-[600px] overflow-y-auto">
          <pre className="whitespace-pre">
            {manifest.rawXml}
          </pre>
        </div>
      )}
    </div>
  );
};
