/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Header Component
 * Strict Top Bar Contract: Brand zone (1 line) — Navigation links — Primary action & theme switch
 */

import React from 'react';
import { Moon, Sun, Layers, PlayCircle, ShieldCheck, BookOpen, Terminal, Github } from 'lucide-react';

export type ActiveTab =
  | 'overview'
  | 'manifest'
  | 'dex'
  | 'native'
  | 'files'
  | 'compatibility'
  | 'tests'
  | 'docs';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  isDark: boolean;
  toggleTheme: () => void;
  hasLoadedApk: boolean;
  onRunTestClick?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  isDark,
  toggleTheme,
  hasLoadedApk,
  onRunTestClick,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-950/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Brand Wordmark (Single line, display face) */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => setActiveTab('overview')}
            className="flex items-center gap-2.5 text-left focus:outline-none group"
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-indigo-600 via-blue-600 to-cyan-500 p-0.5 flex items-center justify-center shadow-sm">
              <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                <Layers className="w-5 h-5 text-cyan-400 group-hover:scale-105 transition-transform" />
              </div>
            </div>
            <span className="text-base font-bold tracking-tight text-slate-900 dark:text-white whitespace-nowrap">
              APK Runtime Engine
            </span>
          </button>
        </div>

        {/* Zone 2: Navigation Links (Single-line, unboxed, subtle hover) */}
        <nav className="hidden md:flex items-center gap-1 lg:gap-2 text-sm font-medium text-slate-600 dark:text-slate-400">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              activeTab === 'overview'
                ? 'text-indigo-600 dark:text-indigo-400 font-semibold bg-indigo-50/60 dark:bg-indigo-950/40'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Dashboard
          </button>

          <button
            onClick={() => setActiveTab('manifest')}
            disabled={!hasLoadedApk}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              !hasLoadedApk
                ? 'opacity-40 cursor-not-allowed'
                : activeTab === 'manifest'
                ? 'text-indigo-600 dark:text-indigo-400 font-semibold bg-indigo-50/60 dark:bg-indigo-950/40'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Manifest
          </button>

          <button
            onClick={() => setActiveTab('dex')}
            disabled={!hasLoadedApk}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              !hasLoadedApk
                ? 'opacity-40 cursor-not-allowed'
                : activeTab === 'dex'
                ? 'text-indigo-600 dark:text-indigo-400 font-semibold bg-indigo-50/60 dark:bg-indigo-950/40'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            DEX Bytecode
          </button>

          <button
            onClick={() => setActiveTab('native')}
            disabled={!hasLoadedApk}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              !hasLoadedApk
                ? 'opacity-40 cursor-not-allowed'
                : activeTab === 'native'
                ? 'text-indigo-600 dark:text-indigo-400 font-semibold bg-indigo-50/60 dark:bg-indigo-950/40'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Native Libs
          </button>

          <button
            onClick={() => setActiveTab('compatibility')}
            disabled={!hasLoadedApk}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap ${
              !hasLoadedApk
                ? 'opacity-40 cursor-not-allowed'
                : activeTab === 'compatibility'
                ? 'text-indigo-600 dark:text-indigo-400 font-semibold bg-indigo-50/60 dark:bg-indigo-950/40'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Compatibility
          </button>

          <button
            onClick={() => setActiveTab('tests')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'tests'
                ? 'text-indigo-600 dark:text-indigo-400 font-semibold bg-indigo-50/60 dark:bg-indigo-950/40'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <ShieldCheck className="w-4 h-4 text-emerald-500 inline" />
            <span>Test Suite</span>
          </button>

          <button
            onClick={() => setActiveTab('docs')}
            className={`px-3 py-1.5 rounded-md transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'docs'
                ? 'text-indigo-600 dark:text-indigo-400 font-semibold bg-indigo-50/60 dark:bg-indigo-950/40'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <BookOpen className="w-4 h-4 text-slate-400 inline" />
            <span>Roadmap & Docs</span>
          </button>
        </nav>

        {/* Zone 3: Actions & Theme Toggle */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={toggleTheme}
            aria-label="Toggle Theme"
            className="p-2 rounded-lg text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-900 transition-colors"
          >
            {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>

          <a
            href="https://github.com/mrhacker690/apkruntime"
            target="_blank"
            rel="noreferrer"
            aria-label="View on GitHub"
            className="p-2 rounded-lg text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-900 transition-colors hidden sm:inline-flex"
          >
            <Github className="w-4 h-4" />
          </a>

          <button
            onClick={() => setActiveTab('tests')}
            className="px-3.5 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg shadow-sm transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Run Test Suite</span>
          </button>
        </div>
      </div>
    </header>
  );
};
