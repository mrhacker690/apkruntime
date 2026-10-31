/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - DEX Bytecode Explorer & Disassembler
 * Deep inspection of Dalvik Executables, headers, Adler32, string pools, classes, and disassembled bytecode.
 */

import React, { useState } from 'react';
import { DexFileAnalysis, DexClass, DexMethod } from '../runtime/core/types';
import {
  Binary,
  Layers,
  Search,
  Code2,
  FileText,
  Hash,
  ChevronRight,
  Cpu,
} from 'lucide-react';

interface DexExplorerProps {
  dexFiles: DexFileAnalysis[];
}

export const DexExplorer: React.FC<DexExplorerProps> = ({ dexFiles }) => {
  const [selectedDexIndex, setSelectedDexIndex] = useState(0);
  const [activeTab, setActiveTab] = useState<'classes' | 'header' | 'strings'>('classes');
  const [selectedClassIndex, setSelectedClassIndex] = useState(0);
  const [selectedMethodIndex, setSelectedMethodIndex] = useState<number | null>(0);
  const [stringSearch, setStringSearch] = useState('');

  if (dexFiles.length === 0) {
    return (
      <div className="p-8 text-center rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-500">
        No Dalvik Executable (classes.dex) files found in this APK.
      </div>
    );
  }

  const currentDex = dexFiles[selectedDexIndex] || dexFiles[0];
  const currentClass: DexClass | undefined = currentDex.classes[selectedClassIndex] || currentDex.classes[0];
  const currentMethods = currentClass ? [...currentClass.directMethods, ...currentClass.virtualMethods] : [];
  const currentMethod: DexMethod | undefined =
    selectedMethodIndex !== null ? currentMethods[selectedMethodIndex] : currentMethods[0];

  const filteredStrings = currentDex.stringsSample.filter(s =>
    s.toLowerCase().includes(stringSearch.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Multi-DEX File Selector */}
      {dexFiles.length > 1 && (
        <div className="flex items-center gap-2 p-1.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-x-auto">
          {dexFiles.map((dex, idx) => (
            <button
              key={idx}
              onClick={() => {
                setSelectedDexIndex(idx);
                setSelectedClassIndex(0);
                setSelectedMethodIndex(0);
              }}
              className={`px-3 py-1.5 text-xs font-mono font-medium rounded-lg transition-colors whitespace-nowrap flex items-center gap-2 ${
                selectedDexIndex === idx
                  ? 'bg-slate-900 text-white dark:bg-slate-800'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <Binary className="w-3.5 h-3.5 text-indigo-400" />
              <span>{dex.name}</span>
              <span className="text-[10px] opacity-75 tabular-nums">({(dex.size / 1024).toFixed(1)} KB)</span>
            </button>
          ))}
        </div>
      )}

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('classes')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeTab === 'classes'
                ? 'bg-slate-900 text-white dark:bg-slate-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Class Definitions & Bytecode ({currentDex.classesCount})
          </button>
          <button
            onClick={() => setActiveTab('header')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeTab === 'header'
                ? 'bg-slate-900 text-white dark:bg-slate-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Header & Adler-32
          </button>
          <button
            onClick={() => setActiveTab('strings')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              activeTab === 'strings'
                ? 'bg-slate-900 text-white dark:bg-slate-800'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            String Pool ({currentDex.stringsCount})
          </button>
        </div>

        <div className="text-xs text-slate-500 font-mono hidden sm:block">
          DEX v{currentDex.header.version} · {currentDex.methodsCount} methods
        </div>
      </div>

      {/* 1. Class Definitions & Bytecode Tab */}
      {activeTab === 'classes' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Classes List */}
          <div className="lg:col-span-4 p-4 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col max-h-[600px]">
            <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">
              Classes ({currentDex.classes.length})
            </h4>

            <div className="space-y-1 overflow-y-auto flex-1 pr-1">
              {currentDex.classes.map((cls, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setSelectedClassIndex(idx);
                    setSelectedMethodIndex(0);
                  }}
                  className={`w-full text-left p-2.5 rounded-lg text-xs font-mono transition-all flex items-center justify-between ${
                    selectedClassIndex === idx
                      ? 'bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 font-bold border border-indigo-200 dark:border-indigo-800'
                      : 'text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800/60'
                  }`}
                >
                  <span className="truncate">{cls.className}</span>
                  <ChevronRight className="w-3.5 h-3.5 opacity-50 shrink-0 ml-1" />
                </button>
              ))}
            </div>
          </div>

          {/* Right Column: Class Details & Disassembled Bytecode */}
          <div className="lg:col-span-8 space-y-6">
            {currentClass ? (
              <>
                {/* Class Meta Box */}
                <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <span className="text-[10px] font-mono text-indigo-600 dark:text-indigo-400 font-semibold uppercase">
                        class definition
                      </span>
                      <h3 className="text-base font-bold text-slate-900 dark:text-white font-mono">
                        {currentClass.className}
                      </h3>
                      {currentClass.superclassName && (
                        <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                          extends {currentClass.superclassName}
                        </p>
                      )}
                    </div>

                    <div className="text-right text-xs font-mono text-slate-500">
                      <div>Flags: 0x{currentClass.accessFlags.toString(16)}</div>
                      {currentClass.sourceFile && <div>Source: {currentClass.sourceFile}</div>}
                    </div>
                  </div>

                  {/* Method Selector Tabs */}
                  {currentMethods.length > 0 && (
                    <div className="pt-3 border-t border-slate-100 dark:border-slate-800">
                      <div className="text-[11px] font-semibold text-slate-500 mb-2">
                        Methods ({currentMethods.length}):
                      </div>
                      <div className="flex gap-2 flex-wrap">
                        {currentMethods.map((m, mIdx) => (
                          <button
                            key={mIdx}
                            onClick={() => setSelectedMethodIndex(mIdx)}
                            className={`px-2.5 py-1 text-xs font-mono rounded-md transition-colors ${
                              selectedMethodIndex === mIdx
                                ? 'bg-indigo-600 text-white font-semibold'
                                : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200'
                            }`}
                          >
                            {m.name}()
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Disassembled Bytecode Viewer */}
                {currentMethod && (
                  <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-950 p-5 font-mono text-xs text-slate-200 space-y-4">
                    <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <Code2 className="w-4 h-4 text-cyan-400" />
                        <span className="font-bold text-white">
                          Disassembled Instructions: {currentMethod.name}()
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center gap-3">
                        {currentMethod.registersSize !== undefined && (
                          <span>registers: {currentMethod.registersSize}</span>
                        )}
                        {currentMethod.insSize !== undefined && (
                          <span>ins: {currentMethod.insSize}</span>
                        )}
                        {currentMethod.insnsSize !== undefined && (
                          <span>words: {currentMethod.insnsSize}</span>
                        )}
                      </div>
                    </div>

                    {currentMethod.instructions && currentMethod.instructions.length > 0 ? (
                      <div className="space-y-1 overflow-x-auto leading-relaxed">
                        {currentMethod.instructions.map((ins, i) => (
                          <div key={i} className="flex gap-3">
                            <span className="text-slate-600 select-none">
                              {(i + 1).toString().padStart(2, '0')}
                            </span>
                            <span
                              className={
                                ins.includes('const')
                                  ? 'text-cyan-300'
                                  : ins.includes('invoke')
                                  ? 'text-amber-300'
                                  : ins.includes('return')
                                  ? 'text-emerald-400'
                                  : 'text-slate-200'
                              }
                            >
                              {ins}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-slate-500 py-4 text-center">
                        Method is abstract or has no bytecode instructions (code_off = 0).
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              <div className="p-8 text-center text-slate-500 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                Select a class to inspect its method bytecode.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 2. Header & Adler-32 Tab */}
      {activeTab === 'header' && (
        <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                DEX 112-Byte Header Inspection
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Magic, integrity checksum, SHA-1 signature, and layout offsets
              </p>
            </div>
            <div className="font-mono text-xs text-emerald-600 dark:text-emerald-400 font-semibold bg-emerald-50 dark:bg-emerald-950/40 px-3 py-1 rounded-full border border-emerald-200 dark:border-emerald-800">
              Valid Dalvik Executable
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">Magic & Version</div>
              <div className="font-bold text-slate-900 dark:text-white">
                dex\n{currentDex.header.version}\0
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">Adler-32 Checksum</div>
              <div className="font-bold text-indigo-600 dark:text-indigo-400 tabular-nums">
                0x{currentDex.header.checksum.toString(16).padStart(8, '0')}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">Endian Tag</div>
              <div className="font-bold text-slate-900 dark:text-white">
                0x{currentDex.header.endianTag.toString(16)} (Little Endian)
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">File Size</div>
              <div className="font-bold text-slate-900 dark:text-white tabular-nums">
                {currentDex.header.fileSize} bytes ({(currentDex.header.fileSize / 1024).toFixed(1)} KB)
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">String IDs Size / Offset</div>
              <div className="font-bold text-slate-900 dark:text-white tabular-nums">
                {currentDex.header.stringIdsSize} @ 0x{currentDex.header.stringIdsOff.toString(16)}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">Type IDs Size / Offset</div>
              <div className="font-bold text-slate-900 dark:text-white tabular-nums">
                {currentDex.header.typeIdsSize} @ 0x{currentDex.header.typeIdsOff.toString(16)}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">Method IDs Size / Offset</div>
              <div className="font-bold text-slate-900 dark:text-white tabular-nums">
                {currentDex.header.methodIdsSize} @ 0x{currentDex.header.methodIdsOff.toString(16)}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">Class Defs Size / Offset</div>
              <div className="font-bold text-slate-900 dark:text-white tabular-nums">
                {currentDex.header.classDefsSize} @ 0x{currentDex.header.classDefsOff.toString(16)}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
              <div className="text-slate-500 text-[10px]">Data Section Size / Offset</div>
              <div className="font-bold text-slate-900 dark:text-white tabular-nums">
                {currentDex.header.dataSize} bytes @ 0x{currentDex.header.dataOff.toString(16)}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. String Pool Tab */}
      {activeTab === 'strings' && (
        <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              DEX String Pool ({currentDex.stringsCount} total, showing first {currentDex.stringsSample.length})
            </h3>
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search strings..."
                value={stringSearch}
                onChange={e => setStringSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-white font-mono focus:outline-none focus:ring-1 focus:ring-indigo-500"
              />
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 divide-y divide-slate-100 dark:divide-slate-800 font-mono text-xs max-h-[500px] overflow-y-auto">
            {filteredStrings.map((str, idx) => (
              <div key={idx} className="p-2.5 flex items-center justify-between gap-4 hover:bg-slate-50 dark:hover:bg-slate-950/40">
                <span className="truncate text-slate-800 dark:text-slate-200">
                  {str}
                </span>
                <span className="text-[10px] text-slate-400 tabular-nums shrink-0">
                  #{idx}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
