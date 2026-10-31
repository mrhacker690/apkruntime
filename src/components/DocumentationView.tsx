/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Documentation & Roadmap View
 * Technical roadmap, architectural specification, local run instructions, and Phase 2 milestones.
 */

import React, { useState } from 'react';
import { BookOpen, Layers, ShieldCheck, Terminal, Rocket, CheckCircle2, ChevronRight } from 'lucide-react';

export const DocumentationView: React.FC = () => {
  const [activeSection, setActiveSection] = useState<'phases' | 'arch' | 'run' | 'security'>('phases');

  return (
    <div className="space-y-6">
      {/* Sub-Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3 overflow-x-auto">
        <button
          onClick={() => setActiveSection('phases')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeSection === 'phases'
              ? 'bg-slate-900 text-white dark:bg-slate-800'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          Phase 1–10 Engineering Roadmap
        </button>
        <button
          onClick={() => setActiveSection('arch')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeSection === 'arch'
              ? 'bg-slate-900 text-white dark:bg-slate-800'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          Modular Architecture
        </button>
        <button
          onClick={() => setActiveSection('run')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeSection === 'run'
              ? 'bg-slate-900 text-white dark:bg-slate-800'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          Run Locally & Deployment
        </button>
        <button
          onClick={() => setActiveSection('security')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
            activeSection === 'security'
              ? 'bg-slate-900 text-white dark:bg-slate-800'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          Security & Sandboxing
        </button>
      </div>

      {/* 1. Phases Roadmap */}
      {activeSection === 'phases' && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-1">
              Phased Engineering Roadmap
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-6">
              Executing real Android applications in web browsers is an operating-system grade endeavor. We progress through 10 strictly verified milestones without false marketing claims.
            </p>

            <div className="space-y-4">
              {/* Phase 1 */}
              <div className="p-4 rounded-xl border border-emerald-300 dark:border-emerald-800/80 bg-emerald-50/40 dark:bg-emerald-950/20">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                    <span className="text-xs font-bold text-emerald-900 dark:text-emerald-300 font-mono">
                      Phase 1: Complete APK Loading, Extraction & Analysis
                    </span>
                  </div>
                  <span className="text-[10px] font-semibold text-emerald-700 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-900/60 px-2 py-0.5 rounded">
                    COMPLETED
                  </span>
                </div>
                <p className="text-xs text-emerald-950 dark:text-emerald-200 leading-relaxed">
                  Implemented pure browser-side ZIP parser, SHA-256 calculation, AndroidManifest binary decoder, DEX header validator, Adler-32 checksum verification, ELF native library detection, honest compatibility grading, and automated test suite.
                </p>
              </div>

              {/* Phase 2 */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">
                    Phase 2: Expanded Binary XML & Resource Engine
                  </span>
                  <span className="text-[10px] font-medium text-slate-500 bg-slate-200 dark:bg-slate-800 px-2 py-0.5 rounded">
                    NEXT MILESTONE
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  Deep parsing of <code className="font-mono">resources.arsc</code> chunk table, layout XML files (<code className="font-mono">res/layout/*.xml</code>), string localization tables, and drawable assets extraction.
                </p>
              </div>

              {/* Phase 3 */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">
                    Phase 3: Complete DEX Parser & Instruction Decoder
                  </span>
                  <span className="text-[10px] font-medium text-slate-500 bg-slate-200 dark:bg-slate-800 px-2 py-0.5 rounded">
                    PLANNED
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  Comprehensive decoding of all 256 Dalvik opcodes, try-catch exception handler tables, debug info line number mapping, and method parameter descriptors.
                </p>
              </div>

              {/* Phase 4 */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">
                    Phase 4: Independent Register-Based DEX Virtual Machine
                  </span>
                  <span className="text-[10px] font-medium text-slate-500 bg-slate-200 dark:bg-slate-800 px-2 py-0.5 rounded">
                    CORE TARGET
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  Virtual register file (v0–vN), stack frame allocation, method invocation dispatcher, object allocation, primitive types, array operations, and garbage collection simulation.
                </p>
              </div>

              {/* Phases 5-10 Summary */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
                <span className="text-xs font-bold text-slate-900 dark:text-white font-mono">
                  Phases 5–10: Framework, Rendering & NDK Translation
                </span>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed mt-2">
                  Phase 5: Android API compatibility layer (<code className="font-mono">android.app, android.os, android.view</code>) · Phase 6: ActivityThread lifecycle manager · Phase 7: Canvas/WebGL graphics & browser touch input · Phase 8: End-to-end execution of compiled Dalvik apps · Phase 9: Expanded framework APIs · Phase 10: WebAssembly ARM64 native JNI translation layer.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2. Modular Architecture */}
      {activeSection === 'arch' && (
        <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
            Software Architecture & Interfaces
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
            The project strictly avoids monolithic code. Every engine has an independent boundary:
          </p>

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-950 p-4 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
            <pre>
{`runtime/
├── core/
│   └── types.ts             <- Strongly-typed APK, Manifest, DEX, and Report models
├── apk-loader/
│   ├── runtime-service.ts   <- Pipeline orchestrator & GitHub fetcher
│   └── sample-apks.ts       <- In-memory standards-compliant binary fixture synthesizer
├── apk-extractor/
│   ├── zip-parser.ts        <- Safe EOCD & Deflate streaming parser (Zip-bomb proof)
│   └── sha256.ts            <- Cryptographic Web Crypto digest with JS fallback
├── manifest-engine/
│   └── axml-parser.ts       <- Binary ResXMLTree chunk & string pool decoder
├── dex-parser/
│   └── dex-parser.ts        <- Dalvik header, Adler32, symbols & disassembler
├── native-inspector/
│   └── elf-inspector.ts     <- ELF binary header inspection & ABI detector
├── compatibility-engine/
│   └── compatibility.ts     <- Objective execution readiness evaluator
└── tests/
    └── runtime-tests.ts     <- Automated in-browser test suite`}
            </pre>
          </div>
        </div>
      )}

      {/* 3. Run Locally & Deploy */}
      {activeSection === 'run' && (
        <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
            How to Run Locally & Free Hosting Deployment
          </h2>

          <div className="space-y-4 font-mono text-xs">
            <div>
              <p className="font-sans font-semibold text-slate-900 dark:text-white mb-1.5">
                1. Clone and Run Locally
              </p>
              <div className="p-3 rounded-lg bg-slate-950 text-slate-200">
                <code>
                  git clone https://github.com/google-ai-studio/apk-runtime-engine.git<br />
                  cd apk-runtime-engine<br />
                  npm install<br />
                  npm run dev
                </code>
              </div>
            </div>

            <div>
              <p className="font-sans font-semibold text-slate-900 dark:text-white mb-1.5">
                2. Run Automated Test Suite
              </p>
              <div className="p-3 rounded-lg bg-slate-950 text-slate-200">
                <code>npm test # or open the in-browser Test Suite tab</code>
              </div>
            </div>

            <div>
              <p className="font-sans font-semibold text-slate-900 dark:text-white mb-1.5">
                3. Deploy Free to Vercel, Netlify, or Cloudflare Pages
              </p>
              <div className="p-3 rounded-lg bg-slate-950 text-slate-200">
                <code>
                  npm run build<br />
                  # Output directory is 'dist' - zero server dependencies needed
                </code>
              </div>
              <p className="font-sans text-xs text-slate-500 mt-2">
                Since all APK decompression, binary parsing, and DEX disassembling happen entirely on the client side via Web Workers and WebAssembly, this project is 100% self-hostable on static CDNs with zero backend infrastructure costs.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* 4. Security & Sandboxing */}
      {activeSection === 'security' && (
        <div className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4">
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
            Security & Sandboxing Architecture
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
            APK files are untrusted user input. The APK Runtime Engine enforces strict security boundaries:
          </p>

          <ul className="space-y-2.5 text-xs text-slate-700 dark:text-slate-300">
            <li className="flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
              <span>
                <strong>Zip-Bomb Mitigation:</strong> Hard limit of 5,000 files and 500 MB total uncompressed volume with compression ratio anomaly thresholds.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
              <span>
                <strong>Path Traversal Defense:</strong> Strips leading slashes, drive letters, and blocks any entry containing <code className="font-mono">../</code> segments.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
              <span>
                <strong>Isolated Execution:</strong> Application code runs in dedicated WebAssembly/Worker sandboxes with zero arbitrary host-page DOM access.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
              <span>
                <strong>Bounds-Checked Parsing:</strong> DataView byte offsets are verified against buffer boundaries before every read to prevent out-of-bounds crashes.
              </span>
            </li>
          </ul>
        </div>
      )}
    </div>
  );
};
