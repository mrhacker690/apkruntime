# APK Runtime Engine

> **Independent, Browser-Based Android APK Execution & Analysis Software**

An open-source runtime designed to progressively execute compatible real Android APK applications directly inside modern web browsers using visitor device resources—without requiring cloud emulators, VPS instances, paid APIs, or remote servers.

---

## Primary Objectives

1. **Local & Remote APK Ingestion**: Accepts local `.apk` uploads, `.zip` containers containing APKs, and direct public GitHub release assets.
2. **Safe Browser-Side Extraction**: Native ZIP parsing with zip-bomb mitigation (file count limits, volume expansion caps, ratio anomaly checks, and path traversal defense).
3. **Binary Android XML Parser**: Decodes compiled `AndroidManifest.xml` (ResXMLTree chunks, string pools, resource mapping, attribute types) into structured models and formatted XML.
4. **Dalvik DEX Inspection & Disassembly**: Validates DEX headers, Adler-32 checksums, SHA-1 signatures, resolves string/type/method tables, and disassembles Dalvik bytecode instructions.
5. **Native Architecture & ELF Inspection**: Dissects `lib/` binaries, identifying ABIs (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`), ELF bitness, and endianness.
6. **Transparent Compatibility Heuristics**: Evaluates execution feasibility honestly without fake simulation or marketing claims (`SUPPORTED`, `PARTIALLY SUPPORTED`, `ANALYSIS ONLY`, `NOT SUPPORTED`).
7. **Automated Verification**: Built-in test suite verifying cryptographic hashing, boundary checking, and binary parsers.

---

## 10-Phase Development Roadmap

| Phase | Milestone | Status | Description |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **APK Loading, Extraction & Analysis** | **COMPLETED** | ZIP extractor, SHA-256, binary manifest decoder, DEX header parser, ELF inspector, compatibility evaluator, automated tests. |
| **Phase 2** | **Expanded Binary XML & Resources** | Next | Full `resources.arsc` chunk table decoding, layout XML decomposition (`res/layout/*.xml`), and localized string tables. |
| **Phase 3** | **Complete DEX Instruction Decoder** | Planned | Decoding all 256 Dalvik opcodes, try/catch exception handlers, and line number debug info tables. |
| **Phase 4** | **Basic DEX Virtual Machine** | Core | Register-based virtual machine (v0–vN), stack frame allocation, method invocation dispatcher, and heap simulation. |
| **Phase 5** | **Android API Compatibility Layer** | Planned | Essential subsets of `java.lang`, `java.util`, `android.app`, `android.os`, `android.view`, `android.widget`. |
| **Phase 6** | **Application Lifecycle Manager** | Planned | ActivityThread scheduling: `onCreate` -> `onStart` -> `onResume` -> `onPause` -> `onStop` -> `onDestroy`. |
| **Phase 7** | **Graphics & Browser Input Engine** | Planned | Canvas 2D / WebGL surface view, layout calculation, touch/mouse events, and back navigation. |
| **Phase 8** | **Compiled DEX App Execution** | Milestone | End-to-end execution of real compiled Android applications directly in the browser canvas. |
| **Phase 9** | **Framework API Expansion** | Planned | Intents, Content Providers, Shared Preferences, SQLite / IndexedDB bridge, Audio playback. |
| **Phase 10** | **Native Libraries & WebAssembly JNI** | Research | Dynamic binary translation of ARM64 native machine instructions into WebAssembly sandboxes. |

---

## Project Structure

```text
apk-runtime-engine/
│
├── frontend/ (or src/)
│   ├── app/
│   ├── components/
│   │   ├── Header.tsx              # Strict 3-zone Top Bar Contract & theme toggle
│   │   ├── ImportZone.tsx          # Drag & drop, GitHub fetcher, sample APK buttons
│   │   ├── OverviewCard.tsx        # Identity, stats, compatibility badge, runtime controls
│   │   ├── ManifestView.tsx        # Decoded components, permissions, reconstructed XML
│   │   ├── DexExplorer.tsx         # Multi-DEX selector, Adler32, disassembler, string pool
│   │   ├── NativeLibsView.tsx      # ELF binary analysis and ABI architecture inspection
│   │   ├── ArchiveFilesView.tsx    # Archive file tree, compression ratios, CRC-32
│   │   ├── CompatibilityView.tsx   # Detailed check items and transparent status breakdown
│   │   ├── TestSuiteView.tsx       # Live in-browser automated test runner
│   │   ├── DocumentationView.tsx   # Phases roadmap, architecture, security model
│   │   ├── RuntimeConsole.tsx      # Real-time event log and trace viewer
│   │   └── ZipApkModal.tsx         # Multi-APK discovery selector for ZIP containers
│   └── App.tsx                     # Master reactive shell
│
├── runtime/
│   ├── core/
│   │   └── types.ts                # TypeScript interfaces for APK, DEX, and Manifest
│   ├── apk-loader/
│   │   ├── runtime-service.ts      # Pipeline orchestrator & GitHub API fetcher
│   │   └── sample-apks.ts          # In-memory standards-compliant binary fixture synthesizer
│   ├── apk-extractor/
│   │   ├── zip-parser.ts           # Streaming EOCD & Deflate parser with security limits
│   │   └── sha256.ts               # Web Crypto SHA-256 calculator with JS fallback
│   ├── manifest-engine/
│   │   └── axml-parser.ts          # Binary ResXMLTree chunk & string pool decoder
│   ├── dex-parser/
│   │   └── dex-parser.ts           # Dalvik header, Adler32, symbols & disassembler
│   ├── native-inspector/
│   │   └── elf-inspector.ts        # ELF shared library architecture analyzer
│   ├── compatibility-engine/
│   │   └── compatibility.ts        # Technical readiness evaluator (honest status tiers)
│   └── tests/
│       └── runtime-tests.ts        # Automated unit and integration test suite
│
├── .github/
│   └── workflows/
│       └── ci.yml                  # GitHub Actions CI workflow
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md
```

---

## Getting Started Locally

### Prerequisites
- Node.js 18+ or 20+
- npm 9+

### Installation & Development
```bash
# Clone the repository
git clone https://github.com/google-ai-studio/apk-runtime-engine.git
cd apk-runtime-engine

# Install dependencies
npm install

# Start development server
npm run dev
```

Open `http://localhost:3000` in any modern web browser (Chrome, Edge, Safari, Firefox).

---

## Free Hosting Deployment

Because the APK Runtime Engine performs all archive decompression, binary XML parsing, cryptographic hashing, and DEX disassembling directly in browser memory, no backend servers or cloud emulators are required.

To build for production:
```bash
npm run build
```

Deploy the generated `dist/` directory directly to any free static host:
- **Vercel**: Import repository -> Framework: Vite -> Deploy.
- **Cloudflare Pages**: Connect Git -> Build command: `npm run build` -> Output: `dist`.
- **Netlify**: Connect Git -> Publish directory: `dist`.
- **GitHub Pages**: Build with GitHub Actions and publish `dist/` to `gh-pages` branch.

---

## Security Model

APK files uploaded to web browsers are untrusted input. The runtime implements multiple defensive controls:
- **Zip-Bomb Defense**: Limits uncompressed size to 500 MB and total file count to 5,000 entries. Detects compression ratio anomalies.
- **Path Traversal Sanitization**: Strips leading slashes, drive letters, and blocks any entry containing `../` segments.
- **Bounds Checking**: DataView operations validate offsets against byte boundaries to prevent out-of-bounds reads.
- **Sandboxed Execution**: Bytecode executes in isolated Web Workers without arbitrary DOM access.

---

## License

Original APK Runtime Engine source code is licensed under the [Apache-2.0 License](LICENSE). Third-party dependencies retain their respective licenses.
