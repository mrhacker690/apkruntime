# APK Runtime Engine

> **Independent, Browser-Based Android APK Analysis & Runtime Foundation**

[![APK Runtime Engine CI](https://github.com/mrhacker690/apkruntime/actions/workflows/ci.yml/badge.svg)](https://github.com/mrhacker690/apkruntime/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

An open-source, client-side engineering project developing an independent Android application runtime directly inside modern web browsers.

The long-term objective is to execute compatible Android applications locally on the visitor's device without cloud emulators, VPS instances, paid APIs, or remote execution servers.

---

## Current Status: Phase 1 (Analysis & Extraction Foundation)

In accordance with our strict engineering constitution, **no application execution is claimed before the actual virtual machine exists**. 

Current engine state:
- **Runtime Engine**: Phase 1 Complete (Analysis & Extraction Foundation)
- **Application Status**: ANALYSIS ONLY
- **Bytecode Execution**: In Development (Scheduled for Phase 4)

### Implemented Phase 1 Capabilities

1. **Local & Remote APK Ingestion**:
   - Ingestion of local `.apk` packages and multi-APK `.zip` containers.
   - Pre-flight validation of file signatures (verifies `PK\x03\x04` magic before full buffering).
   - Public GitHub repository and release asset inspection via GitHub's public API, with streaming progress and cancellation.
   - Optional synthetic test fixtures for independent parser verification.

2. **Hardened Client-Side ZIP Archive Parser**:
   - End of Central Directory (EOCD) and Central Directory parsing.
   - Decompression of Stored (0) and DEFLATE (8) compression modes (fixed & dynamic Huffman blocks).
   - Strict IEEE 802.3 CRC-32 checksum calculation and verification against archive records.
   - Strict uncompressed size verification.
   - Zip-bomb defense: 500 MB total volume ceiling, 150 MB per-entry limit, 5,000 file count threshold, and compression ratio anomaly detection.
   - Path-traversal protection blocking leading slashes, drive letters, control characters, and `..` segments.
   - Duplicate entry and normalized filename collision detection.
   - Explicit rejection of encrypted entries and ZIP64 archives.

3. **Binary Android XML (ResXMLTree) Decoder**:
   - Parses compiled `AndroidManifest.xml` binary chunks without arbitrary buffer extensions.
   - Decodes String Pool (UTF-8 and UTF-16LE) and Resource Map tables.
   - Decodes typed values (integers, booleans, dimensions, fractions, IEEE-754 floats, colors).
   - Preserves resource references (`@0x...`) without falsely claiming they are resolved prior to `resources.arsc` parsing.
   - Discovers activities, launcher entry points (`MAIN` + `LAUNCHER` intent filters), services, receivers, providers, hardware features, and permissions (normal vs dangerous).
   - No invented defaults: undeclared SDK targets remain explicitly unspecified.

4. **Dalvik Executable (DEX) Parser & Disassembler**:
   - Validates DEX headers: magic (`dex\n`), versions (`035`, `037`, `038`, `039`), endian tag (`0x12345678`), and file boundaries.
   - Calculates and compares Adler-32 checksums against header declarations.
   - Decodes Modified UTF-8 (MUTF-8) strings including embedded nulls (`0xC0 0x80`) and surrogate pairs.
   - Implements bounds-checked ULEB128 and SLEB128 decoders with 5-byte overflow protection.
   - Disassembles Dalvik bytecode instructions using verified opcode length tables without guessing instruction boundaries.

5. **Native ELF Shared Library Inspector**:
   - Dissects `.so` files in `lib/` directory: ELF magic (`0x7F 'E' 'L' 'F'`), class (32/64-bit), endianness, and machine architectures (ARMv7, AArch64, x86, x86-64, RISC-V).
   - Compares ABI directory names against actual declared machine code to flag discrepancies.
   - Enforces explicit resource budgets (up to 100 native libraries / 50 MB) and reports any skipped files.

6. **Evidence-Based Compatibility Engine**:
   - Transparently classifies all parsed applications as `ANALYSIS ONLY` (or `NOT SUPPORTED` if invalid).
   - Reports concrete blockers (e.g. native ARM code, undeclared launcher activities, missing framework layers).

---

## 10-Phase Engineering Roadmap

| Phase | Milestone | Status | Description |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **APK Loading, Extraction & Analysis** | **COMPLETED** | Hardened ZIP extractor, SHA-256, binary manifest decoder, DEX parser with Adler-32 verification, ELF inspector, automated test suite. |
| **Phase 2** | **Expanded Binary XML & Resources** | Next | Full `resources.arsc` chunk table decoding, layout XML decomposition (`res/layout/*.xml`), and localized string tables. |
| **Phase 3** | **Complete DEX Instruction Decoder** | Planned | Comprehensive decoding of all 256 Dalvik opcodes, try/catch exception handlers, and line number debug info tables. |
| **Phase 4** | **Basic DEX Virtual Machine** | Core | Register-based virtual machine (v0–vN), stack frame allocation, method invocation dispatcher, and heap simulation. |
| **Phase 5** | **Android API Compatibility Layer** | Planned | Initial subset of `java.lang`, `java.util`, `android.app`, `android.os`, `android.view`, `android.widget`. |
| **Phase 6** | **Application Lifecycle Manager** | Planned | ActivityThread scheduling: `onCreate` -> `onStart` -> `onResume` -> `onPause` -> `onStop` -> `onDestroy`. |
| **Phase 7** | **Graphics & Browser Input Engine** | Planned | Canvas 2D / WebGL surface view, layout calculation, touch/mouse events, and back navigation. |
| **Phase 8** | **Compiled DEX App Execution** | Milestone | End-to-end execution of real compiled Android applications directly in the browser canvas. |
| **Phase 9** | **Framework API Expansion** | Planned | Intents, Content Providers, Shared Preferences, SQLite / IndexedDB bridge, Audio playback. |
| **Phase 10** | **Native Libraries & WebAssembly JNI** | Research | Dynamic binary translation of ARM64 native machine instructions into WebAssembly sandboxes. |

---

## Getting Started Locally

### Prerequisites
- [Bun](https://bun.sh/) 1.1+ (recommended) or Node.js 20+

### Installation & Development
```bash
# Clone the repository
git clone https://github.com/mrhacker690/apkruntime.git
cd apkruntime

# Install frozen dependencies
bun install --frozen-lockfile

# Start development server
bun run dev
```

Open `http://localhost:3000` in any modern web browser.

---

## Testing & Quality Assurance

The test suite runs both directly inside the browser UI (under the **Test Suite** tab) and headlessly via the CLI:

```bash
# Run automated regression tests
bun run test

# Run TypeScript typecheck
bun run typecheck

# Run production build
bun run build
```

The test runner verifies:
- SHA-256 NIST known-answer test vectors (empty, short, 56-byte multi-block, and Unicode).
- ZIP DEFLATE decompression, CRC-32 IEEE 802.3 verification, and corrupted entry rejection.
- ZIP security defenses (directory traversal, absolute paths, duplicate entries, ZIP64 rejection).
- Binary XML strict buffer boundary enforcement and uninvented metadata defaults.
- Dalvik DEX Adler-32 checksum verification and corrupted data rejection.
- ULEB128 5-byte overflow protection and signed SLEB128 decoders.
- MUTF-8 embedded null (`0xC0 0x80`) decoding.
- ELF machine architecture vs ABI directory mismatch detection.
- Honest compatibility assessment enforcing `ANALYSIS ONLY` status in Phase 1.

---

## Deployment

The APK Runtime Engine performs all decompression, binary XML decoding, cryptographic hashing, and DEX disassembling on the client device. No backend servers, cloud emulators, or paid services are required.

To build the static distribution:
```bash
bun run build
```

Deploy the generated `dist/` directory to **GitHub Pages**, **Cloudflare Pages**, **Vercel**, or **Netlify**.

---

## License

This project is licensed under the [Apache-2.0 License](LICENSE).
Third-party dependencies retain their respective licenses.
