# ROLE

Act as a senior Rust engineer, Android runtime developer, DEX reverse-engineering specialist, WebAssembly developer, browser security engineer, TypeScript architect and QA engineer.

You are working on my EXISTING GitHub repository:

https://github.com/mrhacker690/apkruntime

Your responsibility is to deeply audit, repair, test and improve the existing software.

This is a repair task, NOT a new-project generation task.

# CRITICAL RULES

1. Preserve the existing project architecture and working features.
2. Inspect files before modifying them.
3. Never replace working modules with simplified implementations.
4. Never use fake implementations.
5. Never hide errors.
6. Never claim tests passed without executing them.
7. Never mark an APK executable when no actual execution engine exists.
8. Never introduce mandatory paid services or APIs.
9. Do not start developing the DEX virtual machine until Phase 1 is stable.
10. Make actual changes to the connected GitHub repository.

First inspect the complete repository, current GitHub branch, commit history, package configuration, source code, existing tests and workflow.

Create a repair branch before making substantial modifications. Never force-push or overwrite unrelated user changes.

---

# TASK 1 — REPAIR GITHUB ACTIONS COMPLETELY

File:
`.github/workflows/ci.yml`

Verified problem:

The repository contains `bun.lock`, but the current GitHub Actions workflow uses:

- actions/checkout@v4
- actions/setup-node@v4
- npm cache
- npm ci

The current workflow fails because the expected npm lockfile does not exist.

Additional problem: the test command uses:

`npm test || echo "Automated test assertions verified in browser test suite."`

This hides actual test failures.

### Required repairs

Use Bun consistently because the existing repository already has `bun.lock`.

Implement:

- Bun setup using a maintained compatible installation action.
- A pinned Bun version compatible with the existing lockfile.
- Frozen-lockfile installation.
- Node.js 24-compatible GitHub Actions dependencies.
- TypeScript checking.
- Production builds.
- Automated tests.
- Failure reporting.
- Build verification.

Check the latest maintained GitHub Actions releases before selecting versions.

Add appropriate package scripts:

- dev
- build
- preview
- typecheck
- test

CI must execute:

1. Checkout.
2. Install the required runtime.
3. Install frozen dependencies.
4. Run type checking.
5. Run unit tests.
6. Run integration tests.
7. Run production build.

Remove all commands that suppress failures.

A failed test must make the workflow fail.

Do not generate an npm lockfile alongside the Bun lockfile unless there is a documented requirement to support both package managers.

---

# TASK 2 — REMOVE FAKE AND SIMULATED APK EXECUTION

Inspect:

`src/components/OverviewCard.tsx`

This is a critical issue.

The existing Run button currently generates simulated runtime output rather than executing APK bytecode.

Remove:
- Simulated application execution.
- Fake Dalvik register values.
- Fake lifecycle messages.
- Fake 60 FPS rendering messages.
- Fake RUNNING state.
- Simulated application display output.
- Fake restart and pause operations.

Do not delete the existing dashboard.

Preserve the design and replace the fake execution controls with an honest runtime status panel.

Until an actual DEX VM and Android framework exist, display:

RUNTIME ENGINE: NOT IMPLEMENTED

APPLICATION STATUS: ANALYSIS ONLY

EXECUTION: UNAVAILABLE

The Run button must remain disabled.

Do not create an artificial runtime to make the project look complete.

---

# TASK 3 — FIX AUTOMATIC SAMPLE LOADING

Inspect:

`src/App.tsx`

The application currently generates and analyses a sample APK automatically when the website opens.

Remove automatic sample loading.

Instead:

- Start with a clean dashboard.
- Show APK upload controls.
- Provide an optional sample analysis button.
- Clearly label generated examples as SYNTHETIC TEST FIXTURES.
- Never describe synthetic sample output as actual Android application execution.

Keep sample generation available for automated tests.

---

# TASK 4 — COMPLETELY REPAIR ZIP ENGINE

Main file:

`src/runtime/apk-extractor/zip-parser.ts`

This module requires extensive work.

### A. ZIP structure

Implement rigorous validation of:

- EOCD.
- Central directory.
- Local file headers.
- Entry offsets.
- Filename lengths.
- Extra-field lengths.
- File comment lengths.
- Compression methods.
- General-purpose flags.
- Data descriptors.
- File boundaries.
- ZIP64 markers.

Reject unsupported ZIP features explicitly rather than interpreting them incorrectly.

### B. DEFLATE

The existing fallback inflater is incomplete.

It stops on fixed and dynamic Huffman blocks.

Replace this incomplete implementation with a reliable, standards-compatible implementation.

The existing `fflate` dependency may be used after verifying its API and implementation suitability.

Support:

- Stored ZIP entries.
- DEFLATE entries.
- Fixed Huffman blocks.
- Dynamic Huffman blocks.
- Uncompressed DEFLATE blocks.

Never return partially decompressed data as successful extraction.

### C. CRC32

The parser currently reads CRC32 but does not adequately verify extracted content.

Implement:

- CRC32 calculation.
- Central-directory CRC comparison.
- Actual decompressed-size verification.
- Compressed-size validation.
- Extraction integrity reporting.

### D. ZIP security

Strengthen:

- Path traversal detection.
- Absolute path rejection.
- Duplicate filename detection.
- Normalized filename collision detection.
- ZIP bomb detection.
- Entry count limits.
- Maximum archive size.
- Maximum decompressed size.
- Per-entry decompressed size limits.
- Compression-ratio checks.
- Decompression output limits.

The browser's DecompressionStream path must enforce output limits while reading chunks, not after collecting everything in memory.

Never trust uncompressed sizes supplied by an archive.

Reject encrypted ZIP entries unless encryption support is deliberately implemented and tested.

### E. Tests

Create test cases for:

- Empty archives.
- Stored ZIP entries.
- Fixed Huffman DEFLATE.
- Dynamic Huffman DEFLATE.
- Multiple entries.
- Large entries.
- CRC mismatches.
- Corrupt headers.
- Truncated files.
- False EOCD signatures.
- ZIP64 markers.
- Invalid offsets.
- Path traversal.
- Duplicate paths.
- ZIP bombs.
- Output-size mismatches.

---

# TASK 5 — REPAIR SHA-256 ENGINE

File:

`src/runtime/apk-extractor/sha256.ts`

The existing SHA-256 test checks only output length.

That is insufficient.

Implement known-answer tests.

Use standard test vectors, including:

- Empty input.
- `abc`.
- Multi-block input.
- Unicode input.

Verify the Web Crypto implementation and TypeScript fallback independently.

Both implementations must return identical, correct SHA-256 results.

Ensure handling of large inputs does not unnecessarily duplicate huge buffers.

---

# TASK 6 — REPAIR AND STRENGTHEN BINARY ANDROID XML PARSER

File:

`src/runtime/manifest-engine/axml-parser.ts`

Correct all binary parsing and security issues.

### Header validation

Validate:

- Binary XML magic.
- Header size.
- Declared file size.
- Actual buffer size.
- Chunk headers.
- Chunk boundaries.

Never accept chunks extending outside the actual file buffer.

Remove the existing allowance that permits chunks to extend 1,024 bytes beyond the buffer.

### String pool

Implement rigorous validation of:

- String count.
- Style count.
- String offsets.
- Style offsets.
- String data boundaries.
- UTF-8 lengths.
- UTF-16 lengths.
- String terminators.
- Chunk-local offsets.

Avoid uncontrolled allocations from malicious counts.

### Element parsing

Improve:

- Element nesting.
- Namespace handling.
- Start/end element matching.
- Attribute counts.
- Attribute sizes.
- Attribute offsets.
- Resource-map boundaries.
- Typed values.

Support the relevant Android typed values and preserve unknown values transparently.

Do not silently convert unsupported types into misleading strings.

### Metadata

Accurately parse:

- Package name.
- Version code.
- Version name.
- SDK information.
- Application label.
- Icon reference.
- Theme reference.
- Activities.
- Activity aliases.
- Launcher intent filters.
- Services.
- Receivers.
- Providers.
- Permissions.
- Hardware features.
- Exported declarations.

Do not invent SDK defaults when the manifest does not declare them.

Represent missing information as unspecified.

Resource references must not be presented as resolved labels or icons until `resources.arsc` is actually decoded.

### Tests

Add independently generated Android binary XML fixtures.

Test valid manifests, malformed chunks, extreme counts, invalid offsets, UTF encodings, incorrect nesting and invalid typed attributes.

---

# TASK 7 — DEEPLY REPAIR DEX PARSER

File:

`src/runtime/dex-parser/dex-parser.ts`

This is one of the project's most important modules.

### A. DEX header integrity

Validate:

- DEX magic.
- Supported version.
- File size.
- Header size.
- Endian tag.
- Adler-32 checksum.
- SHA-1 signature.
- Data section.
- Map offset.

The current implementation calculates Adler-32 but does not compare it against the stored checksum.

Implement the actual comparison.

Verify SHA-1 against the correct DEX signature range.

Malformed DEX files must produce descriptive parsing errors.

### B. Section validation

Validate all fixed-size data sections before accessing them.

Include:

- String IDs.
- Type IDs.
- Proto IDs.
- Field IDs.
- Method IDs.
- Class definitions.

Every section must have:

- Correct size.
- Correct offset.
- Correct alignment.
- Valid buffer boundaries.
- Safe index references.

Use safe arithmetic to prevent integer overflow.

Do not silently substitute fake table entries when an index is invalid.

### C. String decoding

Implement correct DEX Modified UTF-8 decoding.

Correctly handle:

- UTF-16 length prefixes.
- Multibyte characters.
- Encoded nulls.
- Surrogate pairs.
- Truncated strings.
- Invalid encodings.

### D. ULEB128 and SLEB128

Implement robust decoders.

Requirements:

- Maximum encoded length.
- Overflow detection.
- Truncated input detection.
- Correct signed values.
- Correct cursor advancement.
- Descriptive errors.

### E. Class data

Improve:

- Class definitions.
- Access flags.
- Superclass references.
- Interfaces.
- Source files.
- Static fields.
- Instance fields.
- Direct methods.
- Virtual methods.
- Encoded field indexes.
- Encoded method indexes.
- Code offsets.

Validate all index differences and referenced table indexes.

### F. Code items

Implement correct parsing of:

- Register counts.
- Incoming registers.
- Outgoing registers.
- Try blocks.
- Debug information offsets.
- Instruction sizes.
- Instruction data.
- Exception handler structures.

Reject instruction streams that extend beyond their declared code item.

### G. DEX disassembler

Replace incomplete opcode handling with a version-aware instruction decoder.

Cover all defined instructions for the selected DEX versions.

Include:

- Move instructions.
- Constants.
- Return instructions.
- Branch instructions.
- Conditional operations.
- Object operations.
- Field access.
- Method invocation.
- Arithmetic.
- Conversion.
- Comparison.
- Array operations.
- Switch payloads.
- Fill-array-data payloads.
- Invoke-custom.
- Invoke-polymorphic.
- Method handles.
- Method types.

Correctly identify reserved and unsupported opcode values.

Never guess an instruction's size.

Never silently advance one code unit for an instruction whose actual size is unknown.

Do not truncate internal parsing just because the UI displays only a preview.

### Tests

Use real DEX test fixtures generated independently of the parser implementation.

Test each opcode format and malformed section.

Do not rely exclusively on the project's own generated fixtures.

---

# TASK 8 — REPAIR COMPATIBILITY ENGINE

File:

`src/runtime/compatibility-engine/compatibility.ts`

The current compatibility system can report SUPPORTED when an application:

- Has DEX files.
- Has a launcher activity.
- Contains no detected native libraries.
- Meets basic SDK heuristics.

This does not establish actual Android execution compatibility.

Implement separate capabilities:

1. Archive validity.
2. Manifest parsing.
3. DEX integrity.
4. DEX instruction coverage.
5. Native library requirements.
6. Android framework API coverage.
7. Lifecycle compatibility.
8. Graphics compatibility.
9. Actual runtime execution verification.

Until the real execution engine exists, parsed APKs must remain ANALYSIS ONLY.

`SUPPORTED` should only be assigned after a real execution test succeeds using the actual implemented runtime.

Do not classify all pure Java APKs as executable.

Do not use simple string searches as definitive proof that an application uses or does not use an API.

Make compatibility reports transparent and evidence-based.

---

# TASK 9 — REPAIR NATIVE ELF INSPECTOR

File:

`src/runtime/native-inspector/elf-inspector.ts`

Improve:

- ELF magic.
- ELF class.
- Endianness.
- ELF version.
- Machine architecture.
- Program headers.
- Shared-library metadata.
- ABI detection.

Compare ABI folder names against the architecture declared in ELF metadata.

Do not assume the directory name always proves the architecture.

Inspect all relevant native libraries within documented safety limits.

The existing runtime service extracts only the first ten native libraries. Replace this arbitrary limitation with explicit resource budgets and accurate reporting of any skipped files.

Never report incomplete inspection as full inspection.

---

# TASK 10 — REPAIR GITHUB APK IMPORTER

File:

`src/components/ImportZone.tsx`

Improve GitHub import functionality.

Accept:

- Public GitHub repository URLs.
- GitHub release page URLs.
- Direct APK release asset URLs.
- Direct ZIP asset URLs.

For release pages:

1. Parse owner and repository.
2. Identify the release tag.
3. Call the appropriate GitHub public Releases API endpoint.
4. Retrieve release assets.
5. Filter APK and ZIP assets.
6. Show available assets to the user.
7. Allow one asset to be selected.
8. Download the selected asset.

Do not convert a release page URL into an incomplete download URL.

Implement:

- HTTP status handling.
- Content-length checks.
- Streaming download limits.
- Download cancellation.
- Progress reporting.
- APK signature/header validation.
- ZIP signature validation.
- CORS error handling.

Do not use a paid proxy.

Do not request private GitHub credentials for public repositories.

If the source does not support browser-side CORS, display a clear explanation and offer local upload.

For local uploads, validate file extension, size and file signature before loading the entire file into memory.

---

# TASK 11 — FIX RUNTIME SERVICE

File:

`src/runtime/apk-loader/runtime-service.ts`

Improve the complete analysis pipeline.

Ensure the sequence is:

1. Input validation.
2. APK archive parsing.
3. SHA-256 verification.
4. Entry classification.
5. Manifest extraction.
6. Manifest parsing.
7. DEX discovery.
8. DEX extraction.
9. DEX integrity verification.
10. DEX analysis.
11. Native library inspection.
12. Compatibility evaluation.
13. Structured report creation.

Use typed errors.

Report module-specific failures.

Do not silently continue after a critical parsing failure.

Keep optional metadata failures separate from core archive failures.

Preserve diagnostic logging without logging sensitive user content unnecessarily.

---

# TASK 12 — IMPROVE TEST FRAMEWORK

Main files:

`src/runtime/tests/runtime-tests.ts`

`src/runtime/tests/cli-runner.ts`

Build a meaningful regression-testing system.

Current tests rely heavily on generated sample fixtures.

Keep them, but add independent verification.

Create:

### ZIP tests
Real archives with different compression modes and corrupt data.

### Manifest tests
Real Android-generated binary manifests.

### DEX tests
DEX files generated using independent Android build tooling.

### SHA-256 tests
Known cryptographic test vectors.

### ELF tests
Valid and malformed ELF fixtures.

### Compatibility tests
Cases demonstrating that valid APK analysis does not automatically mean executable compatibility.

### Integration tests
Complete input-to-analysis pipeline.

### Browser tests
Test upload, GitHub import errors, analysis display and runtime status.

Every test must include a meaningful assertion.

A test must fail when the implementation is incorrect.

Avoid tests that merely verify output exists or has the expected length.

Do not automatically mark skipped tests as passed.

Produce a test report with:

- Total tests.
- Passed tests.
- Failed tests.
- Skipped tests.
- Execution duration.
- Failure details.

Exit with a non-zero status when any required test fails.

---

# TASK 13 — FRONTEND IMPROVEMENTS

Preserve the existing premium interface and components.

Improve:

- Upload validation.
- Progress indicators.
- Clear error messages.
- Empty state.
- Loading state.
- Mobile responsiveness.
- Theme initialization.
- Accessibility.
- Analysis report display.

Fix the theme initialization issue in `src/App.tsx`, where the `|| true` expression makes the initial dark-mode state unconditional.

Do not show controls that imply a runtime is available when it is not.

Keep:

- Overview.
- Manifest Explorer.
- DEX Explorer.
- Native Library Explorer.
- Archive Explorer.
- Compatibility Report.
- Test Suite.
- Documentation.
- Runtime Console.

Update the runtime panel to communicate actual engine capabilities.

---

# TASK 14 — PACKAGE AND DOCUMENTATION REPAIR

Files:

- `package.json`
- `bun.lock`
- `README.md`
- `index.html`
- `vite.config.ts`
- `tsconfig.json`

Required changes:

1. Rename generic package name `react-example` to `apk-runtime-engine`.
2. Keep Bun as the single package manager.
3. Pin a compatible package-manager version.
4. Review Node.js requirements.
5. Remove dependencies only after verifying they are unused.
6. Maintain reproducible builds.
7. Correct repository clone instructions.
8. Correct local setup instructions.
9. Correct deployment instructions.
10. Document current runtime limitations.
11. Remove claims that are not supported by implemented code.
12. Document the actual test commands.

The README currently advertises sandboxed bytecode execution and WebAssembly runtime functionality that is not yet implemented.

Correct those claims.

The README must accurately distinguish:

- APK analysis.
- DEX inspection.
- DEX execution.
- Android API compatibility.
- Native execution.

Do not claim completed functionality prematurely.

### Licensing

Existing source files identify Apache-2.0, while the footer says MIT.

Use Apache-2.0 consistently unless the repository owner explicitly chooses otherwise.

Add the complete appropriate LICENSE file.

Update the footer and README to match.

Do not misrepresent the licenses of dependencies.

---

# TASK 15 — GITHUB PAGES AND FREE DEPLOYMENT

Keep the software fully browser-side for current Phase 1 functionality.

Ensure:

- Production build works.
- Static hosting works.
- No backend is required for local APK analysis.
- No paid APIs are required.
- No private keys are exposed.
- Asset paths work on the actual deployment path.
- GitHub Pages deployment instructions are correct.

If configuring GitHub Pages, ensure Vite's base path is correct for the repository URL.

Do not claim that free hosting provides unlimited CPU, bandwidth or storage.

---

# TASK 16 — FINAL VERIFICATION

After all repairs, perform a complete verification.

Run:

1. Frozen dependency installation.
2. TypeScript type checking.
3. Unit tests.
4. Integration tests.
5. Security tests.
6. Production build.
7. Browser tests.
8. GitHub Actions workflow.

Inspect the changed files after tests.

Search for:
- TODO.
- FIXME.
- NOT_IMPLEMENTED.
- Placeholder.
- Mock.
- Fake.
- Simulated execution.
- Empty functions.
- Suppressed test errors.

Do not remove legitimate documentation or test fixtures just to eliminate search matches.

Fix real problems and explain intentional limitations.

---

# TASK 17 — GITHUB COMMIT

After successful verification:

- Review the Git diff.
- Ensure no private secrets are committed.
- Ensure the lockfile matches package.json.
- Commit all intended changes.
- Push the repair branch to the connected GitHub repository.
- Do not force-push.

Do not report a successful push unless GitHub confirms it.

---

# REQUIRED COMPLETION REPORT

When finished, provide a detailed report:

## 1. Repository status
Current branch and commit.

## 2. Critical bugs fixed
List every important repair.

## 3. ZIP engine
Supported compression modes and test results.

## 4. Manifest engine
Implemented parsing features and test results.

## 5. DEX engine
Implemented validation and decoding features.

## 6. Compatibility engine
Explain what can genuinely be verified.

## 7. Import engine
Explain GitHub and local import functionality.

## 8. Security
Report implemented protections and remaining limitations.

## 9. Automated testing
Actual pass/fail counts.

## 10. GitHub Actions
Provide the latest actual workflow result.

## 11. Remaining limitations
Clearly distinguish implemented functionality from planned functionality.

## 12. Next milestone
Recommend the next development task.

# FINAL DEVELOPMENT OBJECTIVE

Make APK Runtime Engine a reliable, secure, independently testable browser-based APK analysis foundation.

Prioritize correctness over feature quantity.

Do not build the DEX VM during this repair task.

Do not pretend applications execute.

First make the existing foundation genuinely reliable.

After the entire Phase 1 repair passes its verification requirements, prepare the project for development of its own DEX virtual machine in Phase 2.