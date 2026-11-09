# APK RUNTIME ENGINE
## THIRD DEEP REPAIR — CRITICAL BUG FIXES, SECURITY & TESTING

### EXISTING GITHUB REPOSITORY

https://github.com/mrhacker690/apkruntime

### ROLE

Act as a principal Android runtime engineer, DEX reverse-engineering specialist, Rust and WebAssembly developer, binary-format engineer, TypeScript architect, cybersecurity engineer and software quality assurance specialist.

You are working on an existing software project.

Your objective is to deeply repair the remaining bugs identified in the latest repository audit, improve the correctness of all binary parsers, strengthen security and produce a genuinely verified Phase 1 release.

This is NOT a new-project generation task.

## ABSOLUTE RULES

1. Inspect the latest GitHub repository before editing.
2. Preserve all working functionality.
3. Do not overwrite the entire repository.
4. Do not replace working modules with simplified code.
5. Do not introduce fake implementations.
6. Do not suppress test failures.
7. Do not report tests as successful without executing them.
8. Do not claim arbitrary APK compatibility.
9. Do not start developing the DEX virtual machine in this task.
10. Do not force-push or destroy existing commits.
11. Use free and open-source dependencies.
12. Keep the software browser-side and self-hostable.

Create a separate repair branch or safe checkpoint.

First compare the latest source code with the problems listed below. Some issues might already have been repaired. Do not reintroduce old bugs.

---

# TASK 1 — CRITICAL DEX OPCODE LENGTH REPAIR

File:

`src/runtime/dex-parser/dex-parser.ts`

This is the highest-priority problem.

The current opcode length table has incorrect entries.

Correct these instructions:

| Opcode | Instruction | Correct length |
|---|---|---:|
| 0xfa | invoke-polymorphic | 4 code units |
| 0xfb | invoke-polymorphic/range | 4 code units |
| 0xfc | invoke-custom | 3 code units |
| 0xfd | invoke-custom/range | 3 code units |
| 0xfe | const-method-handle | 2 code units |
| 0xff | const-method-type | 2 code units |

The code-unit length is measured in 16-bit units.

Do not merely change six array values.

Develop a reliable, version-aware DEX instruction metadata system.

For every supported opcode, maintain:

- Opcode number.
- Mnemonic.
- Instruction format.
- Instruction length.
- DEX version availability.
- Operand layout.
- Register operands.
- Literal operands.
- Reference indexes.
- Payload requirements.

Implement correct instruction lengths for all defined instructions in the selected DEX versions.

Handle special payload formats separately:

- Packed-switch payload.
- Sparse-switch payload.
- Fill-array-data payload.

Important:

The DEX format uses shared opcode values that must be interpreted according to their defined formats and version rules.

Do not confuse unused opcode values with valid instructions.

Unknown or reserved opcodes must produce explicit unsupported-instruction results rather than guessed decoding.

Never silently advance one code unit for an instruction whose length is unknown.

Never decode beyond the declared code item.

Never interpret instruction operands as independent instructions.

### Required opcode tests

Test all instruction lengths.

Explicitly test:

- 10x.
- 12x.
- 11n.
- 11x.
- 10t.
- 20t.
- 21t.
- 21s.
- 21h.
- 21c.
- 22x.
- 22t.
- 22s.
- 22c.
- 23x.
- 30t.
- 31i.
- 31t.
- 31c.
- 32x.
- 35c.
- 3rc.
- 45cc.
- 4rcc.
- 51l.

Verify the next instruction's actual position after every decoded instruction.

Compare decoding with independently generated DEX fixtures.

Use the official Android Dalvik bytecode specification as the reference.

---

# TASK 2 — IMPLEMENT ACTUAL DEX SHA-1 VERIFICATION

File:

`src/runtime/dex-parser/dex-parser.ts`

The current implementation reads the stored SHA-1 signature but does not verify it.

Implement actual signature verification.

DEX header layout:

- SHA-1 signature: bytes 12–31.
- Adler-32 checksum: bytes 8–11.
- File size: bytes 32–35.

The SHA-1 signature must be calculated over the file bytes beginning at offset 32 through the declared file size.

The Adler-32 checksum must be calculated over the bytes beginning at offset 12 through the declared file size.

Verify both independently.

Requirements:

1. Calculate SHA-1.
2. Compare against stored signature.
3. Calculate Adler-32.
4. Compare against stored checksum.
5. Reject mismatches.
6. Report descriptive integrity errors.

The current parser is synchronous.

Choose an appropriate implementation strategy:

- A correctly tested synchronous SHA-1 implementation; or
- A carefully designed asynchronous parser refactor that updates every caller consistently.

Do not introduce an unreliable SHA-1 implementation simply to avoid changing function signatures.

Add known-answer SHA-1 tests.

Include:

- Empty input.
- `abc`.
- Multi-block input.
- Large input.
- DEX signature verification.
- Deliberately corrupted signature.
- Correct signature with incorrect checksum.
- Incorrect signature with correct checksum.

Do not confuse a SHA-1 signature check with application publisher-signature verification. APK signing requires separate verification.

---

# TASK 3 — STRICT DEX FILE BOUNDARY VALIDATION

File:

`src/runtime/dex-parser/dex-parser.ts`

The existing parser compares declared DEX file size with the provided buffer size but later validates sections using the complete buffer length.

This can allow access to appended bytes beyond the declared DEX file.

Repair the complete parsing boundary model.

Create a validated file boundary.

Every DEX parser function must respect it.

Validate:

- Header.
- String IDs.
- Type IDs.
- Proto IDs.
- Field IDs.
- Method IDs.
- Class definitions.
- String data.
- Class data.
- Code items.
- Debug information.
- Exception handlers.
- Map data.

Validate all referenced indexes.

Specifically inspect:

- `protoIdx`.
- `classIdx`.
- `superclassIdx`.
- `sourceFileIdx`.
- `nameIdx`.
- `codeOff`.
- `debugInfoOff`.
- `classDataOff`.

Reject integer overflows and invalid offsets.

Verify section alignment.

Do not silently replace invalid indexes with empty strings or fake class names.

For an extracted DEX entry, verify that its declared file size matches the actual entry length, or explicitly document and test the chosen trailing-data policy.

Never allow parser reads beyond the validated DEX range.

---

# TASK 4 — REPAIR DEX STRING AND LEB128 DECODERS

Review:

`readMutf8String`

`readUleb128`

`readSleb128`

Required improvements:

### MUTF-8

- Correct encoded UTF-16 length verification.
- Embedded null handling.
- Surrogate pair handling.
- Invalid continuation rejection.
- Truncated sequence rejection.
- Missing terminator rejection.
- String allocation limits.
- Boundary enforcement within declared DEX file.

Do not use an unbounded `String.fromCharCode(...largeArray)` operation.

Use a safe string construction approach for large inputs.

### ULEB128

- Maximum five-byte limit.
- Correct 32-bit overflow detection.
- Truncated-input rejection.
- Correct final-byte validation.
- Safe cursor advancement.

### SLEB128

- Correct sign extension.
- Five-byte overflow validation.
- Truncated-input detection.
- Correct signed 32-bit results.

Add independent reference tests.

---

# TASK 5 — FIX ANDROID BINARY XML DECLARED FILE BOUNDARIES

File:

`src/runtime/manifest-engine/axml-parser.ts`

The parser currently establishes:

`maxReadableSize = Math.min(buffer.byteLength, declaredFileSize)`

But several checks still compare against the complete buffer length.

Correct this.

Validate:

- Declared file size.
- Actual file size.
- Header size.
- Chunk offsets.
- Chunk sizes.
- String-pool offsets.
- Resource-map offsets.
- Element offsets.
- Attribute offsets.

Every chunk must remain inside the declared file boundary.

Every substructure must remain inside its parent chunk.

Reject:

- Declared file size smaller than the XML header.
- Declared file size greater than the actual buffer.
- Invalid chunk sizes.
- Overlapping or invalid chunk structures.
- Invalid string offsets.
- Invalid style offsets.
- Invalid attribute counts.
- Truncated strings.
- Incorrect UTF-8 lengths.
- Incorrect UTF-16 lengths.
- Incorrect element nesting.

Do not silently replace malformed string references with empty strings.

Report structured parsing errors.

Preserve valid resource references without pretending to resolve them.

Maintain support for valid Android binary XML manifests.

Also inspect plain-text XML fallback behaviour and ensure malformed input cannot produce misleading successful metadata.

---

# TASK 6 — DEEPLY HARDEN ZIP ARCHIVE PARSER

File:

`src/runtime/apk-extractor/zip-parser.ts`

Preserve the existing `fflate` implementation, CRC32 verification, archive limits and decompression improvements.

Do not replace them with a custom incomplete inflater.

Perform another complete ZIP specification review.

### A. EOCD validation

Implement:

- EOCD signature verification.
- EOCD fixed-header validation.
- Comment-length validation.
- Exact archive-ending validation.
- Multi-disk archive rejection.
- Entry-count consistency.
- Central-directory offset validation.
- Central-directory size validation.

The EOCD signature may occur inside an archive comment.

Do not blindly accept the first matching signature.

### B. Central-directory validation

Every entry must be validated against the declared central-directory boundary, not merely the complete archive buffer.

Validate:

- Central-directory signatures.
- Fixed header size.
- Filename size.
- Extra-field size.
- Comment size.
- Compression method.
- General-purpose flags.
- CRC32.
- Compressed size.
- Uncompressed size.
- Local-header offset.

Verify that parsed entries consume the expected central-directory region.

Reject unsupported archive features accurately.

### C. Multi-disk and ZIP64

Explicitly reject unsupported multi-disk archives.

Implement clear and correct ZIP64 detection.

Do not claim ZIP64 support unless it is actually implemented and tested.

If the software intentionally rejects ZIP64, explain this in the interface and documentation.

### D. Local-header validation

During entry extraction, compare:

- Local filename against central-directory filename.
- Local compression method against central-directory method.
- Relevant general-purpose flags.
- Local CRC where applicable.
- Local sizes where applicable.

Handle data-descriptor mode correctly.

Do not incorrectly reject valid APK archives that legitimately use data descriptors.

Validate:

- Local header offsets.
- Filename bounds.
- Extra-field bounds.
- Compressed-data bounds.
- Central-directory overlap.
- Entry-data overlap.

Reject malformed or overlapping entry data.

### E. CRC32 and decompression

Preserve CRC32 verification.

Verify decompressed sizes.

Verify stored entry sizes.

Ensure unsupported compression methods fail explicitly.

Use safe decompression limits.

Do not allocate unbounded memory using declared archive sizes.

Add tests for fixed and dynamic Huffman streams.

### F. Security testing

Test:

- ZIP bombs.
- Path traversal.
- Duplicate entries.
- Case-insensitive collisions.
- Absolute paths.
- Control characters.
- Malformed central-directory records.
- EOCD signatures within comments.
- Incorrect data descriptors.
- Local/central header mismatch.
- Entry overlap.
- Encrypted entries.
- Multi-disk archives.
- ZIP64 markers.
- Incorrect CRC.
- Truncated compressed data.

---

# TASK 7 — FIX REMOTE DOWNLOAD SIZE LIMIT

File:

`src/runtime/apk-loader/runtime-service.ts`

The previous audit found that the 250 MB download cap is not consistently applied when response streaming is unavailable.

Repair both paths.

Streaming path:

- Enforce the maximum size for every received chunk.
- Cancel the stream immediately when the limit is exceeded.
- Release reader locks.
- Handle AbortController cancellation.
- Prevent unbounded chunk accumulation.
- Report download progress correctly.

Non-streaming fallback:

Do not blindly call `response.arrayBuffer()` before validating the available size information.

Implement a safe fallback strategy.

If response size cannot be safely determined or limited, reject oversized or unsupported download cases with a clear error.

Verify the actual final byte length.

Do not trust Content-Length alone.

Validate file signatures before passing downloaded data to APK analysis.

### Filename handling

Improve filename extraction:

- Decode URL-encoded characters safely.
- Remove query strings and fragments.
- Prevent path-based filename injection.
- Normalize the final filename.
- Avoid silently renaming arbitrary HTML downloads into APK files.

### Error handling

Provide meaningful errors for:

- CORS.
- HTTP 404.
- HTTP 403.
- Rate limiting.
- Network interruption.
- Invalid file signatures.
- Oversized files.
- User cancellation.

---

# TASK 8 — CONNECT REAL DOWNLOAD PROGRESS TO UI

Inspect:

- `src/runtime/apk-loader/runtime-service.ts`
- `src/components/ImportZone.tsx`

The service has an `onProgress` callback, but the UI does not properly use it.

Integrate the actual callback.

Display:

- Downloaded bytes.
- Total bytes when available.
- Download percentage when available.
- Current download speed where accurately measurable.
- Cancellation control.
- Error state.

Never display invented progress.

When total size is unavailable, show downloaded bytes without a fake percentage.

Ensure a completed download transitions into the real APK analysis pipeline.

---

# TASK 9 — FIX NATIVE LIBRARY INSPECTION BUDGET

Inspect:

`src/runtime/apk-loader/runtime-service.ts`

`src/runtime/native-inspector/elf-inspector.ts`

The current native-library inspector has maximum file-count and byte-budget limits.

Correct the budget logic.

Before extracting each native library:

1. Check remaining file budget.
2. Check declared uncompressed size.
3. Verify whether the file fits within remaining byte budget.
4. Only then extract it.
5. Verify actual extracted size.
6. Update accumulated byte count.
7. Record failures and skipped entries.

Never exceed the configured inspection budget.

Do not silently swallow extraction errors.

Report:

- Total libraries discovered.
- Total libraries inspected.
- Total libraries skipped.
- Total bytes inspected.
- Reasons for skipped libraries.
- ABI mismatches.
- Invalid ELF files.

Ensure the UI does not imply complete native-library inspection when files were skipped.

---

# TASK 10 — COMPLETE APK ANALYSIS PIPELINE VALIDATION

File:

`src/runtime/apk-loader/runtime-service.ts`

Audit the complete analysis flow.

Required stages:

1. Input validation.
2. APK archive parsing.
3. SHA-256.
4. Entry validation.
5. Manifest extraction.
6. Binary XML parsing.
7. DEX discovery.
8. DEX extraction.
9. DEX SHA-1 verification.
10. DEX Adler-32 verification.
11. DEX structural parsing.
12. ELF extraction.
13. ELF inspection.
14. Compatibility evaluation.
15. Final structured report.

Use structured errors with clear stages.

Do not silently skip critical parsing errors.

Distinguish optional metadata inspection failure from APK corruption.

Ensure multi-DEX APKs are handled correctly.

Do not confuse a ZIP container containing multiple APKs with a single APK containing multiple DEX files.

Preserve all verified reports and diagnostics.

---

# TASK 11 — EXPAND AUTOMATED REGRESSION TESTS

File:

`src/runtime/tests/runtime-tests.ts`

The existing suite has only 18 tests.

Expand it into a comprehensive parser verification suite.

### SHA-256 and SHA-1

Include known-answer vectors and actual header verification tests.

### ZIP

Test all previously listed archive structures and security cases.

### Binary XML

Test actual valid Android binary XML fixtures and malformed chunks.

### DEX

Create test coverage for:

- Header versions.
- SHA-1 verification.
- Adler-32 verification.
- All opcode lengths.
- Invalid opcode values.
- DEX file-size mismatch.
- Out-of-bounds sections.
- Invalid class indexes.
- Invalid method indexes.
- Invalid proto indexes.
- Invalid superclass indexes.
- Invalid source file indexes.
- Invalid class data.
- Invalid code offsets.
- Debug information boundaries.
- ULEB128.
- SLEB128.
- MUTF-8.
- Multiple DEX files.
- Truncated files.

### ELF

Test:

- ELF32.
- ELF64.
- ARM.
- ARM64.
- x86.
- x86-64.
- RISC-V.
- Invalid headers.
- ABI mismatch.
- Budget exhaustion.
- Skipped files.

### Remote downloads

Test:

- Content-Length available.
- Content-Length missing.
- Misleading Content-Length.
- Interrupted stream.
- Oversized stream.
- Invalid ZIP response.
- HTTP errors.
- Cancellation.

### Compatibility

Ensure valid analysis does not imply executable runtime support.

All APKs must remain `ANALYSIS_ONLY` until a real execution engine has been implemented and actual execution has been verified.

---

# TASK 12 — USE INDEPENDENT TEST FIXTURES

The project currently relies significantly on synthetic fixtures generated by its own code.

Keep those fixtures.

But introduce independent fixtures.

Use:

- Independently generated ZIP files.
- Android SDK-generated binary manifests.
- Android SDK-generated DEX files.
- Independently generated SHA test vectors.
- Real ELF headers from legal test binaries.

Do not use the parser's own output as the only evidence that the parser is correct.

Document fixture origins and licenses.

Do not commit proprietary APKs or copyrighted applications without permission.

---

# TASK 13 — UPDATE GITHUB ACTIONS

File:

`.github/workflows/ci.yml`

Preserve Bun-based dependency installation.

Inspect the current maintained versions of GitHub Actions.

Upgrade outdated actions to maintained releases compatible with the current GitHub Actions runner and Node.js 24.

Keep:

- Frozen Bun installation.
- TypeScript checking.
- Unit tests.
- Integration tests.
- Production builds.

Add any necessary test or security verification steps.

Never suppress failures.

The workflow must fail if any required check fails.

Make sure all jobs run correctly on a clean Ubuntu runner.

---

# TASK 14 — README AND DOCUMENTATION

Update:

`README.md`

Accurately document:

- Current APK analysis functionality.
- ZIP compression support.
- ZIP64 limitations.
- Manifest parser coverage.
- DEX parser coverage.
- Opcode coverage.
- SHA-1 and Adler-32 verification.
- ELF architecture inspection.
- Native inspection budgets.
- Remote GitHub importer limitations.
- Browser security limitations.
- Runtime execution status.

Do not claim complete DEX decoding before it is complete.

Do not claim SHA-1 verification before it is tested.

Do not claim complete ZIP security without the corresponding tests.

Clearly display:

APPLICATION EXECUTION: NOT IMPLEMENTED

Keep the roadmap accurate.

Do not mark unimplemented phases complete.

---

# TASK 15 — PERFORMANCE AND RESOURCE SAFETY

Review the entire analysis pipeline.

Improve:

- Memory management.
- Large archive handling.
- Typed array allocation.
- String decoding.
- Decompression.
- Remote downloads.
- Cancellation.
- Browser responsiveness.

Do not unnecessarily duplicate large APK buffers.

Use safe workers where appropriate.

Do not freeze mobile browsers during large APK analysis.

Use explicit resource budgets.

If a file exceeds supported limits, explain why it cannot be processed.

---

# TASK 16 — FINAL VERIFICATION

After making repairs, execute the complete project verification.

Run:

1. `bun install --frozen-lockfile`
2. `bun run typecheck`
3. `bun run test`
4. All new parser tests.
5. Browser integration tests.
6. Production build.
7. GitHub Actions.

Inspect the final changed files.

Search for:

- Fake execution.
- Simulated execution.
- Suppressed errors.
- Incorrect opcode lengths.
- Unverified integrity claims.
- Unbounded allocations.
- Silent extraction failures.
- Empty implementations.
- Incorrect compatibility claims.

Fix all required failures.

Do not report successful tests unless the actual commands were executed.

---

# TASK 17 — GITHUB COMMIT

After successful verification:

1. Review the Git diff.
2. Verify that no existing working features were removed.
3. Verify the lockfile.
4. Verify licensing.
5. Ensure no secrets were committed.
6. Commit repairs to the repair branch.
7. Push the branch if GitHub write permission is available.

Never force-push.

Do not claim that changes were pushed unless GitHub confirms it.

---

# FINAL ENGINEERING REPORT

Provide:

## Repository
- Branch.
- Latest commit.
- Changed files.

## DEX
- Corrected opcode lengths.
- Supported opcode coverage.
- SHA-1 verification.
- Adler-32 verification.
- Structural validation.
- Remaining limitations.

## ZIP
- Compression support.
- EOCD validation.
- Central/local header validation.
- CRC verification.
- Security checks.
- Remaining limitations.

## Manifest
- Binary XML coverage.
- Boundary validation.
- String pool verification.
- Remaining limitations.

## Remote importer
- GitHub release handling.
- Download size enforcement.
- Streaming progress.
- Cancellation.

## Native inspection
- ABI verification.
- Actual inspection budget.
- Skipped files.

## Automated tests
- Total tests.
- Passed.
- Failed.
- Skipped.
- Execution duration.

## Build verification
- TypeScript result.
- Production build result.
- GitHub Actions result.

## Remaining work
- Known bugs.
- Unsupported formats.
- Next development milestone.

Do not invent test counts or successful results.

---

# FINAL PROJECT DIRECTION

Our objective remains:

APK RUNTIME ENGINE

An independent browser-side Android APK runtime that eventually executes compatible Android applications locally using WebAssembly and visitor-device resources.

No mandatory paid APIs.

No mandatory cloud Android emulator.

No mandatory remote Android server.

No fake application execution.

However, this repair task must ONLY focus on making the existing Phase 1 foundation correct, reliable, secure and thoroughly tested.

Do not start the DEX VM yet.

The next milestone begins only after all required Phase 1 checks pass.

CORRECTNESS FIRST.
REAL IMPLEMENTATION FIRST.
TESTING FIRST.