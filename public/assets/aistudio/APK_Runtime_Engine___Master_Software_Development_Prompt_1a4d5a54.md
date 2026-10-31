# PROJECT: APK RUNTIME ENGINE
## Build an Independent, Browser-Based Android APK Execution Software

Act as a senior Android runtime engineer, operating-system developer, Rust engineer, WebAssembly specialist, browser-engine developer, security engineer and full-stack software architect.

Your task is to develop a serious, extensible, open-source software project called **APK Runtime Engine**.

This is NOT an ordinary website, APK information viewer, APK downloader, Android emulator website or virtual phone interface.

The objective is to develop our own browser-side Android application runtime that progressively gains the ability to execute real Android APK applications directly inside modern web browsers.

The long-term goal is to execute compatible Android applications using the visitor's own device resources, without requiring a cloud Android emulator, VPS, paid API, paid service or remote execution server.

The software must be designed for long-term development, with a modular architecture and independently testable components.

---

# 1. PRIMARY OBJECTIVE

Develop an independent Android APK runtime that:

1. Accepts APK files from local storage.
2. Imports APK files from public GitHub repositories and releases.
3. Extracts APK archive contents.
4. Analyses Android application metadata.
5. Reads Android binary XML manifests.
6. Parses DEX bytecode.
7. Develops its own DEX execution engine.
8. Implements an Android API compatibility layer.
9. Provides an application lifecycle manager.
10. Implements application resource management.
11. Renders supported application interfaces inside the browser.
12. Handles user input, touch interactions and graphics.
13. Progressively supports more Android application functionality.
14. Executes supported applications locally through WebAssembly and browser technologies.

IMPORTANT:

Do not claim that arbitrary Android APK files can already run.

An Android application requires Android framework APIs, runtime behaviour and sometimes native libraries. Implement these capabilities progressively and prove compatibility through real tests.

---

# 2. TECHNOLOGY STACK

Use a modular technology architecture.

Frontend:
- React
- TypeScript
- Vite
- Modern CSS
- HTML5
- Web Workers

Core runtime:
- Rust
- WebAssembly
- wasm-bindgen where appropriate

APK processing:
- ZIP archive parser
- Binary Android XML parser
- DEX parser
- Resource inspection engine

Graphics:
- HTML Canvas
- WebGL where appropriate
- Browser rendering APIs

Storage:
- IndexedDB
- Origin Private File System where supported

Testing:
- Vitest
- Rust unit tests
- Playwright
- Automated browser compatibility tests

Development:
- GitHub
- GitHub Actions
- ESLint
- Prettier
- Cargo

Choose stable, maintained dependencies. Avoid unnecessary libraries and dependencies that make the runtime unnecessarily large.

---

# 3. SOFTWARE ARCHITECTURE

Create independent modules.

PROJECT STRUCTURE:

apk-runtime-engine/
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── layouts/
│   │   ├── hooks/
│   │   ├── services/
│   │   └── styles/
│   │
│   └── public/
│
├── runtime/
│   ├── core/
│   ├── apk-loader/
│   ├── apk-extractor/
│   ├── apk-parser/
│   ├── manifest-engine/
│   ├── dex-parser/
│   ├── dex-vm/
│   ├── class-loader/
│   ├── memory-manager/
│   ├── android-api/
│   ├── activity-manager/
│   ├── resource-engine/
│   ├── graphics-engine/
│   ├── input-engine/
│   ├── audio-engine/
│   ├── network-engine/
│   ├── storage-engine/
│   └── compatibility-engine/
│
├── wasm/
│   ├── src/
│   └── Cargo.toml
│
├── workers/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── apk-samples/
│   └── compatibility/
│
├── examples/
│
├── docs/
│
├── scripts/
│
├── .github/
│   └── workflows/
│
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md

Each module must have a clear responsibility and documented interface.

Do not put the entire runtime inside one JavaScript file.

---

# 4. APK IMPORT ENGINE

Implement a reliable APK import system.

Supported inputs:

- Local APK uploads.
- Public GitHub release APK URLs.
- GitHub repository links.
- GitHub release links.
- Supported ZIP files containing APK files.

Functions:

- APK selection.
- Drag and drop.
- Upload progress.
- File validation.
- File size detection.
- SHA-256 calculation.
- APK archive inspection.
- Automatic APK discovery inside ZIP files.
- Extraction of one selected APK.
- Error reporting.
- Duplicate detection.

GitHub integration:

For public repositories, use GitHub's public API where appropriate to locate release assets.

Allow users to select a release and its APK asset.

Respect browser CORS restrictions. Never secretly upload files to external proxy services.

If a GitHub download cannot be fetched because of browser restrictions, clearly explain the issue and provide a local upload alternative.

Never request a user's GitHub password or embed private API keys.

---

# 5. APK ANALYSIS ENGINE

Build an actual APK metadata analysis system.

Extract and inspect:

- Package name.
- Application label.
- Version name.
- Version code.
- Minimum SDK.
- Target SDK.
- Maximum SDK when present.
- Application icon.
- Activity declarations.
- Launcher activity.
- Services.
- Broadcast receivers.
- Content providers.
- Permissions.
- Requested hardware features.
- Application resources.
- Native library directories.
- DEX file count.
- DEX file sizes.
- Supported ABI information.

Implement a binary AndroidManifest.xml parser.

Do not assume Android manifests are ordinary XML text files.

Handle malformed files safely and report clear parsing errors.

Show a useful APK analysis report.

---

# 6. DEX PARSING ENGINE

Develop our own DEX inspection module.

Implement:

- DEX header validation.
- Magic and version detection.
- Checksum inspection.
- File-size validation.
- String ID parsing.
- Type ID parsing.
- Prototype ID parsing.
- Field ID parsing.
- Method ID parsing.
- Class definition parsing.
- Encoded method information.
- Code item inspection.
- Instruction stream decoding.

Create a DEX instruction decoder.

Develop instruction metadata for the supported DEX instruction set.

Never execute malformed DEX code blindly.

Validate offsets, section limits and data boundaries.

Create sample DEX files and automated parser tests.

---

# 7. DEX VIRTUAL MACHINE

This is the main development objective.

Develop an independent register-based DEX virtual machine.

Implement progressively:

- Virtual registers.
- Stack frames.
- Method invocation.
- Class loading.
- Object allocation.
- Primitive types.
- Arrays.
- Strings.
- Fields.
- Exceptions.
- Arithmetic operations.
- Comparisons.
- Branching.
- Method returns.
- Basic synchronization.
- Garbage collection.

Use a documented execution model.

Do not simulate execution by simply displaying extracted code or producing fake output.

Create automated tests proving that real DEX instructions execute correctly.

Document unsupported instructions.

---

# 8. ANDROID FRAMEWORK COMPATIBILITY

An APK depends on Android framework classes.

Develop a compatibility layer with independently implemented API packages.

Initially prioritize:

- java.lang
- java.util
- java.io
- android.app
- android.content
- android.os
- android.view
- android.widget
- android.graphics
- android.text
- android.util

Start with a small working Android API subset.

Develop:

Application lifecycle:
- Application creation.
- Activity creation.
- Activity start.
- Activity resume.
- Activity pause.
- Activity stop.
- Activity destruction.

Basic UI:
- View.
- TextView.
- Button.
- ImageView.
- LinearLayout.
- FrameLayout.
- Basic layout parameters.
- Canvas drawing.

Basic application communication:
- Intent.
- Bundle.
- Context.
- Handler.
- Basic event callbacks.

Clearly identify methods that are not yet implemented.

Do not falsely report complete Android framework compatibility.

---

# 9. APPLICATION GRAPHICS ENGINE

Develop an independent rendering engine.

The objective is to show the running application's interface directly inside a webpage.

It must NOT display a decorative phone mockup.

Implement:

- Application viewport.
- Text rendering.
- Image rendering.
- Basic layouts.
- Buttons.
- Scrollable views.
- Custom drawing.
- Touch events.
- Pointer events.
- Keyboard input.
- Screen orientation.
- Display scaling.
- Application resizing.

Use Canvas and WebGL where appropriate.

Separate application layout logic from rendering logic.

---

# 10. BROWSER INPUT ENGINE

Implement:

- Touch input.
- Mouse input.
- Keyboard input.
- Tap.
- Double tap.
- Long press.
- Scrolling.
- Dragging.
- Multi-touch where supported.
- Back navigation.
- Keyboard focus.

Make the application usable on mobile browsers and desktop browsers.

---

# 11. AUDIO AND NETWORKING

Build these modules progressively.

Audio:
- Audio output abstraction.
- Supported application audio playback.
- Volume control.
- Audio lifecycle handling.

Networking:
- HTTP request abstraction.
- HTTPS support through browser-approved mechanisms.
- Fetch API integration.
- CORS error handling.
- Network permission management.

Never bypass browser security restrictions.

---

# 12. NATIVE LIBRARY COMPATIBILITY

Native libraries require a separate compatibility strategy.

Inspect:

- ELF headers.
- CPU architecture.
- Shared library dependencies.
- Native library locations.
- JNI declarations.

Explore a WebAssembly-compatible native execution layer.

Do not pretend that ARM or ARM64 native Android libraries can automatically execute inside WebAssembly.

Document architecture incompatibilities.

Create a clear system for identifying unsupported native dependencies.

---

# 13. RUNTIME MANAGEMENT

Create a runtime manager.

Features:

- Create application session.
- Load APK.
- Inspect compatibility.
- Start application.
- Pause execution.
- Resume execution.
- Stop execution.
- Clear application memory.
- Clear application storage.
- Restart application.
- Report runtime crashes.
- Capture runtime logs.

Use Web Workers to isolate heavy processing.

Use WebAssembly modules for appropriate performance-critical components.

Support cancellation and resource limits.

---

# 14. SECURITY

APK files are untrusted input.

Implement:

- Archive path validation.
- ZIP bomb protection.
- File-size limits.
- Memory limits.
- CPU execution budgets.
- DEX instruction validation.
- Bounds checking.
- Malformed archive rejection.
- Sandboxed application execution design.
- No arbitrary host-page DOM access.
- No automatic execution of uploaded files.
- Restricted filesystem access.
- Secure error handling.

Never execute untrusted APK code with unrestricted browser privileges.

---

# 15. USER INTERFACE DESIGN

Create a modern, premium, professional software interface.

Product name:

APK RUNTIME ENGINE

Design direction:

- Clean modern dashboard.
- Dark and light modes.
- Blue and purple accents.
- Professional typography.
- Smooth animations.
- Responsive mobile layout.
- Minimal unnecessary elements.
- Fast loading.
- Accessible controls.

Main dashboard:

HEADER:
- APK Runtime logo.
- Home.
- Documentation.
- GitHub.
- Settings.
- Theme toggle.

MAIN SECTION:

Title:
Run Android Apps in Your Browser

Subtitle:
Explore our independent browser-based Android runtime.

IMPORT AREA:

- Upload APK.
- Import from GitHub.
- Import ZIP.
- Drag and drop files.

ANALYSIS AREA:

Display:

- APK name.
- Package name.
- Version.
- Minimum SDK.
- Target SDK.
- Permissions.
- DEX information.
- Architecture.
- Compatibility status.

RUNTIME AREA:

- Run supported application.
- Pause.
- Resume.
- Restart.
- Stop.
- Fullscreen.
- Runtime logs.

Show a clear compatibility badge:

SUPPORTED
PARTIALLY SUPPORTED
NOT SUPPORTED
ANALYSIS ONLY

Do not activate Run for APK files that the runtime cannot execute.

Do not use fake loading animations to imply an APK is running.

---

# 16. TESTING SYSTEM

Testing is mandatory.

Create:

APK parser unit tests.

Manifest parser tests.

DEX parser tests.

DEX instruction tests.

Memory manager tests.

Android API tests.

Rendering tests.

Application lifecycle tests.

Browser integration tests.

Security tests for malformed APK files.

Use real APK test fixtures that are legally available for development.

Also compile simple Android sample applications ourselves for predictable testing.

Every implemented feature must have a test.

When a test fails:

1. Identify the cause.
2. Fix the implementation.
3. Add a regression test.
4. Run the relevant tests again.

Never claim tests pass without running them.

---

# 17. GITHUB DEVELOPMENT

Create a complete GitHub-ready project.

Requirements:

- Professional README.
- Full source code.
- Clear installation instructions.
- Development instructions.
- Architecture documentation.
- Build instructions.
- Testing documentation.
- Contribution guidelines.
- MIT license for original project code, with third-party licenses preserved.
- GitHub Actions workflow.
- Automated build verification.
- Type checking.
- Linting.
- Rust compilation checks.
- Automated tests.

Never commit API keys, secrets or private tokens.

If GitHub integration is available, create or update the connected repository and commit the actual project files.

Otherwise, provide a complete GitHub-ready source tree.

---

# 18. DEVELOPMENT PHASES

Do not attempt to build every advanced feature in one generation.

Build in strict phases.

PHASE 1:
Complete APK loading, extraction and analysis.

PHASE 2:
Complete AndroidManifest binary parser.

PHASE 3:
Complete DEX parser and instruction decoder.

PHASE 4:
Develop the basic DEX virtual machine.

PHASE 5:
Implement the initial Android API compatibility layer.

PHASE 6:
Implement application lifecycle.

PHASE 7:
Implement graphical rendering and input.

PHASE 8:
Execute a simple Android application compiled into DEX.

PHASE 9:
Expand Android API compatibility.

PHASE 10:
Investigate native libraries, JNI and broader APK compatibility.

At the end of each phase:

- Run tests.
- Fix errors.
- Update documentation.
- Report completed features.
- Report limitations.
- Identify the next development milestone.

---

# 19. STRICT DEVELOPMENT RULES

These rules are mandatory.

1. Build real working software, not a UI-only prototype.
2. Do not return empty functions.
3. Do not use fake buttons.
4. Do not hardcode success responses.
5. Do not simulate APK execution.
6. Do not create fake compatibility reports.
7. Do not claim every APK works.
8. Do not require paid APIs.
9. Do not introduce mandatory cloud Android services.
10. Do not create unnecessary duplicate files.
11. Do not overwrite working modules without testing.
12. Do not remove existing functionality.
13. Maintain clear module interfaces.
14. Use TypeScript types.
15. Handle errors properly.
16. Write comments for complex runtime code.
17. Keep the application lightweight.
18. Optimize memory usage.
19. Test on mobile browsers.
20. Keep the software fully self-hostable.

When an advanced feature cannot yet be implemented, document the limitation and provide a concrete development plan instead of creating a fake implementation.

---

# 20. FIRST TASK: START BUILDING

Begin with Phase 1.

Do not just provide me an architecture explanation.

Actually create the project files and working application.

First implement:

1. Premium responsive user interface.
2. APK file uploader.
3. ZIP file importer.
4. Public GitHub APK importer.
5. Safe browser-side archive extraction.
6. APK metadata analysis.
7. Binary manifest parser foundation.
8. DEX file discovery and header inspection.
9. SHA-256 calculation.
10. Detailed analysis report.
11. Error handling.
12. Automated tests.
13. GitHub Actions.
14. Complete documentation.

Keep the implementation modular so that later DEX VM and Android compatibility modules can be integrated without rebuilding the entire project.

At the end, provide:

- Files created.
- Features actually implemented.
- Tests executed and their results.
- Known limitations.
- How to run locally.
- How to deploy free frontend hosting.
- Exact next steps for Phase 2.

OUR FINAL VISION:

An independent, open-source Android APK runtime that progressively executes real Android applications directly in browsers using local device resources.

No mandatory paid APIs.
No mandatory paid cloud emulator.
No mandatory remote Android server.
No APK installation on visitor devices.

Build the foundation correctly, test continuously and expand compatibility through real engineering.