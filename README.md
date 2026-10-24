# Kernel Call

A native Android application for **static APK analysis and security intelligence**.
Built with Kotlin, Jetpack Compose, and Material 3 — no backend, no cloud services,
no sign-in.

> What Phase 1 does: pick an APK file, read its bytes, and compute a SHA-256
> fingerprint — entirely on the device. Nothing is uploaded, the APK is never
> installed or executed, and **no verdict** (clean / suspicious / malicious) is
> claimed. Deep static analysis findings arrive in Phase 2.

## Features (Phase 2 — static analysis engine)

Phase 2 adds the first real analysis engine on top of the Phase 1 scanner
(architecture: see `ARCHITECTURE.md`):

- **Static APK analysis** (`static.v2` engine): binary AXML manifest parsing
  (package, versionCode/versionName, min/target SDK, declared permissions,
  exported components, debuggable/allowBackup/cleartext flags, boot/SMS intent
  interceptors), zip inventory (dex count, native ABIs, payload-like assets),
  v1 signing-certificate read (subject/issuer/validity), dex URL-literal scan.
- **Honest classification**: every finding is labelled
  `CONFIRMED OBSERVATION`, `HEURISTIC INDICATOR`, `UNKNOWN`, or `SANDBOX ONLY`.
  Unverifiable things (v2/v3 signatures, obfuscation, native behavior) are
  reported openly as unknowns — never fabricated.
- **Evidence store**: reports persisted per SHA-256 in
  `filesDir/reports/*.json` (schemaVersion 2); scan history migrated from the
  Phase 1 format automatically (v1 → v2).
- **APK cache**: content-addressed `filesDir/apkcache/<sha256>.apk`
  (≤ 200 MB/file, 600 MB budget, oldest-first eviction), used for re-analysis.
- **Job lifecycle**: `AnalysisCoordinator` runs engines sequentially with a
  percent + stage label, per-engine duration stats embedded in each report.

Everything below stays true: nothing is uploaded, nothing is installed or
executed by the app, and hashing alone never claims to detect malware.

## Features (Phase 1)

- **Dashboard** — brand header, scan action, total-scan stats and recent scans,
  with a clear empty state for first-time users.
- **Scan** — APK picker (Storage Access Framework), live fingerprinting progress
  (bytes read), result showing `filename`, `size`, and full `SHA-256`.
- **Results** — file identity card plus a reserved section for Phase 2 findings
  that honestly shows "No findings yet".
- **History** — every fingerprint recorded locally (SharedPreferences/JSON),
  with a useful empty state.

## Architecture (deliberately simple)

```
app/src/main/java/com/kernelcall/app/
├── MainActivity.kt                  # Compose entry point
├── analysis/ApkFingerprinter.kt     # SHA-256 streaming on Dispatchers.IO
├── data/ScanRecord.kt               # Immutable scan record model
├── data/ScanHistoryStore.kt         # On-device history (StateFlow + JSON)
└── ui/
    ├── KernelCallApp.kt             # NavHost + bottom navigation
    ├── ScanViewModel.kt             # Scan state machine (Idle/Hashing/Done/Error)
    ├── Formats.kt                   # Size / hash / date formatting
    ├── theme/                       # Dark "security console" theme
    ├── components/                  # PanelCard, EmptyState, InfoRow...
    └── screens/                     # Dashboard, Scan, History, Results
```

Key engineering points:
- Hashing runs on a **coroutine on `Dispatchers.IO`** — the UI never freezes.
- All file access is wrapped in graceful **error handling** with retry UI.
- **Privacy**: the app requests no storage permissions (SAF handles access),
  uploads nothing, installs nothing, and executes nothing.
- **Honesty**: hashing identifies a file; the app never suggests it detects
  malware by itself, and never fabricates analysis findings.

## Requirements

- Android Studio (any recent version) *or* just the Android SDK + a JDK
- JDK 17+ (verified with Oracle JDK 21)
- Android SDK: platform `android-35`, build-tools `35.0.0`

## Building

The repo includes a full Gradle wrapper. There is no need for a system Gradle.

```bat
:: from the project root
gradlew.bat assembleDebug         :: build the debug APK
gradlew.bat testDebugUnitTest     :: JVM unit tests (AXML parser, zip inventory, engine)
```

The first run downloads Gradle 8.10.2 and dependencies automatically.

The debug APK is produced at `app/build/outputs/apk/debug/app-debug.apk`.

### Install on a device

```bat
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

(Enable USB debugging on the phone first; or simply open the project in
Android Studio and press Run.)

### Manual end-to-end smoke test (SAF flow)

1. Launch Kernel Call on the device.
2. Scan tab → *Select APK file* → pick any `.apk` (e.g. one shared via a file
   manager or your own `app-debug.apk` copied into Downloads).
3. Confirm filename + size + SHA-256 appear, *Run static analysis* completes
   with a percent/stage label.
4. Open *View results*: findings are labelled by kind/severity with evidence,
   unknowns are listed openly.

## Project versions

| Component   | Version  |
|-------------|----------|
| Gradle      | 8.10.2   |
| AGP         | 8.7.3    |
| Kotlin      | 2.0.21   |
| Compose BOM | 2024.12.01 |
| min/target  | 26 / 35  |

## Architecture

`ARCHITECTURE.md` documents the long-term platform plan (engine boundaries,
finding/evidence model, job lifecycle, storage & migrations, on-device vs
sandbox separation, Android platform limits, testing strategy).

## Phase 2 (future engines, not present)

Device monitoring engine, isolated sandbox dynamic analysis, threat-intel
enrichment with explainable risk scoring. No placeholder engines exist in the
codebase — engines are added only when they can produce real, evidence-based
output.

## Security house rules

- The app never installs, instantiates, or executes a picked APK.
- No INTERNET permission; scan content never leaves the device.
- Dynamic analysis can only exist in a disposable isolated environment and
  must always emit `SANDBOX_ONLY` findings — never mixed into on-device
  verdicts.
