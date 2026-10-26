# Kernel Call

A native Android application for **static APK analysis, forensic report
export, and security intelligence**. Built with Kotlin, Jetpack Compose, and
Material 3 — no cloud services, no sign-in, no INTERNET permission.

> End-to-end, the app picks an APK, reads its bytes, and computes a SHA-256
> fingerprint on the device (Phase 1); parses the binary manifest, archive,
> certificate and dex content into evidence-backed findings (Phase 2);
> derives deterministic correlation and an explainable risk-surface score
> (Phase 3); and exports/shares a forensic report at the user's command
> (Phase 4). Nothing is uploaded automatically, the APK is never installed
> or executed, and **no verdict** (clean / suspicious / malicious) is ever
> claimed — every finding is labelled by kind and backed by evidence.

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

## Features (Phase 3 — intelligence core)

- **Deterministic correlation** (`Correlator.kt`): evidence-driven rules
  (e.g. SMS/telephony intent interception combined with telephony
  permissions, embedded endpoints with a manifest-permitted cleartext
  channel, boot-time persistence patterns) — each correlation keeps the
  related finding ids as provenance and explains itself in plain language.
- **Explainable risk scoring** (`RiskScorer.kt`): score = capped sum of
  severity-based weights (INFO 0 / LOW 5 / MEDIUM 15 / HIGH 25), reduced
  to 60% for heuristic indicators and scaled by observation confidence
  (HIGH 100% / MEDIUM 75% / LOW 50%); duplicate evidence is counted once.
  Result: a 0–100 **risk-surface indicator** with band
  (LOW/MODERATE/ELEVATED/HIGH) and a contribution list showing exactly
  what added how much. Never a malware verdict, never a calibrated
  probability — no AI model is involved.
- **Honest limitations**: known blind spots (heuristics, unresolvable
  checks) are surfaced as explicit limitations instead of phantom score.
- **Legacy reports**: schema-v2 reports simply show their intelligence as
  absent with a re-run hint; nothing is fabricated.
- Report persistence moves to `schemaVersion 3`; v2 files stay loadable.

## Features (Phase 4 — forensic report export & sharing)

- **Export & share card** in the results screen (visible only when a
  report exists): *Save JSON*, *Save text*, *Share*.
- **JSON export**: the full, schema-versioned report representation
  (schema 3 report includes intelligence; a legacy schema-v2 export
  simply omits the `intelligence` block) — written exactly as the app
  models it, parseable by standard JSON tools, round-trip tested.
- **Plain-text forensic report**: ASCII-rendered summary with APK identity
  (+ full SHA-256), analysis metadata and engine timings, risk score/band
  when available, severity distribution, findings with kind/confidence/
  rule/evidence, correlation explanations with provenance, limitations,
  open unknowns — and a clear notice that the content is indicator-based,
  never proof that the APK is malicious or safe.
- **No fabrication**: legacy reports state that the score and correlations
  do not exist for them; export never invents fields.
- **Safety/privacy posture**: saving uses SAF `CreateDocument` (no storage
  permission), sharing uses the system share sheet as plain text, every
  dynamic value is control-char-escaped so observed data cannot forge
  report structure, writes run off the main thread, and export files are
  named from the digest (`kernelcall-report-<sha12>.json|.txt`) only.
- Everything above stays true: nothing is uploaded automatically, and the
  app still has no INTERNET permission.

Everything below stays true: nothing is uploaded, nothing is installed or
executed by the app, and hashing alone never claims to detect malware.

## Features (Phase 5 — visual security dashboard & installed-app scanner)

- **Installed-app scanner**: the app lists the launchable packages Android
  exposes to it (via a `<queries>` intent filter for `ACTION_MAIN` /
  `CATEGORY_LAUNCHER` — deliberately **no `QUERY_ALL_PACKAGES`**, so the
  list is exactly what the platform's package-visibility rules allow and
  nothing more). Search by app label or package name, optional
  "include system apps" toggle, per-app icons rendered locally in memory.
- **Honest eligibility**: an app is analysable only when the platform
  exposes an accessible base APK path; the app's own package is excluded.
  Non-listed apps remain reachable through the existing manual SAF import.
- **Scan queue**: multiple apps are fingerprinted and statically analysed
  one at a time (dedupe of already-queued/running packages, "cancel
  pending", per-item states QUEUED / RUNNING / DONE / UNREADABLE / ERROR
  with the real reason). Every percent/stage shown comes from actual
  events — byte counts from the fingerprinter and stage labels from the
  analysis coordinator — nothing is simulated.
- **Visual dashboard**: native Compose `Canvas` charts (no new
  dependencies) — a 270° **risk gauge** for the latest analysed app, the
  **severity distribution** across all persisted reports, and
  **findings-by-category** bars; summary cards (scanned / analysed /
  findings / high-severity) are aggregated by pure, unit-tested helpers
  from real persisted data only. When nothing has been analysed, the
  gauge shows an honest "no score" state instead of a fabricated number.
- **Results enrichment**: the intelligence card now shows the risk gauge
  and a per-report category chart.
- **History enrichment**: records created by the installed-app scanner
  carry the package name (additive, tolerated by the schema-v2 history
  format — old payloads parse unchanged).
- All prior guarantees hold: analysis never installs, executes, or
  uploads anything; no INTERNET permission; indicator-based output, never
  a verdict.

Everything below stays true: nothing is uploaded, nothing is installed or
executed by the app, and hashing alone never claims to detect malware.

## Features (Phase 1)

- **Dashboard** — brand header, "Scan installed apps" action (Phase 5),
  manual APK import fallback, risk gauge, summary and severity/category
  charts from persisted reports, and recent scans with an empty state for
  first-time users.
- **Scan** — APK picker (Storage Access Framework), live fingerprinting progress
  (bytes read), result showing `filename`, `size`, and full `SHA-256`.
- **Results** — file identity card, engine run stats, the intelligence card
  (risk-surface score with score explanation, correlations, limitations, or
  an honest "predates the intelligence layer" note for legacy reports),
  findings with evidence, open unknowns, and the Phase 4 export & share card.
- **History** — every fingerprint recorded locally (SharedPreferences/JSON),
  with a useful empty state.

## Architecture (deliberately simple)

```
app/src/main/java/com/kernelcall/app/
├── MainActivity.kt                  # Compose entry point
├── analysis/ApkFingerprinter.kt     # SHA-256 streaming on Dispatchers.IO
├── core/
│   ├── engine/                      # AnalysisEngine, AnalysisCoordinator (job lifecycle)
│   ├── intelligence/                # Correlator + RiskScorer (deterministic, tested)
│   ├── model/                       # Finding, Evidence, AnalysisReport, Intelligence
│   ├── storage/                     # ReportStore, ApkCacheStore (content-addressed)
│   └── export/                      # ForensicTextReport + ReportExporter (Phase 4)
├── data/ScanRecord.kt               # Immutable scan record model
├── data/ScanHistoryStore.kt         # On-device history (StateFlow + JSON)
├── core/installed/InstalledScanning.kt  # Filtering + scan-queue state machine (pure)
├── core/dashboard/DashboardStats.kt     # Pure report aggregation for charts
├── engines/staticengine/            # AXML parser, zip inventory, certs, dex strings
└── ui/
    ├── KernelCallApp.kt             # NavHost + bottom navigation
    ├── ScanViewModel.kt             # Scan + analysis state machines
    ├── Formats.kt                   # Size / hash / date formatting
    ├── theme/                       # Dark "security console" theme
    ├── components/                  # PanelCard, EmptyState, InfoRow...
    └── screens/                     # Dashboard, Scan, History, Results (export card)
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
gradlew.bat testDebugUnitTest     :: JVM unit tests (AXML parser, zip inventory, engine,
                                  ::    intelligence, report export)
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
   unknowns are listed openly, and the intelligence card shows the score
   explanation, correlations and limitations.
5. In the results screen use the *Export & share* card: *Save JSON* and
   *Save text* write to a location you pick via SAF; *Share* opens the
   system share sheet with the plain-text forensic report. The exported
   files are indicator-based static analysis — never a verdict.

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

## Future engines (not implemented)

Device monitoring engine, isolated sandbox dynamic analysis, and optional
threat-intel feed ingestion are planned future engines. No placeholder
engines exist in the codebase — engines are added only when they can produce
real, evidence-based output. The Phase 4 export exports only what actually
exists; it never simulates these capabilities.

## Security house rules

- The app never installs, instantiates, or executes a picked APK.
- No INTERNET permission; scan content never leaves the device.
- Dynamic analysis can only exist in a disposable isolated environment and
  must always emit `SANDBOX_ONLY` findings — never mixed into on-device
  verdicts.
