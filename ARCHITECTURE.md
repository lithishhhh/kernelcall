# Kernel Call — Architecture Plan (revised for the long-term vision)

Kernel Call is a lightweight, offline-first **Android Security Intelligence
Platform**. Phase 1 shipped a verified fingerprint scanner; this plan revises
the technical direction towards the full product:

static APK analysis → user-configured device monitoring → isolated dynamic
analysis → threat intelligence & explainable risk → unified evidence store,
reports, timelines, remediation guidance.

**Principles**

1. **Evidence before verdicts.** Every finding links to raw, reproducible
   evidence. Distinguish `CONFIRMED_OBSERVATION` (fact read from the file /
   device), `HEURISTIC_INDICATOR` (pattern that *may* warrant review),
   `UNKNOWN` (capability or information gap, stated openly), and
   `SANDBOX_ONLY` (result that can only be produced inside an isolated
   environment). Risk wording is always explainable, never fabricated.
2. **No suspicious APK ever runs on the user's everyday device.** The on-device
   app only *reads* files. Dynamic analysis is architecturally restricted to an
   isolated environment (work profile / disposable emulator / lab device) and
   is a future phase — no partial or simulated ("fake sandbox") execution.
3. **Offline-first, no mandatory cloud.** Optional user-configured feeds may
   enrich later phases; nothing is ever uploaded automatically.

---

## 1. Module boundaries and interfaces

Everything currently lives in one Gradle module `:app`; the code is organized
into boundary-clean packages so each engine can be extracted into a Gradle
module without touching consumers. Extracting `:core-model`, `:core-engine`
and `:engines-static` is expected once multi-module builds pay for themselves.

| Package (future module)   | Responsibility | Stability contract |
|---------------------------|----------------|--------------------|
| `core.model` `:core-model` | `Finding`, `Evidence`, `Severity`, `FindingKind`, `AnalysisReport`, JSON (de)serialization | frozen data contracts; additive evolution with `schemaVersion` |
| `core.engine` `:core-engine` | `AnalysisEngine` interface, `EngineContext`, `EngineResult`, `AnalysisCoordinator`, job lifecycle | engines only depend on these |
| `core.storage` `:core-storage` | `ApkCacheStore` (cached APK bytes), `ReportStore` (analysis reports), scan-history persistence + migrations | file/JSON based, no ORM for now |
| `engines.static` | `StaticAnalysisEngine`: APK zip/integrity, AXML manifest parser, v1 signature certificates, dex string observations, permission/component heuristics | no UI imports |
| `engines.monitor` (future) | user-configured device monitoring within Android limits (install events, granted-permission inventory) | consumes `core.engine` API |
| `engines.sandbox` (future) | drives isolated dynamic analysis; **only ever emits `SANDBOX_ONLY` findings** | lab/AVD integration, never runs untrusted code in app process |
| `engines.intel` (future) | optional feed ingestion + explainable risk scoring over reports | enriches, never overrides evidence |

Shared interface (implemented today by `StaticAnalysisEngine`):

```kotlin
interface AnalysisEngine {
    val id: String          // stable id stored inside reports, e.g. "static.v1"
    val title: String
    suspend fun analyse(context: EngineContext): EngineResult
}
```

## 2. Common finding / evidence data model

- `Finding(id, engineId, title, summary, kind: FindingKind, severity: Severity,
  evidence: List<Evidence>, recommendation?, detectedAt)`
- `Evidence(type: String, label: String, value: String, location: String?)`
  — e.g. `(manifest, permission, android.permission.RECORD_AUDIO, application)`
- `AnalysisReport(schemaVersion, sha256, fileName, sizeBytes, generatedAt,
  engines: List<EngineRunStats(engineId, durationMs, findingCount)>,
  findings, unknowns: List<String>)`

Rules: findings are **append-only per sha256** (re-runs replace the report for
that file, which is deterministic because content-addressed). Evidence values
are the *raw observations*; human-readable interpretation lives in
`summary`/`recommendation` only.

## 3. Analysis-job lifecycle and progress

`IDLE → RUNNING(overallPercent, stageLabel) → COMPLETED | FAILED | CANCELLED`

- `AnalysisCoordinator` runs engines sequentially; engine `n` covers
  `[n·100/N, (n+1)·100/N)` of overall progress. Each engine reports an
  internal `(percent, stage)` tuple via `EngineContext.onProgress`;
  the coordinator interpolates, the ViewModel exposes a `StateFlow` and the UI
  is the only consumer.
- Every engine run is bounded by cooperative cancellation (checked before each
  stage). Failures inside one engine degrade to an `UNKNOWN` note + failed
  run-stats instead of failing the whole report whenever the failure is
  engine-local; write errors persist as `FAILED`.
- Stage labels are user-facing strings ("Reading manifest…"), percent is
  mechanical. Each report records per-engine `durationMs` — this *is* the
  built-in performance measurement surface (§7).

## 4. Local persistence and migration

- `filesDir/records.json` — scan history (schemaVersion 2). v1 (Phase 1) stored
  a single JSON string in SharedPreferences; on first load v1 records are
  imported, the legacy key is removed, and all future writes go to the file.
  Record model gains additive optional fields (`cacheStored`), parsed with
  defaults for old payloads.
- `filesDir/apkcache/<sha256>.apk` — cached APK bytes for re-analysis
  (content-addressed). Budgeted (cap per file 200 MB, total budget with
  oldest-first eviction); files are only ever copied in, never executed.
- `filesDir/reports/<sha256>.json` — analysis reports, keyed by fingerprint so
  history ↔ reports join without foreign keys.
- Forward-only integer `schemaVersion`; unknown fields tolerated; deletion and
  export APIs must exist before analytics/re-sync features (privacy §6).

## 5. On-device vs sandbox

| Runs on the user's device | Runs only in isolated sandbox (future) |
|---------------------------|----------------------------------------|
| hash / zip entry inventory / AXML manifest parse / v1 cert parse / dex string scan / on-device monitoring via public APIs | **execution of the APK**, network capture, behavioral rules, unpacking/dropper detonation, instrumentation |

The app process never installs, instantiates, links an APK's native code, or
invokes `PackageInstaller`. Static findings are `CONFIRMED`/`HEURISTIC`;
anything requiring execution is exclusively `SANDBOX_ONLY` and produced by
`engines.sandbox` inside a disposable environment.

## 6. Android permission, battery, privacy, platform limits

- **Permissions:** no dangerous permissions today; file access only via SAF
  (`OpenDocument`), no storage-permission requests. Future monitoring uses
  public APIs only (`QUERY_ALL_PACKAGES` requires a policy justification —
  preferred: manifest-declaration based approaches, or user-initiated polling;
  install-session events via `PackageInstaller` for the app's own profile).
- **Background/battery:** Android 12+ foreground-service limits and Doze
  restrict long scans; policy = analysis happens user-initiated in foreground
  first, `WorkManager` only for deferred user-approved jobs, no periodic
  background scanning without explicit user opt-in.
- **Platform floors:** dynamic analysis in a work profile cannot observe the
  main profile — isolation is a feature, not a gap. Unsigned/v2-only APKs
  certify hash-level identity but limit static insight → recorded as `UNKNOWN`.
- **Privacy/local law posture:** scan content stays on device; no network
  permission; telemetry never added without opt-in; reports exportable by
  explicit user action only.

## 7. Testing and performance strategy

- **JVM unit tests** (pure Kotlin engines): AXML parser against a *real*
  manifest fixture pulled from a live installed app on the test device; zip
  inventory against generated archives; heuristics against synthetic dex
  content; report JSON structural round-trip sanity.
- **Instrumented/device verification:** SAF end-to-end pick → hash → analysis
  on a real phone; manual smoke checklist in README.
- **Performance:** every report embeds per-engine durations; targets: manifest
  parse < 500 ms, full static pass < 10 s for a 100 MB APK on a mid-range
  device; hashing throughput logged; memory held constant by streaming (no
  full-file buffering except bytes already streamed during hashing).
- **House rules for tests:** no network, no fixtures > 100 KB, engines
  deterministic (timestamps injected) so tests are stable.
