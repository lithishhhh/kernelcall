package com.kernelcall.app.ui.installed

import android.app.Application
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kernelcall.app.analysis.ApkFingerprinter
import com.kernelcall.app.core.engine.AnalysisCoordinator
import com.kernelcall.app.core.installed.AppScanState
import com.kernelcall.app.core.installed.AppScanStatus
import com.kernelcall.app.core.installed.InstalledAppEntry
import com.kernelcall.app.core.installed.InstalledScanning
import com.kernelcall.app.core.installed.QueueItemStatus
import com.kernelcall.app.core.installed.ScanQueue
import com.kernelcall.app.core.installed.ScanQueueItem
import com.kernelcall.app.core.installed.ScanQueueState
import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.data.ScanHistoryStore
import com.kernelcall.app.data.ScanRecord
import com.kernelcall.app.core.storage.ApkCacheStore
import com.kernelcall.app.core.storage.ReportStore
import com.kernelcall.app.engines.staticengine.StaticAnalysisEngine
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class InstalledAppsUiState(
    val loading: Boolean = true,
    val loadError: String? = null,
    /** every launchable package the platform exposes to us (query-filtered view via InstalledScanning) */
    val apps: List<InstalledAppEntry> = emptyList(),
    val query: String = "",
    val includeSystem: Boolean = false,
    /** selected package names (subset of apps) */
    val selected: Set<String> = emptySet(),
    val queue: ScanQueueState = ScanQueueState(),
    /** package -> last known scan status for status chips */
    val statuses: Map<String, AppScanStatus> = emptyMap(),
)

/**
 * Phase 5 owner of the installed-app scanning pipeline:
 * launcher-visible app list -> selection -> per-package queue worker
 * (fingerprint -> cache import -> static analysis -> report persist ->
 * history record with packageName). No app reading ever executes or
 * installs anything; base APK files are read with plain File input streams.
 */
class InstalledAppsViewModel(application: Application) : AndroidViewModel(application) {

    private val appContext = application.applicationContext
    private val ownPackage: String = application.packageName
    val historyStore: ScanHistoryStore = ScanHistoryStore.get(application)
    private val cacheStore = ApkCacheStore.get(application)
    private val reportStore = ReportStore.get(application)
    private val coordinator = AnalysisCoordinator()

    private val _uiState = MutableStateFlow(InstalledAppsUiState())
    val uiState: StateFlow<InstalledAppsUiState> = _uiState.asStateFlow()

    /** queue worker busy flag to keep sequential single-scan semantics */
    @Volatile
    private var pumping = false

    init {
        loadAppsAndStatuses()
    }

    private fun loadAppsAndStatuses() {
        _uiState.value = _uiState.value.copy(loading = true, loadError = null)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pm = appContext.packageManager
                val launcherIntent = Intent(Intent.ACTION_MAIN)
                    .addCategory(Intent.CATEGORY_LAUNCHER)
                val apps = pm.queryIntentActivities(launcherIntent, 0)
                    .mapNotNull { resolveInfo ->
                        val activityInfo = resolveInfo.activityInfo
                            ?: return@mapNotNull null
                        val pkg = activityInfo.packageName
                            ?: return@mapNotNull null
                        if (pkg == ownPackage) return@mapNotNull null
                        val appInfo = try {
                            pm.getApplicationInfo(pkg, 0)
                        } catch (_: PackageManager.NameNotFoundException) {
                            return@mapNotNull null // not visible to us; skip honestly
                        }
                        InstalledAppEntry(
                            packageName = pkg,
                            label = appInfo.loadLabel(pm).toString().ifBlank { pkg },
                            isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                                (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                            sourceDir = appInfo.publicSourceDir ?: appInfo.sourceDir,
                        )
                    }
                    .distinctBy { it.packageName }
                _uiState.value = _uiState.value.copy(loading = false, apps = apps)
                refreshStatuses()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    loadError = e.message
                        ?: "The installed-app list could not be read. Try again or use manual APK import.",
                )
            }
        }
    }

    // ------------------------------------------------------------------
    // Selection and filtering (pure logic delegated to InstalledScanning)
    // ------------------------------------------------------------------

    fun setQuery(query: String) {
        _uiState.value = _uiState.value.copy(query = query)
    }

    fun setIncludeSystem(include: Boolean) {
        _uiState.value = _uiState.value.copy(includeSystem = include)
    }

    fun toggleSelected(packageName: String) {
        val current = _uiState.value
        val next = if (packageName in current.selected) {
            current.selected - packageName
        } else {
            current.selected + packageName
        }
        _uiState.value = current.copy(selected = next)
    }

    fun clearSelection() {
        _uiState.value = _uiState.value.copy(selected = emptySet())
    }

    fun visibleAppsWithStatus(): List<Pair<InstalledAppEntry, AppScanStatus?>> =
        InstalledScanning.filterApps(
            _uiState.value.apps,
            ownPackage,
            _uiState.value.includeSystem,
            _uiState.value.query,
        ).map { it to _uiState.value.statuses[it.packageName] }

    fun eligibleCount(): Int = InstalledScanning.filterApps(
        _uiState.value.apps, ownPackage, _uiState.value.includeSystem, _uiState.value.query,
    ).count { entry ->
        _uiState.value.queue.items.none {
            it.packageName == entry.packageName && it.status == QueueItemStatus.UNREADABLE
        }
    }

    // ------------------------------------------------------------------
    // Scanning
    // ------------------------------------------------------------------

    fun scanSelected() {
        val state = _uiState.value
        val targets = state.apps.filter { it.packageName in state.selected }
            .map { it.toQueueItem() }
        enqueueAndPump(state, targets)
    }

    fun scanEligible() {
        val state = _uiState.value
        val targets = InstalledScanning.filterApps(
            state.apps, ownPackage, state.includeSystem, state.query,
        ).map { it.toQueueItem() }
        enqueueAndPump(state, targets)
    }

    private fun InstalledAppEntry.toQueueItem() = ScanQueueItem(
        packageName = packageName,
        label = label,
        status = QueueItemStatus.PENDING,
    )

    private fun enqueueAndPump(state: InstalledAppsUiState, targets: List<ScanQueueItem>) {
        if (targets.isEmpty()) return
        val nextQueue = ScanQueue.enqueue(state.queue, targets)
        if (nextQueue === state.queue) return // nothing admissible changed
        _uiState.value = state.copy(queue = nextQueue)
        pump()
    }

    fun cancelPending() {
        _uiState.value = _uiState.value.copy(
            queue = ScanQueue.cancelPending(_uiState.value.queue),
        )
    }

    /** Sequential queue worker: one app at a time, each step real work. */
    private fun pump() {
        if (pumping) return
        pumping = true
        viewModelScope.launch(Dispatchers.IO) {
            try {
                while (true) {
                    val next = _uiState.value.queue.items.firstOrNull {
                        it.status == QueueItemStatus.PENDING
                    } ?: break
                    processItem(next)
                }
            } finally {
                pumping = false
            }
        }
    }

    private suspend fun processItem(item: ScanQueueItem) {
        val packageName = item.packageName
        // Guard the cancel race: the item may have been dropped after the
        // worker picked it; then it must not be scanned behind the user's back.
        val stillQueued = _uiState.value.queue.items.any {
            it.packageName == packageName && it.status == QueueItemStatus.PENDING
        }
        if (!stillQueued) return
        val app = _uiState.value.apps.firstOrNull { it.packageName == packageName }
        if (app == null || app.sourceDir == null) {
            fail(packageName, QueueItemStatus.ERROR, "This app's APK path is no longer accessible.")
            return
        }

        _uiState.value = _uiState.value.copy(queue = ScanQueue.markRunning(_uiState.value.queue, packageName))

        val source = File(app.sourceDir)
        val meta = try {
            ApkFingerprinter.fingerprint(source) { processed, total ->
                val current = _uiState.value
                _uiState.value = current.copy(
                    queue = ScanQueue.fingerprintProgress(
                        current.queue, packageName, processed, total,
                    ),
                )
            }
        } catch (e: Exception) {
            fail(packageName, QueueItemStatus.ERROR,
                "APK bytes could not be read for fingerprinting: ${e.message ?: "unknown error"}")
            return
        }

        val record = ScanRecord(
            id = System.currentTimeMillis(),
            fileName = app.label,
            sizeBytes = meta.sizeBytes,
            sha256 = meta.sha256,
            scannedAt = System.currentTimeMillis(),
            packageName = packageName,
        )
        historyStore.add(record)

        val staged = try {
            cacheStore.import(source, meta.sha256, meta.sizeBytes)
        } catch (_: Exception) {
            null
        }
        if (staged == null) {
            fail(
                packageName,
                QueueItemStatus.UNREADABLE,
                "The APK could not be staged for analysis (too large or unreadable)." +
                    " Its fingerprint is in history; use manual APK import to analyse it.",
            )
            return
        }
        historyStore.update(record.copy(cacheStored = true))

        val report: AnalysisReport = try {
            coordinator.run(
                sha256 = meta.sha256,
                fileName = app.label,
                sizeBytes = meta.sizeBytes,
                engines = listOf(StaticAnalysisEngine()),
                apkFile = staged,
                onProgress = { percent, stage ->
                    val s = _uiState.value
                    _uiState.value = s.copy(
                        queue = ScanQueue.analysisProgress(
                            s.queue, packageName, percent, stage,
                        ),
                    )
                },
            )
        } catch (e: Exception) {
            fail(packageName, QueueItemStatus.ERROR,
                "Static analysis failed: ${e.message ?: "unknown error"}")
            return
        }

        reportStore.save(report)

        val done = _uiState.value
        _uiState.value = done.copy(
            queue = ScanQueue.complete(
                done.queue,
                packageName,
                meta.sha256,
                report.intelligence?.risk?.score ?: 0,
                report.intelligence?.risk?.band?.name ?: "LOW",
                record.id,
            ),
        )
        refreshStatuses()
    }

    /** small helper to avoid a coerce call site typo — real fingerprint bytes only */
    private fun ferriteProgress(
        packageName: String,
        processed: Long,
        total: Long?,
    ): InstalledAppsUiState {
        val s = _uiState.value
        return s.copy(queue = ScanQueue.fingerprintProgress(s.queue, packageName, processed, total))
    }

    private fun fail(packageName: String, status: QueueItemStatus, message: String) {
        _uiState.value = _uiState.value.copy(
            queue = ScanQueue.fail(_uiState.value.queue, packageName, status, message),
        )
    }

    // ------------------------------------------------------------------
    // Status chips (package -> most recent persisted knowledge)
    // ------------------------------------------------------------------

    private suspend fun refreshStatuses() = withContext(Dispatchers.IO) {
        val apps = _uiState.value.apps
        if (apps.isEmpty()) return@withContext
        val byPackage = historyStore.records.value
            .sortedBy { it.scannedAt }
            .filter { it.packageName != null }
            .groupBy { it.packageName!! }
        val statuses = apps.associate { app ->
            val latest = byPackage[app.packageName]?.lastOrNull()
            val status = when {
                latest == null -> AppScanStatus(state = AppScanState.NOT_SCANNED)
                else -> {
                    val report = reportStore.load(latest.sha256)
                    when {
                        report?.intelligence != null -> AppScanStatus(
                            state = AppScanState.ANALYZED,
                            score = report.intelligence?.risk?.score,
                            band = report.intelligence?.risk?.band?.name,
                        )
                        else -> AppScanStatus(state = AppScanState.HASH_ONLY)
                    }
                }
            }
            app.packageName to status
        }
        _uiState.value = _uiState.value.copy(statuses = statuses)
    }
}

