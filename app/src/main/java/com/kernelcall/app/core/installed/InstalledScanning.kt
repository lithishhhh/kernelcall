package com.kernelcall.app.core.installed

/**
 * Phase 5 pure installed-app model and scan-queue state machine.
 *
 * No Android imports by design: filtering, eligibility and state transitions
 * live here so they are unit-testable; the ViewModel only feeds real
 * PackageManager data in and surfaces the state out.
 */
data class InstalledAppEntry(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    /** base APK path when the platform exposes one; null = not accessible */
    val sourceDir: String?,
)

enum class AppScanState { NOT_SCANNED, HASH_ONLY, ANALYZED, UNREADABLE }

/** Status of one installed app, derived from persisted history/reports. */
data class AppScanStatus(
    val state: AppScanState,
    val score: Int? = null,
    val band: String? = null,
    val reason: String? = null,
)

object InstalledScanning {

    /**
     * Eligibility for static analysis (honest, evidence-based):
     *  - the platform must expose an accessible base APK path
     *  - our own app is excluded (nothing to learn, keeps the demo focused)
     * Launcher visibility (system or not) is a display flag, not an
     * eligibility rule; the UI lets the user choose.
     */
    fun isEligible(entry: InstalledAppEntry, ownPackage: String): Boolean =
        entry.sourceDir != null &&
            entry.packageName != ownPackage &&
            entry.packageName.isNotBlank()

    /** Case-insensitive search over app label and package name. */
    fun matchesSearch(entry: InstalledAppEntry, query: String): Boolean {
        if (query.isBlank()) return true
        val q = query.trim().lowercase()
        return entry.label.lowercase().contains(q) ||
            entry.packageName.lowercase().contains(q)
    }

    fun filterApps(
        entries: List<InstalledAppEntry>,
        ownPackage: String,
        includeSystem: Boolean,
        query: String,
    ): List<InstalledAppEntry> =
        entries.filter { entry ->
            isEligible(entry, ownPackage) &&
                (includeSystem || !entry.isSystem) &&
                matchesSearch(entry, query)
        }
}

// ---------------------------------------------------------------------------
// Scan queue state machine (pure)
// ---------------------------------------------------------------------------

enum class QueueItemStatus { PENDING, RUNNING, DONE, UNREADABLE, ERROR }

/**
 * One item of an installed-app scan queue. Percent/stage mirror REAL
 * progress events from the fingerprinter and the analysis coordinator —
 * they are never simulated.
 */
data class ScanQueueItem(
    val packageName: String,
    val label: String,
    val status: QueueItemStatus,
    val percent: Int = 0,
    val stage: String = "Queued",
    val sha256: String? = null,
    val score: Int? = null,
    val band: String? = null,
    /** history record id for opening results once done */
    val recordId: Long? = null,
    val message: String? = null,
)

data class ScanQueueState(
    val items: List<ScanQueueItem> = emptyList(),
    /** packages with work queued or running; blocks duplicate enqueues */
    val activePackages: Set<String> = emptySet(),
) {
    val runningItem: ScanQueueItem?
        get() = items.firstOrNull { it.status == QueueItemStatus.RUNNING }

    val pendingCount: Int
        get() = items.count { it.status == QueueItemStatus.PENDING }

    val hasActiveWork: Boolean
        get() = activePackages.isNotEmpty()
}

object ScanQueue {

    /**
     * Builds a queue from requested packages:
     *  - packages already queued/running are skipped (duplicate protection);
     *  - packages whose last known status is UNREADABLE are skipped too —
     *    re-reading them does not improve, the platform refused access.
     */
    fun enqueue(
        current: ScanQueueState,
        requested: List<ScanQueueItem>,
    ): ScanQueueState {
        val blocked = current.activePackages +
            current.items
                .filter { it.status == QueueItemStatus.UNREADABLE }
                .map { it.packageName }
                .toSet()
        val fresh = requested.filter { it.packageName !in blocked }.distinctBy { it.packageName }
        if (fresh.isEmpty()) return current
        return ScanQueueState(
            items = current.items + fresh.map { it.copy(status = QueueItemStatus.PENDING) },
            activePackages = current.activePackages + fresh.map { it.packageName }.toSet(),
        )
    }

    fun markRunning(state: ScanQueueState, packageName: String): ScanQueueState =
        withPackage(state, packageName) {
            it.copy(status = QueueItemStatus.RUNNING, stage = "Fingerprinting APK bytes")
        }

    /** Real fingerprint progress: bytes read (total only when the platform declares it). */
    fun fingerprintProgress(
        state: ScanQueueState,
        packageName: String,
        bytesProcessed: Long,
        totalBytes: Long?,
    ): ScanQueueState = withPackage(state, packageName) { item ->
        // Pre-engine phase of the bar: fingerprinting occupies 0..4%.
        val percent = if (totalBytes != null && totalBytes > 0) {
            (bytesProcessed * 4 / totalBytes).toInt().coerceIn(0, 4)
        } else {
            0
        }
        item.copy(
            status = QueueItemStatus.RUNNING,
            percent = percent,
            stage = "Fingerprinting APK bytes (" + humanSize(bytesProcessed) +
                (totalBytes?.let { " of " + humanSize(it) } ?: "") + ")",
        )
    }

    /** Real coordinator/engine progress (percent + stage label passthrough). */
    fun analysisProgress(
        state: ScanQueueState,
        packageName: String,
        percent: Int,
        stage: String,
    ): ScanQueueState = withPackage(state, packageName) { item ->
        item.copy(
            status = QueueItemStatus.RUNNING,
            // monotonic; engine phase occupies 4..99 of the bar
            percent = item.percent.coerceAtLeast(percent.coerceIn(4, 99)),
            stage = stage,
        )
    }

    fun complete(
        state: ScanQueueState,
        packageName: String,
        sha256: String,
        score: Int,
        band: String,
        recordId: Long,
    ): ScanQueueState =
        releaseActive(
            withPackage(state, packageName) {
                it.copy(
                    status = QueueItemStatus.DONE,
                    percent = 100,
                    stage = "Analysis complete",
                    sha256 = sha256,
                    score = score,
                    band = band,
                    recordId = recordId,
                    message = null,
                )
            },
            packageName,
        )

    fun fail(
        state: ScanQueueState,
        packageName: String,
        status: QueueItemStatus,
        message: String,
    ): ScanQueueState =
        releaseActive(
            withPackage(state, packageName) {
                it.copy(status = status, stage = "Stopped", message = message)
            },
            packageName,
        )

    /** Drops every PENDING item; a RUNNING item keeps its worker. */
    fun cancelPending(state: ScanQueueState): ScanQueueState {
        val runningPackages = state.items
            .filter { it.status == QueueItemStatus.RUNNING }
            .map { it.packageName }
            .toSet()
        val kept = state.items.filter { it.status != QueueItemStatus.PENDING }
        return state.copy(
            items = kept,
            activePackages = state.activePackages.intersect(runningPackages),
        )
    }

    private fun withPackage(
        state: ScanQueueState,
        packageName: String,
        update: (ScanQueueItem) -> ScanQueueItem,
    ): ScanQueueState =
        state.copy(items = state.items.map { if (it.packageName == packageName) update(it) else it })

    private fun releaseActive(state: ScanQueueState, packageName: String): ScanQueueState =
        state.copy(activePackages = state.activePackages - packageName)

    private fun humanSize(bytes: Long): String = when {
        bytes >= 1024L * 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f GB",
            bytes / 1024.0 / 1024 / 1024)
        bytes >= 1024L * 1024 -> String.format(java.util.Locale.US, "%.1f MB",
            bytes / 1024.0 / 1024)
        bytes >= 1024L -> String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }
}
