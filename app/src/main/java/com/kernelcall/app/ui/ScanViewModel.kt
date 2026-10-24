package com.kernelcall.app.ui

import androidx.lifecycle.AndroidViewModel
import android.app.Application
import android.net.Uri
import androidx.lifecycle.viewModelScope
import com.kernelcall.app.analysis.ApkFingerprinter
import com.kernelcall.app.core.engine.AnalysisCoordinator
import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.storage.ApkCacheStore
import com.kernelcall.app.core.storage.ReportStore
import com.kernelcall.app.data.ScanHistoryStore
import com.kernelcall.app.data.ScanRecord
import com.kernelcall.app.engines.staticengine.StaticAnalysisEngine
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** UI state of the Scan screen fingerprint step. */
sealed interface ScanUiState {
    data object Idle : ScanUiState
    data class Hashing(
        val fileName: String,
        val bytesProcessed: Long,
        val totalBytes: Long?,
    ) : ScanUiState
    data class Done(val record: ScanRecord) : ScanUiState
    data class Error(val message: String) : ScanUiState
}

/** UI state of the follow-up static analysis job. */
sealed interface AnalysisUiState {
    data object Idle : AnalysisUiState
    data class Running(val percent: Int, val stage: String) : AnalysisUiState
    data class Completed(val sha256: String) : AnalysisUiState
    data class Error(val message: String) : AnalysisUiState
}

/**
 * Owns the whole flow: pick -> fingerprint (IO) -> cache copy -> (user runs)
 * -> static analysis job -> report persisted by sha256.
 */
class ScanViewModel(application: Application) : AndroidViewModel(application) {

    private val appContext = application.applicationContext
    val historyStore: ScanHistoryStore = ScanHistoryStore.get(application)
    private val cacheStore = ApkCacheStore.get(application)
    private val reportStore = ReportStore.get(application)
    private val coordinator = AnalysisCoordinator()

    private val _uiState = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    private val _analysisState = MutableStateFlow<AnalysisUiState>(AnalysisUiState.Idle)
    val analysisState: StateFlow<AnalysisUiState> = _analysisState.asStateFlow()

    /** Last top-level failure; used by error UI to know what to offer next. */
    private var cachedFileAvailable = false

    fun onApkPicked(uri: Uri?) {
        if (uri == null) return // user cancelled the picker

        val resolver = appContext.contentResolver
        val provisionalName = uri.lastPathSegment ?: "selected file"
        _uiState.value = ScanUiState.Hashing(
            fileName = provisionalName.substringAfterLast('/'),
            bytesProcessed = 0,
            totalBytes = null,
        )

        viewModelScope.launch {
            try {
                val meta = ApkFingerprinter.fingerprint(resolver, uri) { processed, total ->
                    val current = _uiState.value
                    if (current is ScanUiState.Hashing) {
                        _uiState.value = current.copy(
                            bytesProcessed = processed,
                            totalBytes = total,
                        )
                    }
                }
                val record = ScanRecord(
                    id = System.currentTimeMillis(),
                    fileName = meta.fileName,
                    sizeBytes = meta.sizeBytes,
                    sha256 = meta.sha256,
                    scannedAt = System.currentTimeMillis(),
                )
                historyStore.add(record)

                // Cache the bytes so the static engine can analyse later steps
                // without re-picking. Files that are too big stay uncached and
                // history shows hash-only records.
                cachedFileAvailable = cacheStore.import(
                    resolver, uri, record.sha256, record.sizeBytes
                ) != null
                if (cachedFileAvailable) {
                    historyStore.update(record.copy(cacheStored = true))
                }

                _uiState.value = ScanUiState.Done(
                    record.copy(cacheStored = cachedFileAvailable)
                )
                _analysisState.value = AnalysisUiState.Idle
            } catch (e: Exception) {
                _uiState.value = ScanUiState.Error(
                    message = e.message
                        ?: "The APK could not be fingerprinted. Try picking the file again.",
                )
            }
        }
    }

    fun runStaticAnalysis() {
        val scan = _uiState.value
        if (scan !is ScanUiState.Done) return
        if (_analysisState.value is AnalysisUiState.Running) return

        if (!scan.record.cacheStored) {
            _analysisState.value = AnalysisUiState.Error(
                message = "This APK was not stored for analysis (too large or unreadable). " +
                    "Fingerprint data is still valid."
            )
            return
        }

        _analysisState.value = AnalysisUiState.Running(0, "Preparing analysis")
        viewModelScope.launch {
            try {
                val report = coordinator.run(
                    sha256 = scan.record.sha256,
                    fileName = scan.record.fileName,
                    sizeBytes = scan.record.sizeBytes,
                    engines = listOf(StaticAnalysisEngine()),
                    apkFile = cacheStore.fileFor(scan.record.sha256),
                    onProgress = { percent, stage ->
                        _analysisState.value = AnalysisUiState.Running(percent, stage)
                    },
                )
                reportStore.save(report)
                _analysisState.value = AnalysisUiState.Completed(report.sha256)
            } catch (e: Exception) {
                _analysisState.value = AnalysisUiState.Error(
                    message = e.message ?: "Static analysis failed unexpectedly."
                )
            }
        }
    }

    fun reset() {
        _uiState.value = ScanUiState.Idle
        _analysisState.value = AnalysisUiState.Idle
        cachedFileAvailable = false
    }

    fun loadReportFor(sha256: String): AnalysisReport? = reportStore.load(sha256)
}
