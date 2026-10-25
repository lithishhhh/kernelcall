package com.kernelcall.app.core.storage

import android.content.Context
import com.kernelcall.app.core.model.AnalysisReport
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists AnalysisReport JSON per sha256 under filesDir/reports.
 * Content-addressed, offline-only, never leaves the device.
 */
class ReportStore(context: Context) {

    private val dir = File(context.filesDir, "reports").apply {
        if (!exists()) mkdirs()
    }

    /** Bumped on every successful save; observers recompute aggregates. */
    private val _savedVersion = MutableStateFlow(0)
    val savedVersion: StateFlow<Int> = _savedVersion.asStateFlow()

    fun save(report: AnalysisReport): Boolean = try {
        val target = File(dir, "${report.sha256}.json")
        val temp = File("$target.part")
        temp.writeText(report.toJson(), Charsets.UTF_8)
        val ok = temp.renameTo(target)
        if (ok) _savedVersion.value = _savedVersion.value + 1
        ok
    } catch (_: Exception) {
        false
    }

    fun load(sha256: String): AnalysisReport? = try {
        val file = File(dir, "$sha256.json")
        if (file.exists()) AnalysisReport.fromJson(file.readText(Charsets.UTF_8)) else null
    } catch (_: Exception) {
        null
    }

    fun has(sha256: String): Boolean = File(dir, "$sha256.json").exists()

    companion object {
        @Volatile private var instance: ReportStore? = null

        fun get(context: Context): ReportStore =
            instance ?: synchronized(this) {
                instance ?: ReportStore(context.applicationContext).also { instance = it }
            }
    }
}
