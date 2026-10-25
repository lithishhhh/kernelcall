package com.kernelcall.app.core.export

import android.content.Context
import android.content.Intent
import android.net.Uri
import com.kernelcall.app.core.model.AnalysisReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Export formats with the SAF mime types and file suffixes they map to.
 * The JSON format is the exact schema-versioned report representation the
 * app persists (no invented fields); the text format is the human-readable
 * forensic summary.
 */
enum class ExportFormat(val mimeType: String, val fileSuffix: String) {
    JSON("application/json", ".json"),
    TEXT("text/plain", ".txt"),
}

/**
 * User-triggered export of one already-persisted analysis report.
 *
 * Policy compiled here for the whole app:
 *  - Files are written only to a location the user picks via SAF
 *    (CreateDocument); no storage permissions, nothing automatic.
 *  - The name is derived from the content SHA-256, never from raw
 *    user-supplied text, so it is always a safe document name.
 *  - The write happens off the main thread and never throws.
 *  - Sharing is a plain-text send through the system share sheet
 *    (user-driven only); the app itself has no INTERNET permission and
 *    uploads nothing.
 */
object ReportExporter {

    /** Deterministic, path-safe document name derived from the digest. */
    fun suggestedFileName(report: AnalysisReport, format: ExportFormat): String =
        "kernelcall-report-" + report.sha256.take(12).lowercase() + format.fileSuffix

    /** Share-sheet subject line; control characters never leave this app. */
    fun shareSubject(report: AnalysisReport): String =
        "Kernel Call forensic static analysis - " + ForensicTextReport.escape(report.fileName)

    /** Plain-text share payload for the Android system share sheet. */
    fun shareIntent(report: AnalysisReport, chooserTitle: String): Intent =
        Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, shareSubject(report))
            putExtra(Intent.EXTRA_TEXT, ForensicTextReport.build(report))
        }.let { Intent.createChooser(it, chooserTitle) }

    /**
     * Writes [report] in [format] to a user-picked [uri]. Runs on
     * Dispatchers.IO, returns false on any failure, never throws. Only the
     * generated report document is written — never the APK bytes.
     */
    suspend fun write(
        context: Context,
        uri: Uri,
        report: AnalysisReport,
        format: ExportFormat,
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val content = when (format) {
                ExportFormat.JSON -> report.toJson()
                ExportFormat.TEXT -> ForensicTextReport.build(report)
            }
            context.contentResolver.openOutputStream(uri)?.use { output ->
                output.write(content.toByteArray(Charsets.UTF_8))
                output.flush()
            } != null
        } catch (_: Exception) {
            false
        }
    }
}
