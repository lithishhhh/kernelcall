package com.kernelcall.app.core.dashboard

import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.RiskBand
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.data.ScanRecord

/**
 * Phase 5 pure aggregation over persisted scan history and stored reports.
 * Given a report loader this is a pure function; the ViewModel runs it on
 * Dispatchers.IO. Numbers come only from real persisted data — when no
 * report exists for a record, it counts as scanned-but-not-analyzed and
 * contributes nothing to findings/scores (nothing invented).
 */
data class DashboardStats(
    val scannedApps: Int,
    val analyzedReports: Int,
    val totalFindings: Int,
    val highSeverityFindings: Int,
    /** severity counts aggregated over every persisted report */
    val severityCounts: Map<Severity, Int>,
    /** findings-by-category counts over every persisted report */
    val categoryCounts: Map<String, Int>,
    /** most recent analysis that actually produced intelligence, if any */
    val latest: LatestAnalysis? = null,
    /** record ids (newest first) that have no stored analysis report */
    val scannedWithoutReport: List<Long> = emptyList(),
)

data class LatestAnalysis(
    val recordId: Long,
    val fileName: String,
    val sha256: String,
    val score: Int,
    val band: RiskBand,
    val findingsCount: Int,
    val unknownsCount: Int,
)

object ReportAggregates {

    fun severityCounts(findings: List<Finding>): Map<Severity, Int> =
        Severity.entries.associateWith { severity -> findings.count { it.severity == severity } }

    /** Findings grouped by the stable category slug recorded on each finding. */
    fun categoryCounts(findings: List<Finding>): Map<String, Int> =
        findings.groupingBy { it.category.ifBlank { "unclassified" } }.eachCount()
            .toSortedMap()
}

object DashboardStatsBuilder {

    /**
     * [loadReport] is called per sha (IO in production); pure otherwise.
     * Returns null stats only when there is no history at all — an empty
     * dashboard displays its empty state instead of fabricated zeros.
     */
    fun build(
        records: List<ScanRecord>,
        loadReport: (sha256: String) -> AnalysisReport?,
    ): DashboardStats? {
        if (records.isEmpty()) return null

        val reports = records.mapNotNull { record ->
            loadReport(record.sha256)?.let { record to it }
        }

        val allFindings = reports.flatMap { (record, report) -> report.findings }
        val analyzedShas = reports.map { (_, report) -> report.sha256 }.toSet()
        val noReportIds = records
            .filter { record -> record.sha256 !in analyzedShas }
            .map { it.id }

        val latest = reports.firstOrNull()?.let { (record, report) ->
            report.intelligence?.risk?.let { risk ->
                LatestAnalysis(
                    recordId = record.id,
                    fileName = record.fileName,
                    sha256 = record.sha256,
                    score = risk.score,
                    band = risk.band,
                    findingsCount = report.findings.size,
                    unknownsCount = report.unknowns.size,
                )
            }
        }

        return DashboardStats(
            scannedApps = records.size,
            analyzedReports = reports.map { it.second.sha256 }.distinct().size,
            totalFindings = allFindings.size,
            highSeverityFindings = allFindings.count { it.severity == Severity.HIGH },
            severityCounts = ReportAggregates.severityCounts(allFindings),
            categoryCounts = ReportAggregates.categoryCounts(allFindings),
            latest = latest,
            scannedWithoutReport = noReportIds,
        )
    }
}
