package com.kernelcall.app.core.engine

import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.model.EngineRunStats
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.core.model.UnknownNote
import java.io.File

/**
 * Runs engines sequentially and assembles one AnalysisReport.
 *
 * Engine-local problems degrade to an UNKNOWN note + failed stats so a single
 * parser bug can never make an entire report disappear.
 */
class AnalysisCoordinator {

    suspend fun run(
        sha256: String,
        fileName: String,
        sizeBytes: Long,
        engines: List<AnalysisEngine>,
        apkFile: File?,
        onProgress: (percent: Int, stage: String) -> Unit,
    ): AnalysisReport {
        onProgress(0, "Preparing analysis")

        val allFindings = mutableListOf<Finding>()
        val allUnknowns = mutableListOf<UnknownNote>()
        val stats = mutableListOf<EngineRunStats>()

        engines.forEachIndexed { index, engine ->
            val engineBase = (index * 100) / engines.size
            val engineSpan = 100 / engines.size

            var result: EngineResult? = null
            try {
                result = engine.analyse(
                    EngineContext(
                        apkFile = apkFile,
                        sha256 = sha256,
                        fileName = fileName,
                        sizeBytes = sizeBytes,
                        onProgress = { percentInEngine, stage ->
                            val overall = engineBase + (percentInEngine * engineSpan / 100)
                            onProgress(overall.coerceIn(0, 100), stage)
                        }
                    )
                )
            } catch (e: Exception) {
                allUnknowns.add(
                    UnknownNote(
                        engineId = engine.id,
                        message = "${engine.title}: engine could not complete " +
                            "(${e.message ?: "unexpected error"})",
                    )
                )
                stats.add(
                    EngineRunStats(
                        engineId = engine.id,
                        durationMs = 0,
                        findingCount = 0,
                        unknownCount = 1,
                    )
                )
            }

            result?.let { r ->
                allFindings.addAll(r.findings)
                allUnknowns.addAll(r.unknowns)
                stats.add(
                    EngineRunStats(
                        engineId = engine.id,
                        durationMs = r.durationMs,
                        findingCount = r.findings.size,
                        unknownCount = r.unknowns.size,
                    )
                )
            }
        }

        // Intelligence derivation is a real compute step — report it as its
        // own stage rather than silently jumping to "Analysis complete".
        onProgress(99, "Assessing risk-surface score")

        val correlations = com.kernelcall.app.core.intelligence.Correlator.correlate(allFindings)
        val risk = com.kernelcall.app.core.intelligence.RiskScorer.assess(allFindings, correlations, allUnknowns)
        val intelligence = com.kernelcall.app.core.model.Intelligence(correlations, risk)

        onProgress(100, "Analysis complete")

        return AnalysisReport(
            schemaVersion = AnalysisReport.CURRENT_SCHEMA_VERSION,
            sha256 = sha256,
            fileName = fileName,
            sizeBytes = sizeBytes,
            generatedAt = System.currentTimeMillis(),
            engines = stats,
            findings = sortFindings(allFindings),
            unknowns = allUnknowns,
            intelligence = intelligence,
        )
    }

    private fun sortFindings(findings: List<Finding>): List<Finding> {
        val order = mapOf(
            Severity.HIGH to 0,
            Severity.MEDIUM to 1,
            Severity.LOW to 2,
            Severity.INFO to 3,
        )
        return findings.sortedBy { order[it.severity] ?: 4 }
    }
}
