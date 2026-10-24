package com.kernelcall.app.core.engine

import com.kernelcall.app.core.model.EngineRunStats
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.UnknownNote
import java.io.File

/**
 * Contract every analysis engine implements. Engines must never execute the
 * APK, never leave the device, and must classify every finding honestly
 * (see FindingKind).
 */
interface AnalysisEngine {
    /** Stable identifier persisted in reports, e.g. "static.v2". */
    val id: String
    val title: String

    suspend fun analyse(context: EngineContext): EngineResult
}

/**
 * [apkFile] may be null (engine sees only hash/size metadata when the file was
 * not cached); engines must degrade gracefully in that case.
 */
data class EngineContext(
    val apkFile: File?,
    val sha256: String,
    val fileName: String,
    val sizeBytes: Long,
    /** percent within the engine (0..100), plus user-facing stage label */
    val onProgress: (percent: Int, stage: String) -> Unit,
) {
    val hasApkFile: Boolean get() = apkFile != null && apkFile.exists()
}

data class EngineResult(
    val findings: List<Finding>,
    val unknowns: List<UnknownNote>,
    val durationMs: Long,
) {
    fun toStats() = EngineRunStats(
        engineId = findings.firstOrNull()?.engineId ?: "unknown",
        durationMs = durationMs,
        findingCount = findings.size,
        unknownCount = unknowns.size,
    )
}

class EngineFailureException(message: String, cause: Throwable? = null) : Exception(message, cause)
