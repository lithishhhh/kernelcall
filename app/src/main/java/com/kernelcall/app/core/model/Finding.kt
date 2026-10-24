package com.kernelcall.app.core.model

/**
 * The classification of a finding, enforced app-wide.
 *
 * CONFIRMED_OBSERVATION -- a fact read directly from the file/device; no
 *     interpretation beyond naming what was observed.
 * HEURISTIC_INDICATOR   -- a pattern that *may* warrant attention; never an
 *     assertion that malware is present.
 * UNKNOWN               -- an openly stated inability or information gap.
 * SANDBOX_ONLY          -- a result that can only be produced in an isolated
 *     analysis environment; on-device engines must never emit this kind
 *     without having actually run inside one.
 */
enum class FindingKind { CONFIRMED_OBSERVATION, HEURISTIC_INDICATOR, UNKNOWN, SANDBOX_ONLY }

enum class Severity { INFO, LOW, MEDIUM, HIGH }

/**
 * How certain the *observation itself* is. Deliberately orthogonal to
 * [Severity]: a fact can be read with high confidence while its security
 * relevance stays low, and an uncertain pattern can still be serious.
 */
enum class Confidence { HIGH, MEDIUM, LOW }

/** Stable rule/slot identifiers used for correlation and dedup keys. */
object Categories {
    const val MANIFEST = "manifest"
    const val ARCHIVE = "archive"
    const val CODE = "code"
    const val CERTIFICATE = "certificate"
    const val CORRELATION = "correlation"
}

/**
 * A single raw, reproducible observation backing a finding.
 * [type] is a stable slug ("permission", "manifest_attr", "zip_entry", ...).
 */
data class Evidence(
    val type: String,
    val label: String,
    val value: String,
    val location: String? = null,
)

data class Finding(
    val id: String,
    val engineId: String,
    val title: String,
    val summary: String,
    val kind: FindingKind,
    val severity: Severity,
    val evidence: List<Evidence>,
    val recommendation: String? = null,
    val detectedAt: Long,
    /** additive Phase 3 fields; defaults keep Phase 2 call sites and files valid */
    val category: String = Categories.MANIFEST,
    val ruleId: String = "",
    val confidence: Confidence = Confidence.MEDIUM,
)

/** An openly stated gap: the engine could not check something, and says so. */
data class UnknownNote(val engineId: String, val message: String)
