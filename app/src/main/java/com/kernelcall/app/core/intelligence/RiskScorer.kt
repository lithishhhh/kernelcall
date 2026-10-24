package com.kernelcall.app.core.intelligence

import com.kernelcall.app.core.model.Confidence
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.RiskAssessment
import com.kernelcall.app.core.model.RiskBand
import com.kernelcall.app.core.model.ScoreContribution
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.core.model.UnknownNote
import kotlin.math.roundToInt

/**
 * Deterministic, explainable risk scoring over one report's findings.
 *
 * Model (documented contract, unit-tested):
 *  - Base weight comes ONLY from severity: INFO 0, LOW 5, MEDIUM 15, HIGH 25 points.
 *  - The observation kind adjusts the weight, never replaces it:
 *      CONFIRMED_OBSERVATION = full weight  (fact read from the file),
 *      HEURISTIC_INDICATOR   = 60% weight   (pattern, not established fact),
 *      UNKNOWN / SANDBOX_ONLY findings contribute 0 points; unknowns are
 *      surfaced as limitations instead of phantom score.
 *  - Observation certainty ([Confidence]) scales the weight:
 *      HIGH 100%, MEDIUM 75%, LOW 50%. Confidence and severity stay separate
 *      concepts: severity is impact, confidence is how sure we are at all.
 *  - Deduplication: findings whose (ruleId + evidence fingerprint) repeat are
 *      counted once, so repeated evidence never multiplies the score.
 *  - Correlations add their own declared [com.kernelcall.app.core.model.CorrelationFinding.scoreWeight]
 *      (combination signal; consolidations declare 0).
 *  - Score = min(100, sum). Bands: 0-9 LOW, 10-39 MODERATE, 40-64 ELEVATED, 65+ HIGH.
 *
 * The score is a risk-surface indicator, never a malware verdict and never a
 * calibrated probability of maliciousness.
 */
object RiskScorer {

    private val severityBase = mapOf(
        Severity.INFO to 0,
        Severity.LOW to 5,
        Severity.MEDIUM to 15,
        Severity.HIGH to 25,
    )

    private const val HEURISTIC_FACTOR = 0.6

    private val confidenceFactor = mapOf(
        Confidence.HIGH to 1.0,
        Confidence.MEDIUM to 0.75,
        Confidence.LOW to 0.5,
    )

    fun bandFor(score: Int): RiskBand = when {
        score >= 65 -> RiskBand.HIGH
        score >= 40 -> RiskBand.ELEVATED
        score >= 10 -> RiskBand.MODERATE
        else -> RiskBand.LOW
    }

    fun assess(
        findings: List<Finding>,
        correlations: List<com.kernelcall.app.core.model.CorrelationFinding>,
        unknowns: List<UnknownNote>,
    ): RiskAssessment {
        var totalMillis = 0L  // score kept exact as milli-points before rounding
        val contributions = mutableListOf<ScoreContribution>()
        val seenRuleFingerprints = HashSet<String>()

        findings.forEach { finding ->
            val weight = scoreWeightOf(finding) ?: return@forEach
            val fingerprint = fingerprint(finding)
            if (!seenRuleFingerprints.add(fingerprint)) return@forEach  // duplicate evidence path
            totalMillis += weight
            contributions.add(
                ScoreContribution(
                    refFindingId = finding.id,
                    refRuleId = finding.ruleId,
                    description = contributionDescription(finding),
                    weight = (weight / 1000.0).roundToInt(),
                )
            )
        }

        correlations.forEach { correlation ->
            if (correlation.scoreWeight > 0 &&
                seenRuleFingerprints.add(correlation.ruleId)
            ) {
                totalMillis += correlation.scoreWeight * 1000L
                contributions.add(
                    ScoreContribution(
                        refFindingId = correlation.id,
                        refRuleId = correlation.ruleId,
                        description = "correlation: ${correlation.title}",
                        weight = correlation.scoreWeight,
                    )
                )
            }
        }

        val score = (totalMillis / 1000.0).roundToInt().coerceIn(0, 100)

        val limitations = mutableListOf(
            "Static analysis only — no runtime or sandbox behavior is part of this score.",
            "An indicator of risk-surface, not a verdict that the APK is malicious.",
        )
        val unknownFindings = findings.count { it.kind == FindingKind.UNKNOWN }
        val unknownNotes = unknowns.size
        val unresolved = unknownFindings + unknownNotes
        val heuristicCount = findings.count { it.kind == FindingKind.HEURISTIC_INDICATOR }
        if (heuristicCount > 0) {
            limitations.add("$heuristicCount heuristic indicator(s) depend on pattern " +
                "interpretation; their weight is reduced by design.")
        }
        if (unresolved > 0) {
            limitations.add("$unresolved unresolved check(s) could not be completed, " +
                "which caps the confidence available for scoring.")
        }

        return RiskAssessment(
            score = score,
            band = bandFor(score),
            contributions = contributions.sortedByDescending { it.weight },
            limitations = limitations,
        )
    }

    /** milli-points for one finding, or null when it must not score. */
    private fun scoreWeightOf(finding: Finding): Long? {
        if (finding.kind == FindingKind.UNKNOWN || finding.kind == FindingKind.SANDBOX_ONLY) return null
        val base = severityBase[finding.severity] ?: return null
        if (base == 0) return null
        val kindFactor = when (finding.kind) {
            FindingKind.CONFIRMED_OBSERVATION -> 1.0
            FindingKind.HEURISTIC_INDICATOR -> HEURISTIC_FACTOR
            else -> return null
        }
        val factor = kindFactor * (confidenceFactor[finding.confidence] ?: 0.75)
        return (base * factor * 1000).roundToInt().toLong()
    }

    private fun contributionDescription(finding: Finding): String {
        val kindLabel = when (finding.kind) {
            FindingKind.CONFIRMED_OBSERVATION -> "observed"
            FindingKind.HEURISTIC_INDICATOR -> "heuristic"
            else -> finding.kind.name.lowercase()
        }
        return "${finding.severity.name.lowercase()} $kindLabel — ${finding.title}"
    }

    /** stable identity of the evidence behind a finding (dedup key). */
    private fun fingerprint(finding: Finding): String =
        finding.ruleId.ifBlank { "bare:${finding.title}" } + "|" +
            finding.evidence.joinToString(";") { "${it.type}&${it.label}&${it.value}" }
}
