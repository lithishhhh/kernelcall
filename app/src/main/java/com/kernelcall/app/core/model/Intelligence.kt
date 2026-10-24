package com.kernelcall.app.core.model

/**
 * Phase 3 intelligence artifacts derived from findings after all engines ran.
 * Deterministically computed, never fetched, never calibrated probabilities.
 */
enum class RiskBand { LOW, MODERATE, ELEVATED, HIGH }

/**
 * One line of the scoring explanation: what added how much and why.
 * [weight] is in score points before capping.
 */
data class ScoreContribution(
    val refFindingId: String,
    val refRuleId: String,
    val description: String,
    val weight: Int,
)

data class RiskAssessment(
    val score: Int,                       // 0..100, capped sum of deterministic weights
    val band: RiskBand,
    val contributions: List<ScoreContribution>,
    val limitations: List<String>,
)

/** Result of one correlation rule; only facts that co-occur become rules. */
data class CorrelationFinding(
    val id: String,
    val ruleId: String,
    val title: String,
    val explanation: String,
    val severity: Severity,
    /** finding ids whose evidence combined to fire this rule (provenance) */
    val relatedFindingIds: List<String>,
    val sharedEvidence: List<Evidence>,
    /** consolidations add no score weight; real signal combinations may */
    val scoreWeight: Int,
)

/**
 * Container for the derived intelligence of one report. Old persisted
 * reports (schema 2) simply have this absent — parsed as null.
 */
data class Intelligence(
    val correlations: List<CorrelationFinding>,
    val risk: RiskAssessment,
) {
    companion object {
        const val SCHEMA_VERSION = 3
    }
}
