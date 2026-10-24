package com.kernelcall.app.core.intelligence

import com.kernelcall.app.core.model.CorrelationFinding
import com.kernelcall.app.core.model.Evidence
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.Severity

/**
 * Deterministic, evidence-driven correlation rules. Every rule consults only
 * what is actually present in the finding set of ONE report. No runtime
 * behavior is claimed from static facts, and consolidation never deletes
 * provenance (related finding ids are preserved).
 */
object Correlator {

    /** Rules listed here are the stable, testable contract of the platform. */
    const val RULE_TELEPHONY_PAIR = "intel.correlate.telephony"
    const val RULE_CLEARTEXT_NETWORK = "intel.correlate.cleartext-network"
    const val RULE_PERSISTENCE = "intel.correlate.persistence"
    const val RULE_OVERLAP = "intel.correlate.overlap-consolidation"

    private val SMS_AND_TELEPHONY_PERMISSIONS = setOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_CALL_LOG",
    )

    private val BOOT_PERMISSIONS = setOf(
        "android.permission.RECEIVE_BOOT_COMPLETED",
    )

    fun correlate(findings: List<Finding>): List<CorrelationFinding> {
        val out = mutableListOf<CorrelationFinding>()
        out.addIf(evaluateTelephonyPair(findings))
        out.addIf(evaluateCleartextNetwork(findings))
        out.addIf(evaluatePersistence(findings))
        out.addAll(evaluateEvidenceOverlap(findings))
        return out
    }

    // R1: SMS/telephony intent interception + related permission declaration.
    private fun evaluateTelephonyPair(findings: List<Finding>): CorrelationFinding? {
        val intercept = findings.firstOrNull {
            it.ruleId == "static.intent.telephony" && it.kind == FindingKind.HEURISTIC_INDICATOR
        } ?: return null
        val perms = findings.filter {
            it.ruleId == "static.manifest.permission" &&
                it.evidence.any { e -> e.type == "manifest" && e.value in SMS_AND_TELEPHONY_PERMISSIONS }
        }
        if (perms.isEmpty()) return null

        val shared = intercept.evidence + perms.flatMap { it.evidence }
        return CorrelationFinding(
            id = RULE_TELEPHONY_PAIR,
            ruleId = RULE_TELEPHONY_PAIR,
            title = "SMS/telephony interception stack",
            explanation = "The app both intercepts SMS/telephony intents " +
                "(${intercept.title}) and declares related telephony permissions " +
                "(${perms.size} rule(s)). Each fact alone is legitimate in messaging " +
                "apps; their combination is a pattern worth manual review because " +
                "subscription-fraud malware also shows it. No runtime behavior " +
                "has been observed — static evidence only.",
            severity = Severity.MEDIUM,
            relatedFindingIds = (listOf(intercept.id) + perms.map { it.id }).distinct(),
            sharedEvidence = shared.distinctBy { Triple(it.type, it.label, it.value) },
            scoreWeight = 18,
        )
    }

    // R2: embedded endpoints + a permitted unencrypted channel.
    private fun evaluateCleartextNetwork(findings: List<Finding>): CorrelationFinding? {
        val urls = findings.firstOrNull { it.ruleId == "static.dex.urls" } ?: return null
        val cleartext = findings.firstOrNull {
            it.ruleId == "static.manifest.cleartext" && it.evidence.any { e -> e.value == "true" }
        } ?: return null

        return CorrelationFinding(
            id = RULE_CLEARTEXT_NETWORK,
            ruleId = RULE_CLEARTEXT_NETWORK,
            title = "Network endpoints + cleartext channel permitted",
            explanation = "URL-shaped endpoints exist in the dex content and the " +
                "manifest permits cleartext (HTTP) traffic. The evidence does not " +
                "prove any endpoint is contacted, nor unencrypted; the combination " +
                "warrants closer review. Network behavior claims require sandbox analysis.",
            severity = Severity.MEDIUM,
            relatedFindingIds = listOf(urls.id, cleartext.id),
            sharedEvidence = (urls.evidence + cleartext.evidence)
                .distinctBy { Triple(it.type, it.label, it.value) },
            scoreWeight = 18,
        )
    }

    // R3: boot-time start + boot permission in the same manifest.
    private fun evaluatePersistence(findings: List<Finding>): CorrelationFinding? {
        val boot = findings.firstOrNull { it.ruleId == "static.intent.boot" } ?: return null
        val perms = findings.filter {
            it.ruleId == "static.manifest.permission" &&
                it.evidence.any { e -> e.type == "manifest" && e.value in BOOT_PERMISSIONS }
        }
        if (perms.isEmpty()) return null

        return CorrelationFinding(
            id = RULE_PERSISTENCE,
            ruleId = RULE_PERSISTENCE,
            title = "Boot-time persistence pattern",
            explanation = "A component starts after device reboot and the manifest " +
                "also declares RECEIVE_BOOT_COMPLETED. Commonly benign; a " +
                "self-starting restart pattern is nonetheless part of typical " +
                "malware behavior reached only via dynamic analysis.",
            severity = Severity.LOW,
            relatedFindingIds = (listOf(boot.id) + perms.map { it.id }).distinct(),
            sharedEvidence = (boot.evidence + perms.flatMap { it.evidence })
                .distinctBy { Triple(it.type, it.label, it.value) },
            scoreWeight = 8,
        )
    }

    // R4: overlapping evidence consolidated — provenance kept, zero score.
    private fun evaluateEvidenceOverlap(findings: List<Finding>): List<CorrelationFinding> {
        val seen = HashMap<Triple<String, String, String>, MutableList<Finding>>()
        findings.forEach { finding ->
            finding.evidence.forEach { evidence ->
                val key = Triple(evidence.type, evidence.label, evidence.value)
                seen.getOrPut(key) { mutableListOf() }.add(finding)
            }
        }
        return seen.filter { it.value.size > 1 }.map { (key, owners) ->
            CorrelationFinding(
                id = RULE_OVERLAP,
                ruleId = RULE_OVERLAP,
                title = "Shared evidence consolidated (${owners.size} findings)",
                explanation = "Different findings cite the same observed fact " +
                    "(${key.second} = ${key.third}). This is a deduplication note for " +
                    "explainability: it adds no score weight and preserves both " +
                    "finding ids as provenance.",
                severity = Severity.INFO,
                relatedFindingIds = owners.map { it.id }.distinct(),
                sharedEvidence = listOf(Evidence(key.first, key.second, key.third)),
                scoreWeight = 0,
            )
        }
    }

    private fun <T> MutableList<T>.addIf(value: T?) {
        if (value != null) add(value)
    }
}
