package com.kernelcall.app.core.export

import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.Severity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Renders one [AnalysisReport] as a readable plain-text forensic summary.
 *
 * Honesty rules enforced here:
 *  - Only data that actually exists in the report is printed. A schema-v2
 *    report without intelligence says exactly that — no score, correlation,
 *    AI result, or verdict is ever invented.
 *  - Every dynamic value passes through [escape], so control characters in
 *    observed values (titles, URLs, certificate fields...) cannot forge
 *    report structure in the exported text.
 *  - The document always states that this is an indicator-based analysis,
 *    not proof that the APK is malicious or safe.
 */
object ForensicTextReport {

    private const val WIDE = "============================================================"
    private const val NARROW = "------------------------------------------------------------"

    /** Builds the full plain-text report (ASCII only for maximum portability). */
    fun build(report: AnalysisReport): String = StringBuilder().apply {
        val b = this

        b.appendLine(WIDE)
        b.appendLine("KERNEL CALL - FORENSIC STATIC ANALYSIS REPORT")
        b.appendLine(WIDE)
        b.appendLine("NOTICE: This report contains indicator-based static analysis.")
        b.appendLine("Findings are observations and heuristics read from the file on")
        b.appendLine("the analysis device. This is NOT proof that the APK is malicious,")
        b.appendLine("and it can never prove that an APK is safe. No dynamic, sandbox")
        b.appendLine("or runtime execution analysis was performed.")
        b.appendLine()

        // 1. APK identity
        b.appendLine("1. APK IDENTITY")
        b.appendLine("  File name : " + escape(report.fileName))
        b.appendLine("  Size      : " + String.format(Locale.US, "%,d", report.sizeBytes) + " bytes")
        b.appendLine("  SHA-256   : " + escape(report.sha256.lowercase()))
        b.appendLine()

        // 2. Analysis metadata
        b.appendLine("2. ANALYSIS METADATA")
        b.appendLine("  Report schema version : ${report.schemaVersion}")
        b.appendLine("  Report generated      : ${timestamp(report.generatedAt)} (UTC)")
        if (report.engines.isEmpty()) {
            b.appendLine("  Engine runs           : not recorded")
        } else {
            b.appendLine("  Engine runs (timings in ms):")
            report.engines.forEach { engine ->
                b.appendLine(
                    "    " + escape(engine.engineId) + " : ${engine.durationMs} ms - " +
                        "${engine.findingCount} finding(s), ${engine.unknownCount} unknown(s)"
                )
            }
        }
        b.appendLine()

        // 3. Intelligence (may be absent on legacy schema-v2 reports)
        b.appendLine("3. RISK-SURFACE INTELLIGENCE")
        val intel = report.intelligence
        if (intel == null) {
            b.appendLine(
                "  Indicator risk score and correlations : none (report schema " +
                    "version ${report.schemaVersion})"
            )
            b.appendLine("  No score, correlation or AI result exists for this report;")
            b.appendLine("  nothing is invented here. Re-running static analysis on this")
            b.appendLine("  file generates the intelligence layer for this APK.")
        } else {
            b.appendLine(
                "  Score : ${intel.risk.score}/100 (band ${intel.risk.band.name})"
            )
            b.appendLine("  This is an indicator of code-level risk surface derived from")
            b.appendLine("  static evidence only - never a verdict of maliciousness.")
            if (intel.risk.contributions.isNotEmpty()) {
                b.appendLine("  Score explanation:")
                intel.risk.contributions.forEach { contribution ->
                    b.appendLine("    +${contribution.weight} : " + escape(contribution.description))
                }
            }
            if (intel.correlations.isNotEmpty()) {
                b.appendLine("  Correlated indicators (${intel.correlations.size}):")
                intel.correlations.forEach { correlation ->
                    val suffix = if (correlation.scoreWeight > 0) {
                        " (+${correlation.scoreWeight} score)"
                    } else {
                        " (consolidation only, no score)"
                    }
                    b.appendLine("    - " + escape(correlation.title) +
                        " [${correlation.severity.name}]" + suffix)
                    b.appendLine("      " + escape(correlation.explanation))
                    if (correlation.relatedFindingIds.isNotEmpty()) {
                        b.appendLine(
                            "      Provenance: " +
                                escape(correlation.relatedFindingIds.joinToString(", "))
                        )
                    }
                    if (correlation.sharedEvidence.isNotEmpty()) {
                        b.appendLine("      Shared evidence:")
                        correlation.sharedEvidence.forEach { evidence ->
                            b.appendLine("        - " + escape(evidenceLine(evidence)))
                        }
                    }
                }
            }
            if (intel.risk.limitations.isNotEmpty()) {
                b.appendLine("  Limitations of this score:")
                intel.risk.limitations.forEach { limitation ->
                    b.appendLine("    - " + escape(limitation))
                }
            }
        }
        b.appendLine()

        // 4. Severity distribution
        b.appendLine("4. SEVERITY DISTRIBUTION")
        Severity.entries.forEach { severity ->
            val count = report.findings.count { it.severity == severity }
            b.appendLine("  ${severity.name.padEnd(8)}: $count")
        }
        b.appendLine()

        // 5. Findings with evidence
        b.appendLine("5. FINDINGS (${report.findings.size})")
        if (report.findings.isEmpty()) {
            b.appendLine("  (none recorded by this report)")
        } else {
            report.findings.forEachIndexed { index, finding ->
                b.appendLine(NARROW)
                b.appendLine("  [${index + 1}] " + escape(finding.title))
                b.appendLine("      Kind       : ${kindLabel(finding.kind)}")
                b.appendLine("      Severity   : ${finding.severity.name}")
                b.appendLine("      Confidence : ${finding.confidence.name}")
                if (finding.ruleId.isNotBlank()) {
                    b.appendLine("      Rule       : ${escape(finding.ruleId)}")
                }
                b.appendLine("      Summary    : " + escape(finding.summary))
                finding.recommendation?.let {
                    if (it.isNotBlank()) b.appendLine("      Next step  : " + escape(it))
                }
                if (finding.evidence.isEmpty()) {
                    b.appendLine("      Evidence   : none recorded")
                } else {
                    b.appendLine("      Evidence (${finding.evidence.size}):")
                    finding.evidence.forEach { evidence ->
                        b.appendLine("        - " + escape(evidenceLine(evidence)))
                    }
                }
            }
        }
        b.appendLine()

        // 6. Open unknowns
        b.appendLine("6. OPEN UNKNOWNS (${report.unknowns.size})")
        if (report.unknowns.isEmpty()) {
            b.appendLine("  (none recorded for this run)")
        } else {
            report.unknowns.forEach { note ->
                b.appendLine("  - [${escape(note.engineId)}] " + escape(note.message))
            }
        }

        b.appendLine()
        b.appendLine(WIDE)
        b.appendLine("End of report. Produced entirely on this device; the sharing or")
        b.appendLine("saving you just performed is the only way this content moves.")
        b.appendLine(WIDE)
    }.toString()

    /**
     * Makes any dynamic report value safe for embedding in plain-text output:
     * control characters become visible escapes so an observed value can never
     * forge report lines inside the exported document.
     */
    internal fun escape(value: String): String {
        val out = StringBuilder(value.length + 8)
        value.forEach { ch ->
            when {
                ch == '\n' -> out.append("\\n")
                ch == '\r' -> out.append("\\r")
                ch == '\t' -> out.append("\\t")
                ch.code < 0x20 || ch.code == 0x7F ->
                    out.append("\\x" + ch.code.toString(16).padStart(2, '0'))
                else -> out.append(ch)
            }
        }
        return out.toString()
    }

    /** One raw observation as a single line: type / label / value / location. */
    private fun evidenceLine(evidence: com.kernelcall.app.core.model.Evidence): String {
        val location = evidence.location?.let { " ($it)" } ?: ""
        return "${evidence.type} / ${evidence.label} : ${evidence.value}$location"
    }

    private fun kindLabel(kind: FindingKind): String = when (kind) {
        FindingKind.CONFIRMED_OBSERVATION -> "CONFIRMED OBSERVATION"
        FindingKind.HEURISTIC_INDICATOR -> "HEURISTIC INDICATOR"
        FindingKind.UNKNOWN -> "UNKNOWN"
        FindingKind.SANDBOX_ONLY -> "SANDBOX ONLY"
    }

    private fun timestamp(millis: Long): String {
        if (millis <= 0) return "unknown"
        val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        return format.format(Date(millis))
    }
}
