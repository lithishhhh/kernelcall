package com.kernelcall.app

import com.kernelcall.app.core.export.ForensicTextReport
import com.kernelcall.app.core.export.ExportFormat
import com.kernelcall.app.core.export.ReportExporter
import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.model.Categories
import com.kernelcall.app.core.model.Confidence
import com.kernelcall.app.core.model.CorrelationFinding
import com.kernelcall.app.core.model.EngineRunStats
import com.kernelcall.app.core.model.Evidence
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.Intelligence
import com.kernelcall.app.core.model.RiskAssessment
import com.kernelcall.app.core.model.RiskBand
import com.kernelcall.app.core.model.ScoreContribution
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.core.model.UnknownNote
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Export tests exercise only synthetic data. They verify that what is
 * exported is exactly what exists in the report model — nothing more,
 * nothing invented — and that hostile-looking evidence values cannot
 * corrupt the exported document.
 */
class ReportExportTest {

    private val sha256 = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"

    private fun finding(
        id: String = "synthetic:static.manifest.permission:SEND_SMS",
        title: String = "Permission declared: SEND_SMS",
        kind: FindingKind = FindingKind.CONFIRMED_OBSERVATION,
        severity: Severity = Severity.INFO,
        confidence: Confidence = Confidence.HIGH,
        ruleId: String = "static.manifest.permission",
        evidence: List<Evidence> = listOf(
            Evidence("manifest", "uses-permission", "android.permission.SEND_SMS",
                "AndroidManifest.xml"),
        ),
        summary: String = "synthetic summary",
        recommendation: String? = "Confirm the permission is required.",
    ) = Finding(
        id = id,
        engineId = "static.v2",
        title = title,
        summary = summary,
        kind = kind,
        severity = severity,
        evidence = evidence,
        recommendation = recommendation,
        detectedAt = 1_700_000_000_000,
        category = Categories.MANIFEST,
        ruleId = ruleId,
        confidence = confidence,
    )

    private fun correlation() = CorrelationFinding(
        id = "intel.correlate.telephony",
        ruleId = "intel.correlate.telephony",
        title = "SMS/telephony interception stack",
        explanation = "Intercepts SMS intents and declares telephony permissions.",
        severity = Severity.MEDIUM,
        relatedFindingIds = listOf("synthetic:one", "synthetic:two"),
        sharedEvidence = listOf(Evidence("manifest", "intent-action", "SMS_RECEIVED")),
        scoreWeight = 18,
    )

    private fun intelligence() = Intelligence(
        correlations = listOf(correlation()),
        risk = RiskAssessment(
            score = 42,
            band = RiskBand.ELEVATED,
            contributions = listOf(
                ScoreContribution("synthetic:one", "synthetic.rule.a",
                    "medium heuristic — intercept", 18),
            ),
            limitations = listOf(
                "Static analysis only — no runtime or sandbox behavior is part of this score.",
            ),
        ),
    )

    private fun report(
        schemaVersion: Int = 3,
        intelligence: Intelligence? = intelligence(),
        findings: List<Finding> = listOf(finding()),
        engines: List<EngineRunStats> = listOf(
            EngineRunStats("static.v2", 4210, 10, 3),
        ),
        unknowns: List<UnknownNote> = listOf(
            UnknownNote("static.v2", "v2/v3 signatures could not be read statically."),
        ),
    ) = AnalysisReport(
        schemaVersion = schemaVersion,
        sha256 = sha256,
        fileName = "sample-app.apk",
        sizeBytes = 5_242_880,
        generatedAt = 1_700_000_000_000,
        engines = engines,
        findings = findings,
        unknowns = unknowns,
        intelligence = intelligence,
    )

    // ---------- JSON export ----------

    @Test
    fun `json export round-trips to an identical report`() {
        val original = report()
        val exported = original.toJson()
        val reparsed = AnalysisReport.fromJson(exported)
        assertEquals(original, reparsed)
    }

    @Test
    fun `legacy v2 json export omits intelligence entirely`() {
        val legacy = report(schemaVersion = 2, intelligence = null)
        val exported = legacy.toJson()
        assertFalse(exported.contains("""intelligence"""))
        val reparsed = AnalysisReport.fromJson(exported)
        assertEquals(legacy, reparsed)
        assertEquals(2, reparsed?.schemaVersion)
        assertEquals(true, reparsed?.intelligence == null)
    }

    @Test
    fun `json export keeps odd values parseable and exact`() {
        val hostile = "Evil \"quotes\" backslash \\ tab\tnext%line"
        val original = report(
            findings = listOf(
                finding(
                    title = hostile,
                    evidence = listOf(Evidence("dex", "url", "http://x/?a=1&#38;b=2")),
                ),
            ),
        )
        val exported = original.toJson()
        val parsed = JSONObject(exported)
        assertEquals(3, parsed.optInt("schemaVersion"))
        val reparsed = AnalysisReport.fromJson(exported)
        assertEquals(hostile, reparsed?.findings?.first()?.title)
        assertEquals("http://x/?a=1&#38;b=2", reparsed?.findings?.first()?.evidence?.first()?.value)
    }

    // ---------- text export ----------

    @Test
    fun `text export shows identity score and non-verdict notice`() {
        val text = ForensicTextReport.build(report())
        assertTrue(text.contains("KERNEL CALL - FORENSIC STATIC ANALYSIS REPORT"))
        assertTrue(text.contains(sha256.lowercase()))
        assertTrue(text.contains("sample-app.apk"))
        assertTrue(text.contains("5,242,880 bytes"))
        assertTrue(text.contains("Score : 42/100 (band ELEVATED)"))
        assertTrue(text.contains("NOT proof that the APK is malicious"))
        assertTrue(text.contains("never prove that an APK is safe"))
        assertTrue(text.contains("static.v2 : 4210 ms - 10 finding(s), 3 unknown(s)"))
        assertTrue(text.contains("Report schema version : 3"))
    }

    @Test
    fun `text export renders findings evidence confidence correlations limitations`() {
        val text = ForensicTextReport.build(
            report(
                findings = listOf(
                    finding(), finding(
                        id = "synthetic:heuristic",
                        title = "URL-like strings in dex",
                        kind = FindingKind.HEURISTIC_INDICATOR,
                        severity = Severity.LOW,
                        confidence = Confidence.MEDIUM,
                        ruleId = "static.dex.urls",
                        evidence = listOf(
                            Evidence("dex", "url", "http://example.example/payload",
                                "classes.dex"),
                        ),
                        summary = "Pattern may indicate endpoints.",
                        recommendation = null,
                    ),
                ),
            ),
        )
        assertTrue(text.contains("Risk-surface intelligence") ||
            text.contains("RISK-SURFACE INTELLIGENCE"))
        assertTrue(text.contains("CONFIRMED OBSERVATION"))
        assertTrue(text.contains("HEURISTIC INDICATOR"))
        assertTrue(text.contains("Confidence : HIGH"))
        assertTrue(text.contains("static.dex.urls"))
        assertTrue(text.contains("http://example.example/payload (classes.dex)"))
        assertTrue(text.contains("SMS/telephony interception stack"))
        assertTrue(text.contains("declares telephony permissions"))
        assertTrue(text.contains("Provenance: synthetic:one, synthetic:two"))
        assertTrue(text.contains("SMS_RECEIVED"))
        assertTrue(text.contains(
            "Static analysis only — no runtime or sandbox behavior is part of this score.",
        ))
        assertTrue(text.contains("+18 : medium heuristic — intercept"))
    }

    @Test
    fun `legacy v2 text export states absence without fabricating a score`() {
        val text = ForensicTextReport.build(
            report(schemaVersion = 2, intelligence = null),
        )
        assertTrue(text.contains("none (report schema version 2)"))
        assertTrue(text.contains("nothing is invented here"))
        assertFalse(text.contains("Score : "))
        assertFalse(text.contains("ELEVATED"))
        assertFalse(text.contains("MODERATE"))
        assertFalse(text.contains("Impact never:"))
        assertFalse(text.contains("Intel"))
    }

    @Test
    fun `empty legacy report renders without crashing`() {
        val text = ForensicTextReport.build(
            report(
                schemaVersion = 2,
                intelligence = null,
                findings = emptyList(),
                engines = emptyList(),
                unknowns = emptyList(),
            ),
        )
        assertTrue(text.contains("FINDINGS (0)"))
        assertTrue(text.contains("(none recorded by this report)"))
        assertTrue(text.contains("Engine runs           : not recorded"))
        assertTrue(text.contains("OPEN UNKNOWNS (0)"))
        assertTrue(text.contains("SHA-256   : " + sha256.lowercase()))
    }

    @Test
    fun `text export escapes control characters in dynamic values`() {
        val text = ForensicTextReport.build(
            report(
                findings = listOf(
                    finding(
                        title = "evil\nline${'\u0001'}tab${'\t'}cr${'\u0007'}",
                        evidence = listOf(
                            Evidence("manifest", "attr", "value with\rCR"),
                        ),
                    ),
                ),
            ),
        )
        assertTrue(text.contains("""evil\nline\x01tab\tcr\x07"""))
        assertTrue(text.contains("""value with\rCR"""))
        assertFalse(text.contains("evil\nline"))
        assertFalse(text.contains("value with\rCR"))
    }

    // ---------- naming ----------

    @Test
    fun `suggested file names are derived from the digest only`() {
        val jsonName = ReportExporter.suggestedFileName(report(), ExportFormat.JSON)
        val textName = ReportExporter.suggestedFileName(report(), ExportFormat.TEXT)
        assertTrue(Regex("""kernelcall-report-[0-9a-f]{12}\.json""").matches(jsonName))
        assertTrue(Regex("""kernelcall-report-[0-9a-f]{12}\.txt""").matches(textName))
        assertFalse(textName.contains(Regex("""[^A-Za-z0-9.\-]""")))
    }

    @Test
    fun `share subject keeps control characters escaped`() {
        val text = ReportExporter.shareSubject(
            report(findings = emptyList(), intelligence = null),
        )
        assertFalse(text.contains('\n'))
        assertFalse(text.contains('\r'))
        assertFalse(text.contains('\t'))
        assertTrue(text.contains("sample-app.apk"))
    }
}
