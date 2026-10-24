package com.kernelcall.app

import com.kernelcall.app.core.intelligence.Correlator
import com.kernelcall.app.core.intelligence.RiskScorer
import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.model.Categories
import com.kernelcall.app.core.model.Confidence
import com.kernelcall.app.core.model.EngineRunStats
import com.kernelcall.app.core.model.Evidence
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.RiskBand
import com.kernelcall.app.core.model.UnknownNote
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetic logic fixtures only. Nothing here is labeled as a real-world
 * detection; every Finding is constructed in-test to exercise rules.
 */
class IntelligenceTest {

    private fun finding(
        title: String = "Synthetic finding",
        kind: FindingKind = FindingKind.HEURISTIC_INDICATOR,
        severity: com.kernelcall.app.core.model.Severity =
            com.kernelcall.app.core.model.Severity.MEDIUM,
        ruleId: String = "synthetic.rule",
        category: String = Categories.CODE,
        confidence: Confidence = Confidence.HIGH,
        evidence: List<Evidence> = listOf(Evidence("synthetic", "value", "x")),
        engineId: String = "synthetic.engine",
    ) = Finding(
        id = "$engineId:$ruleId:$title",
        engineId = engineId,
        title = title,
        summary = "synthetic",
        kind = kind,
        severity = severity,
        evidence = evidence,
        detectedAt = 1_700_000_000_000,
        category = category,
        ruleId = ruleId,
        confidence = confidence,
    )

    private val perm = fun(name: String) = Finding(
        id = "synthetic:static.manifest.permission:$name",
        engineId = "synthetic.engine",
        title = "Permission declared: $name",
        summary = "synthetic",
        kind = FindingKind.CONFIRMED_OBSERVATION,
        severity = com.kernelcall.app.core.model.Severity.INFO,
        evidence = listOf(Evidence("manifest", "uses-permission", name, "AndroidManifest.xml")),
        detectedAt = 1_700_000_000_000,
        category = Categories.MANIFEST,
        ruleId = "static.manifest.permission",
    )

    private val telephonyIntercept = Finding(
        id = "synthetic:static.intent.telephony:intercept",
        engineId = "synthetic.engine",
        title = "Telephony/SMS intent interception",
        summary = "synthetic",
        kind = FindingKind.HEURISTIC_INDICATOR,
        severity = com.kernelcall.app.core.model.Severity.MEDIUM,
        evidence = listOf(
            Evidence("manifest", "intent-action", "SMS_RECEIVED -> receiver:MemberReceiver")
        ),
        detectedAt = 1_700_000_000_000,
        category = Categories.MANIFEST,
        ruleId = "static.intent.telephony",
        confidence = Confidence.MEDIUM,
    )

    // ---------- scoring ----------

    @Test
    fun `empty report scores zero in LOW band`() {
        val risk = RiskScorer.assess(emptyList(), emptyList(), emptyList())
        assertEquals(0, risk.score)
        assertEquals(RiskBand.LOW, risk.band)
        assertTrue(risk.limitations.isNotEmpty())
    }

    @Test
    fun `score is bounded at 100`() {
        val many = (1..20).map {
            finding(title = "T$it", ruleId = "synthetic.rule.$it", severity =
            com.kernelcall.app.core.model.Severity.HIGH)
        }
        val risk = RiskScorer.assess(many, emptyList(), emptyList())
        assertEquals(100, risk.score)
        assertEquals(RiskBand.HIGH, risk.band)
    }

    @Test
    fun `duplicate evidence is counted once`() {
        val a = finding(ruleId = "synthetic.rule.dup", evidence =
        listOf(Evidence("synthetic", "value", "same")))
        val b = finding(ruleId = "synthetic.rule.dup", evidence =
        listOf(Evidence("synthetic", "value", "same")))
        val risk = RiskScorer.assess(listOf(a, b), emptyList(), emptyList())
        assertEquals(1, risk.contributions.size)
        val single = RiskScorer.assess(listOf(a), emptyList(), emptyList())
        assertEquals(single.score, risk.score)
    }

    @Test
    fun `same ruleId with different evidence scores twice`() {
        val a = finding(ruleId = "synthetic.rule", evidence =
        listOf(Evidence("synthetic", "value", "first")))
        val b = finding(ruleId = "synthetic.rule", evidence =
        listOf(Evidence("synthetic", "value", "second")))
        val risk = RiskScorer.assess(listOf(a, b), emptyList(), emptyList())
        assertEquals(2, risk.contributions.size)
    }

    @Test
    fun `heuristic contributes less than confirmed at equal severity`() {
        val confirmed = finding(kind = FindingKind.CONFIRMED_OBSERVATION)
        val heuristic = finding(kind = FindingKind.HEURISTIC_INDICATOR)
        val confirmedRisk = RiskScorer.assess(listOf(confirmed), emptyList(), emptyList())
        val heuristicRisk = RiskScorer.assess(listOf(heuristic), emptyList(), emptyList())
        assertTrue(confirmedRisk.score > heuristicRisk.score)
        assertTrue(heuristicRisk.score > 0)
    }

    @Test
    fun `confidence scales score separately from severity`() {
        val highConf = finding(confidence = Confidence.HIGH)
        val lowConf = finding(confidence = Confidence.LOW)
        val high = RiskScorer.assess(listOf(highConf), emptyList(), emptyList())
        val low = RiskScorer.assess(listOf(lowConf), emptyList(), emptyList())
        assertTrue(high.score > low.score)
        assertTrue(low.score > 0)
    }

    @Test
    fun `UNKNOWN kind findings add no score and appear as limitations`() {
        val unknown = finding(kind = FindingKind.UNKNOWN)
        val note = UnknownNote("synthetic.engine", "capability gap")
        val risk = RiskScorer.assess(listOf(unknown), emptyList(), listOf(note))
        assertEquals(0, risk.score)
        assertTrue(
            risk.limitations.any { it.contains("unresolved") }
        )
    }

    @Test
    fun `band boundaries are 10, 40, 65`() {
        assertEquals(RiskBand.LOW, RiskScorer.bandFor(0))
        assertEquals(RiskBand.LOW, RiskScorer.bandFor(9))
        assertEquals(RiskBand.MODERATE, RiskScorer.bandFor(10))
        assertEquals(RiskBand.MODERATE, RiskScorer.bandFor(39))
        assertEquals(RiskBand.ELEVATED, RiskScorer.bandFor(40))
        assertEquals(RiskBand.ELEVATED, RiskScorer.bandFor(64))
        assertEquals(RiskBand.HIGH, RiskScorer.bandFor(65))
        assertEquals(RiskBand.HIGH, RiskScorer.bandFor(100))
    }

    @Test
    fun `mixed findings produce deterministic score`() {
        val list = listOf(
            finding(title = "a", kind = FindingKind.CONFIRMED_OBSERVATION, ruleId = "r.c1",
                severity = com.kernelcall.app.core.model.Severity.HIGH),
            finding(title = "b", kind = FindingKind.HEURISTIC_INDICATOR, ruleId = "r.h2",
                severity = com.kernelcall.app.core.model.Severity.MEDIUM),
            finding(title = "c", kind = FindingKind.CONFIRMED_OBSERVATION, ruleId = "r.i3",
                severity = com.kernelcall.app.core.model.Severity.LOW),
            finding(title = "d", kind = FindingKind.UNKNOWN, ruleId = "r.u4",
                severity = com.kernelcall.app.core.model.Severity.LOW),
        )
        val first = RiskScorer.assess(listOf(*list.toTypedArray()), emptyList(), emptyList())
        val second = RiskScorer.assess(listOf(*list.reversed().toTypedArray()),
            emptyList(), emptyList())
        assertEquals(first.score, second.score)
        assertEquals(first.contributions.map { it.refRuleId },
            second.contributions.map { it.refRuleId })
    }


    // ---------- correlation ----------

    @Test
    fun `telephony correlation fires only with matching permission`() {
        val without = Correlator.correlate(listOf(telephonyIntercept))
        assertTrue(without.none { it.ruleId == Correlator.RULE_TELEPHONY_PAIR })

        val with = Correlator.correlate(
            listOf(perm("android.permission.RECEIVE_SMS"), telephonyIntercept)
        )
        val rule = with.first { it.ruleId == Correlator.RULE_TELEPHONY_PAIR }
        assertEquals(2, rule.relatedFindingIds.size)  // provenance kept
        assertTrue(rule.explanation.contains("intercepts"))
        assertTrue(rule.scoreWeight > 0)
    }

    @Test
    fun `cleartext correlation fires only with endpoints plus cleartext flag`() {
        val urls = finding(
            title = "endpoints",
            ruleId = "static.dex.urls",
            evidence = listOf(Evidence("dex", "url literal", "http://example.test/x")),
        )
        val cleartext = finding(
            title = "cleartext",
            ruleId = "static.manifest.cleartext",
            kind = FindingKind.CONFIRMED_OBSERVATION,
            evidence = listOf(Evidence("manifest", "android:usesCleartextTraffic", "true")),
        )
        assertTrue(
            Correlator.correlate(listOf(urls))
                .none { it.ruleId == Correlator.RULE_CLEARTEXT_NETWORK }
        )
        val both = Correlator.correlate(listOf(urls, cleartext))
        assertTrue(both.any { it.ruleId == Correlator.RULE_CLEARTEXT_NETWORK })
    }

    @Test
    fun `overlapping evidence consolidates without losing provenance and scores zero`() {
        val shared = Evidence("synthetic", "same key", "same value")
        val a = finding(title = "A", ruleId = "synthetic.a", evidence = listOf(shared))
        val b = finding(title = "B", ruleId = "synthetic.b", evidence = listOf(shared))
        val scoreWithout = RiskScorer.assess(listOf(a, b), emptyList(), emptyList())
        val result = Correlator.correlate(listOf(a, b))
        val consolidation = result.first { it.ruleId == Correlator.RULE_OVERLAP }
        assertEquals(setOf(a.id, b.id), consolidation.relatedFindingIds.toSet())
        assertEquals(0, consolidation.scoreWeight)
        val risk = RiskScorer.assess(listOf(a, b), result, emptyList())
        assertEquals(scoreWithout.score, risk.score)
    }

    @Test
    fun `persistence correlation matches boot component plus boot permission`() {
        val boot = finding(
            title = "boot",
            ruleId = "static.intent.boot",
            kind = FindingKind.HEURISTIC_INDICATOR,
            severity = com.kernelcall.app.core.model.Severity.LOW,
            evidence = listOf(
                Evidence("manifest", "intent-action", "BOOT_COMPLETED -> receiver:R")
            ),
        )
        val p = perm("android.permission.RECEIVE_BOOT_COMPLETED")
        assertTrue(
            Correlator.correlate(listOf(boot))
                .none { it.ruleId == Correlator.RULE_PERSISTENCE }
        )
        assertTrue(
            Correlator.correlate(listOf(boot, p))
                .any { it.ruleId == Correlator.RULE_PERSISTENCE }
        )
    }

    // ---------- persistence + compatibility ----------

    @Test
    fun `schema 2 report parses with model defaults and no intelligence`() {
        val legacy = """
            {"schemaVersion":2,"sha256":"abc","fileName":"old.apk","sizeBytes":10,
             "generatedAt":1700000000000,
             "engines":[{"engineId":"static.v2","durationMs":5,"findingCount":0,"unknownCount":1}],
             "findings":[{"id":"static.v2:t:1","engineId":"static.v2","title":"T",
                          "summary":"S","kind":"CONFIRMED_OBSERVATION","severity":"LOW",
                          "detectedAt":1700000000000,"evidence":[]}],
             "unknowns":[{"engineId":"static.v2","message":"m"}]}
        """.trimIndent()
        val report = AnalysisReport.fromJson(legacy)
        assertNotNull(report)
        assertNull(report!!.intelligence)
        assertEquals(Categories.MANIFEST, report.findings[0].category)
        assertEquals("", report.findings[0].ruleId)
        assertEquals(Confidence.MEDIUM, report.findings[0].confidence)
    }

    @Test
    fun `schema 3 report round-trips intelligence`() {
        val correlations = Correlator.correlate(
            listOf(perm("android.permission.RECEIVE_SMS"), telephonyIntercept)
        )
        val risk = RiskScorer.assess(
            listOf(perm("android.permission.RECEIVE_SMS"), telephonyIntercept),
            correlations,
            listOf(UnknownNote("static.v2", "gap")),
        )
        val report = AnalysisReport(
            schemaVersion = AnalysisReport.CURRENT_SCHEMA_VERSION,
            sha256 = "abc123",
            fileName = "new.apk",
            sizeBytes = 42,
            generatedAt = 1_700_000_000_123,
            engines = listOf(EngineRunStats("static.v2", 12, 2, 0)),
            findings = listOf(perm("android.permission.RECEIVE_SMS"), telephonyIntercept),
            unknowns = listOf(UnknownNote("static.v2", "gap")),
            intelligence = com.kernelcall.app.core.model.Intelligence(correlations, risk),
        )
        val parsed = AnalysisReport.fromJson(report.toJson())
        assertNotNull(parsed)
        val intel = parsed!!.intelligence
        assertNotNull(intel)
        assertEquals(risk.score, intel!!.risk.score)
        assertEquals(risk.band, intel.risk.band)
        assertEquals(intel.correlations.size, correlations.size)
        assertTrue(intel.correlations.all { it.relatedFindingIds.isNotEmpty() })
        assertEquals(
            intel.risk.limitations.size,
            intel.risk.limitations.distinct().size,
        )
        assertFalse(parsed.findings.isEmpty())
    }
}
