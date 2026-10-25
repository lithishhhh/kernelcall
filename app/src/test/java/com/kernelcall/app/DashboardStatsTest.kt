package com.kernelcall.app

import com.kernelcall.app.core.dashboard.DashboardStatsBuilder
import com.kernelcall.app.core.dashboard.ReportAggregates
import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.model.Categories
import com.kernelcall.app.core.model.Intelligence
import com.kernelcall.app.core.model.RiskAssessment
import com.kernelcall.app.core.model.RiskBand
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.data.ScanRecord
import com.kernelcall.app.data.ScanRecordCodec
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure Phase 5 aggregation over persisted history + stored reports. */
class DashboardStatsTest {

    private fun record(sha: String, packageName: String? = null, at: Long = 0) =
        ScanRecord(
            id = at,
            fileName = "$sha-name",
            sizeBytes = 10_000,
            sha256 = sha,
            scannedAt = at,
            packageName = packageName,
        )

    private fun report(
        sha: String,
        findingsSeverities: List<Severity> = emptyList(),
        withIntel: Boolean = true,
    ): AnalysisReport = AnalysisReport(
        schemaVersion = 3,
        sha256 = sha,
        fileName = "$sha-name",
        sizeBytes = 10_000,
        generatedAt = 1,
        engines = emptyList(),
        findings = findingsSeverities.mapIndexed { index, severity ->
            com.kernelcall.app.core.model.Finding(
                id = "f$index",
                engineId = "synthetic",
                title = "Synthetic $index",
                summary = "",
                kind = com.kernelcall.app.core.model.FindingKind.CONFIRMED_OBSERVATION,
                severity = severity,
                evidence = emptyList(),
                detectedAt = 0,
                category = if (index % 2 == 0) Categories.MANIFEST else Categories.CODE,
                ruleId = "synthetic.rule",
            )
        },
        unknowns = emptyList(),
        intelligence = if (withIntel) {
            Intelligence(
                correlations = emptyList(),
                risk = RiskAssessment(42, RiskBand.ELEVATED, emptyList(), emptyList()),
            )
        } else null,
    )

    @Test
    fun `empty history yields null stats (no fabricated zeros)`() {
        assertNull(DashboardStatsBuilder.build(emptyList()) { null })
    }

    @Test
    fun `counts only real persisted reports`() {
        val records = listOf(record("aaa", at = 1), record("bbb", packageName = "pkga", at = 2), record("ccc", at = 3))
        val stats = DashboardStatsBuilder.build(records) { sha ->
            when (sha) {
                "aaa" -> report("aaa", listOf(Severity.HIGH, Severity.HIGH, Severity.LOW))
                "bbb" -> report("bbb", listOf(Severity.HIGH))
                else -> null
            }
        }
        assertNotNull(stats)
        assertEquals(3, stats!!.scannedApps)
        assertEquals(2, stats.analyzedReports)
        assertEquals(4, stats.totalFindings)
        assertEquals(3, stats.highSeverityFindings)
        assertEquals(listOf<Long>(3), stats.scannedWithoutReport)
        assertEquals(3, stats.categoryCounts[Categories.MANIFEST])
        assertEquals(1, stats.categoryCounts[Categories.CODE])
        assertEquals(3, stats.severityCounts[Severity.HIGH])
        assertEquals(1, stats.severityCounts[Severity.LOW])
        // "latest" is the first record in caller-sorted (newest-first) order
        assertEquals("aaa", stats.latest?.sha256)
        assertEquals(42, stats.latest?.score)
        assertEquals(RiskBand.ELEVATED, stats.latest?.band)
    }

    @Test
    fun `latest without intelligence is null, not invented`() {
        val records = listOf(record("aaa"))
        val stats = DashboardStatsBuilder.build(records) { sha ->
            report(sha, withIntel = false)
        }
        assertNull(stats!!.latest)
        assertEquals(1, stats.analyzedReports)
    }

    @Test
    fun `pure severity and category aggregation helpers`() {
        val counts = ReportAggregates.severityCounts(
            report("x", listOf(Severity.MEDIUM, Severity.INFO)).findings,
        )
        assertEquals(1, counts[Severity.MEDIUM])
        assertEquals(1, counts[Severity.INFO])
        val categories = ReportAggregates.categoryCounts(
            report("x", listOf(Severity.MEDIUM, Severity.INFO)).findings,
        )
        assertEquals(1, categories[Categories.MANIFEST])
        assertEquals(1, categories[Categories.CODE])
    }

    @Test
    fun `codec round trip keeps packageName and is tolerant of old payloads`() {
        val records = listOf(
            record("aaa", packageName = "com.app.one", at = 1),
            record("bbb", packageName = null, at = 2),
        )
        val encoded = ScanRecordCodec.encode(records).toString()
        val decoded = ScanRecordCodec.decode(JSONArray(encoded))
        assertEquals(2, decoded.size)
        assertEquals("com.app.one", decoded[0].packageName)
        assertEquals(null, decoded[1].packageName)

        // old phase-2..4 payload: no packageName key at all
        val legacy = JSONArray(
            """[{"id":1,"fileName":"a","sizeBytes":5,"sha256":"abc","scannedAt":7,"cacheStored":true}]""",
        )
        val fromLegacy = ScanRecordCodec.decode(legacy)
        assertEquals(1, fromLegacy.size)
        assertNull(fromLegacy[0].packageName)
        assertTrue(fromLegacy[0].cacheStored)
    }
}
