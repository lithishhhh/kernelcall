package com.kernelcall.app

import com.kernelcall.app.core.engine.AnalysisCoordinator
import com.kernelcall.app.core.engine.EngineContext
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.engines.staticengine.StaticAnalysisEngine
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Runs the real static engine on a real pulled manifest plus a synthetic dex;
 * every assertion maps to an honestly classified finding or unknown.
 */
class StaticAnalysisEngineTest {

    private fun writeTestApk(): File {
        val manifest = javaClass.classLoader!!
            .getResourceAsStream("fixtures/manifest_binary_axml.bin")!!.readBytes()

        // Synthetic dex-shaped payload embedding URL literals exactly like a
        // real MUTF-8 dex string table would contain them.
        val dexPayload = buildList {
            add("dex\n035".repeat(30))
            add("https://telemetry.example.com/beacon/v1")
            add("https://tracker.example.com/collect?id=")
            add("https://cdn.example.com/models.bin")
            add(ByteArray(600) { it.toByte() })
        }.flatMap { if (it is ByteArray) it.toList() else (it as String).toByteArray(Charsets.ISO_8859_1).toList() }
            .toByteArray()

        val file = File.createTempFile("kc-engine", ".apk").apply { deleteOnExit() }
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml")); zip.write(manifest); zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes.dex")); zip.write(dexPayload); zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/loader.jar")); zip.write("PAYLOAD".toByteArray()); zip.closeEntry()
        }
        return file
    }

    @Test
    fun reportsExportedComponentAndDebuggableFlagsWithHonestKinds() = runBlocking {
        val apk = writeTestApk()
        var lastPercent = -1
        val result = StaticAnalysisEngine().analyse(
            EngineContext(apk, sha256 = "aaaabbbb", fileName = "test.apk", sizeBytes = apk.length(),
                onProgress = { p, _ -> lastPercent = p })
        )

        val titles = result.findings.map { it.title }
        assertTrue(titles.any { it.startsWith("Exported components") })
        assertTrue(titles.any { it.startsWith("Debuggable application") })

        val exported = result.findings.first { it.title.startsWith("Exported components") }
        assertEquals(FindingKind.HEURISTIC_INDICATOR, exported.kind)
        assertEquals(Severity.LOW, exported.severity)
        assertTrue(exported.evidence.any { it.value.contains("MainActivity") })

        val debuggable = result.findings.first { it.title == "Debuggable application" }
        assertEquals(FindingKind.CONFIRMED_OBSERVATION, debuggable.kind)
        assertEquals(Severity.HIGH, debuggable.severity)
    }

    @Test
    fun reportsDexUrlsAsHeuristicIndicatorOnly() = runBlocking {
        val apk = writeTestApk()
        val result = StaticAnalysisEngine().analyse(
            EngineContext(apk, "aaaabbbb", "test.apk", apk.length()) { _, _ -> }
        )

        val urlFinding = result.findings.firstOrNull { it.title.startsWith("Network endpoints") }
        assertTrue("url finding missing", urlFinding != null)
        assertEquals(FindingKind.HEURISTIC_INDICATOR, urlFinding!!.kind)
        assertTrue(urlFinding.evidence.any { it.value.contains("telemetry.example.com") })
    }

    @Test
    fun statesV1SignatureGapAsUnknown() = runBlocking {
        val apk = writeTestApk()
        val result = StaticAnalysisEngine().analyse(
            EngineContext(apk, "aaaabbbb", "test.apk", apk.length()) { _, _ -> }
        )

        assertTrue(result.unknowns.any { it.message.contains("Signature Scheme") })
        val noV1 = result.findings.filter { it.kind == FindingKind.UNKNOWN }
            .any { it.title.contains("v1") }
        assertTrue("no v1 unknown finding recorded", noV1)
    }

    @Test
    fun coordinatorAssemblesReportWithProgressAndStats() = runBlocking {
        val apk = writeTestApk()
        val report = AnalysisCoordinator().run(
            sha256 = "aaaabbbb",
            fileName = "test.apk",
            sizeBytes = apk.length(),
            engines = listOf(StaticAnalysisEngine()),
            apkFile = apk,
            onProgress = { _, _ -> },
        )

        assertEquals("aaaabbbb", report.sha256)
        assertEquals(1, report.engines.size)
        assertEquals("static.v2", report.engines[0].engineId)
        assertTrue(report.engines[0].durationMs >= 0)
        assertTrue(report.findings.isNotEmpty())
    }
}
