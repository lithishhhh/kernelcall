package com.kernelcall.app

import com.kernelcall.app.core.installed.AppScanState
import com.kernelcall.app.core.installed.AppScanStatus
import com.kernelcall.app.core.installed.InstalledAppEntry
import com.kernelcall.app.core.installed.InstalledScanning
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure filtering/eligibility logic of the Phase 5 installed scanner. */
class InstalledScanningTest {

    private val own = "com.kernelcall.app"

    private fun entry(
        pkg: String,
        label: String = pkg,
        isSystem: Boolean = false,
        sourceDir: String? = "/data/app/$pkg/base.apk",
    ) = InstalledAppEntry(pkg, label, isSystem, sourceDir)

    @Test
    fun `own package is excluded from eligibility`() {
        val list = listOf(entry(own), entry("com.other.app"))
        val filtered = InstalledScanning.filterApps(list, own, includeSystem = true, query = "")
        assertEquals(listOf("com.other.app"), filtered.map { it.packageName })
    }

    @Test
    fun `apps without accessible sourceDir are not eligible`() {
        val entry = entry("com.hidden.app", sourceDir = null)
        assertFalse(InstalledScanning.isEligible(entry, own))
    }

    @Test
    fun `system apps follow the includeSystem flag`() {
        val system = entry("com.system.app", isSystem = true)
        val user = entry("com.user.app", isSystem = false)
        val withSystem = InstalledScanning.filterApps(listOf(system, user), own, true, "")
        val userOnly = InstalledScanning.filterApps(listOf(system, user), own, false, "")
        assertEquals(2, withSystem.size)
        assertEquals(listOf("com.user.app"), userOnly.map { it.packageName })
    }

    @Test
    fun `search matches label and package case-insensitively`() {
        val signal = entry("com.signal.app", label = "Signal")
        val other = entry("com.mail.app", label = "Mail")
        val both = InstalledScanning.filterApps(listOf(signal, other), own, true, "SIG")
        assertTrue(both.map { it.packageName }.contains("com.signal.app"))
        val byPackage = InstalledScanning.filterApps(listOf(signal, other), own, true, "mail.app")
        assertEquals(listOf("com.mail.app"), byPackage.map { it.packageName })
    }

    @Test
    fun `blank query matches everything`() {
        val apps = listOf(entry("a.app"), entry("b.app"))
        assertTrue(InstalledScanning.filterApps(apps, own, true, "  ").size == 2)
    }

    @Test
    fun `status objects only carry what state implies`() {
        val notScanned = AppScanStatus(state = AppScanState.NOT_SCANNED)
        assertEquals(null, notScanned.score)
        val analysed = AppScanStatus(state = AppScanState.ANALYZED, score = 22, band = "MODERATE")
        assertEquals(22, analysed.score)
        assertEquals("MODERATE", analysed.band)
    }
}
