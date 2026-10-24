package com.kernelcall.app

import com.kernelcall.app.engines.staticengine.BinaryManifestParser
import com.kernelcall.app.engines.staticengine.ManifestParseException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Parses a REAL AndroidManifest.xml (binary AXML) pulled from an installed
 * debug build of this very app on a live device. Failure here means real
 * shipping manifests parse incorrectly, not just synthetic ones.
 */
class BinaryManifestParserTest {

    private fun fixtureBytes(): ByteArray =
        javaClass.classLoader!!.getResourceAsStream("fixtures/manifest_binary_axml.bin")
            ?.readBytes()
            ?: error("fixture missing — put manifest_binary_axml.bin in test resources")

    @Test
    fun parsesRealManifestIdentity() {
        val data = BinaryManifestParser.parse(fixtureBytes())

        assertEquals("com.kernelcall.app", data.packageName)
        assertNotNull(data.versionCode)
        assertTrue(data.versionCode!! >= 1)
    }

    @Test
    fun parsesRealManifestSdkLevels() {
        val data = BinaryManifestParser.parse(fixtureBytes())
        assertEquals(26, data.minSdkVersion)
        assertEquals(35, data.targetSdkVersion)
    }

    @Test
    fun findsMainActivityAndExportedTrue() {
        val data = BinaryManifestParser.parse(fixtureBytes())
        val main = data.components.firstOrNull { it.name.endsWith(".MainActivity") }

        assertNotNull("MainActivity should be present", main)
        assertEquals("activity", main!!.type)
        assertEquals(true, main.exported)
        assertNull(main.permission)
    }

    @Test
    fun parsesDeclaredPermissionsFromMergedManifest() {
        val data = BinaryManifestParser.parse(fixtureBytes())
        // The debug merged manifest carries the androidx.core dynamic-receiver
        // signature permission; assert it is captured unchanged.
        assertTrue(
            data.permissions.contains(
                "com.kernelcall.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
            ),
        )
    }

    @Test
    fun fastRejectsNonBinaryXml() {
        val bogus = "not a binary xml".toByteArray(Charsets.UTF_8)
        try {
            BinaryManifestParser.parse(bogus)
            throw AssertionError("expected ManifestParseException")
        } catch (e: ManifestParseException) {
            // expected
        }
    }
}
