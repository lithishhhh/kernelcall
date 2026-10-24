package com.kernelcall.app

import com.kernelcall.app.engines.staticengine.ApkArchive
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Zip-inventory evidence checks against a small archive built here. */
class ApkArchiveTest {

    private fun writeTestApk(): File {
        val file = File.createTempFile("kc-test", ".apk").apply { deleteOnExit() }
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("classes.dex")); zip.write("PRIMARY_CODE".toByteArray()); zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes2.dex")); zip.write("SECONDARY_CODE".toByteArray()); zip.closeEntry()

            // compressed .so
            zip.putNextEntry(ZipEntry("lib/arm64-v8a/libcode.so")); zip.write(ByteArray(4096)); zip.closeEntry()

            // stored (uncompressed) .so — requires precomputed size + crc
            val stored = ZipEntry("lib/x86/libstored.so").apply {
                method = ZipEntry.STORED
                size = 2048L
                crc = CRC32().apply { update(ByteArray(2048)) }.value
            }
            zip.putNextEntry(stored); zip.write(ByteArray(2048)); zip.closeEntry()

            zip.putNextEntry(ZipEntry("META-INF/CERT.RSA")); zip.write("SIG".toByteArray()); zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/model.tflite")); zip.write("AI".toByteArray()); zip.closeEntry()
            zip.putNextEntry(ZipEntry("assets/plugin.jar")); zip.write("EXE-LIKE".toByteArray()); zip.closeEntry()
        }
        return file
    }

    @Test
    fun inventoryCountsDexNativeAndSignatureEntries() {
        val apk = writeTestApk()
        val summary = ApkArchive.inspect(apk)

        assertEquals(listOf("classes.dex", "classes2.dex"), summary.dexFiles)
        assertEquals(listOf("arm64-v8a", "x86"), summary.nativeAbis)
        assertEquals(2, summary.nativeSharedObjects.size)
        assertEquals(1, summary.storedNativeLibs)
        assertEquals(listOf("META-INF/CERT.RSA"), summary.v1SignatureFiles)
        assertTrue(summary.extraDexLikeAssets.contains("assets/plugin.jar"))
        assertEquals(7, summary.entryCount)
    }
}
