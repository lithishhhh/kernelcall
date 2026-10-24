package com.kernelcall.app.engines.staticengine

import java.io.File
import java.util.zip.ZipFile

/**
 * Reads raw strings out of classes*.dex without executing or decompiling.
 * Finds URL-shaped literals and compares them against public-suffix rules.
 * The output is evidence ("these literals exist in the dex"), not a verdict.
 */
data class DexStringObservation(
    val uniqueUrlCount: Int,
    val sampleUrls: List<String>,   // max 20
    val hosts: List<String>,        // unique, sorted, max 20
    val scannedDexFiles: Int,
    val scannedBytes: Long,
)

object DexStrings {

    private val URL_IN_BYTES = Regex("(https?://)[^\\x00-\\x20\"'\\\\<>]{4,300}", RegexOption.IGNORE_CASE)

    fun scan(apk: File, dexNames: List<String>): DexStringObservation {
        val urls = linkedSetOf<String>()
        var bytesScanned = 0L
        var filesScanned = 0

        ZipFile(apk).use { zip ->
            dexNames.forEach { name ->
                val entry = zip.getEntry(name) ?: return@forEach
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                filesScanned++
                bytesScanned += bytes.size

                URL_IN_BYTES.findAll(String(bytes, Charsets.ISO_8859_1)).forEach {
                    match -> urls.add(match.value.lowercase())
                }
            }
        }

        val hosts = urls.mapNotNull { url ->
            try { java.net.URI(url).host?.lowercase() } catch (_: Exception) { null }
        }.toSortedSet().take(20)

        return DexStringObservation(
            uniqueUrlCount = urls.size,
            sampleUrls = urls.take(20).toList(),
            hosts = hosts,
            scannedDexFiles = filesScanned,
            scannedBytes = bytesScanned,
        )
    }
}
