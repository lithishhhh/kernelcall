package com.kernelcall.app.engines.staticengine

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * Inventory of a real APK file derived from its zip structure plus the v1
 * (JAR) signing certificates if present. All values are raw observations.
 */
data class ApkArchiveSummary(
    val entryCount: Int,
    val dexFiles: List<String>,
    val nativeAbis: List<String>,
    val nativeSharedObjects: List<String>,
    val storedNativeLibs: Int,           // .so entries stored UNCOMPRESSED (installer-friendly)
    val v1SignatureFiles: List<String>,  // META-INF/*.RSA|DSA|EC
    val extraDexLikeAssets: List<String>, // dex/jar payloads inside resources/assets
    val largestEntries: List<EntryStat>,
    val totalUncompressedBytes: Long,
)

data class EntryStat(val name: String, val sizeBytes: Long)

object ApkArchive {

    fun inspect(apk: File): ApkArchiveSummary {
        if (!apk.exists()) throw ApkArchiveException("APK file is no longer cached.")
        try {
            ZipFile(apk).use { zip ->
                val dexFiles = mutableListOf<String>()
                val abis = linkedSetOf<String>()
                val soNames = mutableListOf<String>()
                var storedNativeLibs = 0
                val v1SigFiles = mutableListOf<String>()
                val assetDexLike = mutableListOf<String>()
                val largest = mutableListOf<EntryStat>()
                var totalUncompressed = 0L

                val entries = zip.entries().asSequence().toList()
                entries.forEach { entry: ZipEntry ->
                    val name = entry.name
                    totalUncompressed += entry.size.takeIf { it >= 0 } ?: 0

                    when {
                        name.endsWith(".dex") && !name.contains('/') -> dexFiles.add(name)
                        (!name.startsWith("META-INF/") && !name.startsWith("res/") &&
                            !name.startsWith("r/") && name.endsWith(".dex")) ->
                            assetDexLike.add(name)
                        name.startsWith("assets/") && (name.endsWith(".jar") || name.endsWith(".dex")) ->
                            assetDexLike.add(name)
                        name.startsWith("lib/") && name.endsWith(".so") -> {
                            val abi = name.removePrefix("lib/").substringBefore('/')
                            if (abi.isNotEmpty()) abis.add(abi)
                            soNames.add(name)
                            if (entry.method == ZipEntry.STORED) storedNativeLibs++
                        }
                    }
                    if (name.startsWith("META-INF/")) {
                        val upper = name.uppercase()
                        if (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC")) {
                            v1SigFiles.add(name)
                        }
                    }
                }

                largest.addAll(
                    entries
                        .filter { it.size >= 0 }
                        .sortedByDescending { it.size }
                        .take(5)
                        .map { EntryStat(it.name, it.size) }
                )

                return ApkArchiveSummary(
                    entryCount = entries.size,
                    dexFiles = dexFiles,
                    nativeAbis = abis.toList(),
                    nativeSharedObjects = soNames,
                    storedNativeLibs = storedNativeLibs,
                    v1SignatureFiles = v1SigFiles,
                    extraDexLikeAssets = assetDexLike,
                    largestEntries = largest,
                    totalUncompressedBytes = totalUncompressed,
                )
            }
        } catch (e: Exception) {
            throw ApkArchiveException("The cached APK could not be read as a zip archive.", e)
        }
    }
}

class ApkArchiveException(message: String, cause: Throwable? = null) : Exception(message, cause)
