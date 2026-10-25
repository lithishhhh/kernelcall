package com.kernelcall.app.core.storage

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import java.io.File
import java.io.InputStream

/**
 * Stores the picked APK's bytes under filesDir/apkcache/<sha256>.apk so later
 * analysis runs can happen without re-picking the file. Content-addressed;
 * a global byte budget evicts the oldest copies first.
 *
 * Cached files are data for static parsers only — they are never installed
 * or executed.
 */
class ApkCacheStore(context: Context) {

    private val cacheDir = File(context.filesDir, "apkcache").apply {
        if (!exists()) mkdirs()
    }

    /**
     * Copies the referenced file into the cache. Returns null when the file
     * could not be cached (too large, unreadable, or > [MAX_TOTAL_BUDGET]).
     */
    fun import(resolver: ContentResolver, uri: Uri, sha256: String, declaredSize: Long): File? {
        if (declaredSize > MAX_FILE_SIZE) return null
        val target = fileFor(sha256)
        if (target.exists() && target.length() == declaredSize) return target

        return try {
            val stream = resolver.openInputStream(uri) ?: return null
            copyStreamInto(target, stream, declaredSize)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Phase 5: imports an installed app's accessible base APK bytes from a
     * local file path into the cache (never installed or executed).
     */
    fun import(source: File, sha256: String, declaredSize: Long): File? {
        if (declaredSize > MAX_FILE_SIZE) return null
        if (declaredSize < 0) return null // unknown size: not cacheable
        val target = fileFor(sha256)
        if (target.exists() && target.length() == declaredSize) return target

        return try {
            val stream = try {
                source.inputStream()
            } catch (_: Exception) {
                return null
            }
            copyStreamInto(target, stream, declaredSize)
        } catch (_: Exception) {
            null
        }
    }

    /** Shared copy/budget/evict core for both entry points. */
    private fun copyStreamInto(target: File, stream: InputStream, declaredSize: Long): File? {
        return try {
            val temp = File(target.absolutePath + ".part")
            var copied = 0L
            stream.use { input ->
                temp.outputStream().use { out ->
                    val buffer = ByteArray(512 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read == -1) break
                        if (read > 0) {
                            copied += read
                            if (declaredSize in 1 until copied || copied > MAX_FILE_SIZE) {
                                temp.delete()
                                return null // provider lied about size / oversized
                            }
                            out.write(buffer, 0, read)
                        }
                    }
                }
            }
            if (declaredSize < 0) {
                temp.delete(); return null // unknown size: not cacheable
            }
            if (copied == 0L) {
                temp.delete(); return null
            }
            if (!temp.renameTo(target)) {
                temp.delete(); return null
            }
            evictOld(keepExisting = target)
            target
        } catch (_: Exception) {
            null
        }
    }

    fun fileFor(sha256: String): File = File(cacheDir, "$sha256.apk")

    /** Simple size-budget eviction: oldest lastModified first, never the current file. */
    private fun evictOld(keepExisting: File) {
        var files = cacheDir.listFiles()?.filter { it.isFile } ?: return
        var total = files.sumOf { it.length() }
        while (total > MAX_TOTAL_BUDGET) {
            val oldest = files
                .filter { it != keepExisting }
                .minByOrNull { it.lastModified() } ?: break
            total -= oldest.length()
            oldest.delete()
            files = cacheDir.listFiles()?.filter { it.isFile } ?: break
        }
    }

    companion object {
        const val MAX_FILE_SIZE = 200L * 1024 * 1024      // 200 MB per APK
        const val MAX_TOTAL_BUDGET = 600L * 1024 * 1024   // 600 MB cache budget

        @Volatile private var instance: ApkCacheStore? = null

        fun get(context: Context): ApkCacheStore =
            instance ?: synchronized(this) {
                instance ?: ApkCacheStore(context.applicationContext).also { instance = it }
            }
    }
}
