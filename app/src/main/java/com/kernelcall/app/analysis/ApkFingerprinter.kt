package com.kernelcall.app.analysis

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/**
 * Static fingerprint data read from an APK the user picked or an installed
 * app's accessible APK path (Phase 5).
 *
 * This is **not** an analysis verdict. It only describes the file itself.
 */
data class ApkFileMeta(
    val fileName: String,
    val sizeBytes: Long,
    val sha256: String,
)

class ApkReadException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Reads an APK — through the Storage Access Framework (user-picked file) or
 * from an installed app's accessible world-readable APK path — and computes a
 * SHA-256 fingerprint by streaming the bytes (no copy, no upload, the APK is
 * never installed or executed).
 */
object ApkFingerprinter {

    /**
     * [onProgress] receives the number of bytes processed so far, called on a
     * background thread.
     */
    suspend fun fingerprint(
        resolver: ContentResolver,
        uri: Uri,
        onProgress: (bytesProcessed: Long, totalBytes: Long?) -> Unit,
    ): ApkFileMeta = withContext(Dispatchers.IO) {
        val displayName = queryDisplayName(resolver, uri)
            ?: throw ApkReadException("Could not read the selected file's name.")

        val declaredSize = querySize(resolver, uri)

        val stream = try {
            resolver.openInputStream(uri)
        } catch (e: Exception) {
            throw ApkReadException("Android refused access to the selected file.", e)
        } ?: throw ApkReadException("Android could not open the selected file.")

        digestStream(displayName, declaredSize, stream, onProgress)
    }

    /**
     * Installed-app variant: fingerprints the accessible base APK at an
     * absolute file path (e.g. /data/app/.../base.apk). Runs on
     * Dispatchers.IO; the APK is only read as bytes.
     */
    suspend fun fingerprint(
        file: File,
        onProgress: (bytesProcessed: Long, totalBytes: Long?) -> Unit,
    ): ApkFileMeta = withContext(Dispatchers.IO) {
        val stream = try {
            file.inputStream()
        } catch (e: Exception) {
            throw ApkReadException("Android refused access to this app's APK file.", e)
        }
        digestStream(file.name, file.length(), stream, onProgress)
    }

    /** Shared streaming digest core for both entry points. */
    private fun digestStream(
        fileName: String,
        declaredSize: Long?,
        stream: InputStream,
        onProgress: (bytesProcessed: Long, totalBytes: Long?) -> Unit,
    ): ApkFileMeta {
        val digest = MessageDigest.getInstance("SHA-256")
        var bytesProcessed = 0L
        val buffer = ByteArray(512 * 1024)

        stream.use { input ->
            while (true) {
                val read = try {
                    input.read(buffer)
                } catch (e: Exception) {
                    throw ApkReadException("The APK file could not be read.", e)
                }
                if (read == -1) break
                if (read > 0) {
                    digest.update(buffer, 0, read)
                    bytesProcessed += read
                    onProgress(bytesProcessed, declaredSize)
                }
            }
        }

        return ApkFileMeta(
            fileName = fileName,
            sizeBytes = if (declaredSize != null && declaredSize >= 0) declaredSize else bytesProcessed,
            sha256 = digest.digest().joinToString("") { "%02x".format(it) },
        )
    }

    private fun queryDisplayName(resolver: ContentResolver, uri: Uri): String? =
        queryColumn(resolver, uri, OpenableColumns.DISPLAY_NAME)

    /** Returns null when the provider does not declare a size up front. */
    private fun querySize(resolver: ContentResolver, uri: Uri): Long? =
        queryColumn(resolver, uri, OpenableColumns.SIZE)?.toLongOrNull()?.takeIf { it >= 0 }

    private fun queryColumn(resolver: ContentResolver, uri: Uri, column: String): String? =
        try {
            resolver.query(uri, arrayOf(column), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(column)
                    if (index >= 0) cursor.getString(index) else null
                } else {
                    null
                }
            }
        } catch (_: Exception) {
            null
        }
}
