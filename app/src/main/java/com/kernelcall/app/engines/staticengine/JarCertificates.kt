package com.kernelcall.app.engines.staticengine

import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.zip.ZipFile

/**
 * v1 (JAR) signing certificate info. v2/v3-only signed APKs contain no
 * META-INF certificates — that absence is reported so the engine can state
 * the gap as UNKNOWN instead of guessing.
 */
data class CertificateObservation(
    val subjectCn: String?,
    val issuerCn: String?,
    val notBefore: Long?,
    val notAfter: Long?,
    val expired: Boolean?,
    val selfSigned: Boolean?,
)

object JarCertificates {

    /**
     * Returns null when no v1 signature block exists (caller reports UNKNOWN).
     */
    fun read(apk: File): CertificateObservation? {
        return try {
            ZipFile(apk).use { zip ->
                val sigEntry = zip.entries().asSequence()
                    .filter {
                        it.name.startsWith("META-INF/") &&
                            (it.name.uppercase().endsWith(".RSA") ||
                                it.name.uppercase().endsWith(".DSA") ||
                                it.name.uppercase().endsWith(".EC"))
                    }
                    .firstOrNull() ?: return null

                val certs = zip.getInputStream(sigEntry).use { input ->
                    CertificateFactory.getInstance("X509")
                        .generateCertificates(input)
                        .filterIsInstance<X509Certificate>()
                }
                val primary = certs.firstOrNull() ?: return null

                val now = Date()
                val notAfter: Date? = primary.notAfter
                val expired = notAfter?.before(now)

                CertificateObservation(
                    subjectCn = extractCn(primary.subjectX500Principal?.name),
                    issuerCn = extractCn(primary.issuerX500Principal?.name),
                    notBefore = primary.notBefore?.time,
                    notAfter = notAfter?.time,
                    expired = expired,
                    selfSigned = primary.subjectX500Principal?.name ==
                        primary.issuerX500Principal?.name,
                )
            }
        } catch (_: Exception) {
            // unreadable certificate data: caller records an UNKNOWN
            null
        }
    }

    private fun extractCn(dn: String?): String? =
        dn?.split(',')?.map { it.trim() }
            ?.firstOrNull { it.startsWith("CN=", ignoreCase = true) }
            ?.removePrefix("CN=")?.removePrefix("cn=")
}
