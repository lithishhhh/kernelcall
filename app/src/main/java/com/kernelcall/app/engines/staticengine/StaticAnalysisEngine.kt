package com.kernelcall.app.engines.staticengine

import com.kernelcall.app.core.engine.AnalysisEngine
import com.kernelcall.app.core.engine.EngineContext
import com.kernelcall.app.core.engine.EngineResult
import com.kernelcall.app.core.model.Evidence
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.core.model.UnknownNote
import java.io.File

/**
 * The first real Kernel Call engine: reads manifest, archive, v1 certificates
 * and dex strings from the cached APK and reports:
 *  - CONFIRMED_OBSERVATION for everything directly read,
 *  - HEURISTIC_INDICATOR for patterns that justify human review,
 *  - UNKNOWN notes for honest capability gaps.
 * It never executes the APK and never claims a malware verdict.
 */
class StaticAnalysisEngine : AnalysisEngine {

    override val id = "static.v2"
    override val title = "Static APK Analysis"

    override suspend fun analyse(context: EngineContext): EngineResult {
        val started = System.nanoTime()
        val findings = mutableListOf<Finding>()
        val unknowns = mutableListOf<UnknownNote>()
        val detectedAt = System.currentTimeMillis()

        fun finding(
            title: String,
            summary: String,
            kind: FindingKind,
            severity: Severity,
            evidence: List<Evidence>,
            recommendation: String? = null,
            ruleId: String,
            category: String = com.kernelcall.app.core.model.Categories.MANIFEST,
            confidence: com.kernelcall.app.core.model.Confidence =
                com.kernelcall.app.core.model.Confidence.HIGH,
        ) {
            val slug = title.lowercase().replace(
                Regex("[^a-z0-9]+"), "-"
            ).trim('-')
            findings.add(
                Finding(
                    id = "$id:$ruleId:$slug:${evidence.size}",
                    engineId = id,
                    title = title,
                    summary = summary,
                    kind = kind,
                    severity = severity,
                    evidence = evidence,
                    recommendation = recommendation,
                    detectedAt = detectedAt,
                    category = category,
                    ruleId = ruleId,
                    confidence = confidence,
                )
            )
        }

        try {
            if (!context.hasApkFile) {
                unknowns.add(
                    UnknownNote(
                        engineId = id,
                        message = "APK bytes were not cached (too large or unreadable); " +
                            "only the fingerprint-level metadata above is available.",
                    )
                )
                return EngineResult(findings, unknowns, elapsedSince(started))
            }

            context.onProgress(5, "Reading APK archive")
            val apk: File = context.apkFile!!
            val archive = ApkArchive.inspect(apk)

            context.onProgress(25, "Parsing Android manifest")
            val manifest = readManifest(apk)
            if (manifest == null) {
                unknowns.add(
                    UnknownNote(
                        engineId = id,
                        message = "AndroidManifest.xml could not be parsed; package, " +
                            "permission and component evidence is unavailable.",
                    )
                )
            }

            context.onProgress(45, "Reading signing certificate")
            val cert = JarCertificates.read(apk)
            if (!archive.v1SignatureFiles.isEmpty() && cert == null) {
                unknowns.add(
                    UnknownNote(
                        engineId = id,
                        message = "A v1 signature block exists but its certificate " +
                            "could not be read.",
                    )
                )
            }

            context.onProgress(60, "Scanning dex strings")
            val dexObservation = try {
                DexStrings.scan(apk, archive.dexFiles)
            } catch (e: Exception) {
                null
            }
            if (archive.dexFiles.isEmpty()) {
                unknowns.add(
                    UnknownNote(
                        engineId = id,
                        message = "No root-level classes.dex entries found; the code " +
                            "may be packed or hidden.",
                    )
                )
            } else if (dexObservation == null) {
                unknowns.add(
                    UnknownNote(
                        engineId = id,
                        message = "Dex content could not be scanned for URL strings.",
                    )
                )
            }

            context.onProgress(80, "Correlating evidence")

            // ---------- findings ----------

            if (manifest != null) {
                manifest.permissions.forEach { permission ->
                    val note = PermissionRisk.noteFor(permission)
                    finding(
                        title = "Permission declared: ${permission.removePrefix("android.permission.")}",
                        summary = note
                            ?: "The app declares this permission in its manifest.",
                        kind = FindingKind.CONFIRMED_OBSERVATION,
                        severity = Severity.INFO,
                        evidence = listOf(
                            Evidence("manifest", "uses-permission", permission, "AndroidManifest.xml")
                        ),
                        ruleId = "static.manifest.permission",
                    )
                }

                val exported = manifest.components.filter { it.exported == true }
                if (exported.isNotEmpty()) {
                    finding(
                        title = "Exported components (${exported.size})",
                        summary = "These app entry points are reachable by other apps " +
                            "or the system; every one widens the external attack surface. " +
                            "Review their intent handling for data validation.",
                        kind = FindingKind.HEURISTIC_INDICATOR,
                        severity = Severity.LOW,
                        evidence = exported.take(10).map {
                            Evidence("manifest", "exported=true", "${it.type}:${it.name}")
                        },
                        recommendation = "Confirm each exported component is intended to " +
                            "be reachable externally.",
                        ruleId = "static.manifest.exported",
                        confidence = com.kernelcall.app.core.model.Confidence.MEDIUM,
                    )
                }
                val unspecified = manifest.components.filter { it.exported == null }
                if (unspecified.isNotEmpty()) {
                    finding(
                        title = "Export status not declared for ${unspecified.size} component(s)",
                        summary = "The manifest does not state android:exported, so the " +
                            "effective reachability depends on intent filters and the OS " +
                            "level. Not a defect by itself — flagged as openly indeterminate.",
                        kind = FindingKind.UNKNOWN,
                        severity = Severity.INFO,
                        evidence = unspecified.take(10).map {
                            Evidence("manifest", "no android:exported attribute", "${it.type}:${it.name}")
                        },
                        ruleId = "static.manifest.exported-unspecified",
                    )
                }

                if (manifest.applicationDebuggable == true) {
                    finding(
                        title = "Debuggable application",
                        summary = "android:debuggable=true. On a release binary this is " +
                            "a real security weakness (runtime inspection, memory access " +
                            "by any debugging process).",
                        kind = FindingKind.CONFIRMED_OBSERVATION,
                        severity = Severity.HIGH,
                        evidence = listOf(
                            Evidence("manifest", "android:debuggable", "true", "application")
                        ),
                        recommendation = "Verify this is a debug build; publish builds " +
                            "must not be debuggable.",
                        ruleId = "static.manifest.debuggable",
                    )
                }

                if (manifest.allowBackup == true) {
                    finding(
                        title = "Cloud/local backup enabled",
                        summary = "allowBackup=true. App-private data may leave the app " +
                            "through OS backup mechanisms.",
                        kind = FindingKind.CONFIRMED_OBSERVATION,
                        severity = Severity.LOW,
                        evidence = listOf(
                            Evidence("manifest", "android:allowBackup", "true", "application")
                        ),
                        ruleId = "static.manifest.allowbackup",
                    )
                }

                if (manifest.cleartextTrafficPermitted == true) {
                    finding(
                        title = "Cleartext HTTP traffic allowed",
                        summary = "usesCleartextTraffic=true. Network data can transit " +
                            "unencrypted.",
                        kind = FindingKind.CONFIRMED_OBSERVATION,
                        severity = Severity.MEDIUM,
                        evidence = listOf(
                            Evidence(
                                "manifest",
                                "android:usesCleartextTraffic",
                                "true",
                                "application"
                            )
                        ),
                        recommendation = "Restrict to HTTPS and add a network security config.",
                        ruleId = "static.manifest.cleartext",
                    )
                }

                val bootInitiators = manifest.components
                    .filter { it.intentActions.any { a -> a.contains("BOOT_COMPLETED") } }
                if (bootInitiators.isNotEmpty()) {
                    finding(
                        title = "Runs at device boot",
                        summary = "Components that receive BOOT_COMPLETED start after " +
                            "every reboot. Established behavior for many apps; verify " +
                            "the initialization is expected.",
                        kind = FindingKind.HEURISTIC_INDICATOR,
                        severity = Severity.LOW,
                        evidence = bootInitiators.take(5).map {
                            Evidence(
                                "manifest",
                                "intent-action",
                                "BOOT_COMPLETED -> ${it.type}:${it.name}"
                            )
                        },
                        ruleId = "static.intent.boot",
                    )
                }

                val smsTelephony =
                    manifest.components.filter { comp ->
                        comp.intentActions.any { action ->
                            action.contains("SMS") ||
                                action.contains("TEL") ||
                                action.contains("PHONE")
                        }
                    }
                if (smsTelephony.isNotEmpty()) {
                    finding(
                        title = "Telephony/SMS intent interception",
                        summary = "The app intercepts SMS or telephony intents. Common " +
                            "in messaging apps; also a pattern in subscription-fraud " +
                            "malware (OTP interception).",
                        kind = FindingKind.HEURISTIC_INDICATOR,
                        severity = Severity.MEDIUM,
                        evidence = smsTelephony.take(5).map {
                            Evidence(
                                "manifest",
                                "intent-action",
                                (it.intentActions.firstOrNull() ?: "") + " -> ${it.type}:${it.name}"
                            )
                        },
                        recommendation = "Verify the declared use case matches the app's " +
                            "actual behavior before any further judgement.",
                        ruleId = "static.intent.telephony",
                        confidence = com.kernelcall.app.core.model.Confidence.MEDIUM,
                    )
                }
            }

            // archive-level observations
            if (archive.nativeAbis.isNotEmpty()) {
                finding(
                    title = "Native code present (${archive.nativeAbis.joinToString(", ")})",
                    summary = "${archive.nativeSharedObjects.size} shared libraries are " +
                        "packaged. Static review can read into these only partially — " +
                        "behavior claims would require sandbox instrumentation.",
                    kind = FindingKind.CONFIRMED_OBSERVATION,
                    severity = Severity.INFO,
                    evidence = archive.nativeSharedObjects.take(8).map {
                        Evidence("zip", "payload", it, "APK entries")
                    },
                    ruleId = "static.archive.native",
                    category = com.kernelcall.app.core.model.Categories.ARCHIVE,
                )
            }

            val secondaryDex = archive.extraDexLikeAssets
            if (secondaryDex.isNotEmpty()) {
                finding(
                    title = "Executable payload outside root dex entries",
                    summary = "dex/jar-like files exist inside assets/resources. Some " +
                        "apps legitimately modernize plugins this way; loading class " +
                        "code at runtime from assets is also a classic malware loader " +
                        "pattern. Inspect before any verdict.",
                    kind = FindingKind.HEURISTIC_INDICATOR,
                    severity = Severity.MEDIUM,
                    evidence = secondaryDex.take(10).map {
                        Evidence("zip", "payload", it, "APK entries")
                    },
                    recommendation = "Sandbox review recommended for code-loading logic.",
                    ruleId = "static.archive.payload",
                    category = com.kernelcall.app.core.model.Categories.ARCHIVE,
                    confidence = com.kernelcall.app.core.model.Confidence.LOW,
                )
            }

            if (dexObservation != null && dexObservation.uniqueUrlCount > 0) {
                finding(
                    title = "Network endpoints embedded in dex: ${dexObservation.uniqueUrlCount} unique URL(s)",
                    summary = "URL-shaped literals exist in the dex content of this " +
                        "APK. That is an observation only; it neither confirms " +
                        "malicious intent nor tells whether these endpoints are " +
                        "actually contacted.",
                    kind = FindingKind.HEURISTIC_INDICATOR,
                    severity = Severity.INFO,
                    evidence = dexObservation.sampleUrls.map {
                        Evidence("dex", "url literal", it, "classes*.dex")
                    } + Evidence(
                        "dex-scan",
                        "hosts observed",
                        dexObservation.hosts.joinToString(", ").take(400)
                    ),
                    recommendation = "Network behavior checks belong in sandbox analysis.",
                    ruleId = "static.dex.urls",
                    category = com.kernelcall.app.core.model.Categories.CODE,
                    confidence = com.kernelcall.app.core.model.Confidence.MEDIUM,
                )
            }

            // certificate
            if (cert != null) {
                val expiryNote = when {
                    cert.expired == true -> "The certificate has EXPIRED — any binary it " +
                        "signed is no longer under an active signature claim."
                    cert.selfSigned == true -> "Self-signed certificate (typical for " +
                        "sideloaded apps); no third-party identity is attested."
                    else -> "Third-party signed; identity carried over by the cert chain."
                }
                finding(
                    title = "Signing certificate: ${cert.subjectCn ?: "(no CN)"}",
                    summary = expiryNote,
                    kind = FindingKind.CONFIRMED_OBSERVATION,
                    severity = if (cert.expired == true) Severity.MEDIUM else Severity.INFO,
                    evidence = listOf(
                        Evidence("cert", "subject CN", cert.subjectCn ?: "unknown"),
                        Evidence("cert", "issuer CN", cert.issuerCn ?: "unknown"),
                        Evidence(
                            "cert", "valid until",
                            cert.notAfter?.let { java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).format(it) }
                                ?: "unknown"
                        ),
                        Evidence("cert", "self-signed", cert.selfSigned.toString()),
                        Evidence("zip", "signature block", archive.v1SignatureFiles.first()),
                    ),
                    ruleId = "static.cert.identity",
                    category = com.kernelcall.app.core.model.Categories.CERTIFICATE,
                )
            } else if (archive.v1SignatureFiles.isEmpty()) {
                finding(
                    title = "No v1 (JAR) signature block present",
                    summary = "The APK contains no META-INF RSA/DSA/EC block. Modern " +
                        "signing schemes (v2/v3) sign outside the zip entries, so this " +
                        "is expected for store-signed apps; it limits what this static " +
                        "engine can read about the signer identity.",
                    kind = FindingKind.UNKNOWN,
                    severity = Severity.INFO,
                    evidence = listOf(
                        Evidence("zip", "META-INF signature files", "none found")
                    ),
                    ruleId = "static.cert.v1missing",
                    category = com.kernelcall.app.core.model.Categories.CERTIFICATE,
                )
            }

            // engine capability unknowns (always honest about what we can't see)
            unknowns.add(
                UnknownNote(
                    engineId = id,
                    message = "APK Signature Scheme v2/v3 blocks, obfuscation state, " +
                        "and native-library behavior are outside this engine's static " +
                        "reach in this version.",
                )
            )
        } catch (e: Exception) {
            unknowns.add(
                UnknownNote(
                    engineId = id,
                    message = "Static engine stopped early: ${e.message ?: "unexpected error"}",
                )
            )
        }

        return EngineResult(findings, unknowns, elapsedSince(started))
    }

    private fun readManifest(apk: File): ManifestData? = try {
        java.util.zip.ZipFile(apk).use { zip ->
            val entry = zip.getEntry("AndroidManifest.xml") ?: return null
            BinaryManifestParser.parse(zip.getInputStream(entry).readBytes())
        }
    } catch (e: ManifestParseException) {
        null
    } catch (e: Exception) {
        null
    }

    private fun elapsedSince(startedNanos: Long): Long =
        (System.nanoTime() - startedNanos) / 1_000_000
}
