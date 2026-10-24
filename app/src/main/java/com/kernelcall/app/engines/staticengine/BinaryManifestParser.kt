package com.kernelcall.app.engines.staticengine

/**
 * Pure-Kotlin parser for Android's binary XML (AXML) used inside APKs.
 * No Android framework dependency, so it is unit-testable on the JVM.
 *
 * Extracts the manifest evidence this engine needs: package identity, SDK
 * levels, permissions, application flags, and components.
 */
data class ManifestData(
    val packageName: String?,
    val versionName: String?,
    val versionCode: Int?,
    val minSdkVersion: Int?,
    val targetSdkVersion: Int?,
    val permissions: List<String>,
    val applicationDebuggable: Boolean?,
    val allowBackup: Boolean?,
    val cleartextTrafficPermitted: Boolean?,
    val applicationClass: String?,
    val components: List<ManifestComponent>,
)

data class ManifestComponent(
    val type: String,          // activity | activity-alias | service | receiver | provider
    val name: String,          // resolved FQCN
    val exported: Boolean?,    // null = attribute absent -> handled as "unknown"
    val permission: String?,
    val intentActions: List<String>,
)

class ManifestParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

private class MutableComponent(
    val type: String,
    val name: String,
    val exported: Boolean?,
    val permission: String?,
) {
    val intentActions = mutableListOf<String>()
}

object BinaryManifestParser {

    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_START_ELEMENT = 0x0102
    private const val RES_END_ELEMENT = 0x0103

    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_BOOL = 0x12

    private val COMPONENT_TYPES = setOf(
        "activity", "activity-alias", "service", "receiver", "provider"
    )

    fun parse(bytes: ByteArray): ManifestData {
        val strings = readStringPool(bytes)
            ?: throw ManifestParseException("No XML string pool found (not a binary XML?).")

        var packageName: String? = null
        var versionName: String? = null
        var versionCode: Int? = null
        var minSdk: Int? = null
        var targetSdk: Int? = null
        var debuggable: Boolean? = null
        var allowBackup: Boolean? = null
        var cleartext: Boolean? = null
        var applicationClass: String? = null
        val permissions = mutableListOf<String>()
        val builderComponents = mutableListOf<MutableComponent>()
        var currentComponent: MutableComponent? = null

        val stack = ArrayDeque<String>()

        var offset = 8 // skip the file-level XML header chunk
        while (offset + 8 <= bytes.size) {
            val type = u16(bytes, offset)
            val chunkSize = u32(bytes, offset + 4).toInt()
            if (chunkSize <= 0) break

            when (type) {
                RES_START_ELEMENT -> {
                    val name = strings.getOrNull(u32(bytes, offset + 20).toInt())
                    if (name == null) {
                        // unreadable element name: stop, do not guess
                        break
                    }
                    val attributeCount = u16(bytes, offset + 28)
                    val attrs = readAttributes(bytes, offset, attributeCount, strings)
                    val parent = stack.lastOrNull()

                    when {
                        parent == null && name == "manifest" -> {
                            packageName = attr(attrs, "package").raw
                            versionCode = attr(attrs, "versionCode").int
                            versionName = attr(attrs, "versionName").raw
                        }
                        name == "uses-sdk" && parent == "manifest" -> {
                            minSdk = attr(attrs, "minSdkVersion").int
                            targetSdk = attr(attrs, "targetSdkVersion").int
                        }
                        (name.startsWith("uses-permission")) && parent == "manifest" -> {
                            attr(attrs, "name").raw?.let { permissions.add(it) }
                        }
                        name == "application" && parent == "manifest" -> {
                            debuggable = attr(attrs, "debuggable").bool
                            allowBackup = attr(attrs, "allowBackup").bool
                            cleartext = attr(attrs, "usesCleartextTraffic").bool
                            applicationClass = attr(attrs, "name").raw
                        }
                        name in COMPONENT_TYPES && parent == "application" -> {
                            var compName = attr(attrs, "name").raw ?: "(unnamed)"
                            val exported = attr(attrs, "exported").bool
                            val permission = attr(attrs, "permission").raw
                            val comp = MutableComponent(
                                type = name,
                                name = compName,
                                exported = exported,
                                permission = permission,
                            )
                            builderComponents.add(comp)
                            currentComponent = comp
                        }
                        name == "action" && parent == "intent-filter" -> {
                            currentComponent?.intentActions
                                ?.add(attr(attrs, "name").raw ?: "")
                        }
                    }

                    stack.addLast(name)
                }
                RES_END_ELEMENT -> {
                    val name = stack.removeLastOrNull()
                    if (name in COMPONENT_TYPES) currentComponent = null
                }
                else -> Unit // namespaces, resource map, comments: skipped
            }

            offset += chunkSize
        }

        val pkg = packageName
        return ManifestData(
            packageName = pkg,
            versionName = versionName,
            versionCode = versionCode,
            minSdkVersion = minSdk,
            targetSdkVersion = targetSdk,
            permissions = permissions,
            applicationDebuggable = debuggable,
            allowBackup = allowBackup,
            cleartextTrafficPermitted = cleartext,
            applicationClass = applicationClass?.resolveClassName(pkg),
            components = builderComponents.map { comp ->
                ManifestComponent(
                    type = comp.type,
                    name = comp.name.resolveClassName(pkg),
                    exported = comp.exported,
                    permission = comp.permission,
                    intentActions = comp.intentActions.filter { it.isNotBlank() },
                )
            },
        )
    }

    // ---------- attribute resolution ----------

    private fun attr(attrs: List<AttributeRecord>, name: String): ManifestValue =
        attrs.firstOrNull { it.name == name }?.value ?: ManifestValue.void

    private fun readAttributes(
        bytes: ByteArray,
        elementOffset: Int,
        attributeCount: Int,
        strings: List<String>,
    ): List<AttributeRecord> {
        val attributeStart = u16(bytes, elementOffset + 24) + elementOffset + 16
        val attributeSize = u16(bytes, elementOffset + 26).takeIf { it >= 20 } ?: 20
        val result = mutableListOf<AttributeRecord>()
        for (index in 0 until attributeCount) {
            val base = attributeStart + index * attributeSize
            if (base + 20 > bytes.size) break
            val nameIdx = u32(bytes, base + 4).toInt()
            val rawIdx = u32(bytes, base + 8).toInt()
            val dataType = bytes[base + 15].toInt() and 0xFF
            val data = u32(bytes, base + 16).toInt()
            val raw = if (rawIdx.toInt() == -1) null else strings.getOrNull(rawIdx)
            val value = ManifestValue.resolve(raw, dataType, data)
            result.add(AttributeRecord(name = strings.getOrNull(nameIdx) ?: "?", value = value))
        }
        return result
    }

    private class AttributeRecord(val name: String, val value: ManifestValue)

    private data class ManifestValue(val raw: String?, val int: Int?, val bool: Boolean?) {
        companion object {
            val void = ManifestValue(raw = null, int = null, bool = null)

            fun resolve(raw: String?, dataType: Int, data: Int): ManifestValue = when (dataType) {
                TYPE_STRING -> ManifestValue(raw = raw, int = null, bool = null)
                TYPE_INT_BOOL -> ManifestValue(raw = raw, int = data, bool = data != 0)
                else -> ManifestValue(raw = raw ?: describeNumber(dataType, data), int = data, bool = null)
            }

            private fun describeNumber(dataType: Int, data: Int): String? = when (dataType) {
                0x01 -> "@res/0x%08x".format(data)
                0x02 -> "?attr/0x%08x".format(data)
                0x04 -> "@float/%d".format(data)
                0x05 -> "@dim/%d".format(data)
                else -> data.toString()
            }
        }
    }

    private fun String.resolveClassName(pkg: String?): String {
        if (startsWith('.')) return (pkg ?: "") + this
        if (!contains('.') && pkg != null) return "$pkg.$this"
        return this
    }

    // ---------- string pool ----------

    private fun readStringPool(bytes: ByteArray): List<String>? {
        var offset = 8
        while (offset + 8 <= bytes.size) {
            val type = u16(bytes, offset)
            val chunkSize = u32(bytes, offset + 4).toInt()
            if (chunkSize <= 0 || offset + chunkSize > bytes.size) return null
            if (type == RES_STRING_POOL_TYPE) {
                return decodeStringPool(bytes, offset)
            }
            offset += chunkSize
        }
        return null
    }

    private fun decodeStringPool(bytes: ByteArray, chunkOffset: Int): List<String> {
        val stringCount = u32(bytes, chunkOffset + 8).toInt()
        val flags = u32(bytes, chunkOffset + 16).toInt()
        val stringsStart = u32(bytes, chunkOffset + 20).toInt()
        val isUtf8 = (flags and 0x100) != 0
        val dataBase = chunkOffset + stringsStart
        val results = ArrayList<String>(stringCount)

        for (index in 0 until stringCount) {
            val offIndex = chunkOffset + 28 + index * 4
            if (offIndex + 4 > bytes.size) break
            val relative = u32(bytes, offIndex).toInt()
            var pos = dataBase + relative
            try {
                val decoded = if (isUtf8) {
                    // field 1: char count (1-2 bytes), field 2: byte length (1-2 bytes)
                    val lenA = if ((bytes[pos].toInt() and 0x80) == 0) 1 else 2
                    val charLen = decodeUtf8Length(bytes, pos)
                    val lenB = if ((bytes[pos + lenA].toInt() and 0x80) == 0) 1 else 2
                    val byteLen = decodeUtf8Length(bytes, pos + lenA)
                    String(
                        copyRange(bytes, pos + lenA + lenB, byteLen),
                        Charsets.UTF_8
                    )
                } else {
                    val charLen = decodeUtf16Length(bytes, pos)
                    val lenBytes = if (charLen >= 0x8000) 4 else 2
                    var p = pos + lenBytes
                    val sb = StringBuilder(charLen)
                    repeat(charLen) {
                        sb.append(charAt(bytes, p))
                        p += 2
                    }
                    sb.toString()
                }
                results.add(decoded)
            } catch (_: Exception) {
                break
            }
        }
        return results
    }

    private fun decodeUtf8Length(bytes: ByteArray, pos: Int): Int {
        val first = bytes[pos].toInt() and 0xFF
        return if (first and 0x80 == 0) first else ((first and 0x7F) shl 8) or (bytes[pos + 1].toInt() and 0xFF)
    }

    private fun decodeUtf16Length(bytes: ByteArray, pos: Int): Int {
        val first = u16(bytes, pos)
        return if (first and 0x8000 == 0) first else ((first and 0x7FFF) shl 16) or u16(bytes, pos + 2)
    }

    private fun copyRange(bytes: ByteArray, start: Int, length: Int): ByteArray {
        val startSafe = start.coerceIn(0, bytes.size)
        val endSafe = (start + length).coerceIn(startSafe, bytes.size)
        return bytes.copyOfRange(startSafe, endSafe)
    }

    private fun charAt(bytes: ByteArray, pos: Int): Char =
        u16(bytes, pos).toChar()

    private fun u16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

    private fun u32(bytes: ByteArray, offset: Int): Long =
        (u16(bytes, offset).toLong()) or (u16(bytes, offset + 2).toLong() shl 16)
}
