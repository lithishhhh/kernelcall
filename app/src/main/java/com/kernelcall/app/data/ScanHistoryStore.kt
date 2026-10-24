package com.kernelcall.app.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Schema v2: records live in filesDir/records.json, versioned and
 * forward-migratable. First format (SharedPreferences JSON string) is
 * imported once, then removed — see [migrateLegacy].
 */
class ScanHistoryStore private constructor(context: Context) {

    private val file = File(context.filesDir, "records.json")
    private val legacyPrefs =
        context.getSharedPreferences("kernel_call_history", Context.MODE_PRIVATE)

    private val _records = MutableStateFlow<List<ScanRecord>>(load())
    val records: StateFlow<List<ScanRecord>> = _records.asStateFlow()

    fun add(record: ScanRecord) {
        val updated = listOf(record) + _records.value
        _records.value = updated
        save(updated)
    }

    fun update(record: ScanRecord) {
        val updated = _records.value.map { if (it.id == record.id) record else it }
        _records.value = updated
        save(updated)
    }

    fun findById(id: Long): ScanRecord? = _records.value.firstOrNull { it.id == id }

    private fun save(records: List<ScanRecord>) {
        try {
            val payload = JSONObject()
                .put(SCHEMA_KEY, SCHEMA_VERSION)
                .put(DATA_KEY, encode(records))
            val temp = File(file.absolutePath + ".part")
            temp.writeText(payload.toString(), Charsets.UTF_8)
            if (!temp.renameTo(file)) temp.delete()
        } catch (_: Exception) {
            // persistence failure never blocks the UI; list stays in memory
        }
    }

    private fun load(): List<ScanRecord> {
        val migrated = migrateLegacy()
        if (migrated != null) return migrated

        return try {
            if (!file.exists()) return emptyList()
            val root = JSONObject(file.readText(Charsets.UTF_8))
            when (root.optInt(SCHEMA_KEY)) {
                SCHEMA_VERSION -> decode(root.optJSONArray(DATA_KEY))
                else -> emptyList()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * v1 -> v2 one-time migration. Returns the records when a legacy store
     * existed (and writes them into the v2 file), or null when none existed.
     */
    private fun migrateLegacy(): List<ScanRecord>? {
        val legacyRaw = legacyPrefs.getString(LEGACY_KEY, null)
        return try {
            if (legacyRaw == null) return null
            // legacy payload was a bare JSONArray
            val records = decode(JSONArray(legacyRaw))
            save(records)
            legacyPrefs.edit().remove(LEGACY_KEY).apply()
            records
        } catch (_: Exception) {
            if (legacyPrefs.contains(LEGACY_KEY)) {
                emptyList()
            } else {
                null
            }
        }
    }

    private fun encode(records: List<ScanRecord>): JSONArray {
        val array = JSONArray()
        records.forEach { record ->
            array.put(
                JSONObject()
                    .put("id", record.id)
                    .put("fileName", record.fileName)
                    .put("sizeBytes", record.sizeBytes)
                    .put("sha256", record.sha256)
                    .put("scannedAt", record.scannedAt)
                    .put("cacheStored", record.cacheStored)
            )
        }
        return array
    }

    private fun decode(array: JSONArray): List<ScanRecord> =
        List(array.length()) { index ->
            val item = array.getJSONObject(index)
            ScanRecord(
                id = item.getLong("id"),
                fileName = item.getString("fileName"),
                sizeBytes = item.optLong("sizeBytes", -1),
                sha256 = item.getString("sha256"),
                scannedAt = item.optLong("scannedAt", 0),
                cacheStored = item.optBoolean("cacheStored", false),
            )
        }

    companion object {
        private const val SCHEMA_KEY = "schemaVersion"
        private const val SCHEMA_VERSION = 2
        private const val DATA_KEY = "records"
        private const val LEGACY_KEY = "scan_records"

        @Volatile
        private var instance: ScanHistoryStore? = null

        fun get(context: Context): ScanHistoryStore =
            instance ?: synchronized(this) {
                instance ?: ScanHistoryStore(context.applicationContext).also { instance = it }
            }
    }
}
