package com.kernelcall.app.data

import org.json.JSONArray
import org.json.JSONObject

/**
 * ScanRecord <-> JSON codec extracted so persistence logic is unit-testable.
 * Additive evolution: unknown/missing optional fields are tolerated
 * (e.g. packageName from Phase 5 onward; absent in older payloads).
 */
object ScanRecordCodec {

    fun encode(records: List<ScanRecord>): JSONArray {
        val array = JSONArray()
        records.forEach { record ->
            val item = JSONObject()
                .put("id", record.id)
                .put("fileName", record.fileName)
                .put("sizeBytes", record.sizeBytes)
                .put("sha256", record.sha256)
                .put("scannedAt", record.scannedAt)
                .put("cacheStored", record.cacheStored)
            record.packageName?.let { item.put("packageName", it) }
            array.put(item)
        }
        return array
    }

    fun decode(array: JSONArray): List<ScanRecord> =
        List(array.length()) { index ->
            val item = array.getJSONObject(index)
            ScanRecord(
                id = item.getLong("id"),
                fileName = item.getString("fileName"),
                sizeBytes = item.optLong("sizeBytes", -1),
                sha256 = item.getString("sha256"),
                scannedAt = item.optLong("scannedAt", 0),
                cacheStored = item.optBoolean("cacheStored", false),
                packageName = item.optString("packageName").takeIf { it.isNotEmpty() },
            )
        }
}
