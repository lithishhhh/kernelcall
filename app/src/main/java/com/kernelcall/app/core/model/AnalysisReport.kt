package com.kernelcall.app.core.model

import org.json.JSONArray
import org.json.JSONObject

/** Per-engine measurement embedded in every report (built-in perf surface). */
data class EngineRunStats(
    val engineId: String,
    val durationMs: Long,
    val findingCount: Int,
    val unknownCount: Int,
)

data class AnalysisReport(
    val schemaVersion: Int,
    val sha256: String,
    val fileName: String,
    val sizeBytes: Long,
    val generatedAt: Long,
    val engines: List<EngineRunStats>,
    val findings: List<Finding>,
    val unknowns: List<UnknownNote>,
) {
    fun toJson(): String {
        val root = JSONObject()
            .put("schemaVersion", schemaVersion)
            .put("sha256", sha256)
            .put("fileName", fileName)
            .put("sizeBytes", sizeBytes)
            .put("generatedAt", generatedAt)

        val engineStats = JSONArray()
        this.engines.forEach { stat ->
            engineStats.put(
                JSONObject()
                    .put("engineId", stat.engineId)
                    .put("durationMs", stat.durationMs)
                    .put("findingCount", stat.findingCount)
                    .put("unknownCount", stat.unknownCount)
            )
        }
        root.put("engines", engineStats)

        val findingsJson = JSONArray()
        this.findings.forEach { finding ->
            val evidenceJson = JSONArray()
            finding.evidence.forEach { e ->
                val evObj = JSONObject()
                    .put("type", e.type)
                    .put("label", e.label)
                    .put("value", e.value)
                if (e.location != null) evObj.put("location", e.location)
                evidenceJson.put(evObj)
            }
            val fObj = JSONObject()
                .put("id", finding.id)
                .put("engineId", finding.engineId)
                .put("title", finding.title)
                .put("summary", finding.summary)
                .put("kind", finding.kind.name)
                .put("severity", finding.severity.name)
                .put("detectedAt", finding.detectedAt)
            finding.recommendation?.let { fObj.put("recommendation", it) }
            fObj.put("evidence", evidenceJson)
            findingsJson.put(fObj)
        }
        root.put("findings", findingsJson)

        val unknownsJson = JSONArray()
        this.unknowns.forEach { note ->
            unknownsJson.put(
                JSONObject()
                    .put("engineId", note.engineId)
                    .put("message", note.message)
            )
        }
        root.put("unknowns", unknownsJson)
        return root.toString()
    }

    companion object {
        const val CURRENT_SCHEMA_VERSION = 2

        fun fromJson(raw: String): AnalysisReport? = try {
            val root = JSONObject(raw)
            val engines = mutableListOf<EngineRunStats>()
            val enginesArr = root.optJSONArray("engines") ?: JSONArray()
            for (i in 0 until enginesArr.length()) {
                val item = enginesArr.getJSONObject(i)
                engines.add(
                    EngineRunStats(
                        engineId = item.getString("engineId"),
                        durationMs = item.getLong("durationMs"),
                        findingCount = item.getInt("findingCount"),
                        unknownCount = item.getInt("unknownCount"),
                    )
                )
            }

            val loaded = mutableListOf<Finding>()
            val findingsArr = root.optJSONArray("findings") ?: JSONArray()
            for (i in 0 until findingsArr.length()) {
                val item = findingsArr.getJSONObject(i)
                val evidence = mutableListOf<Evidence>()
                val evArr = item.optJSONArray("evidence") ?: JSONArray()
                for (j in 0 until evArr.length()) {
                    val e = evArr.getJSONObject(j)
                    evidence.add(
                        Evidence(
                            type = e.getString("type"),
                            label = e.getString("label"),
                            value = e.getString("value"),
                            location = e.optString("location").takeIf { it.isNotEmpty() },
                        )
                    )
                }
                loaded.add(
                    Finding(
                        id = item.getString("id"),
                        engineId = item.getString("engineId"),
                        title = item.getString("title"),
                        summary = item.getString("summary"),
                        kind = FindingKind.valueOf(item.getString("kind")),
                        severity = Severity.valueOf(item.getString("severity")),
                        evidence = evidence,
                        recommendation = item.optString("recommendation").takeIf { it.isNotEmpty() },
                        detectedAt = item.getLong("detectedAt"),
                    )
                )
            }

            val unknowns = mutableListOf<UnknownNote>()
            val unknownArr = root.optJSONArray("unknowns") ?: JSONArray()
            for (i in 0 until unknownArr.length()) {
                val item = unknownArr.getJSONObject(i)
                unknowns.add(
                    UnknownNote(
                        engineId = item.getString("engineId"),
                        message = item.getString("message"),
                    )
                )
            }

            AnalysisReport(
                schemaVersion = root.getInt("schemaVersion"),
                sha256 = root.getString("sha256"),
                fileName = root.getString("fileName"),
                sizeBytes = root.getLong("sizeBytes"),
                generatedAt = root.getLong("generatedAt"),
                engines = engines,
                findings = loaded,
                unknowns = unknowns,
            )
        } catch (_: Exception) {
            null
        }
    }
}
