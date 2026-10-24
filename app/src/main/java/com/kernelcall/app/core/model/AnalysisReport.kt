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
    /** present from schema 3 onward; null for schema 2 files (Phase 2) */
    val intelligence: Intelligence? = null,
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
                .put("category", finding.category)
                .put("ruleId", finding.ruleId)
                .put("confidence", finding.confidence.name)
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

        intelligence?.let { intel ->
            val intelJson = JSONObject()

            val correlationsJson = JSONArray()
            intel.correlations.forEach { c ->
                val sharedEv = JSONArray()
                c.sharedEvidence.forEach { e ->
                    sharedEv.put(
                        JSONObject()
                            .put("type", e.type)
                            .put("label", e.label)
                            .put("value", e.value)
                            .apply { if (e.location != null) put("location", e.location) }
                    )
                }
                val related = JSONArray()
                c.relatedFindingIds.forEach { related.put(it) }
                correlationsJson.put(
                    JSONObject()
                        .put("id", c.id)
                        .put("ruleId", c.ruleId)
                        .put("title", c.title)
                        .put("explanation", c.explanation)
                        .put("severity", c.severity.name)
                        .put("scoreWeight", c.scoreWeight)
                        .put("relatedFindingIds", related)
                        .put("sharedEvidence", sharedEv)
                )
            }
            intelJson.put("correlations", correlationsJson)

            val riskJson = JSONObject()
                .put("score", intel.risk.score)
                .put("band", intel.risk.band.name)
            val contribJson = JSONArray()
            intel.risk.contributions.forEach { c ->
                contribJson.put(
                    JSONObject()
                        .put("refFindingId", c.refFindingId)
                        .put("refRuleId", c.refRuleId)
                        .put("description", c.description)
                        .put("weight", c.weight)
                )
            }
            riskJson.put("contributions", contribJson)
            val limitsJson = JSONArray()
            intel.risk.limitations.forEach { limitsJson.put(it) }
            riskJson.put("limitations", limitsJson)
            intelJson.put("risk", riskJson)
            root.put("intelligence", intelJson)
        }
        return root.toString()
    }

    companion object {
        const val CURRENT_SCHEMA_VERSION = Intelligence.SCHEMA_VERSION

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
                        category = item.optString("category").takeIf { it.isNotEmpty() }
                            ?: Categories.MANIFEST,
                        ruleId = item.optString("ruleId"),
                        confidence = runCatching {
                            Confidence.valueOf(item.optString("confidence"))
                        }.getOrDefault(Confidence.MEDIUM),
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

        val intelRoot = root.optJSONObject("intelligence")
        val intelligence = intelRoot?.let { parseIntelligence(it) }

        AnalysisReport(
            schemaVersion = root.getInt("schemaVersion"),
            sha256 = root.getString("sha256"),
            fileName = root.getString("fileName"),
            sizeBytes = root.getLong("sizeBytes"),
            generatedAt = root.getLong("generatedAt"),
            engines = engines,
            findings = loaded,
            unknowns = unknowns,
            intelligence = intelligence,
        )
        } catch (_: Exception) {
            null
        }

    private fun parseIntelligence(intelRoot: JSONObject): Intelligence? = try {
        val correlations = mutableListOf<CorrelationFinding>()
        val corrArr = intelRoot.optJSONArray("correlations") ?: JSONArray()
        for (i in 0 until corrArr.length()) {
            val c = corrArr.getJSONObject(i)
            val shared = mutableListOf<Evidence>()
            val sharedArr = c.optJSONArray("sharedEvidence") ?: JSONArray()
            for (j in 0 until sharedArr.length()) {
                val e = sharedArr.getJSONObject(j)
                shared.add(
                    Evidence(
                        type = e.getString("type"),
                        label = e.getString("label"),
                        value = e.getString("value"),
                        location = e.optString("location").takeIf { it.isNotEmpty() },
                    )
                )
            }
            val related = mutableListOf<String>()
            val relArr = c.optJSONArray("relatedFindingIds") ?: JSONArray()
            for (j in 0 until relArr.length()) related.add(relArr.getString(j))
            correlations.add(
                CorrelationFinding(
                    id = c.getString("id"),
                    ruleId = c.getString("ruleId"),
                    title = c.getString("title"),
                    explanation = c.getString("explanation"),
                    severity = Severity.valueOf(c.getString("severity")),
                    relatedFindingIds = related,
                    sharedEvidence = shared,
                    scoreWeight = c.optInt("scoreWeight", 0),
                )
            )
        }

        val riskObj = intelRoot.getJSONObject("risk")
        val contributions = mutableListOf<ScoreContribution>()
        val contribArr = riskObj.optJSONArray("contributions") ?: JSONArray()
        for (i in 0 until contribArr.length()) {
            val cItem = contribArr.getJSONObject(i)
            contributions.add(
                ScoreContribution(
                    refFindingId = cItem.getString("refFindingId"),
                    refRuleId = cItem.getString("refRuleId"),
                    description = cItem.getString("description"),
                    weight = cItem.getInt("weight"),
                )
            )
        }
        val limitations = mutableListOf<String>()
        val limitsArr = riskObj.optJSONArray("limitations") ?: JSONArray()
        for (i in 0 until limitsArr.length()) limitations.add(limitsArr.getString(i))

        Intelligence(
            correlations = correlations,
            risk = RiskAssessment(
                score = riskObj.getInt("score"),
                band = RiskBand.valueOf(riskObj.getString("band")),
                contributions = contributions,
                limitations = limitations,
            ),
        )
    } catch (_: Exception) {
        null
    }
    }
}
