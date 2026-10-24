package com.kernelcall.app.ui.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kernelcall.app.core.model.AnalysisReport
import com.kernelcall.app.core.model.Finding
import com.kernelcall.app.core.model.FindingKind
import com.kernelcall.app.core.model.RiskBand
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.data.ScanHistoryStore
import com.kernelcall.app.data.ScanRecord
import com.kernelcall.app.ui.Formats
import com.kernelcall.app.ui.components.EmptyState
import com.kernelcall.app.ui.components.PanelCard
import com.kernelcall.app.ui.components.SectionLabel
import com.kernelcall.app.ui.theme.HashStyle
import com.kernelcall.app.ui.theme.KernelCyan
import com.kernelcall.app.ui.theme.KernelGreen
import com.kernelcall.app.ui.theme.KernelRed
import com.kernelcall.app.ui.theme.KernelTextSecondary
import com.kernelcall.app.ui.theme.KernelAmber

@Composable
fun ResultsScreen(
    store: ScanHistoryStore,
    recordId: Long,
    loadReport: (sha256: String) -> AnalysisReport?,
    onBack: () -> Unit,
) {
    val records by store.records.collectAsState()
    val record = records.firstOrNull { it.id == recordId }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back",
                    tint = MaterialTheme.colorScheme.onBackground,
                )
            }
            Text(
                text = "Results",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }

        if (record == null) {
            EmptyState(
                icon = Icons.Filled.Info,
                title = "Record not found",
                message = "This scan record is no longer available.",
            )
            return
        }

        Spacer(Modifier.height(8.dp))

        // File fingerprint card
        PanelCard(modifier = Modifier.fillMaxWidth()) {
            SectionLabel("File identity")
            Spacer(Modifier.height(10.dp))
            RecordRows(record)
        }

        val report = loadReport(record.sha256)
        if (report == null) {
            Spacer(Modifier.height(16.dp))
            PanelCard(modifier = Modifier.fillMaxWidth(), outlined = true) {
                SectionLabel("Static analysis")
                Spacer(Modifier.height(10.dp))
                Text(
                    text = "No analysis report for this file yet. Run static analysis " +
                        "from the Scan tab after picking this APK.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            return@Column
        }

        Spacer(Modifier.height(16.dp))

        // Engine stats
        PanelCard(modifier = Modifier.fillMaxWidth()) {
            SectionLabel("Analysis run")
            Spacer(Modifier.height(10.dp))
            report.engines.forEach { engine ->
                com.kernelcall.app.ui.components.InfoRow(
                    label = engine.engineId,
                    value = "${engine.durationMs} ms · " +
                        "${engine.findingCount} finding(s), " +
                        "${engine.unknownCount} unknown(s)",
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        // Intelligence — explainable score, correlations, open gaps
        IntelligenceCard(report)

        Spacer(Modifier.height(16.dp))

        // Findings
        SectionLabel("Findings (${report.findings.size})")
        Spacer(Modifier.height(10.dp))
        if (report.findings.isEmpty()) {
            Text(
                text = "No findings recorded by this report.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Column(verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(10.dp)) {
                report.findings.forEach { finding ->
                    PanelCard(modifier = Modifier.fillMaxWidth()) {
                        FindingRows(finding)
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        // Unknowns — honest gaps
        SectionLabel("Open unknowns (${report.unknowns.size})")
        Spacer(Modifier.height(10.dp))
        PanelCard(modifier = Modifier.fillMaxWidth(), outlined = true) {
            if (report.unknowns.isEmpty()) {
                Text(
                    text = "None recorded for this run.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Column {
                    report.unknowns.forEach { note ->
                        Row {
                            Text(text = "· ", color = KernelAmber)
                            Text(
                                text = note.message,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))
        Text(
            text = "Report generated " + Formats.timestamp(report.generatedAt) +
                "  ·  All processing was local to this device.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun IntelligenceCard(report: AnalysisReport) {
    SectionLabel("Intelligence")
    Spacer(Modifier.height(10.dp))

    val intel = report.intelligence
    PanelCard(modifier = Modifier.fillMaxWidth()) {
        if (intel == null) {
            Text(
                text = "This report predates the intelligence layer (schema " +
                    report.schemaVersion + "). Nothing is invented here — re-run " +
                    "static analysis on this file to obtain correlation and a " +
                    "risk-surface score.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            return@PanelCard
        }

        // Risk band header
        val bandColor = bandColor(intel.risk.band)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = "Risk-surface score",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = "${intel.risk.score} / 100 · RISK: ${intel.risk.band.name}",
                    style = MaterialTheme.typography.headlineSmall,
                    color = bandColor,
                )
            }
        }
        Text(
            text = "An indicator of code-level risk surface (static evidence only) — " +
                "never a verdict that this APK is malware.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(10.dp))
        SeverityDistribution(report.findings)

        // Why the score is what it is
        if (intel.risk.contributions.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            SectionLabel("Score explanation")
            Column {
                intel.risk.contributions.forEach { contribution ->
                    Row(modifier = Modifier.padding(vertical = 2.dp)) {
                        Text(
                            text = "+${contribution.weight}",
                            style = HashStyle,
                            color = bandColor,
                            modifier = Modifier.width(44.dp),
                        )
                        Text(
                            text = contribution.description,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }
        }

        // Correlations
        if (intel.correlations.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            SectionLabel("Correlated indicators (${intel.correlations.size})")
            Column {
                intel.correlations.forEach { correlation ->
                    Row(modifier = Modifier.padding(top = 6.dp)) {
                        Text(
                            text = "●",
                            color = severityColor(correlation.severity)
                                ?: MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(end = 6.dp),
                        )
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = correlation.title,
                                style = MaterialTheme.typography.titleMedium,
                            )
                            Text(
                                text = correlation.explanation,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                text = "Based on ${correlation.relatedFindingIds.size} finding(s)" +
                                    (if (correlation.scoreWeight > 0)
                                        " · +" + correlation.scoreWeight + " score"
                                    else " · consolidation only"),
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.secondary,
                            )
                        }
                    }
                }
            }
        }

        // Honest limitations
        Spacer(Modifier.height(10.dp))
        SectionLabel("What this score cannot tell you")
        Column {
            intel.risk.limitations.forEach { limitation ->
                Row {
                    Text(text = "· ", color = KernelCyan)
                    Text(
                        text = limitation,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun SeverityDistribution(findings: List<Finding>) {
    SectionLabel("Severity distribution")
    Row(Modifier.fillMaxWidth()) {
        Severity.entries.forEach { severity ->
            val count = findings.count { it.severity == severity }
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("● ", color = severityColor(severity) ?: KernelGreen)
                Text(
                    text = "$count ${severity.name.lowercase()}",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun bandColor(band: RiskBand) = when (band) {
    RiskBand.HIGH -> KernelRed
    RiskBand.ELEVATED -> KernelAmber
    RiskBand.MODERATE -> com.kernelcall.app.ui.theme.KernelTextSecondary
    RiskBand.LOW -> KernelGreen
}

@Composable
private fun FindingRows(finding: Finding) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        severityColor(finding.severity)?.let { color ->
            Text(
                text = "●",
                color = color,
                modifier = Modifier.padding(end = 6.dp),
            )
        }
        Column(Modifier.weight(1f)) {
            Text(
                text = finding.title,
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = kindLabel(finding.kind) + " · " + severityLabel(finding.severity) +
                    " · confidence: " + finding.confidence.name.lowercase() +
                    (if (finding.ruleId.isNotBlank()) " · rule " + finding.ruleId else ""),
                style = MaterialTheme.typography.labelLarge,
                color = kindColor(finding.kind),
            )
        }
    }
    Spacer(Modifier.height(6.dp))
    Text(
        text = finding.summary,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    finding.recommendation?.let {
        Spacer(Modifier.height(6.dp))
        Text(
            text = "Next step: " + it,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.secondary,
        )
    }
    Spacer(Modifier.height(10.dp))
    SectionLabel("Evidence")
    Column {
        finding.evidence.forEach { e ->
            Row(modifier = Modifier.padding(vertical = 2.dp)) {
                Text(
                    text = "· ",
                    style = HashStyle,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Column {
                    Text(
                        text = e.label,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = e.value + (e.location?.let { "  ($it)" } ?: ""),
                        style = HashStyle,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}

private fun severityColor(severity: Severity) = when (severity) {
    Severity.HIGH -> KernelRed
    Severity.MEDIUM -> KernelAmber
    Severity.LOW -> KernelCyan
    Severity.INFO -> KernelGreen
}

private fun kindColor(kind: FindingKind) = when (kind) {
    FindingKind.CONFIRMED_OBSERVATION -> KernelGreen
    FindingKind.HEURISTIC_INDICATOR -> KernelAmber
    FindingKind.UNKNOWN -> KernelCyan
    FindingKind.SANDBOX_ONLY -> com.kernelcall.app.ui.theme.KernelTextSecondary
}

private fun kindLabel(kind: FindingKind) = when (kind) {
    FindingKind.CONFIRMED_OBSERVATION -> "CONFIRMED OBSERVATION"
    FindingKind.HEURISTIC_INDICATOR -> "HEURISTIC INDICATOR"
    FindingKind.UNKNOWN -> "UNKNOWN"
    FindingKind.SANDBOX_ONLY -> "SANDBOX ONLY"
}

private fun severityLabel(severity: Severity) = when (severity) {
    Severity.HIGH -> "HIGH"
    Severity.MEDIUM -> "MEDIUM"
    Severity.LOW -> "LOW"
    Severity.INFO -> "INFO"
}

@Composable
private fun RecordRows(record: ScanRecord) {
    com.kernelcall.app.ui.components.InfoRow("File", record.fileName)
    com.kernelcall.app.ui.components.InfoRow("Size", Formats.size(record.sizeBytes))
    Spacer(Modifier.height(6.dp))
    Text(
        text = "SHA-256",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(4.dp))
    Text(
        text = Formats.hashChunks(record.sha256),
        style = HashStyle,
        color = MaterialTheme.colorScheme.primary,
    )
}
