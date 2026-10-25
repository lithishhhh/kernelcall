package com.kernelcall.app.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kernelcall.app.data.ScanRecord
import com.kernelcall.app.ui.Formats
import com.kernelcall.app.ui.components.ChipTag
import com.kernelcall.app.ui.components.CategoryBarChart
import com.kernelcall.app.ui.components.EmptyState
import com.kernelcall.app.ui.components.PanelCard
import com.kernelcall.app.ui.components.RiskGauge
import com.kernelcall.app.ui.components.SectionLabel
import com.kernelcall.app.ui.components.SeverityBarChart
import com.kernelcall.app.ui.components.ShieldIcon
import com.kernelcall.app.ui.components.bandColor
import com.kernelcall.app.ui.theme.KernelTextSecondary
import com.kernelcall.app.ui.DashboardViewModel

/**
 * Phase 5 dashboard: visual security overview driven by the pure
 * [DashboardStatsBuilder] aggregates — real persisted data only.
 */
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    records: List<ScanRecord>,
    onScanInstalled: () -> Unit,
    onManualImport: () -> Unit,
    onRecordSelected: (Long) -> Unit,
) {
    val stats by viewModel.stats.collectAsStateWithLifecycle()
    val loading by viewModel.loading.collectAsStateWithLifecycle()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 24.dp),
    ) {
        // Brand header
        Row(verticalAlignment = Alignment.CenterVertically) {
            ShieldIcon(modifier = Modifier.width(34.dp))
            Spacer(Modifier.width(12.dp))
            Column {
                Text(
                    text = "Kernel Call",
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Text(
                    text = "Static APK security intelligence",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Spacer(Modifier.height(20.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = onScanInstalled,
                modifier = Modifier.weight(1f).height(48.dp),
            ) { Text("Scan installed apps") }
            OutlinedButton(
                onClick = onManualImport,
                modifier = Modifier.weight(1f).height(48.dp),
            ) { Text("Import an APK file") }
        }

        Spacer(Modifier.height(10.dp))
        Text(
            text = "Everything stays on this device. Files and installed app " +
                "packages are read, hashed, and never installed, executed, " +
                "or uploaded.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(24.dp))

        val current = stats
        if (current == null) {
            if (loading) {
                Box(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 40.dp),
                    contentAlignment = Alignment.Center,
                ) { CircularProgressIndicator() }
            } else {
                PanelCard {
                    EmptyState(
                        icon = Icons.Filled.Search,
                        title = "No scans yet",
                        message = "Scan an installed app or import an APK file. Once " +
                            "analysed, risk overviews and findings appear here.",
                    )
                }
            }
            return@Column
        }

        // Risk gauge for the most recent analysed app
        val latest = current.latest
        PanelCard(modifier = Modifier.fillMaxWidth()) {
            SectionLabel(
                if (latest == null) "Latest scan" else "Latest analysis",
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RiskGauge(
                    score = latest?.score,
                    bandName = latest?.band?.name,
                    modifier = Modifier.size(150.dp),
                )
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    if (latest != null) {
                        Text(
                            text = latest.fileName,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 2,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "${latest.findingsCount} finding(s), " +
                                "${latest.unknownsCount} unknown(s)",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(
                        text = "A static risk-surface indicator, never a malware verdict.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = KernelTextSecondary,
                    )
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        // Summary cards
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            PanelCard(modifier = Modifier.weight(1f)) {
                SectionLabel("Scanned")
                Spacer(Modifier.height(4.dp))
                Text(
                    text = current.scannedApps.toString(),
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            PanelCard(modifier = Modifier.weight(1f)) {
                SectionLabel("Analysed")
                Spacer(Modifier.height(4.dp))
                Text(
                    text = current.analyzedReports.toString(),
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            PanelCard(modifier = Modifier.weight(1f)) {
                SectionLabel("Findings")
                Spacer(Modifier.height(4.dp))
                Text(
                    text = current.totalFindings.toString(),
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            PanelCard(modifier = Modifier.weight(1f)) {
                SectionLabel("High severity")
                Spacer(Modifier.height(4.dp))
                Text(
                    text = current.highSeverityFindings.toString(),
                    style = MaterialTheme.typography.headlineMedium,
                    color = if (current.highSeverityFindings > 0) {
                        com.kernelcall.app.ui.theme.KernelRed
                    } else {
                        com.kernelcall.app.ui.theme.KernelGreen
                    },
                )
            }
        }

        Spacer(Modifier.height(20.dp))

        PanelCard(modifier = Modifier.fillMaxWidth()) {
            SectionLabel("Severity distribution (all reports)")
            Spacer(Modifier.height(10.dp))
            SeverityBarChart(current.severityCounts, modifier = Modifier.fillMaxWidth())
        }

        Spacer(Modifier.height(16.dp))

        if (current.categoryCounts.isNotEmpty()) {
            PanelCard(modifier = Modifier.fillMaxWidth()) {
                SectionLabel("Findings by category (all reports)")
                Spacer(Modifier.height(10.dp))
                CategoryBarChart(current.categoryCounts, modifier = Modifier.fillMaxWidth())
            }
            Spacer(Modifier.height(16.dp))
        }

        // Recent scans
        SectionLabel("Recent scans")
        Spacer(Modifier.height(12.dp))

        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            records.take(3).forEach { record ->
                PanelCard(
                    outlined = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onRecordSelected(record.id) },
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = record.fileName,
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                            )
                            Text(
                                text = Formats.size(record.sizeBytes) + "  ·  " +
                                    Formats.timestamp(record.scannedAt),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        ChipTag(if (record.packageName != null) "APP" else "APK")
                    }
                }
            }
        }
    }
}
