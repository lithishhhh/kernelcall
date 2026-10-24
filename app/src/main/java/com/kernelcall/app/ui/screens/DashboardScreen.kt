package com.kernelcall.app.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kernelcall.app.data.ScanRecord
import com.kernelcall.app.ui.Formats
import com.kernelcall.app.ui.components.ChipTag
import com.kernelcall.app.ui.components.EmptyState
import com.kernelcall.app.ui.components.PanelCard
import com.kernelcall.app.ui.components.SectionLabel
import com.kernelcall.app.ui.components.ShieldIcon

@Composable
fun DashboardScreen(
    records: List<ScanRecord>,
    onScanSelected: () -> Unit,
    onRecordSelected: (Long) -> Unit,
) {
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

        Spacer(Modifier.height(24.dp))

        // Scan action
        Button(
            onClick = onScanSelected,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text("Select an APK to analyse")
        }

        Spacer(Modifier.height(12.dp))
        Text(
            text = "Everything stays on this device. The file is read, hashed, " +
                "and never installed, executed, or uploaded.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(28.dp))

        // Stats
        if (records.isNotEmpty()) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PanelCard(modifier = Modifier.weight(1f)) {
                    SectionLabel("Total scans")
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = records.size.toString(),
                        style = MaterialTheme.typography.headlineMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                PanelCard(modifier = Modifier.weight(1f)) {
                    SectionLabel("Last scan")
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = Formats.timestamp(records.first().scannedAt),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
            Spacer(Modifier.height(28.dp))
        }

        // Recent scans
        SectionLabel("Recent scans")
        Spacer(Modifier.height(12.dp))

        if (records.isEmpty()) {
            PanelCard {
                EmptyState(
                    icon = Icons.Filled.Search,
                    title = "No scans yet",
                    message = "Once you fingerprint an APK, its details will appear " +
                        "here on your dashboard.",
                )
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                records.take(3).forEach { record ->
                    PanelCard(
                        outlined = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onRecordSelected(record.id) },
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth(),
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = record.fileName,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurface,
                                    modifier = Modifier.weight(1f),
                                )
                                ChipTag("SCANNED")
                            }
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = Formats.size(record.sizeBytes) + "  •  " +
                                    Formats.timestamp(record.scannedAt),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}
