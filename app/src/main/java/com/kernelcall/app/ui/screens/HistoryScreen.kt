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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kernelcall.app.data.ScanRecord
import com.kernelcall.app.ui.Formats
import com.kernelcall.app.ui.components.EmptyState
import com.kernelcall.app.ui.components.PanelCard
import com.kernelcall.app.ui.components.SectionLabel

@Composable
fun HistoryScreen(
    records: List<ScanRecord>,
    onRecordSelected: (Long) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 24.dp),
        ) {
            Text(
                text = "Scan History",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = "Every fingerprint created on this device.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (records.isEmpty()) {
            EmptyState(
                icon = Icons.Filled.Info,
                title = "No scan history",
                message = "Fingerprints you create will be listed here. History stays " +
                    "in this app and is never sent anywhere.",
                modifier = Modifier.padding(horizontal = 20.dp),
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(
                    horizontal = 20.dp, vertical = 8.dp,
                ),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                item { SectionLabel("Records") }
                items(records, key = { it.id }) { record ->
                    PanelCard(
                        outlined = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onRecordSelected(record.id) },
                    ) {
                        Row {
                            Column(Modifier.weight(1f)) {
                                Text(
                                    text = record.fileName,
                                    style = MaterialTheme.typography.titleMedium,
                                )
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = Formats.size(record.sizeBytes) + "  •  " +
                                        Formats.timestamp(record.scannedAt),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            Text(
                                text = record.sha256.take(8),
                                style = com.kernelcall.app.ui.theme.HashStyle,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                }
            }
        }
    }
}
