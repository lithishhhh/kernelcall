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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kernelcall.app.core.installed.QueueItemStatus
import com.kernelcall.app.core.installed.ScanQueueItem
import com.kernelcall.app.ui.components.AppIcon
import com.kernelcall.app.ui.components.PanelCard
import com.kernelcall.app.ui.components.SectionLabel
import com.kernelcall.app.ui.installed.InstalledAppsViewModel
import com.kernelcall.app.ui.theme.KernelRed
import com.kernelcall.app.ui.theme.KernelTextSecondary

/**
 * Phase 5 scan-progress screen. Every percent/stage shown here comes from
 * real events: byte counts from the fingerprinter, stage labels from the
 * analysis coordinator/engine — nothing is simulated.
 */
@Composable
fun ScanProgressScreen(
    viewModel: InstalledAppsViewModel,
    onOpenResults: (Long) -> Unit,
    onBack: () -> Unit,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val queue = state.queue

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 24.dp),
    ) {
        Text(
            text = "Scan progress",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = "Apps are processed one at a time. Progress reflects the real " +
                "analysis stages; nothing is installed or executed.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(16.dp))

        if (queue.items.isEmpty()) {
            PanelCard(modifier = Modifier.fillMaxWidth(), outlined = true) {
                Column {
                    Text(
                        text = "No scan is queued yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    TextButton(onClick = onBack) { Text("Back to installed apps") }
                }
            }
            return@Column
        }

        if (queue.hasActiveWork) {
            OutlinedButton(
                onClick = viewModel::cancelPending,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Cancel pending (${queue.pendingCount})")
            }
            Spacer(Modifier.height(12.dp))
        }

        SectionLabel("Queue (${queue.items.size}: " +
            "${queue.items.count { it.status == QueueItemStatus.DONE }} done, " +
            "${queue.pendingCount} pending)")
        Spacer(Modifier.height(10.dp))

        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            queue.items.forEach { item ->
                ProgressItem(
                    item = item,
                    appPackage = item.packageName,
                    onOpenResults = onOpenResults,
                )
            }
        }
    }
}

@Composable
private fun ProgressItem(
    item: ScanQueueItem,
    appPackage: String,
    onOpenResults: (Long) -> Unit,
) {
    PanelCard(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AppIcon(packageName = appPackage, modifier = Modifier.width(48.dp))
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.label,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "${item.percent}%  ·  ${item.stage}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            StatusChip(item)
        }

        if (item.status == QueueItemStatus.RUNNING || item.status == QueueItemStatus.PENDING) {
            Spacer(Modifier.height(10.dp))
            LinearProgressIndicator(
                progress = { item.percent.coerceIn(0, 100) / 100f },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        item.message?.let { message ->
            Spacer(Modifier.height(8.dp))
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = KernelRed,
            )
        }

        if (item.status == QueueItemStatus.DONE && item.recordId != null) {
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        text = item.sha256?.let { "SHA-256 " + it.take(12) + "..." } ?: "",
                        style = MaterialTheme.typography.labelLarge,
                        color = KernelTextSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = "score ${item.score ?: 0}/100 (${item.band ?: "no score"})",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                OutlinedButton(
                    onClick = { onOpenResults(item.recordId!!) },
                ) { Text("View results") }
            }
        }
    }
}

@Composable
private fun StatusChip(item: ScanQueueItem) {
    val (label, color) = when (item.status) {
        QueueItemStatus.PENDING -> "QUEUED" to KernelTextSecondary
        QueueItemStatus.RUNNING -> "RUNNING" to MaterialTheme.colorScheme.primary
        QueueItemStatus.DONE -> "DONE" to MaterialTheme.colorScheme.primary
        QueueItemStatus.UNREADABLE -> "UNREADABLE" to com.kernelcall.app.ui.theme.KernelAmber
        QueueItemStatus.ERROR -> "ERROR" to KernelRed
    }
    Text(
        text = label,
        style = MaterialTheme.typography.labelLarge,
        color = color,
    )
}
