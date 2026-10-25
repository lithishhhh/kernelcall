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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kernelcall.app.core.installed.AppScanState
import com.kernelcall.app.core.installed.AppScanStatus
import com.kernelcall.app.core.installed.InstalledAppEntry
import com.kernelcall.app.core.installed.ScanQueueItem
import com.kernelcall.app.ui.components.AppIcon
import com.kernelcall.app.ui.components.PanelCard
import com.kernelcall.app.ui.components.SectionLabel
import com.kernelcall.app.ui.installed.InstalledAppsViewModel
import com.kernelcall.app.ui.theme.KernelAmber
import com.kernelcall.app.ui.theme.KernelRed
import com.kernelcall.app.ui.theme.KernelTextSecondary

/**
 * Phase 5: installed-app scanner screen. Shows only launchable packages the
 * platform exposes to this app (declared <queries> intent filter); the
 * package-visibility limitation is stated openly in the UI.
 */
@Composable
fun InstalledAppsScreen(
    viewModel: InstalledAppsViewModel,
    onScanProgress: () -> Unit,
    onManualImport: () -> Unit,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var confirmScanAll by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 24.dp),
    ) {
        Text(
            text = "Installed apps",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = "Only launchable apps that Android exposes to Kernel Call are " +
                "listed. Apps whose base APK is not readable are shown but " +
                "cannot be statically analysed.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(14.dp))

        if (state.loading) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 28.dp),
                horizontalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator()
            }
        } else if (state.loadError != null) {
            PanelCard(modifier = Modifier.fillMaxWidth(), outlined = true) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(imageVector = Icons.Filled.Warning, contentDescription = null, tint = KernelAmber)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = state.loadError ?: "",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        } else {
            OutlinedTextField(
                value = state.query,
                onValueChange = viewModel::setQuery,
                placeholder = { Text("Search app name or package") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(
                    checked = state.includeSystem,
                    onCheckedChange = viewModel::setIncludeSystem,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "Include system apps",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(Modifier.height(10.dp))

            val visible = viewModel.visibleAppsWithStatus()
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (visible.isEmpty()) {
                    item {
                        PanelCard(modifier = Modifier.fillMaxWidth(), outlined = true) {
                            Text(
                                text = "No matching apps in the launchable list. " +
                                    "Non-launchable or hidden apps are excluded — " +
                                    "use manual APK import for those.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                items(visible, key = { it.first.packageName }) { (app, status) ->
                    AppRow(
                        app = app,
                        status = status,
                        selected = app.packageName in state.selected,
                        onToggle = { viewModel.toggleSelected(app.packageName) },
                    )
                }
            }

            Spacer(Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = {
                        viewModel.scanSelected()
                        onScanProgress()
                    },
                    enabled = state.selected.isNotEmpty(),
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Scan selected (${state.selected.size})")
                }
                OutlinedButton(
                    onClick = { confirmScanAll = true },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Scan all eligible")
                }
            }
            Spacer(Modifier.height(6.dp))
            TextButton(
                onClick = onManualImport,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("APK not listed? Import a file manually")
            }
        }
    }

    if (confirmScanAll) {
        val count = viewModel.eligibleCount()
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmScanAll = false },
            title = { Text("Scan all eligible apps?") },
            text = {
                Text(
                    text = "$count app(s) will be queued. Each is fingerprinted " +
                        "and statically analysed one at a time; this can take " +
                        "several minutes and CPU/battery. Nothing is installed, " +
                        "executed, or uploaded.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmScanAll = false
                    viewModel.scanEligible()
                    onScanProgress()
                }) { Text("Start") }
            },
            dismissButton = {
                TextButton(onClick = { confirmScanAll = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun AppRow(
    app: InstalledAppEntry,
    status: AppScanStatus?,
    selected: Boolean,
    onToggle: () -> Unit,
) {
    PanelCard(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AppIcon(packageName = app.packageName)
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.label,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.labelLarge,
                    color = KernelTextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                StatusLine(app, status)
            }
            Checkbox(checked = selected, onCheckedChange = null)
        }
    }
}

@Composable
private fun StatusLine(app: InstalledAppEntry, status: AppScanStatus?) {
    val text = when {
        status == null || status.state == AppScanState.NOT_SCANNED -> "Not scanned yet"
        status.state == AppScanState.ANALYZED && status.score != null && status.band != null ->
            "Analysed - score ${status.score}/100 (${status.band.lowercase()})"
        status.state == AppScanState.ANALYZED -> "Analysed (no intelligence block - older report)"
        status.state == AppScanState.HASH_ONLY ->
            "Fingerprint only - run analysis to produce a report"
        else -> status.reason ?: "Not analysable on this device"
    }
    val color = when {
        status?.state == AppScanState.UNREADABLE -> KernelRed
        status != null && status.state == AppScanState.ANALYZED && status.score != null -> MaterialTheme.colorScheme.primary
        else -> KernelTextSecondary
    }
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        color = color,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}
