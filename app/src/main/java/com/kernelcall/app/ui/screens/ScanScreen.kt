package com.kernelcall.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kernelcall.app.ui.Formats
import com.kernelcall.app.ui.ScanViewModel
import com.kernelcall.app.ui.ScanUiState
import com.kernelcall.app.ui.components.InfoRow
import com.kernelcall.app.ui.components.PanelCard
import com.kernelcall.app.ui.components.SectionLabel
import com.kernelcall.app.ui.theme.KernelAmber

private val PICKER_MIME_TYPES = arrayOf(
    "application/vnd.android.package-archive",
    "application/octet-stream",
    "application/zip",
    "*/*",
)

@Composable
fun ScanScreen(
    viewModel: ScanViewModel,
    onOpenResults: (Long) -> Unit,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri -> viewModel.onApkPicked(uri) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 24.dp),
    ) {
        Text(
            text = "APK Scan",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = "Pick an APK file. Kernel Call reads its bytes and computes a " +
                "SHA-256 fingerprint locally.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(24.dp))

        when (val current = state) {
            is ScanUiState.Idle -> IdleState(
                onPick = { picker.launch(PICKER_MIME_TYPES) },
            )
            is ScanUiState.Hashing -> HashingState(current)
            is ScanUiState.Done -> DoneState(
                record = current.record,
                analysisState = viewModel.analysisState.collectAsStateWithLifecycle().value,
                onRunAnalysis = viewModel::runStaticAnalysis,
                onOpenResults = { onOpenResults(current.record.id) },
                onNewScan = viewModel::reset,
            )
            is ScanUiState.Error -> ErrorState(
                message = current.message,
                onRetry = {
                    viewModel.reset()
                    picker.launch(PICKER_MIME_TYPES)
                },
            )
        }

        Spacer(Modifier.height(20.dp))
        PanelCard {
            Row {
                Text(
                    text = "!",
                    style = MaterialTheme.typography.titleMedium,
                    color = KernelAmber,
                )
                Spacer(Modifier.padding(horizontal = 4.dp))
                Text(
                    text = "Static analysis reads files only — it never installs or " +
                        "executes the APK. Findings are observations and heuristics; " +
                        "a safe/malicious verdict needs evidence beyond this engine.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun IdleState(onPick: () -> Unit) {
    PanelCard(modifier = Modifier.fillMaxWidth()) {
        SectionLabel("Step 1")
        Spacer(Modifier.height(6.dp))
        Text(
            text = "Choose an .apk from your device storage.",
            style = MaterialTheme.typography.bodyLarge,
        )
        Spacer(Modifier.height(16.dp))
        Button(onClick = onPick, modifier = Modifier.fillMaxWidth().height(50.dp)) {
            Text("Select APK file")
        }
    }
}

@Composable
private fun HashingState(state: ScanUiState.Hashing) {
    PanelCard(modifier = Modifier.fillMaxWidth()) {
        SectionLabel("Fingerprinting")
        Spacer(Modifier.height(10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(
                modifier = Modifier.padding(end = 14.dp),
                color = MaterialTheme.colorScheme.primary,
            )
            Column {
                Text(
                    text = state.fileName,
                    style = MaterialTheme.typography.titleMedium,
                )
                val progressText = if (state.totalBytes != null) {
                    Formats.size(state.bytesProcessed) + " of " + Formats.size(state.totalBytes)
                } else {
                    Formats.size(state.bytesProcessed) + " read"
                }
                Text(
                    text = progressText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(14.dp))
        LinearProgressIndicator(
            modifier = Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.primary,
        )
    }
}

@Composable
private fun DoneState(
    record: com.kernelcall.app.data.ScanRecord,
    analysisState: com.kernelcall.app.ui.AnalysisUiState,
    onRunAnalysis: () -> Unit,
    onOpenResults: () -> Unit,
    onNewScan: () -> Unit,
) {
    PanelCard(modifier = Modifier.fillMaxWidth()) {
        SectionLabel("Fingerprint complete")
        Spacer(Modifier.height(10.dp))
        InfoRow("File", record.fileName)
        InfoRow("Size", Formats.size(record.sizeBytes))
        Spacer(Modifier.height(6.dp))
        Text(
            text = "SHA-256",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = Formats.hashChunks(record.sha256),
            style = com.kernelcall.app.ui.theme.HashStyle,
            color = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.height(16.dp))
        if (analysisState is com.kernelcall.app.ui.AnalysisUiState.Idle ||
            analysisState is com.kernelcall.app.ui.AnalysisUiState.Error
        ) {
            val enabled = record.cacheStored
            if (!enabled) {
                Text(
                    text = "APK not cached for analysis (too large). " +
                        "Fingerprint record is valid.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
            }
            Button(onClick = onRunAnalysis, modifier = Modifier.fillMaxWidth().height(50.dp)) {
                Text("Run static analysis")
            }
            analysisState.let {
                if (it is com.kernelcall.app.ui.AnalysisUiState.Error) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = it.message,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
        if (analysisState is com.kernelcall.app.ui.AnalysisUiState.Running) {
            SectionLabel("Analysing — " + analysisState.stage)
            Spacer(Modifier.height(6.dp))
            LinearProgressIndicator(
                progress = { analysisState.percent / 100f },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (analysisState is com.kernelcall.app.ui.AnalysisUiState.Completed) {
            Text(
                text = "Static analysis finished. The report is on the Results screen.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(6.dp))
        Button(onClick = onOpenResults, modifier = Modifier.fillMaxWidth().height(50.dp)) {
            Text("View results")
        }
        Spacer(Modifier.height(6.dp))
        TextButton(onClick = onNewScan, modifier = Modifier.fillMaxWidth()) {
            Text("Scan another APK")
        }
    }
}

@Composable
private fun ErrorState(message: String, onRetry: () -> Unit) {
    PanelCard(
        modifier = Modifier.fillMaxWidth(),
        outlined = true,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            androidx.compose.material3.Icon(
                imageVector = Icons.Filled.Warning,
                contentDescription = null,
                tint = KernelAmber,
            )
            Spacer(Modifier.padding(horizontal = 6.dp))
            Text(
                text = "Scan failed",
                style = MaterialTheme.typography.titleMedium,
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(14.dp))
        Button(onClick = onRetry, modifier = Modifier.fillMaxWidth().height(50.dp)) {
            Text("Try again")
        }
    }
}
