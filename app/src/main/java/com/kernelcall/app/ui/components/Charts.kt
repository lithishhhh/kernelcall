package com.kernelcall.app.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.kernelcall.app.core.model.RiskBand
import com.kernelcall.app.core.model.Severity
import com.kernelcall.app.ui.theme.HashStyle
import com.kernelcall.app.ui.theme.KernelCyan
import com.kernelcall.app.ui.theme.KernelGreen
import com.kernelcall.app.ui.theme.KernelRed
import com.kernelcall.app.ui.theme.KernelAmber
import com.kernelcall.app.ui.theme.KernelSurfaceHigh
import com.kernelcall.app.ui.theme.KernelTextPrimary
import com.kernelcall.app.ui.theme.KernelTextSecondary

/** Shared, single-source color mapping for risk bands and severities. */
fun bandColor(band: RiskBand): Color = when (band) {
    RiskBand.HIGH -> KernelRed
    RiskBand.ELEVATED -> KernelAmber
    RiskBand.MODERATE -> KernelCyan
    RiskBand.LOW -> KernelGreen
}

fun severityColor(severity: Severity): Color = when (severity) {
    Severity.HIGH -> KernelRed
    Severity.MEDIUM -> KernelAmber
    Severity.LOW -> KernelCyan
    Severity.INFO -> KernelGreen
}

/**
 * Circular risk gauge drawn with Compose Canvas from a REAL score (0..100).
 * A null score renders the honest "no score" state — never a fake number.
 */
@Composable
fun RiskGauge(
    score: Int?,
    bandName: String?,
    modifier: Modifier = Modifier,
) {
    val track = KernelSurfaceHigh
    val arcColor = if (score != null && bandName != null) {
        bandColor(RiskBand.valueOf(bandName))
    } else {
        KernelTextSecondary
    }
    val sweep = ((score ?: 0).coerceIn(0, 100) / 100f) * 270f

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = strokeWidth()
            val inset = stroke / 2
            val arcSize = Size(size.width - stroke, size.height - stroke)
            // 270-degree gauge: 135deg start, drawn clockwise
            drawArc(
                color = track,
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round),
            )
            if (score != null) {
                drawArc(
                    color = arcColor,
                    startAngle = 135f,
                    sweepAngle = sweep,
                    useCenter = false,
                    topLeft = Offset(inset, inset),
                    size = arcSize,
                    style = Stroke(width = stroke, cap = StrokeCap.Round),
                )
            }
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = if (score == null) {
                    "No score"
                } else {
                    "${score.coerceIn(0, 100)}/100"
                },
                style = MaterialTheme.typography.headlineMedium,
                color = KernelTextPrimary,
            )
            Text(
                text = bandName ?: "not analyzed yet",
                style = MaterialTheme.typography.labelLarge,
                color = arcColor,
            )
        }
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.strokeWidth(): Float = 14.dp.toPx()

/**
 * Horizontal severity bar chart from real counts. Zero-severity rows stay
 * visible with a zero count (honest absence, not hiding). Bars are
 * proportional to the row with the highest count.
 */
@Composable
fun SeverityBarChart(
    counts: Map<Severity, Int>,
    modifier: Modifier = Modifier,
) {
    val max = (counts.values.maxOrNull() ?: 0).coerceAtLeast(1)
    Column(modifier = modifier, verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(6.dp)) {
        Severity.entries.forEach { severity ->
            val count = counts[severity] ?: 0
            BarRow(
                label = severity.name.lowercase().padEnd(6),
                count = count,
                fraction = count.toFloat() / max,
                color = severityColor(severity),
            )
        }
    }
}

/** Findings-by-category horizontal bars from real category slugs. */
@Composable
fun CategoryBarChart(
    counts: Map<String, Int>,
    modifier: Modifier = Modifier,
) {
    val max = (counts.values.maxOrNull() ?: 0)
    Column(modifier = modifier, verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(6.dp)) {
        if (counts.isEmpty()) {
            Text(
                text = "No findings recorded — nothing to chart.",
                style = MaterialTheme.typography.bodyMedium,
                color = KernelTextSecondary,
            )
        }
        counts.forEach { (category, count) ->
            BarRow(
                label = category,
                count = count,
                fraction = count.toFloat() / max.coerceAtLeast(1),
                color = KernelCyan,
            )
        }
    }
}

@Composable
private fun BarRow(label: String, count: Int, fraction: Float, color: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(26.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = KernelTextSecondary,
            modifier = Modifier.width(96.dp),
        )
        Spacer(Modifier.width(8.dp))
        Canvas(
            modifier = Modifier
                .weight(1f)
                .height(12.dp),
        ) {
            drawRoundRect(
                color = KernelSurfaceHigh,
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()),
            )
            if (fraction > 0f) {
                drawRoundRect(
                    color = color,
                    size = Size(size.width * fraction.coerceIn(0f, 1f), size.height),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()),
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        Text(
            text = count.toString(),
            style = HashStyle,
            color = KernelTextPrimary,
            textAlign = TextAlign.Right,
            modifier = Modifier.width(28.dp),
        )
    }
}
