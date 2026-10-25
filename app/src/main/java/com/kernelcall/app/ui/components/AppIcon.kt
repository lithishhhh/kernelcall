package com.kernelcall.app.ui.components

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Renders an installed app's launcher icon, loaded once per package on the
 * IO dispatcher and cached in memory (scaled to a small fixed size — the
 * app never uploads or re-distributes any byte of another app).
 */
object AppIconLoader {

    private const val ICON_SIZE = 96
    private val cache = HashMap<String, ImageBitmap>()

    fun load(context: Context, packageName: String): ImageBitmap? {
        synchronized(cache) { cache[packageName]?.let { return it } }
        return try {
            val drawable = context.packageManager.getApplicationIcon(packageName)
            val bitmap = Bitmap.createBitmap(ICON_SIZE, ICON_SIZE, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, ICON_SIZE, ICON_SIZE)
            drawable.draw(canvas)
            val image = bitmap.asImageBitmap()
            synchronized(cache) { cache[packageName] = image }
            image
        } catch (_: Exception) {
            null
        }
    }
}

@Composable
fun AppIcon(
    packageName: String,
    modifier: Modifier = Modifier,
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var icon by remember(packageName) { mutableStateOf<ImageBitmap?>(null) }
    LaunchedEffect(packageName) {
        icon = withContext(Dispatchers.IO) { AppIconLoader.load(context, packageName) }
    }
    val current = icon
    if (current != null) {
        Image(
            bitmap = current,
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = modifier.size(48.dp),
        )
    } else {
        ShieldIcon(modifier = modifier.size(48.dp))
    }
}
