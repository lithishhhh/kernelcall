package com.kernelcall.app.ui

import java.util.Locale

/** Small format helpers shared by the screens. */
object Formats {

    /** 1536 -> "1.5 KB", 2097152 -> "2.0 MB" (binary units, as file managers show). */
    fun size(bytes: Long): String {
        if (bytes < 0) return "Unknown size"
        val units = arrayOf("B", "KB", "MB", "GB")
        var value = bytes.toDouble()
        var unit = 0
        while (value >= 1024.0 && unit < units.lastIndex) {
            value /= 1024.0
            unit++
        }
        return if (unit == 0) "${bytes} B" else String.format(Locale.US, "%.1f %s", value, units[unit])
    }

    /** Splits a hash into 8-char chunks so it wraps nicely in the UI. */
    fun hashChunks(sha256: String): String =
        sha256.chunked(8).joinToString(" ")

    /** epoch millis -> "12 Oct 2026, 18:04" style label. */
    fun timestamp(millis: Long): String {
        if (millis <= 0) return "Unknown"
        val cal = java.util.Calendar.getInstance()
        cal.timeInMillis = millis
        val day = cal.get(java.util.Calendar.DAY_OF_MONTH).toString()
        val month = arrayOf(
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        )[cal.get(java.util.Calendar.MONTH)]
        val year = cal.get(java.util.Calendar.YEAR)
        val hour = cal.get(java.util.Calendar.HOUR_OF_DAY)
        val minute = cal.get(java.util.Calendar.MINUTE)
        return String.format(
            Locale.US, "%s %s %d, %02d:%02d", day, month, year, hour, minute,
        )
    }
}
