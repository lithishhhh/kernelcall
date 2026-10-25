package com.kernelcall.app

import com.kernelcall.app.ui.Formats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks the scan-timestamp formatting used by the Dashboard/Results screens.
 * Regression: the format string used "%d" for a String day argument, which
 * crashed the Dashboard as soon as any real scan record existed.
 */
class FormatsTest {

    @Test
    fun `timestamp renders day month year time without crashing`() {
        // 2023-11-14 03:00 UTC; formatted in device default zone — verify shape.
        val rendered = Formats.timestamp(1_700_000_000_000)
        assertTrue(Regex("""^\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2}$""").matches(rendered))
    }

    @Test
    fun `non-positive timestamps render as Unknown`() {
        assertEquals("Unknown", Formats.timestamp(0))
        assertEquals("Unknown", Formats.timestamp(-5))
    }
}
