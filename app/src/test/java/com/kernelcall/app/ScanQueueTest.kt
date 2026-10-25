package com.kernelcall.app

import com.kernelcall.app.core.installed.QueueItemStatus
import com.kernelcall.app.core.installed.ScanQueue
import com.kernelcall.app.core.installed.ScanQueueItem
import com.kernelcall.app.core.installed.ScanQueueState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure queue state-machine behavior for installed-app scanning. */
class ScanQueueTest {

    private fun item(pkg: String) = ScanQueueItem(pkg, pkg, QueueItemStatus.PENDING)

    @Test
    fun `enqueue adds fresh pending items and activates them`() {
        val after = ScanQueue.enqueue(ScanQueueState(), listOf(item("a"), item("b")))
        assertEquals(2, after.items.size)
        assertTrue(after.items.all { it.status == QueueItemStatus.PENDING })
        assertEquals(2, after.activePackages.size)
        assertTrue(after.hasActiveWork)
    }

    @Test
    fun `enqueue skips packages already queued or running`() {
        val base = ScanQueue.enqueue(ScanQueueState(), listOf(item("a"), item("b")))
        val running = ScanQueue.markRunning(base, "a")
        val after = ScanQueue.enqueue(running, listOf(item("a"), item("c")))
        // "a" is running -> skipped; "b" not re-requested; only "c" is added
        assertEquals(3, after.items.size)
        assertEquals(listOf("a", "b", "c"), after.items.map { it.packageName })
    }

    @Test
    fun `enqueue skips unreadable packages`() {
        val base = ScanQueue.enqueue(ScanQueueState(), listOf(item("a")))
        val failed = ScanQueue.fail(base, "a", QueueItemStatus.UNREADABLE, "too large")
        val after = ScanQueue.enqueue(failed, listOf(item("a")))
        // nothing added: unreadable stays unreadable, honest non-repetition
        assertEquals(1, after.items.size)
        assertTrue(after.items.all { it.status == QueueItemStatus.UNREADABLE })
    }

    @Test
    fun `fingerprint progress is bounded to the 0-4 percent band`() {
        val base = ScanQueue.enqueue(ScanQueueState(), listOf(item("a")))
        val halfway = ScanQueue.fingerprintProgress(base, "a", 500, 1000)
        assertEquals(2, halfway.items.first().percent)
        assertTrue(halfway.items.first().stage.contains("500 B"))
        val done = ScanQueue.fingerprintProgress(halfway, "a", 1000, 1000)
        assertEquals(4, done.items.first().percent)
        // unknown total must stay honest at 0 percent with byte-only stage
        val noTotal = ScanQueue.fingerprintProgress(base, "a", 750, null)
        assertEquals(0, noTotal.items.first().percent)
        assertTrue(noTotal.items.first().stage.contains("750 B"))
    }

    @Test
    fun `analysis progress is monotonic and bounded to 4-99`() {
        val base = ScanQueue.enqueue(ScanQueueState(), listOf(item("a")))
        val p60 = ScanQueue.analysisProgress(base, "a", 60, "Scanning dex strings")
        val p25 = ScanQueue.analysisProgress(p60, "a", 25, "Parsing Android manifest")
        val first = p60.items.first().percent
        val second = p25.items.first().percent
        assertTrue(second >= first)
        assertEquals(60, second)
        assertTrue(p60.items.first().stage == "Scanning dex strings")
    }

    @Test
    fun `complete records score band recordId and releases the package`() {
        val base = ScanQueue.enqueue(ScanQueueState(), listOf(item("a")))
        val done = ScanQueue.complete(base, "a", "abc123", 55, "ELEVATED", 42L)
        val doneItem = done.items.first()
        assertEquals(QueueItemStatus.DONE, doneItem.status)
        assertEquals(100, doneItem.percent)
        assertEquals("abc123", doneItem.sha256)
        assertEquals(55, doneItem.score)
        assertEquals("ELEVATED", doneItem.band)
        assertEquals(42L, doneItem.recordId)
        assertFalse(done.hasActiveWork)
        assertNull(doneItem.message)
    }

    @Test
    fun `error statuses carry the real reason`() {
        val base = ScanQueue.enqueue(ScanQueueState(), listOf(item("a")))
        val failed = ScanQueue.fail(base, "a", QueueItemStatus.ERROR, "analysis crashed")
        assertEquals(QueueItemStatus.ERROR, failed.items.first().status)
        assertEquals("analysis crashed", failed.items.first().message)
        assertFalse(failed.hasActiveWork)
    }

    @Test
    fun `cancelPending drops only pending items`() {
        val base = ScanQueue.enqueue(ScanQueueState(), listOf(item("a"), item("b"), item("c")))
        val running = ScanQueue.markRunning(base, "a")
        val done = ScanQueue.complete(running, "a", "s", 10, "LOW", 1L)
        val cancelled = ScanQueue.cancelPending(done)
        assertEquals(1, cancelled.items.size) // only DONE remains
        assertFalse(cancelled.hasActiveWork)
    }
}
