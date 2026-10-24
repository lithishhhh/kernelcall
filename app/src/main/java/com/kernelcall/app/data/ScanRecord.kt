package com.kernelcall.app.data

/**
 * A single static scan of an APK file. Identity fields (Phase 1) plus
 * analysis-linkage flags added in store schema v2; old payloads read with
 * defaults.
 */
data class ScanRecord(
    val id: Long,
    val fileName: String,
    val sizeBytes: Long,
    val sha256: String,
    val scannedAt: Long,
    val cacheStored: Boolean = false,
)
