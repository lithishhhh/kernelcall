package com.kernelcall.app.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kernelcall.app.core.dashboard.DashboardStats
import com.kernelcall.app.core.dashboard.DashboardStatsBuilder
import com.kernelcall.app.core.storage.ReportStore
import com.kernelcall.app.data.ScanHistoryStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

/**
 * Phase 5 dashboard aggregation: pure [DashboardStatsBuilder] work is done
 * on IO whenever scan history OR the set of stored reports changes. Values
 * are real persisted data only.
 */
class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    private val reportStore: ReportStore = ReportStore.get(application)
    private val historyStore: ScanHistoryStore = ScanHistoryStore.get(application)

    private val _stats = MutableStateFlow<DashboardStats?>(null)
    val stats: StateFlow<DashboardStats?> = _stats.asStateFlow()

    private val _loading = MutableStateFlow(true)
    val loading: StateFlow<Boolean> = _loading.asStateFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            combine(
                historyStore.records,
                reportStore.savedVersion,
            ) { records, _ -> records }.collect { records ->
                _stats.value = DashboardStatsBuilder.build(records) { sha ->
                    reportStore.load(sha)
                }
                _loading.value = false
            }
        }
    }
}
