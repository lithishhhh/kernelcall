package com.kernelcall.app.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.navArgument
import androidx.navigation.NavType
import com.kernelcall.app.ui.screens.DashboardScreen
import com.kernelcall.app.ui.screens.HistoryScreen
import com.kernelcall.app.ui.screens.ResultsScreen
import com.kernelcall.app.ui.screens.ScanScreen

object Routes {
    const val DASHBOARD = "dashboard"
    const val SCAN = "scan"
    const val HISTORY = "history"
    const val RESULTS = "results/{recordId}"
    fun results(id: Long) = "results/$id"
}

private data class Tab(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

private val tabs = listOf(
    Tab(Routes.DASHBOARD, "Dashboard", Icons.Filled.Home),
    Tab(Routes.SCAN, "Scan", Icons.Filled.Search),
    Tab(Routes.HISTORY, "History", Icons.AutoMirrored.Filled.List),
)

@Composable
fun KernelCallApp(scanViewModel: ScanViewModel = viewModel()) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route

    val showBottomBar = tabs.any { it.route == currentRoute }

    Scaffold(
        bottomBar = {
            if (showBottomBar) {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                ) {
                    tabs.forEach { tab ->
                        val selected = currentRoute == tab.route
                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                navController.navigate(tab.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = {
                                Icon(
                                    imageVector = tab.icon,
                                    contentDescription = tab.label,
                                )
                            },
                            label = { Text(tab.label) },
                        )
                    }
                }
            }
        },
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Routes.DASHBOARD,
            modifier = Modifier.padding(innerPadding),
        ) {
            composable(Routes.DASHBOARD) {
                DashboardScreen(
                    records = scanViewModel.historyStore.records.collectAsState().value,
                    onScanSelected = { navController.navigate(Routes.SCAN) },
                    onRecordSelected = { id -> navController.navigate(Routes.results(id)) },
                )
            }
            composable(Routes.SCAN) {
                ScanScreen(
                    viewModel = scanViewModel,
                    onOpenResults = { navController.navigate(Routes.results(it)) },
                )
            }
            composable(Routes.HISTORY) {
                HistoryScreen(
                    records = scanViewModel.historyStore.records.collectAsState().value,
                    onRecordSelected = { id -> navController.navigate(Routes.results(id)) },
                )
            }
            composable(
                route = Routes.RESULTS,
                arguments = listOf(navArgument("recordId") { type = NavType.LongType }),
            ) { entry ->
                val recordId = entry.arguments?.getLong("recordId") ?: -1L
                ResultsScreen(
                    store = scanViewModel.historyStore,
                    recordId = recordId,
                    loadReport = scanViewModel::loadReportFor,
                    onBack = { navController.popBackStack() },
                )
            }
        }
    }
}
