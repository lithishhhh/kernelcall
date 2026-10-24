package com.kernelcall.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.kernelcall.app.ui.KernelCallApp
import com.kernelcall.app.ui.theme.KernelCallTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            KernelCallTheme {
                KernelCallApp()
            }
        }
    }
}
