package org.beacon.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.beacon.app.ui.BeaconApp

class MainActivity : ComponentActivity() {
    private lateinit var store: IdentityStore
    private var permissionsGranted by mutableStateOf(false)
    private var hasNickname by mutableStateOf(false)

    private val requestPermissions =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
            permissionsGranted = required().all(::granted)
            maybeStart()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = IdentityStore(this)
        hasNickname = store.nickname != null
        permissionsGranted = required().all(::granted)
        setContent {
            BeaconApp(
                needsNickname = !hasNickname,
                permissionsGranted = permissionsGranted,
                onNickname = ::setNickname,
                onRequestPermissions = { requestPermissions.launch(wanted().toTypedArray()) },
                onWipe = ::wipe,
            )
        }
        maybeStart()
    }

    /** Returns an error to show, or null once the nickname is saved. */
    private fun setNickname(name: String): String? {
        val trimmed = name.trim()
        runCatching { org.beacon.mobile.Mobile.checkNickname(trimmed) }.onFailure {
            return "Use 1 to 32 characters, no control characters"
        }
        store.nickname = trimmed
        hasNickname = true
        if (!permissionsGranted) requestPermissions.launch(wanted().toTypedArray())
        maybeStart()
        return null
    }

    private fun maybeStart() {
        if (hasNickname && permissionsGranted && MeshState.node == null) MeshService.start(this)
    }

    private fun wipe() {
        if (MeshState.node != null) {
            MeshService.wipe(this)
        } else {
            store.wipe()
            MeshState.wipe()
        }
        hasNickname = false
    }

    private fun granted(p: String) = checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED

    /** Permissions the mesh cannot run without. */
    private fun required(): List<String> =
        if (Build.VERSION.SDK_INT >= 31) {
            listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_CONNECT,
            )
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    /** Required permissions plus notifications, which are optional. */
    private fun wanted(): List<String> =
        required() + if (Build.VERSION.SDK_INT >= 33) listOf(Manifest.permission.POST_NOTIFICATIONS) else emptyList()
}
