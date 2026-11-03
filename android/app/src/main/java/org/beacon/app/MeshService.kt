package org.beacon.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.beacon.app.ble.BleTransport
import org.beacon.app.wifi.WifiDirect
import org.beacon.mobile.Mobile
import org.beacon.mobile.Node

/**
 * Runs the Go mesh node and the BLE transport in a foreground service, so the
 * phone keeps relaying for others while the screen is off.
 */
class MeshService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var node: Node? = null
    private var ble: BleTransport? = null
    private var wifi: WifiDirect? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startInForeground()
        val store = IdentityStore(this)
        val nickname = store.nickname
        if (nickname == null) {
            stopSelf()
            return
        }
        try {
            val n = Mobile.newNode(store.loadOrCreate(), nickname, MeshState)
            n.start()
            node = n
            MeshState.attach(n, nickname)
            ble = BleTransport(this, n).also { it.start() }
            wifi = WifiDirect(this, n).also { it.start() }
            n.enableFiles(MeshState.downloadsDir(this).path, wifi)
        } catch (e: Exception) {
            Log.e(TAG, "starting the mesh", e)
            stopSelf()
            return
        }
        scope.launch {
            var ticks = 0
            while (isActive) {
                MeshState.refresh(ble?.linkCount ?: 0)
                delay(1000)
                if (++ticks % ROTATE_SECONDS == 0) ble?.rotateInstance()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_WIPE) {
            wipe()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        wifi?.stop()
        ble?.stop()
        node?.stop()
        MeshState.detach()
        super.onDestroy()
    }

    /** Panic wipe: drop every key and message, then stop. */
    private fun wipe() {
        wifi?.stop()
        wifi = null
        ble?.stop()
        ble = null
        node?.wipe()
        node = null
        IdentityStore(this).wipe()
        MeshState.wipe()
        stopSelf()
    }

    private fun startInForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW),
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(R.drawable.ic_beacon)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 29) {
            var type = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            // Android 10 and 11 deliver BLE scan results only to apps with
            // location access, and grant "while in use" access to a background
            // app only through a location foreground service. Without this, a
            // scan started with the screen off (or after Bluetooth comes back)
            // finds nobody. Android 12+ scans with BLUETOOTH_SCAN instead.
            if (Build.VERSION.SDK_INT <= 30 &&
                checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
            ) {
                type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
            }
            startForeground(NOTIFICATION_ID, notification, type)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        private const val TAG = "BeaconMesh"
        private const val CHANNEL = "mesh"
        private const val NOTIFICATION_ID = 1
        private const val ROTATE_SECONDS = 15 * 60
        private const val ACTION_WIPE = "org.beacon.app.WIPE"

        fun start(context: Context) {
            context.startForegroundService(Intent(context, MeshService::class.java))
        }

        fun wipe(context: Context) {
            context.startService(Intent(context, MeshService::class.java).setAction(ACTION_WIPE))
        }
    }
}
