package org.beacon.app.wifi

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.annotation.RequiresApi
import java.net.Inet4Address
import java.net.NetworkInterface
import org.beacon.mobile.Groups
import org.beacon.mobile.Node

/**
 * Forms Wi-Fi Direct groups when the Go file service asks (Groups) and
 * reports back with Node.groupReady / groupFailed / groupGone. Which group to
 * host or join, and who may, is decided in Go; credentials arrive in
 * encrypted mesh messages. Groups use a known name and passphrase
 * (Android 10+), so joining needs no prompt on either phone.
 */
@SuppressLint("MissingPermission") // MeshService starts this only with the permissions granted
class WifiDirect(private val context: Context, private val node: Node) : Groups {
    private val manager: WifiP2pManager? = context.getSystemService(WifiP2pManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private var channel: WifiP2pManager.Channel? = null
    @Volatile private var inGroup = false
    @Volatile private var wanted: String? = null // network we are hosting or joining
    private var registered = false

    fun start() {
        val m = manager ?: return
        channel = m.initialize(context, Looper.getMainLooper(), null)
        val filter = IntentFilter(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
        registered = true
    }

    fun stop() {
        if (registered) runCatching { context.unregisterReceiver(receiver) }
        registered = false
        val m = manager ?: return
        val ch = channel ?: return
        m.removeGroup(ch, null)
        channel = null
    }

    // Called by Go on its own threads; Wi-Fi Direct work happens on the main thread.
    override fun hostGroup(network: String, passphrase: String) {
        main.post { form(network, passphrase, host = true) }
    }

    override fun joinGroup(network: String, passphrase: String) {
        main.post { form(network, passphrase, host = false) }
    }

    private fun form(network: String, passphrase: String, host: Boolean) {
        val m = manager
        val ch = channel
        if (m == null || ch == null) {
            node.groupFailed("Wi-Fi Direct is not available")
            return
        }
        if (Build.VERSION.SDK_INT < 29) {
            node.groupFailed("Wi-Fi Direct sharing needs Android 10 or later")
            return
        }
        val config = WifiP2pConfig.Builder()
            .setNetworkName(network)
            .setPassphrase(passphrase)
            .enablePersistentMode(false)
            .build()
        wanted = network
        val done = object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.i(TAG, if (host) "hosting $network" else "joining $network")
            }

            override fun onFailure(reason: Int) {
                Log.w(TAG, "forming the group failed: $reason")
                wanted = null
                node.groupFailed("Wi-Fi Direct error $reason")
            }
        }
        // One group at a time: leave any old one first.
        m.removeGroup(ch, object : WifiP2pManager.ActionListener {
            override fun onSuccess() = start(m, ch, config, host, done)
            override fun onFailure(reason: Int) = start(m, ch, config, host, done)
        })
    }

    @RequiresApi(29)
    private fun start(m: WifiP2pManager, ch: WifiP2pManager.Channel, config: WifiP2pConfig, host: Boolean,
                      done: WifiP2pManager.ActionListener) {
        if (host) m.createGroup(ch, config, done) else m.connect(ch, config, done)
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, intent: Intent) {
            val m = manager ?: return
            val ch = channel ?: return
            m.requestConnectionInfo(ch) { info ->
                if (info != null && info.groupFormed) {
                    if (wanted == null) return@requestConnectionInfo // not a group we asked for
                    if (info.isGroupOwner) {
                        ready(info.groupOwnerAddress?.hostAddress)
                    } else {
                        // A client's own address comes from DHCP, a moment
                        // after the group forms.
                        findOwnAddress(attempts = 20)
                    }
                } else if (inGroup) {
                    inGroup = false
                    wanted = null
                    Log.i(TAG, "left the group")
                    node.groupGone()
                }
            }
        }
    }

    private fun ready(ip: String?) {
        if (ip == null || inGroup) return
        inGroup = true
        Log.i(TAG, "in the group as $ip")
        node.groupReady(ip)
    }

    private fun findOwnAddress(attempts: Int) {
        val ip = p2pAddress()
        when {
            ip != null -> ready(ip)
            attempts > 0 -> main.postDelayed({ findOwnAddress(attempts - 1) }, 500)
            else -> node.groupFailed("no address on the Wi-Fi Direct group")
        }
    }

    /** This device's IPv4 address on the Wi-Fi Direct interface. */
    private fun p2pAddress(): String? = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && it.name.startsWith("p2p") }
            .flatMap { it.inetAddresses.toList() }
            .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
            ?.hostAddress
    }.getOrNull()

    private companion object {
        const val TAG = "BeaconWifi"
    }
}
