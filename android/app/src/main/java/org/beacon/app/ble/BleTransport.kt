package org.beacon.app.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.beacon.mobile.Link
import org.beacon.mobile.LinkHandler
import org.beacon.mobile.Mobile
import org.beacon.mobile.Node

/**
 * Carries mesh link frames over BLE, as docs/protocol-spec.md ("BLE links")
 * describes. Every device runs a GATT server and advertises; for each pair,
 * the device with the lower instance connects as client. Frames themselves
 * are opaque here: Go builds and checks them.
 *
 * MeshService creates this only after the Bluetooth permissions are granted.
 */
@SuppressLint("MissingPermission")
class BleTransport(private val context: Context, private val node: Node) {
    private val manager = context.getSystemService(BluetoothManager::class.java)
    private val serviceUuid = UUID.fromString(Mobile.BLEServiceUUID)
    private val framesUuid = UUID.fromString(Mobile.BLEFramesUUID)

    @Volatile private var instance: ByteArray = Mobile.newInstance()
    private var server: BluetoothGattServer? = null
    private var frames: BluetoothGattCharacteristic? = null
    private val servers = ConcurrentHashMap<String, ServerPeer>() // devices connected to our server
    private val serverMtu = ConcurrentHashMap<String, Int>()
    private val clients = ConcurrentHashMap<String, ClientPeer>() // our connections to their servers
    @Volatile private var running = false
    @Volatile private var wanted = false // start() was called and stop() was not
    private var watching = false

    /** Live links, for the UI. */
    val linkCount: Int get() = servers.size + clients.values.count { it.link != null }

    /**
     * Turning Bluetooth off (directly or by flight mode) discards our GATT
     * server, advertisement and scan without any callback, so we drop the
     * links when it goes off and set everything up again when it comes back.
     */
    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, intent: Intent) {
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)) {
                BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> if (running) {
                    Log.i(TAG, "Bluetooth turned off; dropping links")
                    teardown()
                }
                BluetoothAdapter.STATE_ON -> if (wanted && !running) {
                    Log.i(TAG, "Bluetooth is back on; restarting")
                    bringUp()
                }
            }
        }
    }

    @Synchronized
    fun start() {
        wanted = true
        if (!watching) {
            val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(stateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                context.registerReceiver(stateReceiver, filter)
            }
            watching = true
        }
        bringUp()
    }

    @Synchronized
    private fun bringUp() {
        if (running) return
        val adapter = manager.adapter ?: return
        if (!adapter.isEnabled) {
            Log.w(TAG, "Bluetooth is off; waiting for it to come on")
            return
        }
        running = true
        Log.i(TAG, "starting GATT server, advertising and scanning")
        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val ch = BluetoothGattCharacteristic(
            framesUuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        ch.addDescriptor(
            BluetoothGattDescriptor(CCCD, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE),
        )
        service.addCharacteristic(ch)
        frames = ch
        server = manager.openGattServer(context, serverCallback)?.also { it.addService(service) }
        // Advertising starts once the service is added (onServiceAdded).
        scan(true)
    }

    @Synchronized
    fun stop() {
        wanted = false
        if (watching) {
            runCatching { context.unregisterReceiver(stateReceiver) }
            watching = false
        }
        teardown()
    }

    /** Drops every link and releases the radio; safe while Bluetooth is going away. */
    @Synchronized
    private fun teardown() {
        running = false
        runCatching { scan(false) }
        runCatching { manager.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
        clients.values.forEach { runCatching { it.shut() } }
        clients.clear()
        servers.values.forEach { it.link.down() }
        servers.clear()
        serverMtu.clear()
        runCatching { server?.close() }
        server = null
    }

    /** Picks a new instance and re-advertises, so it cannot track us for long. */
    fun rotateInstance() {
        if (!running) return
        instance = Mobile.newInstance()
        runCatching { manager.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
        advertise()
    }

    private fun advertise() {
        val advertiser = manager.adapter?.bluetoothLeAdvertiser ?: return
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false) // the name could identify the owner
            .addServiceUuid(ParcelUuid(serviceUuid))
            .build()
        val scanResponse = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceData(ParcelUuid(serviceUuid), instance)
            .build()
        advertiser.startAdvertising(settings, data, scanResponse, advertiseCallback)
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            Log.w(TAG, "advertising failed: $errorCode")
        }
    }

    private fun scan(on: Boolean) {
        val scanner = manager.adapter?.bluetoothLeScanner ?: return
        if (!on) {
            runCatching { scanner.stopScan(scanCallback) }
            return
        }
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(serviceUuid)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_BALANCED).build()
        scanner.startScan(listOf(filter), settings, scanCallback)
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val theirs = result.scanRecord?.getServiceData(ParcelUuid(serviceUuid)) ?: return
            val addr = result.device.address
            if (!running || !Mobile.shouldConnect(instance, theirs)) return
            if (clients.containsKey(addr) || servers.containsKey(addr) || clients.size >= MAX_CLIENTS) return
            val peer = ClientPeer(result.device)
            if (clients.putIfAbsent(addr, peer) == null) peer.connect()
        }

        override fun onScanFailed(errorCode: Int) {
            Log.w(TAG, "scan failed: $errorCode")
        }
    }

    /** Runs one GATT operation at a time and waits for its callback. */
    private class OpGate {
        @Volatile private var latch: CountDownLatch? = null
        @Volatile private var status = 0

        @Synchronized
        fun run(start: () -> Boolean): Int {
            val l = CountDownLatch(1)
            latch = l
            if (!start()) return -1
            if (!l.await(OP_TIMEOUT_MS, TimeUnit.MILLISECONDS)) return -2
            return status
        }

        fun done(s: Int) {
            status = s
            latch?.countDown()
        }
    }

    /** A device connected to our GATT server; we send it notifications. */
    private inner class ServerPeer(val device: BluetoothDevice) : LinkHandler {
        lateinit var link: Link
        val gate = OpGate()

        override fun sendFrame(frame: ByteArray) {
            val srv = server ?: throw IllegalStateException("server closed")
            val ch = frames ?: throw IllegalStateException("server closed")
            val s = gate.run {
                if (Build.VERSION.SDK_INT >= 33) {
                    srv.notifyCharacteristicChanged(device, ch, false, frame) == BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION")
                    synchronized(ch) {
                        ch.value = frame
                        srv.notifyCharacteristicChanged(device, ch, false)
                    }
                }
            }
            if (s != BluetoothGatt.GATT_SUCCESS) throw IllegalStateException("notify failed: $s")
        }

        /** Go gave up on the link (it went silent): forget it and disconnect. */
        override fun close() {
            if (servers.remove(device.address, this)) Log.i(TAG, "link dropped by the mesh, $linkCount links")
            server?.cancelConnection(device)
        }
    }

    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (status == BluetoothGatt.GATT_SUCCESS && running) advertise()
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                servers.remove(device.address)?.link?.let {
                    it.down()
                    Log.i(TAG, "link down (they disconnected, status $status), $linkCount links")
                }
                serverMtu.remove(device.address)
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            serverMtu[device.address] = mtu
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray,
        ) {
            if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            if (descriptor.uuid != CCCD) return
            val addr = device.address
            if (value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
                // The client subscribed: the link is up.
                val peer = ServerPeer(device)
                val mtu = (serverMtu[addr] ?: DEFAULT_ATT_MTU) - ATT_HEADER
                peer.link = runCatching { node.linkUp(addr, mtu.toLong(), peer) }.getOrNull() ?: return
                servers.put(addr, peer)?.link?.down()
                Log.i(TAG, "link up (they connected), mtu $mtu, $linkCount links")
            } else {
                servers.remove(addr)?.link?.down()
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray,
        ) {
            if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            if (characteristic.uuid == framesUuid && !preparedWrite) servers[device.address]?.link?.receive(value)
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            servers[device.address]?.gate?.done(status)
        }
    }

    /** Our connection to another device's server; we write to it. */
    private inner class ClientPeer(val device: BluetoothDevice) : LinkHandler {
        @Volatile var link: Link? = null
        @Volatile private var gatt: BluetoothGatt? = null
        @Volatile private var mtu = DEFAULT_ATT_MTU
        private val gate = OpGate()

        fun connect() {
            gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        }

        fun shut() {
            link?.down()
            link = null
            gatt?.let {
                it.disconnect()
                it.close()
            }
            gatt = null
        }

        private fun characteristic(g: BluetoothGatt) = g.getService(serviceUuid)?.getCharacteristic(framesUuid)

        override fun sendFrame(frame: ByteArray) {
            val g = gatt ?: throw IllegalStateException("disconnected")
            val ch = characteristic(g) ?: throw IllegalStateException("no frames characteristic")
            val s = gate.run { write(g, ch, frame, BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) }
            if (s == BluetoothGatt.GATT_SUCCESS) return
            // Some stacks refuse write without response; fall back once.
            val s2 = gate.run { write(g, ch, frame, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) }
            if (s2 != BluetoothGatt.GATT_SUCCESS) throw IllegalStateException("write failed: $s2")
        }

        private fun write(g: BluetoothGatt, ch: BluetoothGattCharacteristic, frame: ByteArray, type: Int): Boolean =
            if (Build.VERSION.SDK_INT >= 33) {
                g.writeCharacteristic(ch, frame, type) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                run {
                    ch.writeType = type
                    ch.value = frame
                    g.writeCharacteristic(ch)
                }
            }

        /** Go gave up on the link (it went silent): forget it and disconnect. */
        override fun close() {
            if (clients.remove(device.address, this)) Log.i(TAG, "link dropped by the mesh, $linkCount links")
            gatt?.disconnect()
        }

        private val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> g.discoverServices()
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        val wasUp = link != null
                        clients.remove(device.address, this@ClientPeer)
                        shut()
                        if (wasUp) Log.i(TAG, "link down (we lost them, status $status), $linkCount links")
                    }
                }
            }

            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS || characteristic(g) == null) {
                    g.disconnect()
                    return
                }
                g.requestMtu(REQUESTED_MTU)
            }

            override fun onMtuChanged(g: BluetoothGatt, newMtu: Int, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS) mtu = newMtu
                val ch = characteristic(g) ?: return
                val cccd = ch.getDescriptor(CCCD) ?: return
                g.setCharacteristicNotification(ch, true)
                val enable = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                if (Build.VERSION.SDK_INT >= 33) {
                    g.writeDescriptor(cccd, enable)
                } else {
                    @Suppress("DEPRECATION")
                    cccd.value = enable
                    @Suppress("DEPRECATION")
                    g.writeDescriptor(cccd)
                }
            }

            override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    g.disconnect()
                    return
                }
                link = runCatching { node.linkUp(device.address, (mtu - ATT_HEADER).toLong(), this@ClientPeer) }.getOrNull()
                if (link == null) g.disconnect() else Log.i(TAG, "link up (we connected), mtu ${mtu - ATT_HEADER}, $linkCount links")
            }

            override fun onCharacteristicWrite(g: BluetoothGatt, ch: BluetoothGattCharacteristic, status: Int) {
                gate.done(status)
            }

            override fun onCharacteristicChanged(g: BluetoothGatt, ch: BluetoothGattCharacteristic, value: ByteArray) {
                if (ch.uuid == framesUuid) link?.receive(value)
            }

            @Deprecated("Used before Android 13")
            override fun onCharacteristicChanged(g: BluetoothGatt, ch: BluetoothGattCharacteristic) {
                if (Build.VERSION.SDK_INT < 33 && ch.uuid == framesUuid) {
                    @Suppress("DEPRECATION")
                    link?.receive(ch.value)
                }
            }
        }
    }

    private companion object {
        const val TAG = "BeaconBle"
        val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        const val REQUESTED_MTU = 517
        const val DEFAULT_ATT_MTU = 23
        const val ATT_HEADER = 3
        const val MAX_CLIENTS = 6 // phones manage roughly 7 connections in all
        const val OP_TIMEOUT_MS = 2000L
    }
}
