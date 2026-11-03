package org.beacon.app

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.beacon.mobile.Listener
import org.beacon.mobile.Node

/**
 * What the UI shows, shared between MeshService (which owns the Go node) and
 * the activity. Messages live only in memory.
 */
object MeshState : Listener {
    data class Me(val nickname: String, val fingerprint: String)

    private val conversations = Conversations()
    private val _messages = MutableStateFlow<Map<String, List<ChatMessage>>>(emptyMap())
    val messages: StateFlow<Map<String, List<ChatMessage>>> = _messages.asStateFlow()

    private val _peers = MutableStateFlow<List<PeerInfo>>(emptyList())
    val peers: StateFlow<List<PeerInfo>> = _peers.asStateFlow()

    private val _me = MutableStateFlow<Me?>(null)
    val me: StateFlow<Me?> = _me.asStateFlow()

    private val _links = MutableStateFlow(0)
    val links: StateFlow<Int> = _links.asStateFlow()

    private val _relayed = MutableStateFlow(0L)
    /** Packets this phone has passed on for others. */
    val relayed: StateFlow<Long> = _relayed.asStateFlow()

    private val _shares = MutableStateFlow<List<SharedFile>>(emptyList())
    /** Files announced nearby. */
    val shares: StateFlow<List<SharedFile>> = _shares.asStateFlow()

    private val _transfers = MutableStateFlow<List<Transfer>>(emptyList())
    val transfers: StateFlow<List<Transfer>> = _transfers.asStateFlow()

    @Volatile
    var node: Node? = null
        private set

    fun attach(node: Node, nickname: String) {
        this.node = node
        _me.value = Me(nickname, node.fingerprint())
    }

    fun detach() {
        node = null
        _peers.value = emptyList()
        _shares.value = emptyList()
        _transfers.value = emptyList()
        _links.value = 0
    }

    /** Clears everything held in memory, for a panic wipe. */
    fun wipe() {
        detach()
        _me.value = null
        synchronized(conversations) { conversations.clear() }
        _messages.value = emptyMap()
    }

    fun refresh(linkCount: Int) {
        val n = node ?: return
        _peers.value = parsePeers(n.peersJSON())
        _links.value = linkCount
        _relayed.value = parseRelayed(n.statsJSON())
        _shares.value = parseShares(n.sharesJSON())
        _transfers.value = parseTransfers(n.transfersJSON())
    }

    private fun record(m: ChatMessage) {
        synchronized(conversations) {
            conversations.add(m)
            _messages.value = conversations.keys().associateWith { conversations.messages(it) }
        }
    }

    /** Called by Go on its own threads. */
    override fun onMessage(fromFingerprint: String, nickname: String, channel: String, text: String, sentMillis: Long) {
        val conversation = if (channel.isEmpty()) dmKey(fromFingerprint) else channel
        record(ChatMessage(conversation, fromFingerprint, nickname, text, sentMillis, mine = false))
    }

    /** Where downloaded files are saved. */
    fun downloadsDir(context: Context): File =
        (context.getExternalFilesDir("Beacon") ?: File(context.filesDir, "downloads")).also { it.mkdirs() }

    /**
     * Copies the picked file into our storage (the torrent engine needs a
     * real path) and shares it. Returns an error message or null.
     */
    fun shareUri(context: Context, uri: Uri): String? {
        val n = node ?: return "Beacon is not running"
        return try {
            val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { c -> if (c.moveToFirst()) c.getString(0) else null } ?: "shared-file"
            val dir = File(context.filesDir, "shares").also { it.mkdirs() }
            val file = File(dir, safeFileName(name))
            context.contentResolver.openInputStream(uri)?.use { input ->
                file.outputStream().use { input.copyTo(it) }
            } ?: return "Could not read the file"
            n.shareFile(file.path)
            null
        } catch (e: Exception) {
            e.message ?: "Could not share the file"
        }
    }

    /** Starts fetching a file announced nearby. Returns an error message or null. */
    fun getFile(infoHash: String): String? {
        val n = node ?: return "Beacon is not running"
        return try {
            n.getFile(infoHash)
            null
        } catch (e: Exception) {
            e.message ?: "Could not fetch the file"
        }
    }

    /** Sends text to a conversation; returns an error message or null. */
    fun send(conversation: String, text: String): String? {
        val n = node ?: return "Beacon is not running"
        val me = _me.value ?: return "Beacon is not running"
        return try {
            if (isDm(conversation)) n.sendDirect(dmFingerprint(conversation), text)
            else n.sendChannel(conversation, text)
            record(ChatMessage(conversation, me.fingerprint, me.nickname, text, System.currentTimeMillis(), mine = true))
            null
        } catch (e: Exception) {
            e.message ?: "could not send"
        }
    }
}
