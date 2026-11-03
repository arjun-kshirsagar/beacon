package org.beacon.app

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
