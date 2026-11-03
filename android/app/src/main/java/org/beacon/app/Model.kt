package org.beacon.app

import org.json.JSONArray
import org.json.JSONObject

/** The public channel everyone joins. */
const val GENERAL = "#general"

/** A conversation is a channel such as "#general" or "dm:<fingerprint>". */
fun dmKey(fingerprint: String) = "dm:$fingerprint"

fun isDm(conversation: String) = conversation.startsWith("dm:")

fun dmFingerprint(conversation: String) = conversation.removePrefix("dm:")

data class ChatMessage(
    val conversation: String,
    val fromFingerprint: String,
    val nickname: String,
    val text: String,
    val sentMillis: Long,
    val mine: Boolean,
)

data class PeerInfo(val fingerprint: String, val nickname: String, val lastSeenMillis: Long)

/** Fingerprints are shown in groups of four, short form first 16 digits. */
fun shortFingerprint(fp: String) = fp.take(16).chunked(4).joinToString(" ")

/** Parses Node.peersJSON(). Malformed entries are skipped. */
fun parsePeers(json: String): List<PeerInfo> {
    val arr = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
    return (0 until arr.length()).mapNotNull { i ->
        val o = arr.optJSONObject(i) ?: return@mapNotNull null
        val fp = o.optString("fingerprint")
        if (fp.length != 64) return@mapNotNull null
        PeerInfo(fp, o.optString("nickname", "?"), o.optLong("lastSeenMillis"))
    }
}

/**
 * Messages held in memory, by conversation. Nothing is written to disk: by
 * design, history disappears when the app stops.
 */
class Conversations(private val maxPerConversation: Int = 500) {
    private val byKey = LinkedHashMap<String, MutableList<ChatMessage>>()

    fun add(m: ChatMessage) {
        val list = byKey.getOrPut(m.conversation) { mutableListOf() }
        list.add(m)
        if (list.size > maxPerConversation) list.subList(0, list.size - maxPerConversation).clear()
    }

    fun messages(conversation: String): List<ChatMessage> = byKey[conversation]?.toList() ?: emptyList()

    /** #general first, then conversations by most recent message. */
    fun keys(): List<String> {
        val others = byKey.keys.filter { it != GENERAL }
            .sortedByDescending { byKey[it]?.lastOrNull()?.sentMillis ?: 0 }
        return listOf(GENERAL) + others
    }

    fun clear() = byKey.clear()
}

/** Reads the relayed-packet count from Node.statsJSON(). */
fun parseRelayed(json: String): Long = runCatching { JSONObject(json).optLong("Relayed") }.getOrDefault(0)
