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

/** A file someone nearby announced. */
data class SharedFile(
    val infoHash: String,
    val name: String,
    val size: Long,
    val from: String,
    val sources: Int,
    val have: Boolean,
)

/** A file we share, fetch or seed. from maps sender IP to verified bytes. */
data class Transfer(
    val infoHash: String,
    val name: String,
    val state: String,
    val pieces: Int,
    val totalPieces: Int,
    val peers: Int,
    val uploaded: Long,
    val from: Map<String, Long>,
    val path: String,
    val error: String,
) {
    val progress: Float get() = if (totalPieces == 0) 0f else pieces.toFloat() / totalPieces
}

/** Parses Node.sharesJSON(). */
fun parseShares(json: String): List<SharedFile> {
    val arr = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
    return (0 until arr.length()).mapNotNull { i ->
        val o = arr.optJSONObject(i) ?: return@mapNotNull null
        val ih = o.optString("infoHash")
        if (ih.length != 40) return@mapNotNull null
        SharedFile(ih, o.optString("name"), o.optLong("size"), o.optString("from"), o.optInt("sources"),
            o.optBoolean("have"))
    }
}

/** Parses Node.transfersJSON(). */
fun parseTransfers(json: String): List<Transfer> {
    val arr = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
    return (0 until arr.length()).mapNotNull { i ->
        val o = arr.optJSONObject(i) ?: return@mapNotNull null
        val from = o.optJSONObject("from")?.let { f -> f.keys().asSequence().associateWith { f.optLong(it) } } ?: emptyMap()
        Transfer(o.optString("infoHash"), o.optString("name"), o.optString("state"), o.optInt("pieces"),
            o.optInt("totalPieces"), o.optInt("peers"), o.optLong("uploaded"), from, o.optString("path"),
            o.optString("error"))
    }
}

/** Human-readable size. */
fun formatSize(bytes: Long): String = when {
    bytes >= 1L shl 30 -> "%.1f GB".format(bytes / (1L shl 30).toDouble())
    bytes >= 1L shl 20 -> "%.1f MB".format(bytes / (1L shl 20).toDouble())
    bytes >= 1L shl 10 -> "%.1f KB".format(bytes / (1L shl 10).toDouble())
    else -> "$bytes B"
}

/** A file name safe to create in our own directory. */
fun safeFileName(name: String): String {
    val cleaned = name.replace(Regex("[/\\\\:*?\"<>|\\p{Cntrl}]"), "_").trim().trimStart('.')
    return cleaned.take(120).ifEmpty { "shared-file" }
}
