package org.beacon.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelTest {
    private val fpA = "a".repeat(64)
    private val fpB = "b".repeat(64)

    @Test
    fun parsesPeersFromGo() {
        val json = """[{"fingerprint":"$fpA","nickname":"alice","lastSeenMillis":42},
            {"fingerprint":"short","nickname":"bad"}, 7,
            {"fingerprint":"$fpB","nickname":"bob","lastSeenMillis":43}]"""
        val peers = parsePeers(json)
        assertEquals(listOf(PeerInfo(fpA, "alice", 42), PeerInfo(fpB, "bob", 43)), peers)
        assertTrue(parsePeers("not json").isEmpty())
        assertTrue(parsePeers("[]").isEmpty())
    }

    @Test
    fun conversationsCapAndOrder() {
        val c = Conversations(maxPerConversation = 3)
        for (i in 1..5) c.add(ChatMessage(GENERAL, fpA, "alice", "m$i", i.toLong(), mine = false))
        assertEquals(listOf("m3", "m4", "m5"), c.messages(GENERAL).map { it.text })

        c.add(ChatMessage(dmKey(fpB), fpB, "bob", "old", 10, mine = false))
        c.add(ChatMessage(dmKey(fpA), fpA, "alice", "new", 20, mine = false))
        // #general always first, then the most recent conversation.
        assertEquals(listOf(GENERAL, dmKey(fpA), dmKey(fpB)), c.keys())
        c.clear()
        assertEquals(listOf(GENERAL), c.keys())
    }

    @Test
    fun conversationKeys() {
        assertTrue(isDm(dmKey(fpA)))
        assertEquals(fpA, dmFingerprint(dmKey(fpA)))
        assertEquals("aaaa aaaa aaaa aaaa", shortFingerprint(fpA))
    }

    @Test
    fun readsRelayedCount() {
        assertEquals(12L, parseRelayed("""{"Links":2,"Relayed":12}"""))
        assertEquals(0L, parseRelayed("garbage"))
    }

    @Test
    fun parsesFilesFromGo() {
        val ih = "ab".repeat(20)
        val shares = parseShares("""[{"infoHash":"$ih","name":"a.mp4","size":52428800,"from":"alice","sources":2,"have":false},
            {"infoHash":"short"}]""")
        assertEquals(listOf(SharedFile(ih, "a.mp4", 52428800, "alice", 2, false)), shares)

        val t = parseTransfers("""[{"infoHash":"$ih","name":"a.mp4","state":"downloading","pieces":50,
            "totalPieces":200,"peers":2,"uploaded":0,"from":{"192.168.49.1":3000,"192.168.49.20":2000}}]""").single()
        assertEquals(0.25f, t.progress)
        assertEquals(mapOf("192.168.49.1" to 3000L, "192.168.49.20" to 2000L), t.from)
        assertTrue(parseTransfers("[").isEmpty())
    }

    @Test
    fun formatsAndSanitises() {
        assertEquals("50.0 MB", formatSize(50L shl 20))
        assertEquals("512 B", formatSize(512))
        assertEquals("_etc_passwd", safeFileName("/etc/passwd"))
        assertEquals("secret", safeFileName("..secret"))
        assertEquals("shared-file", safeFileName("..."))
        assertEquals("a_b.txt", safeFileName("a\\b.txt"))
    }
}
