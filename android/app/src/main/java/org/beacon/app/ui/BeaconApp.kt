package org.beacon.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.beacon.app.ChatMessage
import org.beacon.app.Transfer
import org.beacon.app.formatSize
import org.beacon.app.GENERAL
import org.beacon.app.MeshState
import org.beacon.app.PeerInfo
import org.beacon.app.dmFingerprint
import org.beacon.app.dmKey
import org.beacon.app.isDm
import org.beacon.app.shortFingerprint

private enum class Tab(val label: String) { Nearby("Nearby"), Chat("Chat"), Files("Files") }

@Composable
fun BeaconApp(
    needsNickname: Boolean,
    permissionsGranted: Boolean,
    onNickname: (String) -> String?,
    onRequestPermissions: () -> Unit,
    onWipe: () -> Unit,
) {
    val colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()
    MaterialTheme(colorScheme = colors) {
        Surface(Modifier.fillMaxSize()) {
            Box(Modifier.safeDrawingPadding()) {
                when {
                    needsNickname -> NicknameScreen(onNickname)
                    !permissionsGranted -> PermissionScreen(onRequestPermissions)
                    else -> MainScreen(onWipe)
                }
            }
        }
    }
}

@Composable
private fun NicknameScreen(onNickname: (String) -> String?) {
    var name by rememberSaveable { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Beacon", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Chat with people nearby over Bluetooth, no internet needed. " +
                "Your identity is a key made on this phone; there is no account.",
        )
        OutlinedTextField(
            value = name,
            onValueChange = { name = it; error = null },
            label = { Text("Nickname") },
            isError = error != null,
            supportingText = { error?.let { Text(it) } },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = { error = onNickname(name) }, enabled = name.isNotBlank()) { Text("Start") }
    }
}

@Composable
private fun PermissionScreen(onRequest: () -> Unit) {
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Bluetooth access", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Beacon finds nearby phones and passes messages through them over Bluetooth. " +
                "It does not use your location.",
        )
        Button(onClick = onRequest) { Text("Allow") }
    }
}

@Composable
private fun MainScreen(onWipe: () -> Unit) {
    var tab by rememberSaveable { mutableStateOf(Tab.Chat) }
    var conversation by rememberSaveable { mutableStateOf(GENERAL) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = {},
                        label = { Text(t.label) },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding)) {
            when (tab) {
                Tab.Nearby -> NearbyScreen(
                    onMessage = { peer -> conversation = dmKey(peer.fingerprint); tab = Tab.Chat },
                    onWipe = onWipe,
                )
                Tab.Chat -> ChatScreen(conversation, onConversation = { conversation = it })
                Tab.Files -> FilesScreen()
            }
        }
    }
}

@Composable
private fun NearbyScreen(onMessage: (PeerInfo) -> Unit, onWipe: () -> Unit) {
    val me by MeshState.me.collectAsState()
    val peers by MeshState.peers.collectAsState()
    val links by MeshState.links.collectAsState()
    val relayed by MeshState.relayed.collectAsState()
    var confirmWipe by remember { mutableStateOf(false) }
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text(me?.nickname ?: "Starting…", style = MaterialTheme.typography.titleMedium)
                    me?.let {
                        Text("Your fingerprint", style = MaterialTheme.typography.labelSmall)
                        Text(it.fingerprint.chunked(4).joinToString(" "), fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall)
                    }
                    Text("$links Bluetooth link${if (links == 1) "" else "s"} · relayed $relayed packets for others",
                        style = MaterialTheme.typography.labelSmall)
                }
            }
        }
        item {
            Text("Nearby (${peers.size})", style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(top = 8.dp))
            if (peers.isEmpty()) Text("Nobody in range yet. Messages hop through other Beacon phones.")
        }
        items(peers, key = { it.fingerprint }) { p ->
            Card(Modifier.fillMaxWidth().clickable { onMessage(p) }) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(p.nickname, style = MaterialTheme.typography.titleSmall)
                        Text(shortFingerprint(p.fingerprint), fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall)
                    }
                    Text("Message", color = MaterialTheme.colorScheme.primary)
                }
            }
        }
        item {
            Spacer(Modifier.height(24.dp))
            TextButton(onClick = { confirmWipe = true }) {
                Text("Panic wipe", color = MaterialTheme.colorScheme.error)
            }
        }
    }
    if (confirmWipe) {
        AlertDialog(
            onDismissRequest = { confirmWipe = false },
            title = { Text("Wipe everything?") },
            text = { Text("Deletes your identity keys and every message on this phone. This cannot be undone.") },
            confirmButton = {
                TextButton(onClick = { confirmWipe = false; onWipe() }) {
                    Text("Wipe", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmWipe = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun ChatScreen(conversation: String, onConversation: (String) -> Unit) {
    val messages by MeshState.messages.collectAsState()
    val peers by MeshState.peers.collectAsState()
    val keys = (listOf(GENERAL) + messages.keys + conversation).distinct()
    val names = peers.associate { it.fingerprint to it.nickname }
    fun title(key: String) = if (isDm(key)) "@" + (names[dmFingerprint(key)] ?: shortFingerprint(dmFingerprint(key))) else key
    val shown = messages[conversation].orEmpty()
    val listState = rememberLazyListState()
    LaunchedEffect(shown.size) { if (shown.isNotEmpty()) listState.animateScrollToItem(shown.size - 1) }

    Column(Modifier.fillMaxSize().imePadding()) {
        LazyRow(Modifier.padding(horizontal = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(keys) { k ->
                FilterChip(selected = k == conversation, onClick = { onConversation(k) }, label = { Text(title(k)) })
            }
        }
        if (isDm(conversation)) {
            Text("End-to-end encrypted: phones that relay it cannot read it.",
                style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 16.dp))
        }
        LazyColumn(Modifier.weight(1f).padding(horizontal = 16.dp), state = listState,
            verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(shown) { MessageRow(it) }
        }
        Composer(onSend = { MeshState.send(conversation, it) })
    }
}

@Composable
private fun MessageRow(m: ChatMessage) {
    val time = DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(m.sentMillis))
    Column(Modifier.fillMaxWidth(), horizontalAlignment = if (m.mine) Alignment.End else Alignment.Start) {
        Text(if (m.mine) "you · $time" else "${m.nickname} · $time", style = MaterialTheme.typography.labelSmall)
        Card { Text(m.text, Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) }
    }
}

@Composable
private fun Composer(onSend: (String) -> String?) {
    var text by rememberSaveable { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    fun send() {
        val t = text.trim()
        if (t.isEmpty()) return
        error = onSend(t)
        if (error == null) text = ""
    }
    Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it; error = null },
            placeholder = { Text("Message") },
            isError = error != null,
            supportingText = error?.let { { Text(it) } },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { send() }),
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(8.dp))
        Button(onClick = { send() }, enabled = text.isNotBlank()) { Text("Send") }
    }
}

@Composable
private fun FilesScreen() {
    val context = LocalContext.current
    val shares by MeshState.shares.collectAsState()
    val transfers by MeshState.transfers.collectAsState()
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        status = "Preparing the file…"
        scope.launch {
            // Copying and hashing a large file takes a while; keep it off the UI thread.
            val err = withContext(Dispatchers.IO) { MeshState.shareUri(context, uri) }
            busy = false
            status = err ?: "Shared. People nearby can now fetch it."
        }
    }
    val mine = transfers.map { it.infoHash }.toSet()
    val nearby = shares.filter { !it.have && it.infoHash !in mine }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            Text("Files", style = MaterialTheme.typography.headlineSmall)
            Text(
                "Files travel phone to phone over Wi-Fi Direct, no internet needed. " +
                    "Every piece is checked, so a file arrives exactly as shared.",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(8.dp))
            Button(onClick = { pick.launch(arrayOf("*/*")) }, enabled = !busy) { Text("Share a file") }
            status?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        if (transfers.isNotEmpty()) {
            item { Text("Your files", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp)) }
            items(transfers, key = { "t" + it.infoHash }) { TransferCard(it) }
        }
        item { Text("Nearby files", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp)) }
        if (nearby.isEmpty()) {
            item { Text("Nothing shared nearby yet.", style = MaterialTheme.typography.bodySmall) }
        }
        items(nearby, key = { "s" + it.infoHash }) { f ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(f.name, style = MaterialTheme.typography.titleSmall)
                        val more = if (f.sources > 1) " and ${f.sources - 1} more" else ""
                        Text("${formatSize(f.size)} · from ${f.from}$more", style = MaterialTheme.typography.bodySmall)
                    }
                    Button(onClick = { status = MeshState.getFile(f.infoHash) }) { Text("Get") }
                }
            }
        }
    }
}

@Composable
private fun TransferCard(t: Transfer) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(t.name.ifEmpty { "Looking up the file…" }, style = MaterialTheme.typography.titleSmall)
            val state = when (t.state) {
                "sharing" -> "Sharing"
                "seeding" -> "Received and verified; sharing it on"
                "downloading" -> "Receiving ${t.pieces}/${t.totalPieces} pieces"
                "asking" -> "Asking for it"
                "joining" -> "Joining the Wi-Fi Direct group"
                "fetching" -> "Getting the file's details"
                "failed" -> "Failed: ${t.error}"
                else -> t.state
            }
            Text(state, style = MaterialTheme.typography.bodySmall)
            if (t.totalPieces > 0 && t.state == "downloading") {
                LinearProgressIndicator(progress = { t.progress }, modifier = Modifier.fillMaxWidth())
            }
            if (t.totalPieces > 0) {
                Text("${t.peers} connected · sent ${formatSize(t.uploaded)} to others",
                    style = MaterialTheme.typography.labelSmall)
            }
            if (t.from.isNotEmpty()) {
                val parts = t.from.entries.sortedByDescending { it.value }.joinToString(", ") { "${it.key}: ${formatSize(it.value)}" }
                Text("Received from ${t.from.size} phone${if (t.from.size == 1) "" else "s"}: $parts",
                    style = MaterialTheme.typography.labelSmall)
            }
            if (t.state == "seeding" && t.path.isNotEmpty()) {
                Text("Saved to ${t.path}", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
