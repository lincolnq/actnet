package net.theavalanche.app

import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AddCircle
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.InputChip
import androidx.compose.material3.InputChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.unit.Dp
import kotlinx.coroutines.launch
import org.json.JSONObject
import uniffi.app_core.ContactRowFfi

// ---------------------------------------------------------------------------
// ComposeMessageView — new-conversation composer.
//
// A consistent layout: To-field with recipient chips, an always-browsable
// (and typing-filtered) contact list, and two persistent actions: DM
// (enabled at exactly one recipient) and New Group (always available).
//
// Mirrors mobile/ios/Actnet/Sources/Views/Chats/ComposeMessageView.swift.
// See docs/30-mobile-ux.md §Compose.
// ---------------------------------------------------------------------------

/**
 * A confirmed recipient. [displayName] may be empty when the user typed a raw
 * DID we haven't seen before; [label] falls back to a truncated DID.
 * Mirrors the nested Swift Chip struct.
 */
data class ComposeChip(
    val id: String,     // == did
    val did: String,
    val displayName: String,
) {
    /** User-visible text for the chip. Never a raw full DID. */
    val label: String
        get() = if (displayName.isEmpty()) shortenDid(did) else displayName
}

/** Shorten a DID for display. Mirrors RecipientTokenField.swift shortenDid(). */
fun shortenDid(did: String): String {
    return if (did.length > 18) "${did.take(12)}…${did.takeLast(4)}" else did
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ComposeMessageView(
    viewModel: AppViewModel,
    initialChips: List<ComposeChip> = emptyList(),
    onDismiss: () -> Unit = {},
    onNavigateToConversation: (Conversation) -> Unit = {},
    onNavigateToNameGroup: (members: List<ComposeChip>, accountId: String, servers: List<ServerInfo>) -> Unit = { _, _, _ -> },
) {
    val accounts by viewModel.accounts.collectAsStateWithLifecycle()

    // Local state
    val chips = remember { mutableStateListOf<ComposeChip>().also { it.addAll(initialChips) } }
    var query by remember { mutableStateOf("") }
    // Acting identity ("From"). Deliberately EMPTY at first: the composer
    // opens showing the whole merged contact book, and the identity gets
    // fixed by whichever gesture comes first — picking a contact (From fills
    // in from the contact's preferred identity) or choosing a From entry
    // (the book filters to what that identity can reach). Either way the
    // other side follows. Single-account users never see the From row and
    // fall back to their only account at action time.
    var selectedAccountId by remember { mutableStateOf<String?>(null) }
    var allContacts by remember { mutableStateOf<List<AppViewModel.AccountContact>>(emptyList()) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var showingContactPicker by remember { mutableStateOf(false) }

    val scope = rememberCoroutineScope()

    // The fixed acting identity, or null while From is still empty. Validated
    // against the live account list (a removed account must not stick). With a
    // single account there's no From row and no ambiguity — it's just active.
    val activeAccountId: String? =
        selectedAccountId?.takeIf { id -> accounts.any { it.id == id } }
            ?: accounts.singleOrNull()?.id

    // The identity actions (DM / New Group / Note to Self) run as: the fixed
    // one, else the only sensible default. Reached with From empty only via
    // raw-DID / scanned recipients.
    val actionAccountId: String? = activeAccountId ?: accounts.firstOrNull()?.id

    val activeAccountServers: List<ServerInfo> = run {
        val id = activeAccountId ?: return@run emptyList()
        accounts.firstOrNull { it.id == id }?.servers ?: emptyList()
    }
    val activeServer: ServerInfo? = activeAccountServers.firstOrNull()

    // Helper: contact name resolution via ViewModel. Resolution runs against
    // the identity that knows the contact (its tag), not the acting identity.
    fun contactName(c: AppViewModel.AccountContact): String {
        return viewModel.resolvedName(did = c.row.did, accountId = c.accountId)
    }

    fun isBot(c: AppViewModel.AccountContact): Boolean {
        return viewModel.isBot(did = c.row.did, accountId = c.accountId)
    }

    // Filtered contact lists mirroring Swift computed vars. The list is the
    // *merged* book across all identities (docs/52 unified-at-query).
    val trimmedQuery = query.trim()
    val queryLooksLikeDid = trimmedQuery.startsWith("did:")

    // Once an acting identity is fixed (either direction), the book filters to
    // contacts that identity knows — groups/DMs are server-local until
    // federation, so offering another identity's contacts would build a
    // cross-server group that can't work. While From is empty: everything.
    val reachableContacts: List<AppViewModel.AccountContact> = run {
        val acting = activeAccountId ?: return@run allContacts
        allContacts.filter { it.accountIds.contains(acting) }
    }

    // Query matching: names always; DIDs only when the query itself looks
    // like a DID (starts with "did:"). DIDs are effectively random strings —
    // substring-matching them against a short name query surfaces unrelated
    // contacts via letters the user can't even see.
    fun matchesQuery(c: AppViewModel.AccountContact, q: String): Boolean {
        if (q.isEmpty()) return true
        return if (q.startsWith("did:")) {
            c.row.did.lowercase().startsWith(q)
        } else {
            c.row.displayName.lowercase().contains(q)
        }
    }

    val peopleResults: List<AppViewModel.AccountContact> = run {
        val q = trimmedQuery.lowercase()
        reachableContacts.filter { c ->
            if (!c.row.isCurated) return@filter false
            if (chips.any { it.did == c.row.did }) return@filter false
            matchesQuery(c, q)
        }
    }

    val otherResults: List<AppViewModel.AccountContact> = run {
        val q = trimmedQuery.lowercase()
        reachableContacts.filter { c ->
            if (c.row.isCurated) return@filter false
            if (chips.any { it.did == c.row.did }) return@filter false
            matchesQuery(c, q)
        }
    }

    // "Note to Self" candidates (a DM with your own identity — docs/04 §5.5,
    // like Signal). Deliberately quiet: it appears ONLY when the user has
    // typed a substring of "note to self", there are no recipients yet
    // (adding yourself to a group makes no sense), and it renders *below*
    // any matching contacts. While From is empty there's no single "self",
    // so each account gets its own labeled entry — picking one fills From,
    // exactly like picking a contact does.
    val noteToSelfCandidates: List<Account> = run {
        if (chips.isNotEmpty()) return@run emptyList()
        val q = trimmedQuery.lowercase()
        if (q.isEmpty() || !"note to self".contains(q)) return@run emptyList()
        when {
            activeAccountId != null -> accounts.filter { it.id == activeAccountId }
            else -> accounts
        }
    }

    val newGroupTitle: String = if (chips.isEmpty()) "New Empty Group" else "New Group (${chips.count()})"

    // Display names that appear on more than one visible contact (e.g. the
    // testbot re-registered across dev-server resets, or two humans genuinely
    // sharing a name). Those rows get a shortened-DID subtitle so identical
    // names are tellable apart — collapsing them instead would let a
    // name-spoofer hide behind a real contact (docs/12).
    val collidingNames: Set<String> = reachableContacts
        .groupingBy { contactName(it).lowercase() }
        .eachCount()
        .filterValues { it > 1 }
        .keys

    fun subtitleFor(c: AppViewModel.AccountContact): String? =
        if (contactName(c).lowercase() in collidingNames) shortenDid(c.row.did) else null

    // The token field owns the chip content (chips are characters in its text
    // buffer — RecipientTokenField.kt, mirroring iOS); Compose pushes new
    // chips in through this handle and mirrors state back via callbacks.
    val tokenHandle = remember { RecipientFieldHandle() }

    // Keep the keyboard up on this screen: the token field is the screen's
    // whole interaction model (full-screen browsing lives behind the + picker).
    // Re-raise it whenever the picker sheet closes; also fires once on entry
    // (backs up the field's own autofocus).
    LaunchedEffect(showingContactPicker) {
        if (!showingContactPicker) {
            tokenHandle.focusAndShowKeyboard()
        }
    }

    // Load the merged contact book once (re-merged if the account set changes).
    LaunchedEffect(accounts) {
        val rows = viewModel.listAllContacts()
        allContacts = rows
        for (c in rows) {
            viewModel.cacheDisplayName(name = c.row.displayName, did = c.row.did)
        }
    }

    // Watch query for contact links
    LaunchedEffect(query) {
        val trimmed = query.trim()
        if (trimmed.isNotEmpty()) {
            handleContactLink(trimmed, chips, activeAccountId)
        }
    }

    fun addChip(did: String, displayName: String) {
        tokenHandle.addChip(Chip(id = did, did = did, displayName = displayName))
    }

    // Adding a contact from the merged book: if From is still empty, the pick
    // fills it with the contact's preferred identity — the identity that most
    // recently talked to this person (docs/52) — and the book filters to what
    // that identity can reach. Later picks never flip the identity; the From
    // row remains the manual control (which filters the other way).
    fun addContactChip(c: AppViewModel.AccountContact) {
        if (activeAccountId == null) {
            selectedAccountId = c.accountId
        }
        addChip(did = c.row.did, displayName = contactName(c))
    }

    fun commitQueryAsChip() {
        if (queryLooksLikeDid) {
            addChip(did = trimmedQuery, displayName = "")
        } else {
            val first = peopleResults.firstOrNull() ?: otherResults.firstOrNull()
            if (first != null) {
                addContactChip(first)
            }
        }
    }

    fun dmTapped() {
        if (chips.size != 1) return
        val accountId = actionAccountId ?: return
        val conv = viewModel.findOrCreateDMConversation(
            recipientDid = chips[0].did,
            accountId = accountId,
        )
        viewModel.setNavigateToConversation(conv)
        onDismiss()
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("New Conversation", style = MaterialTheme.typography.titleMedium)
                        if (activeServer != null) {
                            Text(
                                "at ${activeServer.displayHost}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = LocalAvalancheColors.current.paper,
                ),
            )
        },
        containerColor = LocalAvalancheColors.current.paper,
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                // Consume the insets innerPadding already applied, else
                // imePadding stacks the keyboard height ON TOP of the
                // nav-bar inset — a phantom gap below the action bar.
                .consumeWindowInsets(innerPadding)
                // Keep the DM / New Group action bar above the keyboard
                // (mirrors iOS, where the buttons stay visible while typing).
                .imePadding(),
        ) {
            // Account picker (only shown when there are multiple accounts)
            if (accounts.size > 1) {
                AccountPickerRow(
                    accounts = accounts,
                    selectedAccountId = selectedAccountId,
                    onAccountSelected = { selectedAccountId = it },
                )
                HorizontalDivider()
            }

            // Recipient field with chips
            RecipientFieldRow(
                initialChips = chips.toList(),
                handle = tokenHandle,
                onChipsChanged = { new ->
                    chips.clear()
                    chips.addAll(new.map { ComposeChip(id = it.id, did = it.did, displayName = it.displayName) })
                },
                onQueryChange = { query = it },
                onAddTapped = { showingContactPicker = true },
                onSubmit = { commitQueryAsChip() },
            )
            HorizontalDivider()

            // Autocomplete list — always browsable
            LazyColumn(modifier = Modifier.weight(1f)) {
                // Inline DID add button
                if (queryLooksLikeDid && trimmedQuery.isNotEmpty()) {
                    item {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { addChip(did = trimmedQuery, displayName = "") }
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                Icons.Filled.Person,
                                contentDescription = null,
                                tint = LocalAvalancheColors.current.brand,
                                modifier = Modifier.size(20.dp),
                            )
                            Spacer(Modifier.width(10.dp))
                            Text("Add $trimmedQuery", maxLines = 1, fontSize = 14.sp)
                        }
                    }
                }

                // People section
                if (peopleResults.isNotEmpty()) {
                    item {
                        Text(
                            "People",
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = LocalAvalancheColors.current.muted,
                        )
                    }
                    items(peopleResults, key = { it.row.did }) { c ->
                        ContactRowItem(
                            name = contactName(c),
                            subtitle = subtitleFor(c),
                            isBot = isBot(c),
                            onClick = { addContactChip(c) },
                        )
                    }
                }

                // Other section
                if (otherResults.isNotEmpty()) {
                    item {
                        Text(
                            "Other",
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = LocalAvalancheColors.current.muted,
                        )
                    }
                    items(otherResults, key = { it.row.did }) { c ->
                        ContactRowItem(
                            name = contactName(c),
                            subtitle = subtitleFor(c),
                            isBot = isBot(c),
                            onClick = { addContactChip(c) },
                        )
                    }
                }

                // Note to Self — only on a typed "note to self" substring
                // match, below any matching contacts (see candidates above).
                items(noteToSelfCandidates, key = { "self-${it.id}" }) { acct ->
                    val label =
                        if (noteToSelfCandidates.size > 1) "Note to Self (${acct.displayName})"
                        else "Note to Self"
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (activeAccountId == null) {
                                    selectedAccountId = acct.id
                                }
                                addChip(did = acct.id, displayName = "Note to Self")
                            }
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Filled.Bookmark,
                            contentDescription = null,
                            tint = LocalAvalancheColors.current.brand,
                            modifier = Modifier.size(32.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(label, maxLines = 1)
                    }
                }

                // Empty state
                if (peopleResults.isEmpty() && otherResults.isEmpty() && !queryLooksLikeDid && noteToSelfCandidates.isEmpty()) {
                    item {
                        Text(
                            "No more contacts to add.",
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = LocalAvalancheColors.current.muted,
                        )
                    }
                }
            }

            // Action bar
            ActionBar(
                chips = chips,
                newGroupTitle = newGroupTitle,
                errorMessage = errorMessage,
                onDmTapped = { dmTapped() },
                onNewGroupTapped = {
                    val id = actionAccountId ?: return@ActionBar
                    val servers = accounts.firstOrNull { it.id == id }?.servers ?: emptyList()
                    onNavigateToNameGroup(chips.toList(), id, servers)
                },
            )
        }
    }

    // Contact picker bottom sheet
    if (showingContactPicker) {
        ContactPickerSheet(
            contacts = reachableContacts,
            excludedDids = chips.map { it.did }.toSet(),
            nameFor = { contactName(it) },
            subtitleFor = { subtitleFor(it) },
            isBotFor = { isBot(it) },
            onSelect = { c ->
                addContactChip(c)
                showingContactPicker = false
            },
            onScanLink = { raw ->
                val did = recipientDidFromContactLink(raw) ?: return@ContactPickerSheet false
                if (chips.none { it.did == did }) {
                    chips.add(ComposeChip(id = did, did = did, displayName = ""))
                }
                showingContactPicker = false
                true
            },
            onDismiss = { showingContactPicker = false },
        )
    }
}

// ---------------------------------------------------------------------------
// Account picker row
// ---------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AccountPickerRow(
    accounts: List<Account>,
    selectedAccountId: String?,
    onAccountSelected: (String?) -> Unit,
) {
    // No fallback: an empty From renders its placeholder until the user picks
    // an account — or until picking a contact fills it in. Compact single-line
    // row (no Material text-field chrome — the outlined dropdown box was ~56dp
    // tall for one line of text).
    val selected = accounts.firstOrNull { it.id == selectedAccountId }
    var expanded by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("From:", color = LocalAvalancheColors.current.muted, modifier = Modifier.padding(end = 6.dp))
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
        ) {
            Row(
                modifier = Modifier
                    .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
                    .clip(RoundedCornerShape(8.dp))
                    .padding(horizontal = 4.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = selected?.displayName ?: "Choose account",
                    fontSize = 16.sp,
                    color = if (selected != null) LocalAvalancheColors.current.ink
                    else LocalAvalancheColors.current.muted,
                    maxLines = 1,
                )
                Icon(
                    Icons.Filled.ArrowDropDown,
                    contentDescription = null,
                    tint = LocalAvalancheColors.current.muted,
                    modifier = Modifier.size(20.dp),
                )
            }
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                accounts.forEach { account ->
                    DropdownMenuItem(
                        text = { Text(account.displayName) },
                        onClick = {
                            onAccountSelected(account.id)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Recipient field with chips and query input
// ---------------------------------------------------------------------------

@Composable
private fun RecipientFieldRow(
    initialChips: List<ComposeChip>,
    handle: RecipientFieldHandle,
    onChipsChanged: (List<Chip>) -> Unit,
    onQueryChange: (String) -> Unit,
    onAddTapped: () -> Unit,
    onSubmit: () -> Unit,
) {
    // Real first-line metrics reported by the EditText post-layout (px from
    // its top): AndroidView doesn't participate in Compose baseline
    // alignment, so the label and + button are positioned from these
    // measurements instead of guessed paddings.
    val density = LocalDensity.current
    var fieldBaselinePx by remember { mutableStateOf<Int?>(null) }
    var fieldCenterPx by remember { mutableStateOf<Int?>(null) }
    var labelBaselinePx by remember { mutableStateOf<Float?>(null) }

    val labelTopPad: Dp = run {
        val fb = fieldBaselinePx
        val lb = labelBaselinePx
        if (fb == null || lb == null) 12.dp // pre-measure fallback, corrected next frame
        else with(density) { (fb - lb).coerceAtLeast(0f).toDp() }
    }
    val iconTopPad: Dp = run {
        val c = fieldCenterPx
        if (c == null) 8.dp // pre-measure fallback
        else with(density) { (c - 14.dp.toPx()).coerceAtLeast(0f).toDp() }
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 2.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            "To:",
            color = LocalAvalancheColors.current.muted,
            fontSize = 16.sp,
            onTextLayout = { labelBaselinePx = it.firstBaseline },
            modifier = Modifier.padding(top = labelTopPad, end = 6.dp),
        )
        // The real token field (RecipientTokenField.kt): one EditText whose
        // chips are ImageSpan characters, mirroring the iOS UITextView +
        // NSTextAttachment design. Native text behavior for free: wrapping,
        // caret placement, chip selection, and the two-stage backspace
        // (first press selects the chip, second deletes it). Placeholder is
        // the EditText hint, which the platform shows only when the buffer is
        // completely empty (no chips, no text).
        RecipientTokenField(
            chips = initialChips.map { Chip(id = it.id, did = it.did, displayName = it.displayName) },
            query = "",
            placeholder = "Type a name",
            handle = handle,
            onChipsChanged = onChipsChanged,
            onQueryChanged = onQueryChange,
            onSubmit = onSubmit,
            onFirstLineMetrics = { baseline, center ->
                fieldBaselinePx = baseline
                fieldCenterPx = center
            },
            modifier = Modifier.weight(1f),
        )
        // Plain sized icon, not IconButton — IconButton enforces a 48dp
        // minimum touch target that would dictate the row height. Centered on
        // the field's measured first line.
        Icon(
            Icons.Filled.AddCircle,
            contentDescription = "Add recipient",
            tint = LocalAvalancheColors.current.brand,
            modifier = Modifier
                .padding(top = iconTopPad)
                .size(28.dp)
                .clip(RoundedCornerShape(percent = 50))
                .clickable(onClick = onAddTapped),
        )
    }
}

// ---------------------------------------------------------------------------
// Single contact row in the autocomplete list
// ---------------------------------------------------------------------------

@Composable
private fun ContactRowItem(
    name: String,
    isBot: Boolean,
    onClick: () -> Unit,
    /** Shortened DID shown under the name when display names collide. */
    subtitle: String? = null,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        ContactAvatar(name = name, isBot = isBot, size = 32.dp)
        Spacer(Modifier.width(10.dp))
        Column {
            Text(name, maxLines = 1)
            if (subtitle != null) {
                Text(
                    subtitle,
                    maxLines = 1,
                    fontSize = 12.sp,
                    color = LocalAvalancheColors.current.muted,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Action bar (DM + New Group)
// ---------------------------------------------------------------------------

@Composable
private fun ActionBar(
    chips: List<ComposeChip>,
    newGroupTitle: String,
    errorMessage: String?,
    onDmTapped: () -> Unit,
    onNewGroupTapped: () -> Unit,
) {
    Column {
        if (errorMessage != null) {
            Text(
                errorMessage,
                style = MaterialTheme.typography.bodySmall,
                color = LocalAvalancheColors.current.error,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }
        HorizontalDivider()
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // DM button — prominent when exactly one recipient
            if (chips.size == 1) {
                Button(
                    onClick = onDmTapped,
                    modifier = Modifier.weight(1f).height(48.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = LocalAvalancheColors.current.brand),
                ) {
                    Text("DM")
                }
            } else {
                OutlinedButton(
                    onClick = onDmTapped,
                    modifier = Modifier.weight(1f).height(48.dp),
                    enabled = chips.size == 1,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = LocalAvalancheColors.current.brand),
                ) {
                    Text("DM")
                }
            }

            // New Group button — prominent when 2+ recipients
            if (chips.size >= 2) {
                Button(
                    onClick = onNewGroupTapped,
                    modifier = Modifier.weight(1f).height(48.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = LocalAvalancheColors.current.brand),
                ) {
                    Text(newGroupTitle, maxLines = 1)
                }
            } else {
                OutlinedButton(
                    onClick = onNewGroupTapped,
                    modifier = Modifier.weight(1f).height(48.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = LocalAvalancheColors.current.brand),
                ) {
                    Text(newGroupTitle, maxLines = 1)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ContactPickerSheet — full-list contact picker from the "+" button.
//
// Mirrors the private Swift struct ContactPickerSheet.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactPickerSheet(
    contacts: List<AppViewModel.AccountContact>,
    excludedDids: Set<String>,
    nameFor: (AppViewModel.AccountContact) -> String,
    subtitleFor: (AppViewModel.AccountContact) -> String? = { null },
    isBotFor: (AppViewModel.AccountContact) -> Boolean,
    onSelect: (AppViewModel.AccountContact) -> Unit,
    onScanLink: (String) -> Boolean,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var search by remember { mutableStateOf("") }
    var showingScanner by remember { mutableStateOf(false) }
    var scanError by remember { mutableStateOf<String?>(null) }

    val filtered: List<AppViewModel.AccountContact> = run {
        val q = search.trim().lowercase()
        contacts.filter { c ->
            if (excludedDids.contains(c.row.did)) return@filter false
            if (q.isEmpty()) return@filter true
            // Same rule as the autocomplete: names always, DIDs only for a
            // did:-shaped query (substring-matching random DID characters
            // against a name query surfaces unrelated contacts).
            if (q.startsWith("did:")) {
                c.row.did.lowercase().startsWith(q)
            } else {
                nameFor(c).lowercase().contains(q)
            }
        }
    }
    val people = filtered.filter { it.row.isCurated }
    val other = filtered.filter { !it.row.isCurated }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = LocalAvalancheColors.current.paper,
    ) {
        Column(modifier = Modifier.fillMaxSize()) {
            // Header row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "Add Recipient",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Filled.Close, contentDescription = "Close")
                }
            }

            // Search field
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                placeholder = { Text("Search contacts") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                singleLine = true,
            )

            LazyColumn(modifier = Modifier.weight(1f)) {
                // Scan QR code button
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                scanError = null
                                showingScanner = true
                            }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Filled.QrCodeScanner,
                            contentDescription = null,
                            tint = LocalAvalancheColors.current.brand,
                            modifier = Modifier.size(32.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Text("Scan QR Code", color = LocalAvalancheColors.current.brand)
                    }
                }

                // People section
                if (people.isNotEmpty()) {
                    item {
                        Text(
                            "People",
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = LocalAvalancheColors.current.muted,
                        )
                    }
                    items(people, key = { it.row.did }) { c ->
                        ContactRowItem(
                            name = nameFor(c),
                            subtitle = subtitleFor(c),
                            isBot = isBotFor(c),
                            onClick = { onSelect(c) },
                        )
                    }
                }

                // Other section
                if (other.isNotEmpty()) {
                    item {
                        Text(
                            "Other",
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = LocalAvalancheColors.current.muted,
                        )
                    }
                    items(other, key = { it.row.did }) { c ->
                        ContactRowItem(
                            name = nameFor(c),
                            subtitle = subtitleFor(c),
                            isBot = isBotFor(c),
                            onClick = { onSelect(c) },
                        )
                    }
                }

                // Empty state
                if (filtered.isEmpty()) {
                    item {
                        Text(
                            "No contacts to add.",
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = LocalAvalancheColors.current.muted,
                        )
                    }
                }
            }
        }
    }

    // QR scanner sheet
    if (showingScanner) {
        ModalBottomSheet(
            onDismissRequest = { showingScanner = false },
            containerColor = Color.Black,
        ) {
            QRCodeCameraView(
                onScanned = { value ->
                    showingScanner = false
                    if (onScanLink(value)) {
                        // onScanLink returns true → chip added, dismiss picker
                    } else {
                        scanError = "That QR code isn't an Avalanche contact link."
                    }
                },
                modifier = Modifier.height(400.dp),
            )
        }
    }

    // Scan error dialog
    if (scanError != null) {
        AlertDialog(
            onDismissRequest = { scanError = null },
            title = { Text("Couldn't add contact") },
            text = { Text(scanError ?: "") },
            confirmButton = {
                TextButton(onClick = { scanError = null }) { Text("OK") }
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Link parsing helpers — mirrors ComposeMessageView static methods in Swift.
// ---------------------------------------------------------------------------

/**
 * Extract a recipient DID from a contact link, or null if it isn't one.
 * Mirrors ComposeMessageView.recipientDid(fromContactLink:) in Swift.
 *
 * Supported shapes:
 *   https://go.theavalanche.net/conversation/<did>
 *   https://go.theavalanche.net/i/<base64url {"d":…}>
 */
fun recipientDidFromContactLink(raw: String): String? {
    val trimmed = raw.trim()
    val uri = runCatching { Uri.parse(trimmed) }.getOrNull() ?: return null
    if (uri.host != "go.theavalanche.net") return null
    val parts = uri.pathSegments.filter { it.isNotEmpty() }
    if (parts.size < 2) return null
    return when (parts[0]) {
        "conversation" -> {
            val candidate = parts[1]
            if (candidate.startsWith("did:")) candidate else null
        }
        "i", "invite" -> {
            val data = decodeBase64URL(parts[1]) ?: return null
            val payload = runCatching {
                JSONObject(String(data, Charsets.UTF_8))
            }.getOrNull() ?: return null
            val did = payload.optString("d")
            if (did.startsWith("did:")) did else null
        }
        else -> null
    }
}

/**
 * Attempt to parse a contact link from [raw] and add a chip if successful.
 * Returns true if a DID was extracted and added (or was already present).
 */
private fun handleContactLink(
    raw: String,
    chips: SnapshotStateList<ComposeChip>,
    activeAccountId: String?,
): Boolean {
    val did = recipientDidFromContactLink(raw) ?: return false
    if (chips.none { it.did == did }) {
        chips.add(ComposeChip(id = did, did = did, displayName = ""))
    }
    return true
}

// ---------------------------------------------------------------------------
// Previews
// ---------------------------------------------------------------------------

@Preview(showBackground = true)
@Composable
private fun ComposeMessageViewPreview() {
    AvalancheTheme {
        val account = Account(
            id = "did:example:alice",
            displayName = "Alice",
            servers = listOf(
                ServerInfo(
                    id = "https://home.example.com",
                    name = "Home",
                    url = android.net.Uri.parse("https://home.example.com"),
                ),
            ),
        )
        ComposeMessageView(
            viewModel = rememberPreviewAppViewModel(accounts = listOf(account)),
        )
    }
}
