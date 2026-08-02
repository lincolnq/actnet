package net.theavalanche.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ---------------------------------------------------------------------------
// ConversationSearchView
//
// Mirrors iOS Sources/Views/Chats/ConversationSearchView.swift (docs/37): the
// content pane of the Search tab. A conversation list filtered by title,
// across all accounts — search is a cross-cutting lens, not scoped to the
// selected account tab. Client-side only for v1: filters the already-loaded
// conversation list, no server-side search.
//
// The query is *hoisted to MainTabView*: while the Search tab is active the
// floating bottom bar morphs into the search field (mirroring iOS, where the
// tab bar is replaced by the search field), so this pane only renders results.
// Results scroll behind the floating field (FloatingBarContentPadding).
// ---------------------------------------------------------------------------

@Composable
fun ConversationSearchView(
    viewModel: AppViewModel,
    query: String,
    onOpenConversation: (Conversation) -> Unit = {},
) {
    val conversations by viewModel.conversations.collectAsState()
    val accounts by viewModel.accounts.collectAsState()

    val trimmed = query.trim()
    val results = remember(conversations, trimmed) {
        val sorted = conversations.sortedByDescending { it.lastMessageDate?.time ?: Long.MIN_VALUE }
        if (trimmed.isEmpty()) sorted
        else sorted.filter { it.title.contains(trimmed, ignoreCase = true) }
    }

    if (results.isEmpty() && trimmed.isNotEmpty()) {
        // Mirrors iOS ContentUnavailableView.search
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(LocalAvalancheColors.current.card)
                .statusBarsPadding()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(
                imageVector = Icons.Filled.Search,
                contentDescription = null,
                tint = LocalAvalancheColors.current.muted,
                modifier = Modifier.size(48.dp),
            )
            Text(
                text = "No results for \"$trimmed\"",
                color = LocalAvalancheColors.current.ink,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 16.dp),
            )
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(LocalAvalancheColors.current.card)
                .statusBarsPadding(),
            contentPadding = PaddingValues(bottom = FloatingBarContentPadding),
        ) {
            items(items = results, key = { it.id }) { conversation ->
                val account = accounts.firstOrNull { it.id == conversation.accountId }
                val recipientDid = conversation.recipientDid
                val isBot = !conversation.isGroup &&
                    recipientDid != null &&
                    viewModel.isBot(recipientDid, conversation.accountId)
                ConversationRow(
                    conversation = conversation,
                    account = account,
                    accounts = accounts,
                    unreadCount = viewModel.unreadCount(conversation),
                    isBotConversation = isBot,
                    previewText = conversationPreviewText(viewModel, conversation),
                    modifier = Modifier
                        .fillMaxWidth()
                        .chatRowPressHighlight { onOpenConversation(conversation) }
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                )
                HorizontalDivider(
                    color = LocalAvalancheColors.current.divider.copy(alpha = 0.5f),
                    modifier = Modifier.padding(start = 76.dp),
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun ConversationSearchViewPreview() {
    AvalancheTheme {
        ConversationSearchView(viewModel = rememberPreviewAppViewModel(), query = "")
    }
}
