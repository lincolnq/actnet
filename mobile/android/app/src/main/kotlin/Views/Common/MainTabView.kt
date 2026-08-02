package net.theavalanche.app

import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ---------------------------------------------------------------------------
// MainTabView
//
// Mirrors iOS Sources/Views/Common/MainTabView.swift (docs/37): a bottom tab
// surface with four destinations —
//   - Chats    (message bubble → Message on Material)
//   - Network  (server.rack → Dns on Material)
//   - Settings (gearshape → Settings; a tab pane hosting AccountsView,
//               matching iOS)
//   - Search   (iOS Tab(role: .search))
//
// The bar is a **floating capsule pair**, mirroring the iOS 26 arrangement: a
// main pill (Chats / Network / Settings) plus a *detached* circular search
// bubble beside it. Content scrolls behind them (no docked band — scrollable
// panes add FloatingBarContentPadding at the bottom instead). Tapping search
// replaces the whole floating bar with a search *field* capsule — the Android
// analog of iOS's tab bar morphing into the search field — and closing it
// returns to Chats.
//
// The offline banner is overlaid on top of the content, mirroring iOS
// RootView's ZStack { MainTabView() \n OfflineBanner() }.
//
// Navigation callbacks replace NavigationStack/sheet navigation — the central
// NavGraph in MainActivity wires them. Settings is a switched-in tab pane
// (AccountsView); its deeper screens (identity/server detail, add account,
// scanner, log viewer) remain NavGraph pushes via the callbacks.
// ---------------------------------------------------------------------------

/**
 * Bottom content inset for panes that scroll behind the floating bar, so the
 * last row can scroll clear of it (bar ≈ 70dp + 8dp inset + breathing room).
 */
val FloatingBarContentPadding = 112.dp

@Composable
fun MainTabView(
    appViewModel: AppViewModel,
    // ---- Chats tab callbacks ----
    onOpenConversation: (Conversation) -> Unit = {},
    onOpenAccounts: () -> Unit = {},
    onOpenCompose: () -> Unit = {},
    // ---- Settings tab callbacks (AccountsView is a tab pane, docs/37) ----
    onScanInvite: ((String) -> Unit) -> Unit = {},
    onShowScanner: (() -> Unit) -> Unit = {},
    onNavigateToScanner: ((String) -> Unit) -> Unit = {},
    onNavigateToIdentityDetail: (Account) -> Unit = {},
    onNavigateToServerDetail: (Account, ServerInfo) -> Unit = { _, _ -> },
    onNavigateToAddAccount: () -> Unit = {},
    onOpenLogViewer: () -> Unit = {},
    // ---- Network tab has no extra callbacks for now ----
) {
    val selectedTab by appViewModel.selectedTab.collectAsState()
    // Search query lives here (not in the search pane) because the floating
    // bar *is* the search field while the Search tab is active.
    var searchQuery by rememberSaveable { mutableStateOf("") }

    // System back returns to Chats from any other tab (incl. search, which
    // also clears its query) instead of leaving the app — Chats is home.
    BackHandler(enabled = selectedTab != AppViewModel.Tab.CHATS) {
        searchQuery = ""
        appViewModel.setSelectedTab(AppViewModel.Tab.CHATS)
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(LocalAvalancheColors.current.paper),
    ) {
        // Content fills the whole screen; the floating bar overlays it and
        // scrollable content adds FloatingBarContentPadding at the bottom.
        when (selectedTab) {
            AppViewModel.Tab.CHATS -> ChatsView(
                viewModel = appViewModel,
                onOpenConversation = onOpenConversation,
                onOpenAccounts = onOpenAccounts,
                onOpenCompose = onOpenCompose,
            )
            AppViewModel.Tab.NETWORK -> Box(
                // Network isn't restyled for scroll-behind yet; keep its
                // content clear of the floating bar the simple way.
                modifier = Modifier
                    .fillMaxSize()
                    .navigationBarsPadding()
                    .padding(bottom = 86.dp),
            ) {
                NetworkView(appViewModel = appViewModel)
            }
            AppViewModel.Tab.SETTINGS -> Box(
                // Settings isn't restyled for scroll-behind yet; keep its
                // content clear of the floating bar the simple way.
                modifier = Modifier
                    .fillMaxSize()
                    .navigationBarsPadding()
                    .padding(bottom = 86.dp),
            ) {
                AccountsView(
                    viewModel = appViewModel,
                    onDismiss = { appViewModel.setSelectedTab(AppViewModel.Tab.CHATS) },
                    onScanInvite = onScanInvite,
                    onShowScanner = onShowScanner,
                    onNavigateToScanner = onNavigateToScanner,
                    onNavigateToIdentityDetail = onNavigateToIdentityDetail,
                    onNavigateToServerDetail = onNavigateToServerDetail,
                    onNavigateToAddAccount = onNavigateToAddAccount,
                    onOpenLogViewer = onOpenLogViewer,
                    showsBackButton = false, // tab pane, not a pushed screen
                )
            }
            AppViewModel.Tab.SEARCH -> ConversationSearchView(
                viewModel = appViewModel,
                query = searchQuery,
                onOpenConversation = onOpenConversation,
            )
        }

        // Floating bottom bar: tab pills normally; a search field while the
        // Search tab is active. imePadding keeps the search field riding on
        // top of the keyboard instead of being covered by it.
        Box(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .navigationBarsPadding()
                .imePadding()
                .padding(horizontal = 24.dp)
                .padding(bottom = 8.dp),
        ) {
            if (selectedTab == AppViewModel.Tab.SEARCH) {
                FloatingSearchField(
                    query = searchQuery,
                    onQueryChange = { searchQuery = it },
                    onClose = {
                        searchQuery = ""
                        appViewModel.setSelectedTab(AppViewModel.Tab.CHATS)
                    },
                )
            } else {
                FloatingTabBar(
                    selectedTab = selectedTab,
                    onSelectTab = { appViewModel.setSelectedTab(it) },
                )
            }
        }

        // Offline banner overlaid at the top-center — mirrors iOS RootView
        // ZStack(alignment: .top) + OfflineBanner(). Without the explicit
        // align it would default to the Box's top-start (top-left) corner.
        Box(
            modifier = Modifier
                .align(Alignment.TopCenter)
                // The overlay sits outside any Scaffold, so it must apply the
                // status-bar inset itself — otherwise the pill floats under the
                // status bar in the edge-to-edge window.
                .statusBarsPadding(),
        ) {
            OfflineBanner(appViewModel = appViewModel)
        }
    }
}

// ---------------------------------------------------------------------------
// Floating capsule tab bar (+ detached search bubble)
// ---------------------------------------------------------------------------

/** One height for every floating element: tab pill, search bubble, search field. */
private val FloatingBarHeight = 58.dp

@Composable
private fun FloatingTabBar(
    selectedTab: AppViewModel.Tab,
    onSelectTab: (AppViewModel.Tab) -> Unit,
) {
    val capsule = RoundedCornerShape(FloatingBarHeight / 2)
    // Order matches the pill layout; drives the sliding selection indicator.
    val pillTabs = listOf(
        AppViewModel.Tab.CHATS,
        AppViewModel.Tab.NETWORK,
        AppViewModel.Tab.SETTINGS,
    )
    val itemWidth = 72.dp
    val pillPadding = 5.dp

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center,
    ) {
        // Main pill: Chats / Network / Settings, with a brand-tinted pill that
        // *slides* between items on switch — same decelerate curve as the top
        // account tabs.
        Box(
            modifier = Modifier
                .shadow(elevation = 8.dp, shape = capsule)
                .background(color = LocalAvalancheColors.current.paper, shape = capsule)
                .border(
                    width = 0.5.dp,
                    color = LocalAvalancheColors.current.ink.copy(alpha = 0.08f),
                    shape = capsule,
                )
                .clip(capsule)
                .height(FloatingBarHeight)
                // Inset ALL content by the pill padding so the items, the
                // sliding selection pill, and the press highlight share the
                // exact same 72×48 capsule geometry.
                .padding(pillPadding),
            contentAlignment = Alignment.CenterStart,
        ) {
            val selectedIndex = pillTabs.indexOf(selectedTab)
            if (selectedIndex >= 0) {
                val indicatorOffset by animateDpAsState(
                    targetValue = itemWidth * selectedIndex,
                    animationSpec = tween(durationMillis = 130, easing = LinearOutSlowInEasing),
                    label = "bottomTabIndicator",
                )
                Box(
                    modifier = Modifier
                        .padding(start = indicatorOffset)
                        .width(itemWidth)
                        .fillMaxHeight()
                        .background(
                            color = LocalAvalancheColors.current.brand.copy(alpha = 0.14f),
                            shape = RoundedCornerShape(percent = 50),
                        ),
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                FloatingTabItem(
                    icon = Icons.AutoMirrored.Filled.Message,
                    label = "Chats",
                    selected = selectedTab == AppViewModel.Tab.CHATS,
                    width = itemWidth,
                    onClick = { onSelectTab(AppViewModel.Tab.CHATS) },
                )
                FloatingTabItem(
                    icon = Icons.Filled.Dns,
                    label = "Network",
                    selected = selectedTab == AppViewModel.Tab.NETWORK,
                    width = itemWidth,
                    onClick = { onSelectTab(AppViewModel.Tab.NETWORK) },
                )
                FloatingTabItem(
                    icon = Icons.Filled.Settings,
                    label = "Settings",
                    selected = selectedTab == AppViewModel.Tab.SETTINGS,
                    width = itemWidth,
                    onClick = { onSelectTab(AppViewModel.Tab.SETTINGS) },
                )
            }
        }

        Spacer(modifier = Modifier.width(10.dp))

        // Detached search bubble — mirrors iOS's separated Tab(role: .search).
        SearchBubble(onClick = { onSelectTab(AppViewModel.Tab.SEARCH) })
    }
}

@Composable
private fun SearchBubble(onClick: () -> Unit) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    Box(
        modifier = Modifier
            .shadow(elevation = 8.dp, shape = CircleShape)
            .background(color = LocalAvalancheColors.current.paper, shape = CircleShape)
            .border(
                width = 0.5.dp,
                color = LocalAvalancheColors.current.ink.copy(alpha = 0.08f),
                shape = CircleShape,
            )
            .clip(CircleShape)
            .background(
                if (pressed) LocalAvalancheColors.current.ink.copy(alpha = 0.08f)
                else Color.Transparent,
            )
            .clickable(
                interactionSource = interaction,
                indication = null,
                onClick = onClick,
            )
            .size(FloatingBarHeight),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = Icons.Filled.Search,
            contentDescription = "Search",
            tint = LocalAvalancheColors.current.muted,
        )
    }
}

@Composable
private fun FloatingTabItem(
    icon: ImageVector,
    label: String,
    selected: Boolean,
    width: Dp,
    onClick: () -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    // Same capsule as the sliding selection pill — the item fills the inset
    // content area, so the press highlight is pixel-identical to it.
    val itemShape = RoundedCornerShape(percent = 50)
    val tint = if (selected) LocalAvalancheColors.current.brand else LocalAvalancheColors.current.muted
    Column(
        modifier = Modifier
            .width(width)
            .fillMaxHeight()
            .clip(itemShape)
            // Finger-down highlight; the *selected* backing is the sliding
            // pill drawn behind the item row, not per-item background.
            .background(
                if (pressed) LocalAvalancheColors.current.ink.copy(alpha = 0.08f)
                else Color.Transparent,
            )
            .clickable(
                interactionSource = interaction,
                indication = null,
                onClick = onClick,
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp, Alignment.CenterVertically),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = tint,
            modifier = Modifier.size(22.dp),
        )
        Text(
            text = label,
            fontSize = 10.sp,
            // Pin the line height — the default (~15sp for 10sp text) inflates
            // the label's box and shoves the icon toward the pill's top edge.
            lineHeight = 11.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            color = tint,
        )
    }
}

// ---------------------------------------------------------------------------
// Floating search field (replaces the tab bar while searching)
// ---------------------------------------------------------------------------

@Composable
private fun FloatingSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    onClose: () -> Unit,
) {
    val capsule = RoundedCornerShape(FloatingBarHeight / 2)
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) { focusRequester.requestFocus() }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(elevation = 8.dp, shape = capsule)
            .background(color = LocalAvalancheColors.current.paper, shape = capsule)
            .border(
                width = 0.5.dp,
                color = LocalAvalancheColors.current.ink.copy(alpha = 0.08f),
                shape = capsule,
            )
            .clip(capsule)
            .height(FloatingBarHeight)
            .padding(start = 18.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Filled.Search,
            contentDescription = null,
            tint = LocalAvalancheColors.current.muted,
        )
        Box(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 12.dp),
            contentAlignment = Alignment.CenterStart,
        ) {
            if (query.isEmpty()) {
                Text(
                    text = "Search conversations",
                    color = LocalAvalancheColors.current.muted,
                    fontSize = 16.sp,
                )
            }
            BasicTextField(
                value = query,
                onValueChange = onQueryChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .focusRequester(focusRequester),
                singleLine = true,
                textStyle = TextStyle(
                    color = LocalAvalancheColors.current.ink,
                    fontSize = 16.sp,
                ),
                cursorBrush = SolidColor(LocalAvalancheColors.current.brand),
            )
        }
        IconButton(onClick = onClose) {
            Icon(
                imageVector = Icons.Filled.Close,
                contentDescription = "Close search",
                tint = LocalAvalancheColors.current.muted,
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun MainTabViewPreview() {
    AvalancheTheme {
        MainTabView(appViewModel = rememberPreviewAppViewModel())
    }
}
