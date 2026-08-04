import SwiftUI

/// The app's root tab surface. A native `TabView` so it renders as a real
/// iOS 26 Liquid Glass tab bar (and the `.search` role becomes the detached
/// floating search capsule) — see `docs/37-chat-organization.md`. On iOS 18–25
/// it degrades to the standard opaque tab bar and the search role shows as a
/// normal tab, the same graceful-fallback approach as `composerPillBackground`.
struct MainTabView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        if #available(iOS 26.0, *) {
            tabs.tabBarMinimizeBehavior(.onScrollDown)
        } else {
            tabs
        }
    }

    @ViewBuilder
    private var tabs: some View {
        TabView(selection: $appState.selectedTab) {
            // Brand tab glyphs — design/Chats Bubble.svg and design/Network
            // Globe.svg, imported as template SVGs so the tab tint applies.
            Tab("Chats", image: "TabChats", value: AppState.Tab.chats) {
                ChatsView()
            }

            Tab("Network", image: "TabNetwork", value: AppState.Tab.network) {
                NetworkView()
            }

            Tab("Settings", systemImage: "gearshape", value: AppState.Tab.settings) {
                AccountsView()
            }

            Tab("Search", systemImage: "magnifyingglass", value: AppState.Tab.search, role: .search) {
                ConversationSearchView()
            }
        }
    }
}
