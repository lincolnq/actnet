#if DEBUG
import SwiftUI

// MARK: - Chats "conversation intelligence" prototype (design-only)
//
// A throwaway visual prototype for the tabbed Chats surface (blog:
// 2026-07-intelligence). NOT wired into the app — it exists only to render in
// Xcode previews so we can react to the layout before speccing.
//
// The model on trial: categories are an EXHAUSTIVE PARTITION (Gmail-style),
// not a filter bar. Every conversation lives in exactly one tab; there is no
// "All". Tabs are user-configurable. "Threads" appears as its own home-tab —
// the middle-ground reading where a followed thread is a top-level
// conversation hidden behind the threads pane. Mentions/Saved are deliberately
// NOT here (they're overlapping lenses, not homes).

private struct ProtoConv: Identifiable {
    let id = UUID()
    var title: String
    var preview: String
    var time: String
    var unread: Int = 0
    var icon: String = "person"
    var isBot: Bool = false
    /// Subtle multi-account hint (the axis we haven't settled). nil = single account.
    var accountTint: Color? = nil
    var isThreadRow: Bool = false
    /// For thread rows: which channel the thread hangs off.
    var threadParent: String? = nil
}

private struct ProtoTab: Identifiable {
    let id = UUID()
    var name: String
    var systemImage: String
    var unread: Int = 0
    var convs: [ProtoConv]
}

struct ChatsTabbedPrototype: View {
    @State private var selected: UUID

    private let tabs: [ProtoTab]
    private let threads: [ProtoConv]

    init() {
        let action = ProtoTab(name: "Action", systemImage: "megaphone", unread: 6, convs: [
            ProtoConv(title: "Canvass NW", preview: "Maria: door packets are in the trunk", time: "2m", unread: 4, icon: "person.3", accountTint: .plum400),
            ProtoConv(title: "Phone Bank", preview: "You: shift starts at 6", time: "18m", icon: "person.3", accountTint: .plum400),
            ProtoConv(title: "Action Day Leads", preview: "Sam: route sheet attached 📎", time: "1h", unread: 2, icon: "person.3", accountTint: .moss),
            ProtoConv(title: "Rapid Response", preview: "Dana: standing by", time: "Tue", icon: "person.3", accountTint: .plum400),
        ])
        let personal = ProtoTab(name: "Personal", systemImage: "heart", unread: 1, convs: [
            ProtoConv(title: "Alice", preview: "see you saturday!", time: "5m", unread: 1, icon: "person"),
            ProtoConv(title: "Mom", preview: "You: landed safe", time: "3h", icon: "person"),
            ProtoConv(title: "Book Club", preview: "Jo: chapter 4 tonight", time: "Mon", icon: "person.3"),
        ])
        let updates = ProtoTab(name: "Updates", systemImage: "bell", unread: 0, convs: [
            ProtoConv(title: "adminbot · safe-haven", preview: "Server updated to 0.4.1", time: "6h", icon: "gearshape.2", isBot: true, accountTint: .plum400),
            ProtoConv(title: "adminbot · pseudo.example", preview: "Welcome to Pseudo.", time: "2d", icon: "gearshape.2", isBot: true, accountTint: .moss),
            ProtoConv(title: "Announcements", preview: "Rally location confirmed", time: "2d", icon: "megaphone"),
        ])
        self.tabs = [action, personal, updates]
        // Threads are no longer a tab — they surface as a single catch-up entry
        // pinned to the top of the list (see threadsEntry).
        self.threads = [
            ProtoConv(title: "", preview: "", time: "12m", unread: 3, icon: "arrow.turn.down.right", isThreadRow: true, threadParent: "Canvass NW"),
            ProtoConv(title: "sign-up sheet", preview: "You: added 3 slots", time: "1h", icon: "arrow.turn.down.right", isThreadRow: true, threadParent: "Phone Bank"),
            ProtoConv(title: "venue A vs B", preview: "Sam: B has parking", time: "Yst", unread: 2, icon: "arrow.turn.down.right", isThreadRow: true, threadParent: "Action Day Leads"),
        ]
        _selected = State(initialValue: action.id)
    }

    private var current: ProtoTab { tabs.first { $0.id == selected } ?? tabs[0] }
    private var firstUnreadThread: ProtoConv? { threads.first { $0.unread > 0 } }
    private var unreadThreadCount: Int { threads.filter { $0.unread > 0 }.count }
    private var threadsUnreadTotal: Int { threads.reduce(0) { $0 + $1.unread } }
    private var unreadThreadGroups: [String] { threads.filter { $0.unread > 0 }.compactMap { $0.threadParent } }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                tabStrip
                    // Shelf sits at the very top now that the nav bar is gone;
                    // its avPaper fills up behind the status bar.
                    .background(Color.avPaper.ignoresSafeArea(edges: .top))
                    .overlay(alignment: .bottom) {
                        Rectangle().fill(Color.avMuted.opacity(0.18)).frame(height: 0.5)
                    }
                list
            }
            .background(Color.avCard)
            .toolbar(.hidden, for: .navigationBar)
        }
        .tint(Color.avBrand)
    }

    // Gmail-style tabs: underline for the selected home, count riding the label.
    // Trailing "+" signals the set is user-configurable. No "All" tab — the
    // partition is exhaustive by construction.
    private var tabStrip: some View {
        HStack(spacing: 4) {
            ForEach(tabs) { tab in
                tabButton(tab)
            }
        }
        .frame(maxWidth: .infinity)   // center the tab group
        .padding(.top, 4)
    }

    private func tabButton(_ tab: ProtoTab) -> some View {
        let isSel = tab.id == selected
        return Button { selected = tab.id } label: {
            VStack(spacing: 7) {
                VStack(spacing: 4) {
                    Image(systemName: tab.systemImage)
                        .font(.body)
                        .overlay(alignment: .topTrailing) {
                            if tab.unread > 0 {
                                Text("\(tab.unread)")
                                    .font(.system(size: 9, weight: .bold))
                                    .foregroundStyle(.white)
                                    .padding(.horizontal, 4).padding(.vertical, 1)
                                    .background(Color.avNotification, in: Capsule())
                                    .offset(x: 12, y: -7)
                            }
                        }
                    Text(tab.name).font(.caption2.weight(isSel ? .semibold : .medium))
                }
                .foregroundStyle(isSel ? Color.avBrand : Color.avMuted)
                .frame(width: 62)
                .padding(.top, 8).padding(.bottom, 2)

                Rectangle()
                    .fill(isSel ? Color.avBrand : .clear)
                    .frame(height: 2)
                    .clipShape(Capsule())
            }
        }
    }

    private var list: some View {
        List {
            // Threads only surface on the first (Action) tab, not Personal/Updates.
            if unreadThreadCount > 0 && selected == tabs.first?.id {
                threadsEntry()
                    .listRowBackground(Color.avCard)
                    .listRowSeparatorTint(Color.avMuted.opacity(0.2))
            }
            ForEach(current.convs) { c in
                ProtoRow(conv: c)
                    .listRowBackground(Color.avCard)
                    .listRowSeparatorTint(Color.avMuted.opacity(0.2))
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(Color.avCard)
        // Leave room so the last row scrolls clear of the floating bottom bar.
        .contentMargins(.bottom, 88, for: .scrollContent)
    }

    // A single, deliberately compact catch-up entry pinned atop the list — the
    // threads "home" without a tab. Shorter than a conversation row and with a
    // smaller-than-avatar glyph so it reads as distinct chrome, not a chat.
    private func threadsEntry() -> some View {
        HStack(spacing: 12) {
            Image(systemName: "bubble.left.and.bubble.right.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(Color.avBrand)
                .frame(width: 30, height: 30)
                .background(Color.avBrand.opacity(0.12), in: Circle())
                // Reserve the avatar's footprint (46) so the text lines up with
                // the conversation rows below.
                .frame(width: 46)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text("Threads").font(.subheadline.weight(.semibold)).foregroundStyle(Color.avInk)
                    Text("(\(unreadThreadCount) new)")
                        .font(.caption).foregroundStyle(Color.avBrand)
                    Spacer()
                    Image(systemName: "chevron.right").font(.caption2.weight(.semibold)).foregroundStyle(Color.avMuted)
                }
                // Preview lists the groups the unread threads live in ("in Canvass
                // NW, Action Day Leads"), with the unread badge trailing — same
                // slot as the conversation rows below.
                HStack {
                    (Text("").foregroundStyle(Color.avMuted.opacity(0.8))
                     + Text(unreadThreadGroups.joined(separator: " • ")).foregroundStyle(Color.avMuted.opacity(0.7)))
                        .font(.caption).lineLimit(1)
                    Spacer()
                    Text("\(threadsUnreadTotal)")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.avNotification, in: Capsule())
                }
            }
        }
        .padding(.vertical, -2)
    }
}

private struct ProtoRow: View {
    let conv: ProtoConv

    var body: some View {
        HStack(spacing: 12) {
            avatar
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    if conv.isThreadRow, let parent = conv.threadParent {
                        // A thread row carries its parent channel as context —
                        // this is the "home for a nested object" tell.
                        (Text(parent).foregroundStyle(Color.avMuted)
                         + Text("  ›  ").foregroundStyle(Color.avMuted.opacity(0.6))
                         + Text(conv.title).foregroundStyle(Color.avInk))
                        .font(.subheadline.weight(.medium)).lineLimit(1)
                    } else {
                        Text(conv.title).font(.subheadline.weight(.medium))
                            .foregroundStyle(Color.avInk).lineLimit(1)
                    }
                    Spacer()
                    Text(conv.time).font(.caption).foregroundStyle(Color.avMuted)
                }
                HStack(spacing: 6) {
                    Text(conv.preview).font(.subheadline).foregroundStyle(Color.avMuted).lineLimit(1)
                    Spacer()
                    if conv.unread > 0 {
                        Text("\(conv.unread)")
                            .font(.caption2.weight(.bold)).foregroundStyle(.white)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Color.avNotification, in: Capsule())
                    }
                }
            }
        }
        .padding(.vertical, 3)
    }

    private var avatar: some View {
        let shape: AnyShape = conv.isBot
            ? AnyShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            : AnyShape(Circle())
        return shape
            .fill(Color.avPaper)
            .frame(width: 46, height: 46)
            .overlay { Image(systemName: conv.icon).foregroundStyle(Color.avMuted) }
    }
}

// Composes the tabbed Chats surface with a custom floating bottom bar. We build
// the bar by hand (rather than the system TabView) so the tab capsule and the
// search circle are true siblings — same fill, same height, same float — like
// Slack's bar + detached search button.
private enum ProtoBottomTab { case chats, network, settings }

private struct ProtoTabHost: View {
    @State private var tab: ProtoBottomTab = .chats

    var body: some View {
        ZStack(alignment: .bottom) {
            Group {
                switch tab {
                case .chats: ChatsTabbedPrototype()
                case .network:
                    NavigationStack {
                        ContentUnavailableView(
                            "Network",
                            systemImage: "server.rack",
                            description: Text("Servers and their Projects appear here.")
                        )
                        .navigationTitle("Network")
                    }
                case .settings:
                    NavigationStack {
                        ContentUnavailableView(
                            "Settings",
                            systemImage: "gearshape",
                            description: Text("Accounts, notifications, appearance.")
                        )
                        .navigationTitle("Settings")
                    }
                }
            }
            bottomBar
        }
    }

    // Left: a floating capsule of tab items (Chats / Network / Settings).
    // Right: a separate action bubble holding search + compose together.
    private var bottomBar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 2) {
                tabItem(.chats, "message", "Chats")
                tabItem(.network, "server.rack", "Network")
                tabItem(.settings, "gearshape", "Settings")
            }
            .padding(6)
            .background(Color.avPaper, in: Capsule())
            .overlay(Capsule().stroke(Color.avMuted.opacity(0.18), lineWidth: 0.5))
            .shadow(color: .black.opacity(0.10), radius: 8, x: 0, y: 2)

            Spacer(minLength: 0)

            HStack(spacing: 2) {
                actionButton("magnifyingglass")
                actionButton("square.and.pencil")
            }
            .padding(6)
            .background(Color.avPaper, in: Capsule())
            .overlay(Capsule().stroke(Color.avMuted.opacity(0.18), lineWidth: 0.5))
            .shadow(color: .black.opacity(0.10), radius: 8, x: 0, y: 2)
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 4)
    }

    private func tabItem(_ which: ProtoBottomTab, _ icon: String, _ label: String) -> some View {
        let isSel = tab == which
        return Button { tab = which } label: {
            VStack(spacing: 3) {
                Image(systemName: icon).font(.body)
                Text(label).font(.caption2.weight(.medium))
            }
            .foregroundStyle(isSel ? Color.avBrand : Color.avMuted)
            .frame(width: 66, height: 48)
            .background(isSel ? Color.avBrand.opacity(0.14) : .clear, in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    private func actionButton(_ icon: String) -> some View {
        Button {} label: {
            Image(systemName: icon)
                .font(.body.weight(.semibold))
                .foregroundStyle(Color.avBrand)
                .frame(width: 48, height: 48)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
    }
}

#Preview("Composed")        { ProtoTabHost() }
#Preview("Composed (Dark)") { ProtoTabHost().preferredColorScheme(.dark) }
#endif
