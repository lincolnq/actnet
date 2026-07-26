import SwiftUI

/// Content of the native `.search` role tab (`docs/37-chat-organization.md`).
/// A `.searchable` conversation list filtered by title, across all accounts —
/// search is a cross-cutting lens, not scoped to the selected account tab.
/// Client-side only for v1: filters the already-loaded conversation list, no
/// server-side search.
struct ConversationSearchView: View {
    @EnvironmentObject var appState: AppState
    @State private var query = ""
    @State private var navigationPath = NavigationPath()

    private var results: [Conversation] {
        let sorted = appState.conversations.sorted { a, b in
            (a.lastMessageDate ?? .distantPast) > (b.lastMessageDate ?? .distantPast)
        }
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return sorted }
        return sorted.filter { $0.title.localizedCaseInsensitiveContains(trimmed) }
    }

    var body: some View {
        NavigationStack(path: $navigationPath) {
            List {
                ForEach(results) { conversation in
                    Button {
                        navigationPath.append(conversation)
                    } label: {
                        ConversationRow(conversation: conversation, account: accountFor(conversation))
                    }
                    .buttonStyle(ChatRowButtonStyle())
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.avCard)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .background(Color.avCard)
            .overlay {
                if results.isEmpty && !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    ContentUnavailableView.search(text: query)
                }
            }
            .navigationTitle("Search")
            .navigationBarTitleDisplayMode(.inline)
            .navigationDestination(for: Conversation.self) { conversation in
                ConversationView(conversation: conversation)
            }
        }
        .searchable(text: $query, prompt: "Search conversations")
    }

    private func accountFor(_ conversation: Conversation) -> Account? {
        appState.accounts.first { $0.id == conversation.accountId }
    }
}
