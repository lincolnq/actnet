import SwiftUI
import UIKit

/// New-conversation composer. A consistent layout — To-field with recipient
/// pills, an always-browsable (and typing-filtered) contact list, and two
/// persistent actions: **DM** (enabled at exactly one recipient; opens the
/// existing or a fresh thread) and **New Group** (always available; routes to
/// the Name Group screen). See `docs/30-mobile-ux.md` §Compose.
///
/// Sending identity ("From") starts EMPTY with the whole merged contact book
/// visible; it gets fixed by the first contact pick (the contact's preferred
/// identity — the account that most recently talked to them) or an explicit
/// From choice, and each side filters the other (docs/52 query-time
/// unification). The reachability filter also prevents founding cross-server
/// groups. Cross-server founding proper is deferred (federation).
struct ComposeMessageView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var chips: [Chip] = []
    @State private var query: String = ""
    /// Acting identity ("From"). Deliberately EMPTY at first: the composer
    /// opens showing the whole merged contact book, and the identity gets
    /// fixed by whichever gesture comes first — picking a contact (From fills
    /// in from the contact's preferred identity) or choosing a From entry
    /// (the book filters to what that identity can reach). Either way the
    /// other side follows. Single-account users never see the From row and
    /// fall back to their only account at action time.
    @State private var selectedAccountId: String?
    @State private var allContacts: [AppState.AccountContact] = []
    @State private var sending: Bool = false
    @State private var errorMessage: String?
    @State private var showingContactPicker = false
    /// Drives the push to the Name Group screen from the New Group button.
    @State private var showNameGroup = false
    /// Lets the autocomplete / DID-submit paths push a chip into the
    /// `UITextView`-backed recipient field, which owns the chip content.
    @StateObject private var fieldHandle = RecipientFieldHandle()
    /// Manual keyboard inset (see body): the keyboard stays up across the
    /// Name Group push/pop, and SwiftUI's automatic avoidance loses its inset
    /// while this view is off-window — the bar came back buried behind the
    /// keyboard. The observed height persists, so the layout is right on
    /// return with the keyboard never moving.
    @StateObject private var keyboard = KeyboardHeightObserver()

    /// A confirmed recipient. `displayName` may be empty when the user typed
    /// a raw DID we haven't seen before; `label` falls back to a truncated
    /// DID in that case.
    struct Chip: Identifiable, Hashable {
        let id: String  // == did
        let did: String
        let displayName: String

        /// User-visible text for the chip. Never a raw full DID.
        var label: String { displayName.isEmpty ? shortenDid(did) : displayName }
    }

    init(initialChips: [Chip] = []) {
        _chips = State(initialValue: initialChips)
    }

    private var accounts: [Account] { appState.accounts }

    /// The fixed acting identity, or nil while From is still empty. Validated
    /// against the live account list (a removed account must not stick). With
    /// a single account there's no From row and no ambiguity — it's just
    /// active.
    private var activeAccountId: String? {
        if let sel = selectedAccountId, accounts.contains(where: { $0.id == sel }) {
            return sel
        }
        return accounts.count == 1 ? accounts.first?.id : nil
    }

    /// The identity actions (DM / New Group / Note to Self) run as: the fixed
    /// one, else the only sensible default. Reached with From empty only via
    /// raw-DID / scanned recipients.
    private var actionAccountId: String? { activeAccountId ?? accounts.first?.id }

    /// Servers the active identity belongs to (home server first).
    private var activeAccountServers: [ServerInfo] {
        guard let id = activeAccountId,
              let account = accounts.first(where: { $0.id == id }) else { return [] }
        return account.servers
    }

    /// The server a conversation founded right now would live on — the active
    /// identity's home server. Shown in the header and on the Name Group screen.
    private var activeServer: ServerInfo? { activeAccountServers.first }

    private var trimmedQuery: String {
        query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var queryLooksLikeDid: Bool {
        trimmedQuery.hasPrefix("did:")
    }

    /// Once an acting identity is fixed (either direction), the book filters
    /// to contacts that identity knows — groups/DMs are server-local until
    /// federation, so offering another identity's contacts would build a
    /// cross-server group that can't work. While From is empty: everything.
    private var reachableContacts: [AppState.AccountContact] {
        guard let acting = activeAccountId else { return allContacts }
        return allContacts.filter { $0.accountIds.contains(acting) }
    }

    /// Query matching: names always; DIDs only when the query itself looks
    /// like a DID (starts with "did:"). DIDs are effectively random strings —
    /// substring-matching them against a short name query surfaces unrelated
    /// contacts via letters the user can't even see.
    private func matchesQuery(_ c: AppState.AccountContact, _ q: String) -> Bool {
        guard !q.isEmpty else { return true }
        if q.hasPrefix("did:") {
            return c.row.did.lowercased().hasPrefix(q)
        }
        return c.row.displayName.lowercased().contains(q)
    }

    /// People = curated contacts (docs/35). Filtered by query if present.
    private var peopleResults: [AppState.AccountContact] {
        let q = trimmedQuery.lowercased()
        return reachableContacts.filter { c in
            guard c.row.isCurated, !chips.contains(where: { $0.did == c.row.did }) else { return false }
            return matchesQuery(c, q)
        }
    }

    /// Other = every other contact row. Behaves like a discovery surface.
    private var otherResults: [AppState.AccountContact] {
        let q = trimmedQuery.lowercased()
        return reachableContacts.filter { c in
            guard !c.row.isCurated, !chips.contains(where: { $0.did == c.row.did }) else { return false }
            return matchesQuery(c, q)
        }
    }

    /// "Note to Self" candidates (a DM with your own identity — docs/04 §5.5,
    /// like Signal). Deliberately quiet: it appears ONLY when the user has
    /// typed a substring of "note to self", there are no recipients yet
    /// (adding yourself to a group makes no sense), and it renders *below*
    /// any matching contacts. While From is empty there's no single "self",
    /// so each account gets its own labeled entry — picking one fills From,
    /// exactly like picking a contact does.
    private var noteToSelfCandidates: [Account] {
        guard chips.isEmpty else { return [] }
        let q = trimmedQuery.lowercased()
        guard !q.isEmpty, "note to self".contains(q) else { return [] }
        if let acting = activeAccountId {
            return accounts.filter { $0.id == acting }
        }
        return accounts
    }

    /// Display names that appear on more than one visible contact (e.g. the
    /// testbot re-registered across dev-server resets, or two humans genuinely
    /// sharing a name). Those rows get a shortened-DID subtitle so identical
    /// names are tellable apart — collapsing them instead would let a
    /// name-spoofer hide behind a real contact (docs/12).
    private var collidingNames: Set<String> {
        var counts: [String: Int] = [:]
        for c in reachableContacts {
            counts[contactName(c).lowercased(), default: 0] += 1
        }
        return Set(counts.filter { $0.value > 1 }.keys)
    }

    private func subtitleFor(_ c: AppState.AccountContact) -> String? {
        collidingNames.contains(contactName(c).lowercased()) ? shortenDid(c.row.did) : nil
    }

    /// New Group button label: "New Empty Group" with no recipients, otherwise
    /// "New Group (N)" filled with the recipient count.
    private var newGroupTitle: String {
        chips.isEmpty ? "New Empty Group" : "New Group (\(chips.count))"
    }

    var body: some View {
        NavigationStack {
            // Opt out of SwiftUI's keyboard avoidance and pad manually — the
            // automatic inset is dropped across the Name Group push/pop (the
            // keyboard stays up throughout), leaving the action bar behind
            // the keyboard on return. The home-indicator inset is already
            // applied below the VStack, so subtract it from the pad or the
            // bar floats that far above the keyboard.
            GeometryReader { geo in
                VStack(spacing: 0) {
                    if accounts.count > 1 {
                        accountPicker
                        Divider()
                    }
                    recipientField
                    Divider()
                    // Contacts are always browsable; typing filters them in place.
                    autocompleteList
                    actionBar
                }
                .padding(.bottom, max(0, keyboard.height - geo.safeAreaInsets.bottom))
            }
            .ignoresSafeArea(.keyboard, edges: .bottom)
            .background(Color.avPaper)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    VStack(spacing: 0) {
                        Text("New Conversation").font(.headline)
                        if let server = activeServer {
                            Text("at \(server.displayHost)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel("Cancel")
                }
            }
            .navigationDestination(isPresented: $showNameGroup) {
                NameGroupView(
                    members: chips,
                    accountId: actionAccountId ?? "",
                    servers: actionAccountId.flatMap { id in
                        accounts.first(where: { $0.id == id })?.servers
                    } ?? [],
                    onCreated: { conv in
                        appState.navigateToConversation = conv
                        dismiss()
                    }
                )
            }
        }
        // Load the merged contact book once (re-merged if the account set
        // changes).
        .task(id: appState.accounts) { await loadContacts() }
        // Recognize a contact link pasted into the recipient field (the link
        // another user's app generates) and turn it into a chip.
        .onChange(of: query) { _, newValue in
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            _ = handleContactLink(trimmed)
        }
        .sheet(isPresented: $showingContactPicker) {
            ContactPickerSheet(
                contacts: reachableContacts,
                excludedDids: Set(chips.map(\.did)),
                nameFor: contactName,
                isBotFor: isBot,
                subtitleFor: subtitleFor,
                onSelect: { c in addContactChip(c) },
                onScanLink: handleContactLink
            )
        }
    }

    private var accountPicker: some View {
        HStack {
            Text("From").foregroundStyle(.secondary)
            Picker("Account", selection: $selectedAccountId) {
                // Empty until the user (or a contact pick) fixes the identity.
                Text("Choose account").tag(String?.none)
                ForEach(accounts) { account in
                    Text(account.displayName).tag(Optional(account.id))
                }
            }
            .pickerStyle(.menu)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    private var recipientField: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 8) {
                RecipientTokenField(
                    chips: $chips,
                    query: $query,
                    prefix: "To:",
                    placeholder: "Type a name",
                    handle: fieldHandle,
                    onSubmit: commitQueryAsChip
                )
                .frame(maxWidth: .infinity, alignment: .leading)

                Button {
                    showingContactPicker = true
                } label: {
                    Image(systemName: "plus.circle")
                        .font(.title2)
                        .foregroundStyle(Color.avBrand)
                }
                .accessibilityLabel("Add recipient")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal)
        .padding(.vertical, 10)
    }

    private var autocompleteList: some View {
        List {
            if queryLooksLikeDid && !trimmedQuery.isEmpty {
                Button {
                    addChip(did: trimmedQuery, displayName: "")
                } label: {
                    HStack {
                        Image(systemName: "person.crop.circle.badge.plus")
                        Text("Add \(trimmedQuery)").lineLimit(1)
                    }
                }
                .buttonStyle(ChatRowButtonStyle())
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.avPaper)
            }
            // Headers are ordinary rows, not Section headers — plain-list
            // section headers pin ("stick") while scrolling, which reads as a
            // toolbar over a list this short. Matches Android's plain items.
            if !peopleResults.isEmpty {
                composeSectionHeader("People")
                ForEach(peopleResults) { c in
                    contactRow(c)
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.avPaper)
            }
            if !otherResults.isEmpty {
                composeSectionHeader("Other")
                ForEach(otherResults) { c in
                    contactRow(c)
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.avPaper)
            }
            // Note to Self — only on a typed "note to self" substring match,
            // below any matching contacts (see candidates above).
            ForEach(noteToSelfCandidates) { account in
                Button {
                    if activeAccountId == nil {
                        selectedAccountId = account.id
                    }
                    addChip(did: account.id, displayName: "Note to Self")
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "bookmark.circle.fill")
                            .font(.title2)
                            .frame(width: 32, height: 32)
                            .foregroundStyle(Color.avBrand)
                        Text(noteToSelfCandidates.count > 1
                             ? "Note to Self (\(account.displayName))"
                             : "Note to Self")
                            .foregroundStyle(.primary)
                    }
                }
                .buttonStyle(ChatRowButtonStyle())
            }
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.avPaper)
            if peopleResults.isEmpty && otherResults.isEmpty && !queryLooksLikeDid && noteToSelfCandidates.isEmpty {
                Text("No more contacts to add.")
                    .foregroundStyle(.secondary)
                    .font(.footnote)
                    .listRowBackground(Color.avPaper)
            }
        }
        .listStyle(.plain)
        // Let the header rows collapse to their content — the 44pt default
        // minimum is what made them read as full rows. Contact rows keep
        // their height from the 32pt avatar + row insets.
        .environment(\.defaultMinListRowHeight, 24)
        .scrollContentBackground(.hidden)
        .background(Color.avPaper)
    }

    private func contactRow(_ c: AppState.AccountContact) -> some View {
        Button {
            addContactChip(c)
        } label: {
            HStack(spacing: 10) {
                ContactAvatar(name: contactName(c), isBot: isBot(c), size: 32)
                VStack(alignment: .leading, spacing: 1) {
                    Text(contactName(c))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    if let subtitle = subtitleFor(c) {
                        Text(subtitle)
                            .font(.caption2)
                            .foregroundStyle(Color.avMuted)
                            .lineLimit(1)
                    }
                }
            }
        }
        // Same finger-down backing as the chat list rows — the explicit
        // listRowBackground suppresses the system tap highlight, so press
        // feedback has to come from the button style.
        .buttonStyle(ChatRowButtonStyle())
    }

    /// Whether a contact is a bot, for the hexagon avatar frame
    /// (docs/54-bot-presentation.md). Resolves against the identity that
    /// knows the contact (its tag), not the acting identity.
    private func isBot(_ c: AppState.AccountContact) -> Bool {
        appState.isBot(c.row.did, accountId: c.accountId)
    }

    /// The name to show for a contact. Resolves through the shared
    /// `AppState.resolvedName` path so humans (cached profile) and bots
    /// (server record) render identically; the contact-list rows' own
    /// `displayName` is seeded into that cache in `loadContacts`. Resolution
    /// runs against the identity that knows the contact (its tag). Never a
    /// DID. (User-set overrides — nickname/photo, docs/35 — slot in here once
    /// stored.)
    private func contactName(_ c: AppState.AccountContact) -> String {
        appState.resolvedName(for: c.row.did, accountId: c.accountId)
    }

    /// ONE morphing action — the recommended act for the current recipient
    /// count: "New Empty Group" (quiet outline) at 0, "DM" at exactly 1,
    /// "New Group (N)" at 2+. The non-recommended path at 1 recipient lives
    /// in a small text link under the button. The primary fill is fixed plum
    /// (like the outgoing bubble), so light and dark read identically and
    /// brand color means exactly one thing: "press this".
    private var actionBar: some View {
        VStack(spacing: 0) {
            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(Color.avError)
                    .padding(.horizontal)
            }
            Divider()
            // Always exactly ONE row — the bar never changes height. At one
            // recipient the primary shares the row with a compact "Group"
            // button (the alternate path); otherwise the single button fills.
            HStack(spacing: 10) {
                if chips.count == 1 {
                    Button {
                        dmTapped()
                    } label: {
                        // `label`, not `displayName` — never empty (falls back
                        // to a shortened DID for raw-DID recipients).
                        Text("DM \(chips[0].label)")
                            .lineLimit(1)
                    }
                    .buttonStyle(ComposePrimaryButtonStyle())

                    Button {
                        showNameGroup = true
                    } label: {
                        Text(newGroupTitle)
                    }
                    .buttonStyle(ComposeOutlineButtonStyle(fullWidth: false))
                } else if chips.count >= 2 {
                    Button {
                        showNameGroup = true
                    } label: {
                        Text(newGroupTitle)
                    }
                    .buttonStyle(ComposePrimaryButtonStyle())
                } else {
                    Button {
                        showNameGroup = true
                    } label: {
                        Text(newGroupTitle)
                    }
                    .buttonStyle(ComposeOutlineButtonStyle())
                }
            }
            .disabled(sending)
            .padding(.horizontal)
            .padding(.vertical, 10)
        }
    }

    private func loadContacts() async {
        // The *merged* book across all identities (docs/52 unified-at-query).
        let rows = await appState.listAllContacts()
        await MainActor.run {
            self.allContacts = rows
            // Feed the names we already have into the shared resolver so it
            // doesn't re-fetch them; bots (no cached profile name) fall through
            // to the server lookup via `resolvedName`.
            for c in rows {
                appState.cacheDisplayName(c.row.displayName, for: c.row.did)
            }
        }
    }

    /// Add a recipient. The token field owns the chip content (dedup, clearing
    /// the typed query, selection), then mirrors the result back into `chips` /
    /// `query`.
    private func addChip(did: String, displayName: String) {
        fieldHandle.addChip(Chip(id: did, did: did, displayName: displayName))
    }

    /// Adding a contact from the merged book: if From is still empty, the pick
    /// fills it with the contact's preferred identity — the identity that most
    /// recently talked to this person (docs/52) — and the book filters to what
    /// that identity can reach. Later picks never flip the identity; the From
    /// row remains the manual control (which filters the other way).
    private func addContactChip(_ c: AppState.AccountContact) {
        if activeAccountId == nil {
            selectedAccountId = c.accountId
        }
        addChip(did: c.row.did, displayName: contactName(c))
    }

    /// If `raw` is an Avalanche contact link (QR payload or pasted URL), add the
    /// recipient it points at as a chip and report success. Both link shapes
    /// another user's app can produce carry a DID:
    ///   `https://go.theavalanche.net/conversation/<did>`
    ///   `https://go.theavalanche.net/i/<base64url {"d":…}>`  (d = inviter_did)
    @discardableResult
    private func handleContactLink(_ raw: String) -> Bool {
        guard let did = Self.recipientDid(fromContactLink: raw) else { return false }
        guard !chips.contains(where: { $0.did == did }) else { return true }
        addChip(did: did, displayName: "")
        return true
    }

    /// Extract a recipient DID from a contact link, or `nil` if it isn't one.
    /// Decodes the invite token locally — we only need the DID to make a chip,
    /// not full server validation.
    static func recipientDid(fromContactLink raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), AppState.isDeepLink(url) else { return nil }
        let parts = url.pathComponents.filter { $0 != "/" }
        guard parts.count >= 2 else { return nil }
        switch parts[0] {
        case "conversation":
            return parts[1].hasPrefix("did:") ? parts[1] : nil
        case "i", "invite":
            guard let data = Data(base64URLEncoded: parts[1]),
                  let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let did = payload["d"] as? String,
                  did.hasPrefix("did:") else { return nil }
            return did
        default:
            return nil
        }
    }

    private func commitQueryAsChip() {
        if queryLooksLikeDid {
            addChip(did: trimmedQuery, displayName: "")
        } else if let first = peopleResults.first ?? otherResults.first {
            addContactChip(first)
        }
    }

    /// DM action: jump straight to the thread with the single recipient,
    /// reusing the existing conversation or starting a fresh one. No first
    /// message is sent — the composer just lands the user in the thread.
    private func dmTapped() {
        guard chips.count == 1, let accountId = actionAccountId else { return }
        let conv = appState.findOrCreateDMConversation(
            recipientDid: chips[0].did,
            accountId: accountId
        )
        appState.navigateToConversation = conv
        dismiss()
    }

}

/// Publishes the keyboard's current overlap height from frame notifications.
/// Used by the composer to manage its own keyboard inset (its keyboard stays
/// up across sub-screen pushes, where SwiftUI's automatic avoidance loses
/// state — see the composer body).
@MainActor
private final class KeyboardHeightObserver: ObservableObject {
    @Published var height: CGFloat = 0
    // nonisolated(unsafe): only written once in init and read in deinit for
    // observer removal — NotificationCenter itself is thread-safe.
    nonisolated(unsafe) private var tokens: [NSObjectProtocol] = []

    init() {
        let nc = NotificationCenter.default
        tokens.append(nc.addObserver(
            forName: UIResponder.keyboardWillChangeFrameNotification,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard let frame = (note.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? NSValue)?.cgRectValue else { return }
            MainActor.assumeIsolated {
                self?.height = max(0, UIScreen.main.bounds.maxY - frame.origin.y)
            }
        })
        tokens.append(nc.addObserver(
            forName: UIResponder.keyboardWillHideNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.height = 0 }
        })
    }

    deinit {
        for token in tokens { NotificationCenter.default.removeObserver(token) }
    }
}

/// The composer's single recommended action: full-width, solid plum with
/// white text in BOTH themes (fixed like `avOutgoingBubble` — the dark-mode
/// avBrand flip to pale plum200 is what made the old button states so hard
/// to read). Pressed = slight darken.
private struct ComposePrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(
                Capsule()
                    .fill(Color.plum500.opacity(configuration.isPressed ? 0.8 : 1))
            )
    }
}

/// The quiet variant: hairline ink outline, ink label, no brand color at all.
/// Full-width for the 0-recipient "New Empty Group"; compact (hugging its
/// label) for the side "Group" button next to DM.
private struct ComposeOutlineButtonStyle: ButtonStyle {
    var fullWidth: Bool = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.medium))
            .foregroundStyle(Color.avInk)
            .frame(maxWidth: fullWidth ? .infinity : nil)
            .padding(.horizontal, fullWidth ? 0 : 18)
            .padding(.vertical, 12)
            .background(
                Capsule()
                    .fill(configuration.isPressed ? Color.avInk.opacity(0.06) : Color.clear)
            )
            .overlay(
                Capsule()
                    .strokeBorder(Color.avInk.opacity(0.15), lineWidth: 1)
            )
    }
}

/// A non-sticky section label rendered as an ordinary list row — visually the
/// section-header treatment (uppercased footnote, muted) without the pinning.
private func composeSectionHeader(_ title: String) -> some View {
    Text(title.uppercased())
        .font(.footnote)
        .foregroundStyle(Color.avMuted)
        // Compact, explicit insets — the default list-row insets pad ~11pt
        // vertically, which made these read as full-height rows.
        .listRowInsets(EdgeInsets(top: 12, leading: 16, bottom: 2, trailing: 16))
        .listRowBackground(Color.avPaper)
        .listRowSeparator(.hidden)
}

/// Full-list contact picker presented from the recipient field's "+" button.
/// Mirrors the inline autocomplete's People / Other split, but always shows the
/// whole curated/known set (filterable) rather than reacting to the typed query.
/// Selecting a contact adds it as a chip and dismisses.
private struct ContactPickerSheet: View {
    let contacts: [AppState.AccountContact]
    let excludedDids: Set<String>
    let nameFor: (AppState.AccountContact) -> String
    let isBotFor: (AppState.AccountContact) -> Bool
    let subtitleFor: (AppState.AccountContact) -> String?
    let onSelect: (AppState.AccountContact) -> Void
    /// Adds the recipient encoded in a scanned/pasted contact link; returns
    /// false if the payload isn't a recognizable Avalanche contact link.
    let onScanLink: (String) -> Bool

    @Environment(\.dismiss) private var dismiss
    @State private var search = ""
    @State private var showingScanner = false
    @State private var scanError: String?

    private var filtered: [AppState.AccountContact] {
        let q = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return contacts.filter { c in
            guard !excludedDids.contains(c.row.did) else { return false }
            guard !q.isEmpty else { return true }
            // Same rule as the inline autocomplete: names always, DIDs only
            // for a did:-prefixed query (prefix match).
            if q.hasPrefix("did:") {
                return c.row.did.lowercased().hasPrefix(q)
            }
            return nameFor(c).lowercased().contains(q)
        }
    }

    private var people: [AppState.AccountContact] { filtered.filter(\.row.isCurated) }
    private var other: [AppState.AccountContact] { filtered.filter { !$0.row.isCurated } }

    var body: some View {
        NavigationStack {
            List {
                Button {
                    scanError = nil
                    showingScanner = true
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "qrcode.viewfinder")
                            .font(.title3)
                            .frame(width: 32, height: 32)
                            .foregroundStyle(Color.avBrand)
                        Text("Scan QR Code")
                            .foregroundStyle(Color.avBrand)
                    }
                }
                .buttonStyle(ChatRowButtonStyle())
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.avPaper)
                // Plain rows, not Section headers — those pin while scrolling.
                if !people.isEmpty {
                    composeSectionHeader("People")
                    ForEach(people, content: row)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.avPaper)
                }
                if !other.isEmpty {
                    composeSectionHeader("Other")
                    ForEach(other, content: row)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.avPaper)
                }
                if filtered.isEmpty {
                    Text("No contacts to add.")
                        .foregroundStyle(.secondary)
                        .font(.footnote)
                        .listRowBackground(Color.avPaper)
                }
            }
            .listStyle(.plain)
            .environment(\.defaultMinListRowHeight, 24)
            .scrollContentBackground(.hidden)
            .background(Color.avPaper)
            .searchable(text: $search, prompt: "Search contacts")
            .navigationTitle("Add Recipient")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel("Close")
                }
            }
            .sheet(isPresented: $showingScanner) {
                NavigationStack {
                    QRScannerView { value in
                        showingScanner = false
                        if onScanLink(value) {
                            dismiss()
                        } else {
                            scanError = "That QR code isn't an Avalanche contact link."
                        }
                    }
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { showingScanner = false }
                        }
                    }
                }
            }
            .alert("Couldn't add contact", isPresented: .constant(scanError != nil)) {
                Button("OK") { scanError = nil }
            } message: {
                Text(scanError ?? "")
            }
        }
    }

    private func row(_ c: AppState.AccountContact) -> some View {
        Button {
            onSelect(c)
            dismiss()
        } label: {
            HStack(spacing: 10) {
                ContactAvatar(name: nameFor(c), isBot: isBotFor(c), size: 32)
                VStack(alignment: .leading, spacing: 1) {
                    Text(nameFor(c))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    if let subtitle = subtitleFor(c) {
                        Text(subtitle)
                            .font(.caption2)
                            .foregroundStyle(Color.avMuted)
                            .lineLimit(1)
                    }
                }
            }
        }
        .buttonStyle(ChatRowButtonStyle())
    }
}

#if DEBUG
/// Shared preview environment: one account plus a spread of contact cases —
/// curated humans, a human whose profile hasn't resolved yet (→ "Unknown"), and
/// a bot whose name lives server-side and resolves through the same path as
/// humans (the normalization this view relies on).
@MainActor
private func composePreviewState() -> AppState {
    let me = Account(
        id: "did:plc:me",
        displayName: "Me",
        avatarData: nil,
        servers: [ServerInfo(
            id: "https://server.example",
            name: "Example",
            url: URL(string: "https://server.example")!
        )]
    )
    let contacts: [ContactRowFfi] = [
        ContactRowFfi(did: "did:plc:alice", displayName: "Alice Rivera", isCurated: true, lastInteractionAtMs: 0),
        ContactRowFfi(did: "did:plc:bob", displayName: "Bob Chena", isCurated: true, lastInteractionAtMs: 0),
        ContactRowFfi(did: "did:plc:carol", displayName: "Carol X", isCurated: false, lastInteractionAtMs: 0),
        // Empty local name: a bot resolves its name server-side (via
        // `getAccountInfo`), which is also where `isBot` comes from — so this
        // row exercises the bot avatar chrome (docs/54-bot-presentation.md).
        ContactRowFfi(did: "did:local:adminbot", displayName: "", isCurated: false, lastInteractionAtMs: 0),
    ]
    return AppState.preview(
        accounts: [me],
        contacts: contacts,
        botNames: ["did:local:adminbot": "Adminbot"]
    )
}

#Preview("Empty") {
    ComposeMessageView()
        .environmentObject(composePreviewState())
}

#Preview("Multiple recipients") {
    ComposeMessageView(initialChips: [
        ComposeMessageView.Chip(id: "did:plc:alice", did: "did:plc:alice", displayName: "Alice Rivera"),
        ComposeMessageView.Chip(id: "did:plc:alice2", did: "did:plc:alice", displayName: "Alice Rivera Two"),
        ComposeMessageView.Chip(id: "did:plc:alice3", did: "did:plc:alice", displayName: "Alice Rivera Three"),
        ComposeMessageView.Chip(id: "did:plc:alice4", did: "did:plc:alice", displayName: "Alice Rivera Four")


    ])
    .environmentObject(composePreviewState())
}
#endif
