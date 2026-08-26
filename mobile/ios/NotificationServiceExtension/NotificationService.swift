import UserNotifications
import os

/// Notification Service Extension (docs/16, Stage 5 — Signal-parity presentation).
///
/// The relay sends a content-free alert + `mutable-content` push; iOS invokes
/// this extension, which fetches + decrypts the actual message(s) on-device via
/// app-core. Following Signal's model
/// (docs/signal-research/notification-service-extension.md), banners are
/// decoupled from pushes: every fetched message is posted as its own local
/// notification, and the triggering push is completed with empty content so its
/// placeholder never appears.
///
/// **Entitlement gate:** suppressing the placeholder requires Apple's
/// notification-filtering entitlement
/// (`com.apple.developer.usernotifications.filtering` — Signal ships it in
/// `SignalNSE-AppStore.entitlements`). Without it, iOS ignores an empty
/// completion and displays the original payload, so an empty completion would
/// *add* a stray banner rather than remove one (verified on device). Until the
/// grant lands, `hasFilteringEntitlement` is false and we fall back to the
/// rewrite model: the newest fetched message rewrites the triggering banner,
/// extras are posted as local notifications, and no-op/failure paths deliver
/// the generic placeholder (a burst can therefore still leave stray generic
/// banners — the known gap the entitlement closes).
///
/// Targeting is deferred (docs/16): the push carries no account hint, so we
/// fetch every local account.
///
/// `didReceive` runs on a framework-provided background queue and can run
/// concurrently in this reused process. Fetches are serialized on `workQueue`;
/// a queued fetch that a newer push has superseded skips its fetch entirely,
/// since any fetch drains every account's mailbox (Signal's
/// `enqueueCancellingPrevious`, adapted to our synchronous FFI — a blocking
/// fetch can't be interrupted mid-flight, so only queued work is skippable).
class NotificationService: UNNotificationServiceExtension {

    /// Flip to true once Apple grants
    /// `com.apple.developer.usernotifications.filtering` and the key is added
    /// to the NSE entitlements (docs/16 Stage 5). True = full Signal parity:
    /// every message is a local notification and the placeholder is suppressed
    /// on every path. False = rewrite model (see header).
    private static let hasFilteringEntitlement = false

    private static let log = Logger(subsystem: "net.theavalanche.nse", category: "NotificationService")

    /// Serializes fetches across concurrent / stacked `didReceive` calls.
    private static let workQueue = DispatchQueue(label: "net.theavalanche.nse.fetch")

    /// Process-wide mutable state, lock-guarded (didReceive calls can be
    /// concurrent; Swift concurrency checking requires the wrapper).
    private final class SharedState: @unchecked Sendable {
        private let lock = NSLock()
        /// Bumped per push; a queued fetch holding a stale ticket skips its fetch.
        private var generation = 0
        /// One "phone locked" banner per process; later pushes before first
        /// unlock complete with the placeholder (or silently, with the
        /// entitlement).
        private var shownLockedBanner = false

        func nextTicket() -> Int {
            lock.lock(); defer { lock.unlock() }
            generation += 1
            return generation
        }

        func isStale(_ ticket: Int) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return ticket < generation
        }

        /// True the first time it's called in this process.
        func claimLockedBanner() -> Bool {
            lock.lock(); defer { lock.unlock() }
            let wasShown = shownLockedBanner
            shownLockedBanner = true
            return !wasShown
        }
    }

    private static let state = SharedState()

    private let handlerLock = NSLock()
    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var bestAttempt: UNMutableNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        handlerLock.lock()
        self.contentHandler = contentHandler
        self.bestAttempt = request.content.mutableCopy() as? UNMutableNotificationContent
        handlerLock.unlock()

        let ticket = Self.state.nextTicket()
        Self.workQueue.async { self.run(ticket: ticket) }
    }

    /// iOS is about to kill the extension. Anything already posted as a local
    /// notification survives; the rest is fetched by the next push or app
    /// launch. With the entitlement the placeholder is suppressed; without it
    /// iOS shows the original payload no matter what we pass, so deliver the
    /// best attempt explicitly.
    override func serviceExtensionTimeWillExpire() {
        Self.log.error("time expired before fetch completed")
        finishNoOp()
    }

    private func run(ticket: Int) {
        if Self.state.isStale(ticket) {
            // A newer push is queued behind us and its fetch drains the same
            // mailboxes; skip ours.
            Self.log.info("skipping fetch: superseded by a newer push")
            finishNoOp()
            return
        }

        // Shared secrets/paths (docs/16 deps 1–2).
        let dbKey: String
        do {
            dbKey = try SecureEnclaveKeyManager.dbPassphrase()
        } catch let err as SecureEnclaveKeyManager.KeyManagerError where err.isDeviceLockedSinceBoot {
            // Before first unlock, `kSecAttrAccessibleAfterFirstUnlock*` items
            // are unreadable — nothing can be decrypted until the user unlocks.
            // Show the actionable static banner once per process.
            let showBanner = Self.state.claimLockedBanner()
            Self.log.error("db key unreadable: device locked since boot")
            if showBanner { finish(.phoneLocked) } else { finishNoOp() }
            return
        } catch {
            Self.log.error("db key unreadable: \(String(describing: error), privacy: .public)")
            finishNoOp()
            return
        }
        guard let dbDir = AppGroup.dbDir else {
            Self.log.error("no app group container")
            finishNoOp()
            return
        }

        let fm = FileManager.default
        var items: [NotifItemFfi] = []
        let accounts = SharedAccountStore.load()
        for account in accounts {
            let dbPath = dbDir.appendingPathComponent(account.dbFilename).path
            guard fm.fileExists(atPath: dbPath) else { continue }
            // Best-effort per account: a failure for one must not sink the rest.
            do {
                items.append(contentsOf: try fetchNotifications(dbPath: dbPath, dbKey: dbKey))
            } catch {
                Self.log.error("fetch failed for \(account.dbFilename, privacy: .public): \(String(describing: error), privacy: .public)")
            }
        }
        Self.log.info("fetched \(items.count) item(s) across \(accounts.count) account(s)")
        deliver(items)
    }

    /// Present the fetched messages.
    ///
    /// Entitlement mode: post every message as a local notification and
    /// complete the triggering push with empty content (suppressed).
    /// Fallback mode: the newest message rewrites the triggering banner (so the
    /// common single-message case shows exactly one banner), extras become
    /// local notifications, and an empty fetch delivers the placeholder.
    private func deliver(_ items: [NotifItemFfi]) {
        let sorted = items.sorted { $0.sentAtMs < $1.sentAtMs }

        let asLocalNotifications: [NotifItemFfi]
        if Self.hasFilteringEntitlement {
            asLocalNotifications = sorted
        } else {
            guard let newest = sorted.last else {
                finishNoOp()
                return
            }
            asLocalNotifications = Array(sorted.dropLast())
            handlerLock.lock()
            if let best = bestAttempt { apply(newest, to: best) }
            handlerLock.unlock()
        }

        let center = UNUserNotificationCenter.current()
        let posts = DispatchGroup()
        for item in asLocalNotifications {
            let content = UNMutableNotificationContent()
            apply(item, to: content)
            let req = UNNotificationRequest(
                identifier: "\(item.accountId)-\(item.conversationId)-\(item.sentAtMs)",
                content: content,
                trigger: nil)
            posts.enter()
            center.add(req) { error in
                if let error {
                    Self.log.error("failed to post notification: \(String(describing: error), privacy: .public)")
                }
                posts.leave()
            }
        }
        // Don't complete until the posts have landed — completing lets iOS
        // suspend the process, which could drop in-flight adds.
        _ = posts.wait(timeout: .now() + 5)

        if Self.hasFilteringEntitlement {
            finish(.empty)
        } else {
            handlerLock.lock()
            let best = bestAttempt
            handlerLock.unlock()
            finish(best ?? .empty)
        }
    }

    /// Complete a path that has nothing (new) to show. With the entitlement,
    /// empty content suppresses the placeholder; without it, iOS displays the
    /// original payload whatever we return, so hand back the best attempt.
    private func finishNoOp() {
        if Self.hasFilteringEntitlement {
            finish(.empty)
        } else {
            handlerLock.lock()
            let best = bestAttempt
            handlerLock.unlock()
            finish(best ?? .empty)
        }
    }

    /// Atomically consume the content handler; later calls are no-ops (e.g. a
    /// fetch that finishes after `serviceExtensionTimeWillExpire` already fired).
    private func finish(_ content: UNNotificationContent) {
        handlerLock.lock()
        let handler = contentHandler
        contentHandler = nil
        handlerLock.unlock()
        handler?(content)
    }

    /// Populate a notification's title/body/routing from a fetched item, matching
    /// the in-app `NotificationPresenter` shape (title = sender for DMs, group
    /// name for groups; userInfo carries conversation + account for tap routing).
    private func apply(_ item: NotifItemFfi, to content: UNMutableNotificationContent) {
        if item.isGroup {
            content.title = item.groupTitle ?? "New message"
            content.body = item.senderDisplayName.isEmpty
                ? item.body
                : "\(item.senderDisplayName): \(item.body)"
        } else {
            content.title = item.senderDisplayName.isEmpty ? "New message" : item.senderDisplayName
            content.body = item.body
        }
        content.sound = .default
        content.threadIdentifier = item.conversationId
        content.userInfo = [
            "conversationId": item.conversationId,
            "accountId": item.accountId,
        ]
    }
}

private extension UNNotificationContent {
    /// With the filtering entitlement, completing with no alert title/body
    /// suppresses the placeholder banner entirely.
    static var empty: UNNotificationContent { UNMutableNotificationContent() }

    /// Static banner for the locked-since-boot case — surfaced rather than
    /// silenced because the user can act on it.
    static var phoneLocked: UNNotificationContent {
        let content = UNMutableNotificationContent()
        content.body = "Unlock your phone to see new messages."
        content.sound = .default
        return content
    }
}
