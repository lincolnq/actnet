# Notification Service Extension (NSE) Behavior

How Signal-iOS receives pushes and turns them into user-visible notifications. The NSE target lives in `SignalNSE/` (five source files); most of the machinery it invokes is shared code in `SignalServiceKit`.

## The Big Picture

Signal's pushes are **content-free wake-up signals**. The server cannot include message content in an APNs push (it only has ciphertext addressed to a device, and Signal doesn't want plaintext or even sender metadata going through Apple). So the flow is:

1. Server sends a nearly-empty APNs push with `mutable-content` set (set purely server-side — the client never inspects the `aps` dict).
2. iOS launches the NSE process and calls `didReceive`.
3. The NSE opens Signal's **authenticated chat websocket**, drains the message queue, decrypts and processes everything, and posts one local notification per notifiable message via `UNUserNotificationCenter` — the same code path the main app uses.
4. The NSE completes the *original* push with empty (badge-only) content, so the placeholder push itself never appears.

## 1. What the Server Sends

### Payload contents

The push payload carries no message data. The alert body is a server-supplied localization key, `APN_Message` = **"You may have new messages"** (`Signal/translations/en.lproj/Localizable.strings:209`). The client keeps this string only so genstrings retains it — it is "the fallback message used for push notifications when the NSE or main app is unable to process them" (`SignalServiceKit/Util/CommonStrings.swift:481-487`).

The client-side payload parsing (`AppDelegate.swift:1614-1630`, `handleSilentPushContent`) recognizes exactly two custom keys, both for challenges rather than messages:

| Key | Meaning |
|---|---|
| `challenge` | Pre-auth challenge token during registration — proves the device can receive pushes (`RegistrationSession.swift:75`) |
| `rateLimitChallenge` | Spam/rate-limit push challenge, handed to `SpamChallengeResolver` |
| *(anything else)* | "You may have messages" — triggers a fetch |

No Swift source anywhere references `aps`, `mutable-content`, or `content-available`. The comment in `NotificationService.swift:161-164` confirms the raw push has generic displayable content: "By default the OS will present whatever the raw content of the original notification is to the user otherwise."

### Push token registration

- Only the **standard ("vanilla") APNs token** is registered with Signal's server: `PUT v1/accounts/apn` with `{"apnRegistrationId": <hex token>}` (`OWSRequestFactory.swift:166-171`, `SyncPushTokensJob.swift:97-102`).
- **VoIP push tokens are no longer supported** (`PushRegistrationManager.swift:180`). A `PKPushRegistry` is still created, but solely to receive *local* VoIP payloads relayed from the NSE (see §2) — its token is never uploaded.
- Push registration is mutually exclusive with "manual message fetch" mode (`fetchesMessages` account attribute) for push-less devices (`RegistrationRequestFactory.swift:251`).

### Token health / rotation

Since pushes carry nothing, a silently-broken APNs token means silently missed messages. `APNSRotationStore` (`SignalServiceKit/Util/APNSRotationStore.swift`) exists for "interop between the NSE and SyncPushTokensJob": both the main app (`AppDelegate.swift:1566`) and the NSE (`NotificationService.swift:146-148`) call `didReceiveAPNSPush()` on every push to record the token as known-working. If on app launch the fetch pulls down new messages the push path never announced, `SyncPushTokensJob` rotates the token (known-good expiry 60 days, min rotation interval 1 week; gated on the `enableAutoAPNSRotation` remote config flag).

## 2. NSE ↔ Main App Communication

The NSE runs as a separate process sharing the app group container (`group.<prefix>.signal.group`), the GRDB database, keychain, and shared `UserDefaults` (`NSEContext.swift:31-47`, `SignalNSE.entitlements`). Coordination happens through four mechanisms:

### a. Shared database + cross-process change signal

Both processes write to the same database. `SDSCrossProcess` (`SignalServiceKit/Storage/Database/SDSCrossProcess.swift`) posts a Darwin notification (`org.signal.sdscrossprocess.<processType>`, via `notify(3)`) after writes and listens for every process type but its own. On each incoming push the NSE also re-warms its caches "to pick up changes made by the main app" (`NotificationService.swift:129-130`), and the NSE environment (database, app setup) is initialized once per process and reused across `didReceive` calls (`NotificationService.swift:29-31`, `NSEEnvironment.swift`).

### b. The connection lock — who gets the websocket

Only one process should hold the authenticated chat websocket. This is arbitrated by `ConnectionLock` (`SignalServiceKit/Network/ConnectionLock.swift`): a byte-range `flock`-style lock on the shared file `chat-connection.lock`, plus Darwin notifications (`org.signal.connection.<priority>`) for preemption. Priorities (`OWSChatConnection.swift:888-895`): share extension = 1 (most important), **main app = 2, NSE = 3** (least important).

The protocol:
- A process must acquire the lock before opening the socket (`OWSChatConnection.swift:983-984`).
- When a more important process wants the lock, it posts the Darwin notification for each lower priority; the NSE's interrupt callback cycles (closes) its socket immediately (`OWSChatConnection.swift:1062-1070`: "Cycling the socket because the connection lock was interrupted").
- On the NSE side, `BackgroundMessageFetcher.waitForFetchingProcessingAndSideEffects()` races normal completion against `waitUntilIdentifiedConnectionShouldBeClosed()` (`BackgroundMessageFetcher.swift:91-116`) — so when the main app launches and steals the connection, the NSE's fetch aborts and it completes silently, leaving the work to the main app.

Note: an older design where the main app posted a `mainAppHandledNotification` Darwin notification is gone; the connection lock replaced that handshake.

### c. Call handoff — NSE wakes the main app

The NSE never rings a call itself. When it decrypts a call **offer** (or a valid group-ring opaque message; answers/ice/hangup/busy are simply dropped — `NSECallMessageHandler.swift:155-157`), it:

1. Persists the *already-decrypted* envelope into a shared-DB queue, `KeyValueStore(collection: "PendingCallMessageStore")` (`CallMessageRelay.enqueueCallMessageForMainApp`, `CallMessageRelay.swift:81-99`).
2. Suspends its own message processing for 10 seconds so it doesn't consume messages the main app needs for the call (`NSECallMessageHandler.swift:188-193`, suspension reason `.nseWakingUpApp`).
3. Calls `CXProvider.reportNewIncomingVoIPPushPayload(...)` (`NSECallMessageHandler.swift:196`) — an OS API that launches the main app as if it had received a VoIP push. The payload is just `["CallMessageRelayPayload": <uuid>]`; no call content travels through it.

The main app receives this via its `PKPushRegistry` delegate (`PushRegistrationManager.swift:146-177`), drains the pending-call-message store, adjusts `serverDeliveryTimestamp` for the enqueue delay so stale rings expire, re-processes the envelopes, and must report a CallKit call before returning ("or else we risk a PushKit penalty").

### d. Missed-call validity buffer

When computing message age for RingRTC's is-this-ring-still-valid check, the NSE adds a 10-second `bufferSecondsForMainAppToAnswerRing` (`NSECallMessageHandler.swift:42-50`). Offers RingRTC rejects become missed-call interactions/notifications directly in the NSE.

## 3. Fetching and Processing (inside the NSE)

`NotificationService.didReceive` (`NotificationService.swift:85-96`) pushes work onto a `SerialTaskQueue` with `enqueueCancellingPrevious` — **a newer push cancels the in-flight fetch** (fine, since any fetch drains the whole queue). Notable lifecycle facts from the header comment (`NotificationService.swift:10-27`): the NSE process is reused across pushes, `didReceive` can run twice concurrently in one process, and iOS kills the extension after ~30 seconds.

The fetch itself (`fetchAndProcessMessages`, `NotificationService.swift:180-226`) uses the same `BackgroundMessageFetcher` as the main app's background push handling:

1. Start the Signal proxy relay if configured.
2. `start()` — request chat connections (websocket, via the connection lock) and start group message processors.
3. Wait for "done": server sends a **queue-empty** marker on the websocket (`OWSChatConnection.swift:1180-1203`, `hasEmptiedInitialQueue`), then message processing drains, then outgoing receipts, outgoing messages (e.g. auto-replies from notification actions aren't relevant here, but delivery receipts are), sync-message tasks, storage service, attachment backfills, and finally all pending notification posts (`BackgroundMessageFetcher.swift:118-143`). There is no REST fallback — envelope delivery is websocket-only.
4. A `Cron.runOnce` piggybacks on the open socket (`NotificationService.swift:200-206`).
5. Disconnect and wait for the socket to close before letting the process suspend.

Decryption and message processing are the full shared pipeline (`MessageProcessor` / `MessageReceiver`), so the NSE writes real `TSIncomingMessage`s etc. to the shared database — the main app doesn't re-fetch or re-process them.

### Error/edge behavior of the original push

- **Device not yet unlocked after reboot** (DB keys unavailable, `KeychainError.notAllowed`): shows one static notification, "phone locked" (`NOTIFICATION_BODY_PHONE_LOCKED_FORMAT`); subsequent pushes before first unlock complete silently (`NotificationService.swift:104-124`).
- **Not registered / corrupt registration, app expired, fetch canceled**: complete silently with empty content.
- **`serviceExtensionTimeWillExpire`** (30s limit): cancel everything and complete silently so the raw "You may have new messages" placeholder is never shown (`NotificationService.swift:156-165`).
- **Success**: the returned content is *badge-only* — the unread count is set on it (`NotificationService.swift:219-225`). All real notifications were already posted separately.

## 4. Presenting Notifications

The NSE does **not** use the `contentHandler` to display message notifications (one push may correspond to zero or many messages). Instead, during processing, `NotificationPresenterImpl` → `UserNotificationPresenter.notify()` (`SignalServiceKit/Notifications/UserNotificationsPresenter.swift:102-212`) posts **local** notifications via `UNUserNotificationCenter.add()`, one per event, with:

- A category identifier driving action buttons (reply, mark-as-read, thumbs-up, call back…) registered by the main app at permission time.
- `userInfo` (`AppNotificationUserInfo`) carrying `threadId`, `messageId`, `reactionId`, `storyMessageId`, `isMissedCall`, etc. — this is the index that later enables cancellation/editing.
- `threadIdentifier` for iOS thread grouping, an `INSendMessageIntent` donation for communication-style notifications (sender avatar), and the per-thread or global notification sound.
- Since `NSEContext.frontmostViewController()` returns nil and `isMainAppAndActive` is false, none of the main app's "you're looking at this thread" suppression applies in the NSE (`NotificationPresenterImpl.swift:285-316`); muted-thread and preview-type ("name only" / "no name or content") logic still applies when composing title/body.

### Editing and removing already-presented notifications

There is no UNNotificationContent "edit" API, so all editing is **cancel-by-identifier** (both delivered and pending) or **replace** (cancel + re-add under the same identifier):

- **Delayed delivery to beat desktop reads**: if a sync message from a linked device arrived in the last 60 seconds, incoming message/reaction notifications are scheduled with a 20-second `UNTimeIntervalNotificationTrigger` instead of firing immediately (`UserNotificationsPresenter.swift:75-77, 140-150`). If a read receipt for that message arrives in the meantime (`OWSReceiptManager.swift:760-795`), the pending request is removed and the user is never notified.
- **Read receipts from linked devices** cancel notifications for the read message and everything earlier in that thread (`OWSReceiptManager.swift:794-795`).
- **Remote delete** of a message cancels its notification (`TSMessage.swift:497`); **reaction removal** cancels the reaction's notification (`TSMessage.swift:227`, `OWSReaction.swift:134`).
- **Missed-call updates** use `replacingIdentifier` with a stable per-call grouping UUID (`NotificationPresenterImpl.swift:464,489,519`) so e.g. a "missed call" can be replaced by "missed call from someone with a changed safety number" rather than stacking.
- Cancellation matches by scanning all delivered + pending requests' `userInfo` for the relevant `threadId`/`messageId`/`reactionId`/story id (`UserNotificationsPresenter.swift:404-457`).
- The main app on activate clears categories flagged `shouldClearOnAppActivate` (`UserNotificationsPresenter.swift:326-353`); opening a conversation cancels that thread's notifications.

Because both processes talk to the same `UNUserNotificationCenter` store, notifications posted by the NSE can be cancelled later by the main app and vice versa — e.g. the NSE itself, while processing a batch, will post a message notification and then cancel it moments later if a linked-device read receipt appears in the same queue drain.
