# Socket & database lifecycle around backgrounding/suspension

How the main app manages the chat websocket, background task assertions, and database
safety (the 0xDEAD10CC problem) across the active → background → suspended → active cycle,
and how it hands the connection to/from the NSE. Complements
[notification-service-extension.md](notification-service-extension.md) §2b (connection lock).

## TL;DR

- The socket's "desired state" is a pure **reference count of `ConnectionToken`s** — there is
  no app-active check or timer inside `OWSChatConnection` itself.
- The "keep the socket open after backgrounding" behavior is in `AppDelegate.refreshConnection`:
  on **willResignActive** the app swaps its foreground tokens for a `BackgroundMessageFetcher`
  wrapped in an OS background task, and keeps the socket until fetching/processing goes idle or
  a **180-second** deadline — with the OS assertion itself expiring around **~30 seconds** in
  practice. So the real grace interval is "whatever iOS grants the background task", with 180s
  as the self-imposed cap.
- There is **no GRDB database suspension in the current code**. The 0xDEAD10CC defense is
  entirely: hold a background task assertion for the whole duration of any work that touches
  the DB, tear work down in the ~5s expiration window, and shrink transactions while
  backgrounded.
- The NSE handoff happens at background-task **end/expiration**, not at resign-active: the app
  closes the socket, waits for the disconnect to finish, and only then releases the file lock
  and the OS assertion — guaranteeing the lock is free before the process suspends (a
  suspended process would otherwise hold its `fcntl` lock indefinitely).

## 1. Desired socket state — `OWSChatConnection`

`OWSChatConnection` keeps the socket open iff **someone holds a `ConnectionToken`** and no
"fatal" error blocks sockets:

- `requestConnection()` mints a token; `releaseConnection()` retires it. Desired state is
  simply `!activeTokenIds.isEmpty` (`OWSChatConnection.swift:270-307`).
- `shouldSocketBeOpen()` = "no `canOpenWebSocketError`" AND "at least one token"
  (`OWSChatConnection.swift:316-323`). `canOpenWebSocketError` covers app-expired
  (`OWSChatConnection.swift:237-242`) and, for the identified connection, not-registered
  (`OWSChatConnection.swift:935-943`). Transient errors (no network, 5xx) never set it.
- `_applyDesiredSocketState()` reconciles: open → `ensureWebsocketExists()`, closed →
  `disconnectIfNeeded()` + wake anyone in `waitUntilSocketShouldBeClosed()`
  (`OWSChatConnection.swift:325-335`).

So the half-remembered "keep the socket N seconds after resigning active" constant does
**not** live here. `OWSChatConnection` observes only censorship-circumvention changes, app
expiry (`OWSChatConnection.swift:96-111`), proxy config (`OWSChatConnection.swift:536-545`),
and for the auth socket registration state and stories-enabled
(`OWSChatConnection.swift:904-919`). It never looks at app-active/background notifications.
All lifecycle policy is in whoever holds tokens — for the main app, `AppDelegate`.

Related constants that *do* live here:

| Constant | Value | Meaning |
|---|---|---|
| `socketReconnectDelay` | 5s (`OWSChatConnection.swift:439`) | max average exponential backoff between reconnect attempts after failures (first retry immediate, `OWSChatConnection.swift:772-805`) |
| `keepaliveInterval` | 30s (`OWSChatConnection.swift:1085`) | `GET /v1/keepalive` on the auth socket, on top of libsignal's own websocket pings (`OWSChatConnection.swift:1081-1091`) |

Both identified and unidentified connections use the token mechanism;
`ChatConnectionManagerImpl.requestConnections()` returns a token for each
(`ChatConnectionManager.swift:70`). Only the **identified** connection participates in the
cross-process `ConnectionLock` (`OWSChatConnection.swift:983-984`; the unauth subclass has no
lock).

## 2. The background grace period — `AppDelegate.refreshConnection`

`refreshConnection(isAppActive:shouldRunCron:)` (`AppDelegate.swift:1428-1491`) is called from
three places:

- **becoming active** — `handleActivation()` → `refreshConnection(isAppActive: true, shouldRunCron: true)` (`AppDelegate.swift:1360`)
- **`applicationWillResignActive`** → `refreshConnection(isAppActive: false, ...)` (`AppDelegate.swift:80-91`). Note: resign-active, *not* didEnterBackground — `applicationDidEnterBackground` only logs (and `exit(0)`s if the low-storage launch screen is up, `AppDelegate.swift:102-108`, `1098-1099`).
- **launching while not active** (e.g. woken in the background) → `refreshConnection(isAppActive: false, ...)` "Fetch messages as soon as possible after launching" (`AppDelegate.swift:779-784`)

The inactive path (`AppDelegate.swift:1443-1490`):

1. Drop the foreground tokens (`activeConnectionTokens = []`) — but the socket doesn't close
   yet, because…
2. …a `BackgroundMessageFetcher` is built and started inside
   `UIApplication.shared.beginBackgroundTask(backgroundBlock:completionHandler:)`.
   `backgroundFetcher.start()` immediately requests its own connection tokens
   (`BackgroundMessageFetcher.swift:77-80`), so token ownership transfers seamlessly; only
   then are the old foreground tokens released (`AppDelegate.swift:1454`).
3. The background block then waits via `backgroundFetcher.waitUntil(deadline:)` with
   **`waitDeadline = startDate.adding(180)`** — the code comments: "This will usually be
   limited to 30 seconds rather than 3 minutes" (`AppDelegate.swift:1466-1469`), i.e. the OS
   assertion expires long before the 180s cap. (If the user isn't past registration, it just
   sleeps to the deadline instead of watching the fetcher.) The wait also aborts early if the
   connection decides it should be closed — e.g. the share extension preempts the lock
   (`BackgroundMessageFetcher.swift:102-116`).
4. Completion (`AppDelegate.swift:1481-1488`): if **interrupted** (returned to foreground) →
   `backgroundFetcher.reset()` just drops the tokens. If **finished or expired** →
   `stopAndWaitBeforeSuspending()` — see §5.

So: *trigger* = `applicationWillResignActive`; *duration* = min(OS background-task grant ≈30s,
180s), or less if message fetching/processing reaches idle sooner.

## 3. Background task assertions

Two coexisting systems:

### a. `BackgroundTaskHandle` (the socket one)

`UIApplication.beginBackgroundTask(backgroundBlock:completionHandler:)`
(`UIApplication+OWS.swift:30-83`) wraps one `UIBackgroundTaskIdentifier` around an async
operation plus a completion. Yes — **an OS assertion is held the entire time the socket is
open in the background** (`backgroundFetchHandle`, `AppDelegate.swift:1424-1426`).

Expiration path: iOS calls the expiration handler → `handle.expire()` → the operation Task is
**canceled**, then the completion runs with `.expired`, and only after *both* finish is
`endBackgroundTask` called (`UIApplication+OWS.swift:201-213` — "The `completionHandler` runs
STRICTLY AFTER `backgroundBlock`"). The doc comment is explicit that releasing the assertion
early is not an option because it "would cause the app to suspend too early, risking other
problems such as dead10cc crashes", and that "As of iOS 18, we have about 5 seconds to handle
an expiration" (`UIApplication+OWS.swift:48-57`).

### b. `OWSBackgroundTask` (the RAII one, everywhere else)

`OWSBackgroundTask` (`SignalServiceKit/Util/OWSBackgroundTask.swift`) is the older
scoped-work primitive: init starts it, `end()`/deinit finishes it. All instances share **one**
aggregated UIKit assertion via `OWSBackgroundTaskManager`, which only actually begins an OS
task while the app is inactive and at least one task is live
(`OWSBackgroundTask.swift:283-305`), and keeps the assertion alive for an extra **0.25s**
"continuity" window after the last task ends so back-to-back tasks don't churn assertions
(`OWSBackgroundTask.swift:363-389`). On OS expiration, the manager fires every registered
expiration block synchronously on main, then ends the (already expired) task
(`OWSBackgroundTask.swift:335-361`); each task's `completionBlock` gets `.expired`. In
extensions it no-ops but pretends success (`OWSBackgroundTask.swift:278-281`).

These bracket short critical sections rather than the socket: e.g. resign-active log flush
(`AppDelegate.swift:95-99`), and each group-message-processing batch
(`GroupMessageProcessor.swift:92`), so the app doesn't suspend mid-write. Most expiration
blocks just log/stop; nothing suspends the database (see §4).

## 4. The 0xDEAD10CC defense — there is no database suspension

**Current code has no GRDB database-suspension feature.** Grepping for
suspend/resume/isSuspended in storage and app-lifecycle code turns up nothing that touches
the database connection; the only "suspension" machinery is `MessagePipelineSupervisor`,
which pauses *message processing* (an app-level concept), not SQLite. If you remember
`suspendDatabase`/GRDB `suspendNotification`, that's an older design that's since been
removed. (This checkout has truncated history — a single commit — so the removal can't be
dated from here.)

`0xDEAD10CC` is mentioned exactly three times, and together they describe the actual defense:

1. **Never be suspended while holding the SQLite file lock — by holding an assertion
   instead.** The `BackgroundTaskHandle` comment (`UIApplication+OWS.swift:48-57`) frames
   dead10cc as the reason the assertion is held until all work is torn down. All background
   socket/fetch/processing work runs under either that handle or an `OWSBackgroundTask`.
   The ~5s expiration window is used to *cancel* work, and in-flight writes simply finish —
   transactions are kept small so this is fast.

2. **Shrink transactions while backgrounded.** `GroupMessageProcessor` drops its batch size
   from 16 to 1 when `CurrentAppContext().isInBackground()`: "This (only slightly) makes it
   less likely that we'll hit a 0xdead10cc crash and need to re-do work we've already done.
   TODO: Stop processing batches when suspending." (`GroupMessageProcessor.swift:111-117`).
   Note the TODO — batches are *not* currently stopped at suspension, just narrowed.

3. **Give up when a dead10cc is unavoidable.** If the user backgrounds mid link'n'sync
   restore, the app cancels the restore, resets all app data, and exits: "If the user exits
   in the middle of syncing we'll probably crash anyway (dead10cc)"
   (`LinkAndSyncProvisioningProgressViewController.swift:157-173`).

Adjacent but not lifecycle-triggered: the write path schedules truncating WAL checkpoints
after bursts of writes (budget of 32 writes, ≥250ms apart, on a utility queue —
`GRDBDatabaseStorageAdapter.swift:103-114`, `396-414`), which keeps the WAL small so any
process's crash/kill recovery is cheap; it is not tied to backgrounding.

Since nothing suspends the DB, there's also **no resume step on foregrounding**, and no
"database is suspended" error path for in-flight writes to hit.

## 5. Suspension handoff — how the lock reaches the NSE

The main app does *not* release the connection at resign-active — it deliberately keeps
fetching (§2). The clean handoff happens when the background task ends (idle, deadline, or
OS expiration), via `stopAndWaitBeforeSuspending()` (`BackgroundMessageFetcher.swift:145-162`):

1. Release the connection tokens → desired state flips → `disconnectIfNeeded()` starts an
   async disconnect (`OWSChatConnection.swift:638-656`). (This runs in a fresh `Task` so the
   expiration-path cancellation doesn't propagate into the cleanup,
   `BackgroundMessageFetcher.swift:145-149`.)
2. `waitForDisconnectIfClosed()` awaits the disconnect task (`OWSChatConnection.swift:658-668`).
   The auth connection's state setter wraps every transition to `.closed` so that the
   `ConnectionLock` is released only **after** the disconnect task completes
   (`OWSChatConnection.swift:1028-1039`, `releaseConnectionLock` at `1072-1079`).
3. Wait for any already-scheduled notifications to post, then return — and only then does
   `BackgroundTaskHandle` call `endBackgroundTask` (`UIApplication+OWS.swift:208-212`),
   letting the process actually suspend.

Why the strict ordering matters: the lock is a byte-range `fcntl` lock on the shared
`chat-connection.lock` file (`ConnectionLock.swift:8-24`, `110-138`). Kernel file locks are
released on process **death** (fd close), but *not* on mere suspension — a suspended app
still holds them. If the app suspended while holding byte 0, the NSE could never take the
socket. The sequence above guarantees release-before-suspend. Conversely there's nothing the
app needs to do for jetsam/termination: the fd closes and the kernel frees the lock.

Two more properties of the handoff:

- **The NSE never preempts the main app.** Darwin-notification interrupts only flow from
  more-important to less-important processes (share = 1, main = 2, NSE = 3;
  `OWSChatConnection.swift:888-895`, `ConnectionLock.swift:52-79`). The NSE just blocks
  polling byte 0 (try-lock with 0.1–3s backoff, cancellable —
  `ConnectionLock.swift:153-169`) until the main app's release, bounded in practice by the
  NSE's own ~30s push budget. During the app's post-background fetch window, an NSE push
  simply waits — and usually finds the messages already processed into the shared DB.
- **On return to foreground the transfer is flap-free in the other direction**: new
  foreground tokens are requested *before* the old/background ones are released
  (`AppDelegate.swift:1431-1435`), and a pending disconnect is awaited before re-acquiring
  the lock inside the next connect attempt (`OWSChatConnection.swift:576-579`,
  `connectChatService` acquires the lock at `983-984`).

## 6. Foreground ordering

`applicationWillEnterForeground` does nothing but log (`AppDelegate.swift:47-49`). Everything
hangs off **`applicationDidBecomeActive`** → `runNowOrWhenAppDidBecomeReadySync { handleActivation() }`
(`AppDelegate.swift:51-76`), so on cold launches all of this waits for app-readiness
(migrations etc.); on a warm foreground it runs immediately.

Order inside `handleActivation()` (`AppDelegate.swift:1332-1389`):

1. (async, fire-and-forget) prekey check.
2. **`refreshConnection(isAppActive: true, shouldRunCron: true)`** (`AppDelegate.swift:1360`):
   request fresh foreground tokens → release old ones → `interrupt()` the background fetch
   handle ("We're back in the foreground… just tear it down without waiting",
   `AppDelegate.swift:1439-1442`), whose completion `reset()`s the fetcher's tokens. The
   actual socket connect happens async on the connection's serial queue; acquiring the
   `ConnectionLock` inside `connectChatService` is what preempts the NSE (posting the
   priority-3 Darwin notification, `ConnectionLock.swift:75-79` → NSE cycles its socket, see
   NSE doc §2b). Cron starts as a foreground task.
3. (async) `groupMessageProcessorManager.startAllProcessors()` (`AppDelegate.swift:1363-1367`).
4. (async, next runloop) contact fetch, remote-notification re-registration
   (`AppDelegate.swift:1371-1382`).

There is **no explicit sequencing** between these: no DB resume exists (§4), and "message
processing" isn't a discrete kicked-off step in the foreground path — it's push-driven.
Envelopes arriving on the newly opened socket are enqueued into `MessageProcessor` by the
socket's listener callback (`OWSChatConnection.swift:1164-1178`), acks are sent per-envelope,
and the server's queue-empty marker sets `hasEmptiedInitialQueue`
(`OWSChatConnection.swift:1180-1203`). So the effective order is: tokens → lock acquisition
(NSE preempted) → socket open → envelopes stream in → processing, with each step gated only
by the previous one's completion, not by lifecycle callbacks.

One launch-vs-activation nuance: on a background launch, `refreshConnection(isAppActive:
false, ...)` runs from the app-ready path (`AppDelegate.swift:779-784`), so a
`BackgroundMessageFetcher` (not foreground tokens) opens the socket; if the app then becomes
active, step 2 above swaps ownership to foreground tokens without closing the socket.
