# Activism Social Network — Technical Implementation

## Philosophy

Two principles govern every technical decision here:

- **Don't implement cryptography; use audited implementations.** The academic literature on secure messaging is rich, and Signal has already done the hard work of turning it into production-quality, open-source code. Our job is to compose those primitives correctly, not to reinvent them.
- **Make whole classes of vulnerabilities impossible.** The right tool for security-critical server software is one where memory safety bugs — buffer overflows, use-after-free, data races — cannot exist by construction, not one where we try hard to avoid them.

---

## Core cryptographic stack

### libsignal

The cryptographic foundation is **[libsignal](https://github.com/signalapp/libsignal)**, Signal's open-source cryptographic library. It is primarily written in Rust and provides bindings for Swift, Kotlin, and TypeScript. We use it directly rather than reimplementing any of the schemes it provides.

What libsignal gives us:

- **Double Ratchet Algorithm** — forward secrecy for 1:1 and small-group chats. Each message uses a fresh key derived from a ratcheting key chain; compromising one message key doesn't compromise past or future messages.
- **X3DH (Extended Triple Diffie-Hellman)** — asynchronous key establishment. Alice can initiate an encrypted session with Bob before Bob is online, using Bob's prekeys published to the server.
- **Sealed sender** — the server cannot determine who sent a message to whom, only that some authorized group member sent it.
- **zkgroup / anonymous credentials** — the scheme from the Chase/Perrin/Zaverucha paper ("The Signal Private Group System"), which provides Signal-style group membership guarantees. Members prove they belong to a group without revealing which member they are. This is the basis for action-bound groups.

### Primitive choices

All of these are provided by libsignal or the RustCrypto / dalek-cryptography ecosystem:

| Primitive | Algorithm | Notes |
|---|---|---|
| Key agreement | X25519 | ECDH on Curve25519 |
| Signatures | Ed25519 | Fast, small signatures |
| Symmetric encryption | AES-256-GCM | AEAD; ChaCha20-Poly1305 where AES hardware acceleration is unavailable |
| Key derivation | HKDF-SHA-256 | |
| Group credentials | Ristretto255 | Prime-order group for anonymous credential scheme |
| Password hashing | Argon2id | For any user-facing secrets |

### What we are not doing

We are not implementing any of these schemes ourselves. We are not using OpenSSL directly. We are not using any crypto primitives that haven't been through independent academic and implementation review.

---

## Server implementation

### Language: Rust

The homeserver is written in **Rust**. The reasons are security-first:

- **Memory safety by construction.** The entire class of vulnerabilities that plague C/C++ servers — buffer overflows, use-after-free, dangling pointers, data races — cannot occur in safe Rust. This is not "we try hard to avoid them"; it is a compile-time guarantee. For a server handling encrypted communications for activists, this matters enormously.
- **No garbage collector.** Consistent, predictable latency without GC pauses. Important for real-time messaging.
- **libsignal is Rust.** We use the library natively without an FFI boundary on the server.
- **Increasingly the industry standard for security-critical infrastructure.** Cloudflare, AWS, Mozilla, and the Linux kernel have all moved security-sensitive components to Rust for these reasons.

### Framework and runtime

- **Tokio** — async runtime. The de facto standard for high-performance async Rust; handles tens of thousands of concurrent connections efficiently.
- **Axum** — HTTP framework built on Tokio and Tower. Type-safe, composable, well-maintained. Handles the HTTP/WebSocket layer.
- **WebSockets** for real-time message delivery to connected clients. HTTP/2 for server-to-server federation transport, with mutual TLS for authentication.
- **sqlx** — async PostgreSQL client with compile-time query checking. Queries are verified against the actual schema at compile time, eliminating a class of runtime errors.

### Database

- **PostgreSQL** on the server. Stores encrypted message blobs, routing metadata, group credential state, DID registrations, push pseudonyms, push queuing, and session tokens (with `expires_at` columns and a background cleanup task). The server stores ciphertext it cannot read; the schema reflects this — message content columns are `bytea`, never text.
- **Rate limiting** is handled in-process with Tokio. For multi-instance deployments, PostgreSQL advisory locks or a lightweight counter table are sufficient at the scales activist org servers will realistically reach.
- No Redis. The homeserver dependency is a single binary plus PostgreSQL.

### Server-to-server federation

Homeservers authenticate to each other using their own DID-based keys. The transport is HTTPS with request signing (similar to ActivityPub's HTTP Signatures, but using Ed25519 keys from the server's DID document). A receiving server verifies the signature against the sending server's DID before processing any federated request.

---

## Mobile implementation

### Architecture: Rust core + native UI

The mobile apps share a **Rust core** that handles all cryptography, networking, local database access, and business logic. The UI layer is native per platform. This is the same architecture Signal uses internally.

- **iOS:** Swift/SwiftUI UI layer. The Rust core is compiled to a static library and exposed to Swift via **UniFFI** (Mozilla's tool for generating Swift/Kotlin/Python bindings from Rust).
- **Android:** Kotlin/Jetpack Compose UI layer. Same Rust core, same UniFFI bindings.

This means the security-critical code — crypto operations, key storage, message processing — is written once, in Rust, and reviewed once. UI differences between platforms are confined to the presentation layer.

### On-device storage

- **SQLCipher** — SQLite with AES-256 transparent encryption, keyed from the user's device credentials. All local message history, group state, and keys are encrypted at rest.
- Keys are stored in the platform secure enclave (iOS Secure Enclave / Android Keystore) where hardware support is available. The SQLCipher database key is derived from a secret held in the secure enclave, so extracting the database without the device's hardware key is not useful.

### Calls

Calls are substrate-level, not a Project. They surface in the app's Calls tab and are available in any DM or group chat.

**1:1 calls** use WebRTC peer-to-peer. The homeserver acts as a signaling channel only — it brokers the initial WebRTC handshake over the existing WebSocket connection, then steps aside. Media flows directly between devices. STUN/TURN servers handle NAT traversal; the TURN server relays media when a direct connection isn't possible but learns nothing about content. DTLS-SRTP provides media encryption.

**Group calls** require a media server. Pure peer-to-peer doesn't scale past 3–4 participants — each participant would need to send their video stream to every other participant simultaneously. Instead, participants send one stream each to a **Selective Forwarding Unit (SFU)**, which routes streams to recipients without decoding them. We use **LiveKit**, an open-source SFU written in Go that is self-hostable and actively maintained.

E2E encryption for group calls is provided by **WebRTC Insertable Streams** (a W3C API): clients encrypt media frames before they leave the device using keys derived from the group's key material, and decrypt on receipt. The SFU forwards encrypted frames it cannot read. This is the same approach Signal uses for group calls.

**Large broadcasts** (hundreds or thousands of listeners, e.g. a movement-wide address) are not calls — they are one-to-many streams. LiveKit supports this mode alongside its SFU mode. The distinction matters: a call is bidirectional and has a practical size limit of tens of participants; a broadcast is unidirectional and scales to any audience size. The app should expose these as distinct experiences rather than trying to make one UI cover both.

The LiveKit SFU is a separate deployable component from the homeserver. Small orgs can run it on the same machine; larger deployments will want it separate. It is the one infrastructure dependency besides PostgreSQL that self-hosters need to run for full functionality.

### Push

The mobile client registers a per-(user, server) pseudonym with the push relay at account creation on each homeserver. The relay is a simple Rust service; its only job is the pseudonym → push token mapping described in the design document. It holds no message content and no cross-server linkage.

---

## Security practices

### Open source and auditable

All code — homeserver, mobile apps, push relay, cryptographic core — is open source. For this user base, "trust us" is not a valid security argument. The code is the security argument.

### Third-party audits

Before launch, independent security audits of the cryptographic implementation and the server software. This is standard practice for Signal, Matrix/Element, and other serious encrypted messaging projects, and it is non-negotiable here. Audit reports are published in full.

### Reproducible builds

Builds are reproducible: the same source produces the same binary, verifiably. Users and auditors can confirm that the app they're running matches the published source code. This is a defense against a compromised build pipeline inserting malicious code.

### Dependency management and supply chain

- **`cargo audit`** runs in CI and blocks on known vulnerabilities in any dependency.
- Dependencies are pinned in `Cargo.lock` and reviewed on update.
- The dependency tree is kept as small as practical. Every dependency is a supply-chain risk.
- The cryptographic dependencies (libsignal, RustCrypto) are treated as especially sensitive and audited separately.

### Threat modeling as a living document

The threat model in the design document is reviewed and updated as the implementation evolves. New features go through a threat-model pass before landing.

---

## Performance

### Compilation

Rust compile times are slower than Go or interpreted languages, but manageable:

- **Incremental compilation** in development — only changed crates recompile.
- **sccache** for shared build caching in CI.
- **Workspace structure** organized to minimize recompilation: the cryptographic core, the server logic, and the federation layer are separate crates. A change to the federation layer doesn't recompile the crypto core.
- **cargo-nextest** for faster parallel test execution.

### Runtime

- Near-C execution performance. No GC pauses. Rust's zero-cost abstractions mean high-level code compiles to the same machine code as hand-optimized C.
- Tokio's async runtime handles high connection counts efficiently with minimal thread overhead.
- Message encryption/decryption is fast: AES-256-GCM with hardware acceleration (AES-NI on x86, ARMv8 Crypto Extensions on mobile) runs at multiple GB/s.
- The server is designed to be horizontally scalable: multiple homeserver instances can run behind a load balancer with shared PostgreSQL.

### Self-hostability

The homeserver ships as a single statically-linked binary plus PostgreSQL. Docker images are provided for convenience. There is no requirement to run our infrastructure.

### Capacity planning

Resource requirements vary significantly by use case. All figures below assume a Rust homeserver with PostgreSQL on the same machine unless noted. The dominant costs are concurrent WebSocket connections (messaging), storage (media attachments and document snapshots), and bandwidth (calls).

| Deployment | Active users | Suggested spec | Approx. cost |
|---|---|---|---|
| Small org / single action | ~100 | 1 vCPU, 1 GB RAM, 20 GB SSD | ~$6/mo |
| Medium org | ~1,000 | 2 vCPU, 4 GB RAM, 100 GB SSD | ~$20/mo |
| Large org | ~10,000 | 4+ vCPU, 16 GB RAM, separate PostgreSQL | ~$80–150/mo |
| Push relay | Serves many homeservers | 1 vCPU, 512 MB RAM | ~$4/mo |

A few notes on what drives these numbers:

- **Messaging** is cheap. Each concurrent WebSocket connection uses roughly 50–100 KB of RAM in a well-optimized Rust server. CPU cost is minimal — the server handles encrypted blobs, not plaintext. 1,000 concurrent connections is well within a 1 GB RAM machine.
- **Media attachments** are the main storage driver. Text messages are tiny; a server with active photo/file sharing needs storage budgeted accordingly. Object storage (S3-compatible) is the right answer at any meaningful scale — keep the homeserver stateless with respect to files.
- **Calls are the most resource-intensive component** and are handled by LiveKit, not the homeserver. A 10-person video call at 720p uses roughly 15–20 Mbps of SFU bandwidth. A small org running occasional calls can share a machine with the homeserver; an org with frequent concurrent calls should run LiveKit on dedicated hardware or a separate VPS. Audio-only calls are roughly 10× cheaper on bandwidth.
- **Collaborative documents** add modest storage overhead (encrypted operation logs + snapshots) but negligible CPU or RAM.
- **Large announcement groups** (thousands of members) are fine for messaging but generate a burst of push relay traffic when a message is sent. The relay fans out pushes asynchronously so this doesn't block the sender, but the relay needs enough outbound bandwidth to handle the burst.

---

## Open questions

1. **Federation transport details.** HTTP/2 + request signing is the plan, but the exact signing scheme and key rotation story for server-to-server auth needs to be specced out before implementing federation.

2. **Key transparency.** For high-assurance users, a key transparency log (similar to what Google's E2E and WhatsApp have deployed) would let users verify that the server isn't silently substituting keys. Significant implementation work; worth revisiting after the core ships.

3. **Rust core / UniFFI maturity.** UniFFI is solid but the async story across the FFI boundary is still evolving. Monitor and adopt improvements as they land.

---

## Staged build plan

Each stage produces a testable, shippable increment. Later stages depend on earlier ones; within a stage, components can be built in parallel. The order is chosen to get encrypted 1:1 messaging working as early as possible — that is the load-bearing core everything else rests on.

---

### Stage 1 — Rust cryptographic core

**What gets built:**

- Cargo workspace skeleton: separate crates for `crypto`, `store`, `net`, `server`, `relay`, and `app-core` (the UniFFI boundary crate)
- libsignal integration: X3DH prekey generation and key-bundle construction; Double Ratchet session initialization and message encrypt/decrypt
- SQLCipher-backed local store: schema for sessions, prekey material, and message queue; key derived from a placeholder secret (real secure-enclave integration comes in Stage 3)
- UniFFI interface definitions for the functions mobile UI will need; stub bindings generated but not yet wired to a real UI

**Why first:** Everything else in the system is downstream of correct crypto. Getting this isolated, tested, and reviewed before connecting it to a server or UI eliminates an entire class of integration bugs.

**Testing:**
- Unit tests in `crypto` crate covering encrypt → decrypt round-trips, ratchet advancement, and prekey consumption
- Property-based tests (using `proptest`) on session state: any sequence of sends and receives should leave the session in a consistent state
- All tests run in CI with `cargo-nextest`; `cargo audit` blocks on any advisory

---

### Stage 2 — Homeserver MVP

**What gets built:**

- PostgreSQL schema: accounts, DID registrations, prekey bundles, encrypted message queue, device sessions, push pseudonyms (stub only), rate-limit counters
- Axum HTTP server: account registration, device auth (session token issuance), prekey upload and fetch, message send (store-and-forward), WebSocket endpoint for real-time delivery
- Background task: expire queued messages and session tokens; vacuum prekeys below refill threshold
- `did:plc` stub: local DID creation and document storage (no PLC directory interaction yet — full DID portability is a federation-stage concern)
- Docker Compose file: homeserver + PostgreSQL for local development

**Why second:** The homeserver is the counterpart the crypto core needs to be useful. Having both lets us test a full end-to-end message path — encrypt on one device, relay through the server, decrypt on another — before writing any UI.

**Testing:**
- Integration tests: spin up a real Postgres instance (via `testcontainers-rs`), run account registration, prekey exchange, and a message round-trip
- sqlx compile-time query checks catch schema/query mismatches at build time
- HTTP endpoint fuzz testing with `cargo-fuzz` on the message ingestion path
- Load test: simulate 1,000 concurrent WebSocket connections, verify no memory growth or dropped messages

---

### Stage 3 — Mobile apps: 1:1 encrypted DMs

**What gets built:**

- iOS (Swift/SwiftUI) and Android (Kotlin/Jetpack Compose) app shells wired to the Rust core via UniFFI
- Secure key storage: SQLCipher database key held in iOS Secure Enclave / Android Keystore
- Account creation and onboarding: generate DID, generate prekeys, register with homeserver, display recovery key
- **Chats tab:** unified conversation list sorted by recency with unread indicators; 1:1 DM conversation view (text, images, files); message send/receive over WebSocket with offline queue drain on reconnect
- Placeholder **Calls** and **Network** tabs (visible but empty)
- Basic push notification wakeup: app wakes on ping and fetches new messages (push relay not yet live; development uses polling as a stand-in)

**Why third:** This is the first thing a real user can interact with. Getting Signal-quality 1:1 DMs on both platforms is the acceptance criterion for the first user-facing milestone.

**Testing:**
- XCTest (iOS) and Espresso (Android) UI tests covering the account creation flow and message send/receive
- Cross-platform interop test: iOS device sends an encrypted message, Android device decrypts it correctly, and vice versa — run against a real test homeserver in CI
- Manual: dog-food the app internally for day-to-day team communication starting here

---

### Stage 4 — Action-bound groups

**What gets built:**

- libsignal zkgroup / anonymous credentials on the homeserver: group creation, member credential issuance, membership proofs, sealed sender for group messages
- Group messaging in the Rust core and on the server; groups appear in the Chats tab alongside DMs
- Group admin surface in the app: create group, invite members, assign roles (admin / member), approve join requests
- **Message expiry:** timer stored in encrypted group state; clients delete on schedule; homeserver deletes its copy on the same schedule; timer cannot be extended by the server
- Announcement-only mode: enforced at the protocol level so non-admin members cannot post

**Why fourth:** Action-bound groups are the primary organizing primitive. They need the crypto foundation from Stage 1 and the server/mobile layers from Stages 2–3. Message expiry ships here, not later — retrofitting it is much harder than building it in from the start.

**Testing:**
- Multi-client integration test: 20 simulated clients join a group, exchange messages, verify each client decrypts correctly, and that no client can impersonate another (sealed sender)
- Expiry test: set a 10-second timer, verify server and clients both delete on schedule; verify the server cannot re-serve a deleted message
- Credential verification test: a client with a tampered credential is rejected by the server
- Announcement-only test: non-admin send attempt is rejected at the protocol level

---

### Stage 5 — Push notifications

**What gets built:**

- Push relay: standalone Rust service with a single table mapping `(pseudonym) → (device_token, platform)`; exposes two endpoints — one for clients to register a pseudonym, one for homeservers to send a wakeup
- APNs and FCM integration in the relay: sends a content-free wakeup (no subject, no body) on receipt of a homeserver ping
- Pseudonym rotation: clients rotate their pseudonym periodically (default: weekly); old pseudonym is valid for a grace period then deleted
- Homeserver integration: on message delivery, fire a push ping to the relay for each recipient device not currently on a live WebSocket

**Why fifth:** Push is required for the app to be practically usable (no one polls for messages). It's decoupled enough from groups and crypto that it can wait until basic messaging is stable, but it should land before federation so the relay design can be validated at single-server scale first.

**Testing:**
- Unit tests: relay correctly maps pseudonyms, rejects unknown pseudonyms, and rotates gracefully
- Integration test with APNs/FCM sandbox: send a wakeup, verify the device receives it and the payload contains no user-identifiable content
- Privacy test: confirm the relay's access log contains only pseudonyms and timestamps — no homeserver identity, no content
- Rotation test: old pseudonym stops receiving after the grace period; new pseudonym receives correctly

---

### Stage 6 — Project framework

**What gets built:**

- Project registration API on the homeserver: a Project declares its scopes (e.g., "read availability for users in this group," "send push to RSVP'd attendees") and receives a Project identity
- User-facing permission grant flow: when a user is added to a Project-managed group or opens a Project for the first time, the app presents the requested scopes for approval
- Bot first-class support: bots are created as Project-owned accounts with their own keys; they join groups as normal members; their presence is visible to all group members
- Project deep links: `actnet://project/<server>/<project-id>/<path>` scheme registered on iOS and Android; links open the correct Project view or navigate into a chat
- **Network tab** in the app: hierarchical list of servers → Projects; tap a Project to open its full-screen view
- Project host SDK (Rust crate + documentation): the interface Project developers use to interact with the substrate

**Why sixth:** The Project framework is what turns the substrate into a platform. It needs stable groups and push underneath it, but it does not need federation — Projects are single-server by default and the cross-server guest model can be layered on later. Building the SDK here, before the first-party Projects, means the first-party Projects are built the same way third-party developers will build.

**Testing:**
- Scope enforcement test: a Project attempts an operation outside its granted scopes; the server rejects it
- Bot visibility test: all group members can enumerate bots in their group; a bot cannot hide its presence
- Deep link test: tapping an `actnet://` link from outside the app opens the correct view on both platforms
- SDK smoke test: a minimal "hello world" Project (a bot that echoes messages) is built against the SDK and run against a test homeserver

---

### Stage 7 — First-party Projects

Built in this sub-order, since each one exercises more of the framework:

**7a — Channel Directory**

A server's browsable listing of open and semi-open groups. Simplest possible Project: reads group metadata, displays it, handles join and join-request flows. Validates that the Project framework's read scopes and the Network tab UX work end-to-end.

*Tests:* Open join completes in one tap and lands user in the correct group in the Chats tab. Application-required join triggers an admin notification. Unlisted groups do not appear.

**7b — Team Assignment**

Sign-up flow → team placement → encrypted team group. Exercises: scoped write to user profile, roster encryption under user keys, team-lead role with scoped permission to read roster. Swap request matching is a straightforward two-sided queue.

*Tests:* Sign-up creates account, user lands in correct team group. Team lead can read roster; members cannot. Bidirectional swap request matches correctly; unmatched request stays queued.

**7c — Action Day**

Map with admin-set markers + ephemeral location upload + announcement-only encrypted group. Key constraint: location records are deleted on a rolling window and purged completely when the action ends. The announcement group is a standard action-bound group in announcement-only mode.

*Tests:* Admin pushes a marker; all participants receive it and it appears on the map. Participant location is visible to others within the rolling window. After the rolling window, location is no longer returned by the server. After action end, all location records are gone. Non-admin send to the announcement group is rejected.

**7d — Q&A Bot**

A bot that answers questions by grounding responses in an admin-provided document corpus. Exercises the bot framework end-to-end: bot joins a group, receives messages, calls the LLM API with retrieved context, replies. The "don't speculate" constraint is enforced by the prompt; if the retrieval step returns nothing above a confidence threshold, the bot says so.

*Tests:* Bot answers a question that is clearly in the corpus. Bot declines to answer a question outside the corpus. Bot correctly cites its source. Bot appears in the group member list.

**7e — Collaborative Documents**

CRDT operations broadcast through an action-bound group channel; server stores encrypted operation blobs; periodic snapshots. New members sync from the latest snapshot.

*Tests:* Two clients concurrently edit the same document; both converge to the same state. New member joins after 100 operations, syncs from snapshot, and sees the correct document. Server cannot reconstruct the document from the blobs it stores.

**7f — Engagement Tracking**

Observer bots in action-bound groups surface high-engagement moments to an organizer dashboard. The bots are visible group members. The dashboard is accessible only to organizers with explicit access. Data is never aggregated across servers.

*Tests:* Bot is visible in group member list. Organizer sees the dashboard; non-organizer gets a 403. A flagged message links back to the correct conversation. No engagement data is transmitted to any external server.

---

### Stage 8 — Calls

**What gets built:**

- **1:1 calls:** WebRTC signaling over the existing WebSocket connection; STUN/TURN for NAT traversal; DTLS-SRTP media encryption; Calls tab on iOS and Android
- **Group calls:** LiveKit SFU integration; E2E encryption via WebRTC Insertable Streams (clients encrypt frames before they leave the device; SFU forwards ciphertext); group call UI (grid/speaker layout)
- **Large broadcasts:** LiveKit's broadcast mode exposed as a distinct UX from calls — unidirectional, scales to thousands of listeners

**Why eighth:** Calls are infrastructure-intensive and not required for the core organizing use case. They're also the one component that requires a second deployable service (LiveKit). Getting the substrate and all first-party Projects right first means this stage doesn't destabilize an already-working system.

**Testing:**
- 1:1 call: two clients connect, verify audio reaches both sides; simulate NAT by forcing TURN relay and verify call still works
- Group call encryption test: capture SFU traffic and verify frames are encrypted (no decodable video/audio) at the SFU — the SFU should be blind to content
- Large broadcast: spin up a LiveKit instance, simulate 500 listener connections, verify the homeserver's CPU and memory are not affected (all load is on LiveKit)
- Calls tab UI tests: incoming call notification, accept/decline, in-call controls

---

### Stage 9 — Federation

**What gets built:**

- Server-to-server transport: HTTPS with Ed25519 request signing; receiving server verifies the signature against the sending server's DID document before processing
- Full `did:plc` integration: DID creation, update, and deactivation synced with the PLC directory; DID resolution for remote users
- Cross-server DM delivery: Alice on server A can DM Bob on server B; A looks up B's DID, finds its homeserver, and relays the encrypted message
- Cross-server casual groups: ad-hoc encrypted group chats spanning homeservers (peer-managed, no Project required)
- Guest participation in action-bound groups: homeserver A issues a guest credential for a user, homeserver B's Project accepts it and grants scoped access
- Selective federation: homeserver admins configure an allowlist of servers they federate with

**Why ninth:** Federation is a meaningful differentiator for resilience and multi-org organizing, but the system is fully usable without it. Every first-party Project works on a single homeserver. Deferring federation means the complexity of cross-server delivery, DID portability, and guest credentials doesn't slow down the path to a working, deployable product. It also means the federation design can be informed by real usage patterns from the single-server deployment rather than guessed at upfront.

**Testing:**
- Two-homeserver integration harness in CI (two Docker Compose stacks, networked together): Alice on server A DMs Bob on server B; verify end-to-end encryption is preserved across the relay boundary
- Guest credential test: user on server A joins an action-bound group on server B as a guest; verify scoped access (can post, cannot see full member list)
- Federation fault injection: server B is unreachable; server A queues the message and retries; verify no message loss and no timeout leak to the user
- Selective federation test: server A rejects a federation request from a server not on its allowlist

---

### Stage 10 — Security hardening and launch readiness

This stage runs in parallel with Stages 7–9 and extends after them.

**What gets built / done:**

- **Reproducible builds:** iOS, Android, and server builds are made reproducible; documented verification steps published alongside each release
- **CI hardening:** `cargo audit` already runs; add `cargo deny` for license and duplicate-dependency checks; add scheduled supply-chain diff alerts for dependency updates
- **Third-party security audit:** engage an external firm to audit the cryptographic core (`crypto` crate + libsignal integration), the homeserver (auth, message handling), and the mobile key storage implementation; publish the full report
- **Threat model review:** walk through every stage's output against the threat model in the design document; document any new attack surfaces introduced and the mitigations in place
- **Operational security for the relay:** the push relay is a metadata target; audit its logging, ensure no cross-server linkage is retained, and document its operational trust assumptions

**Testing / acceptance criteria:**

- Audit report published with no unmitigated critical or high findings
- Reproducible build verification passes for a fresh build from source on a clean machine
- All CI checks pass on a dependency update PR within 24 hours of a new advisory
- A "red team" exercise (internal or external) attempts to: extract message content from a seized homeserver, link a user's activity across servers via push metadata, impersonate a group member. Each attempt should fail in a documented way.

---

### Summary table

| Stage | Deliverable | Key acceptance criterion |
|---|---|---|
| 1 | Rust crypto core | Encrypt → decrypt round-trip passes; ratchet property tests pass |
| 2 | Homeserver MVP | 1,000 concurrent WebSocket connections; message round-trip under load |
| 3 | Mobile: 1:1 DMs | iOS ↔ Android interop test passes; dog-food begins |
| 4 | Action-bound groups | 20-client group test; expiry verified server- and client-side |
| 5 | Push notifications | Content-free wakeup confirmed; relay log contains no user identity |
| 6 | Project framework | Scope enforcement; bot visibility; deep links |
| 7 | First-party Projects | Each Project's acceptance tests (see above) |
| 8 | Calls | SFU blindness verified; group call E2E encryption confirmed |
| 9 | Federation | Cross-server DM round-trip; fault injection passes |
| 10 | Hardening + audit | Audit report published; reproducible builds verified; red team exercises pass |
