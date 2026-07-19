# Chat Organization

Status: draft for review. UX + data-model proposal. Motivated by the
"conversation intelligence" post (theavalanche.net/blog/2026-07-intelligence)
and by real multi-account confusion in current testing.

## The idea in one line

Give the Chats screen a row of **tabs** that partition your conversations, and
let those tabs be filled either by a **deterministic rule** (e.g. "everything on
safe-haven.org") or, later, by an **on-device classifier** that sorts by topic.
Same surface, two sources of assignment.

## Baseline: feels like Signal first

The default is a plain **unified inbox** — one conversation per row, sorted by
recency, **no tab row at all**. This is the governing principle from `00`: the app
must feel like Signal, not Slack/Discord. A single-account user with a handful of
conversations should never see a tab.

Tabs are **progressive disclosure** — the surface appears only when there's a
concrete reason to present it, e.g.:

- you have **more than one account/server** (the near-term trigger — this is what
  surfaces tabs for testers), or
- the on-device classifier has something genuinely useful to propose, or
- you turn them on yourself.

Until one of those, the tab surface stays out of the way entirely — same
discipline as the Threads catch-up entry and the shelf (`32`): **quiet when empty,
present only once they earn it.** Everything below describes the surface *once it
has been surfaced*.

## Core model: tabs are homes, not filters

Tabs are an **exhaustive partition** — every conversation lives in **exactly
one** tab. There is no "All" tab. This is the Gmail-tabs model (Primary / Social
/ …), not a filter bar you narrow down from a master list. Tabs are
**user-configurable**.

- **Homes vs. lenses.** A tab is a *home* (a conversation belongs to one).
  Cross-cutting collections like Mentions / Saved are *lenses* (a message shows
  up through them without leaving its home) — those belong on the shelf (`32`),
  **not** as tabs.
- **Threads** are the middle case: home-like (own read state, own stream) but
  nested under a parent that has its own home. So threads are **not** a tab.
  They surface as a single compact **catch-up entry pinned atop the list** (see
  below), consistent with `32`'s "threads live in a launcher, not the inbox."

## Assignment: what's load-bearing, and what's just a mechanism

What the design commits to is the *shape* of assignment, not how it's computed:

- **Single-home partition.** However a conversation's tab is decided, it lands in
  exactly one — the exhaustive-partition guarantee above.
- **Two sources of assignment coexist on one surface.**
  - **Structural (deterministic).** By account/server or any other hard predicate.
    No model, works on every device, available from day one.
  - **AI-suggested (device-gated).** On-device conversation-intelligence classifies
    by topic/shape (participant count, group title, history, bot activity), per the
    blog, and *proposes* topic tabs; degrades to manual where the models aren't
    available.
- **One evolving configuration, not two regimes.** There is no migration from
  "server tabs" to "content tabs." A multi-account tester starts with account tabs;
  later, topic tabs are added and the account tabs drain — or one stays as a
  catch-all to quarantine a server. Continuous, user-driven reconfiguration, never
  a discrete switch.
- **Automatic behavior never stomps the user's setup.** *(The one genuinely
  load-bearing rule here.)* The AI *proposes*; the user accepts, edits, or ignores.
  Auto-classification fills the tabs the user has; it does not silently reorganize
  them.
- **One axis at a time.** Server and topic are orthogonal, and a single-home
  partition can express only one — you cannot have both "all Safe Haven" and "all
  Action" as tabs, since a conversation that is both must pick one home. The second
  axis is a **lens/search**, not a parallel tab row (see homes vs. lenses). So
  "keep server separation after going topic-first" = search by server.

**Likely mechanism — not a commitment.** The simplest way to satisfy all of the
above is probably *one ordered list of tab definitions, first-match-wins* (like
mail filters), with an explicit manual move as a per-conversation override. But
that's an implementation choice; other structures (priority scores, a single
classifier with structural pre-empts, purely explicit per-conversation assignment)
could meet the same guarantees. **Do not treat first-match-wins ordering as part
of the design** — it's the default we'd reach for, nothing depends on it.

## The tab organizer

A single screen — the **tab organizer** — is the home for all of this: it shows
your tabs and lets you **move conversations between them** (and, later, create,
rename, and adjust how tabs are filled). It is reached two ways:

- **Deliberately**, from Settings → "Organize conversations".
- **On its own**, when complexity crosses a threshold and the app offers to help
  you organize. The **default trigger is adding a second server/account** — the
  moment the flat inbox starts mixing contexts is exactly when tabs earn their
  place, and it is the concrete progressive-disclosure trigger from *Baseline*.
  Other thresholds (conversation count, an AI proposal worth showing) can feed the
  same prompt later.

A manual move is a **per-conversation assignment that overrides any automatic
assignment** (like Gmail's sticky "move to tab") — consistent with *AI proposes,
user disposes*: a structural criterion or the classifier may suggest a home, but
an explicit move wins and sticks.

**v1 scope is deliberately thin.** We don't yet need full tab editing. The screen
starts as little more than the destination the second-server prompt opens — enough
to introduce account tabs and nudge a conversation's home. Richer editing (custom
criteria, rename) fills in as the assignment sources grow. The point of specifying
it now is to **reserve the one place** organization lives, so every later
capability has an obvious home instead of accreting scattered controls.

## Multi-account: organization replaces marking

We deliberately **do not surface which server/account a conversation is on in the
inbox rows** — no per-row badge, tint, or dot. Rationale:

- A conversation is bound to exactly one of your identities **by construction**
  (a DM from your pseudonymous persona and one from your real identity are
  *different conversations* — different `my_did`, different conversation id). So
  the conversation itself *is* the context; you can't "act as the wrong persona"
  inside it. There is no per-message identity choice to get wrong.
- For groups/DMs the right home is usually self-evident; genuine ambiguity is
  rare.
- If a user wants server separation, they **make it a tab** ("Safe Haven",
  "pseudo.example"). Organization does the disambiguation the badge used to.

One thing we keep (it *reinforces* the above rather than contradicting it):

- **Compose-time identity default.** Starting a *new* conversation has no
  existing context, so the app picks the acting identity via `preferred_identity`
  (`52`). Compose-flow concern, not homescreen chrome.

## The Threads catch-up entry

Not a tab. A single compact row pinned to the **top of the primary tab's list**
when there are unread threads:

- Shorter than a conversation row; smaller-than-avatar glyph; text aligned to the
  conversation rows below.
- Title shows the count of **unread threads**; the trailing unread badge shows
  total unread **messages** across them.
- Preview lists the groups the unread threads are in ("in Canvass NW, Action Day
  Leads").
- Hidden on other tabs.

(A visual prototype of all of the above lives in
`mobile/ios/.../Views/Chats/ChatsTabbedPrototype.swift`, `#if DEBUG` only.)

## Phasing (capability, not migration)

The tab surface is shipped once; what grows over time is the set of rule *sources*
feeding it. No user ever migrates between regimes.

1. **The tab surface + structural rules** — auto-create a tab per account/server
   for multi-account users (zero-config separation in testing), plus
   manual/custom tabs. Routes each conversation to its account tab via the
   conversation's `my_did`, which works today — no keying change needed.
   Deterministic, device-independent.
2. **AI-suggested tabs** — on-device topic classifier that *proposes* tabs onto
   the same surface; message-level overrides; per-tab notification rules. The user
   curates; nothing auto-reorganizes.

## Open / deferred

- On-device classification mechanics and model availability tiers.
- Message-level overrides (what pierces a muted tab).
- Per-tab notification rules.
- Full tab-organizer editing (custom criteria, rename, and — if we go with an
  ordered-list mechanism — reorder) — the screen exists as the reserved home; rich
  editing is deferred past v1.
- Exact auto-prompt thresholds beyond "added a second server" (conversation
  count, AI-proposal quality).
- Whether the primary tab is special (it currently hosts the Threads entry).

## Rejected / not doing

- **Per-row account marking** (badge/tint/dot) — organization via tabs replaces
  it; a bare marker reads as noise without a legend.
- **A filter bar with an "All" view** — tabs are an exhaustive partition, not a
  filter over one master list.
- **Threads as its own tab** — it's a nested object, not a home; it gets the
  catch-up entry instead.
- **A discrete "switch" from server tabs to content tabs** — there is one
  evolving configuration, not two regimes to migrate between.
