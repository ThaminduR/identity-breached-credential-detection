# Breached credential detection

Feature documentation. For building and deploying, see [README.md](README.md).

- [What it does](#what-it-does)
- [How enforcement works](#how-enforcement-works)
- [The source model](#the-source-model)
- [When a source cannot answer](#when-a-source-cannot-answer)
- [Configuration reference](#configuration-reference)
- [The local blocklist](#the-local-blocklist)
- [Deployment suggestions](#deployment-suggestions)
- [What to monitor](#what-to-monitor)
- [Troubleshooting](#troubleshooting)
- [Known gaps](#known-gaps)
- [Writing a breach source](#writing-a-breach-source)

## What it does

Composition rules — length, character classes, dictionary words — say nothing about whether a password is
already published. A password can satisfy every rule in the policy and still appear in a breach corpus millions
of times, which is exactly what makes credential stuffing work.

This refuses those passwords at the point they are set, and it does so on **every** path, not just the ones
someone remembered to hook.

## How enforcement works

`BreachDetectionListener` sits on `AbstractUserStoreManager` at **order 420**. Every path that sets a password
converges there:

| Path | Hook |
|---|---|
| Self-registration | `doPreAddUser` |
| Administrative user creation | `doPreAddUser` |
| Invitation acceptance | `doPreAddUser` |
| Self-service password change | `doPreUpdateCredential` |
| Administrative reset | `doPreUpdateCredentialByAdmin` |
| Password recovery | `doPreUpdateCredentialByAdmin` |

Anything added later converges there too, including a path against a secondary user store — which is the point
of intercepting at the store rather than at each portal.

**Order matters.** 420 sits after input validation at 3 and before the service extension at 10000:

```
    3  ── composition rules          a password failing length or character class
                                     never reaches a breach source
  420  ── breach detection           ← here
10000  ── service extension          in-product policy resolves before any
                                     customer extension runs
```

### What the user sees

A refusal is a `UserStoreClientException` carrying a `PolicyViolationException` — a **client** error with its
reason, never a server fault, which a portal cannot distinguish from an outage.

| Code | Message | Cause |
|---|---|---|
| `BRD-60001` | This password has appeared in a known data breach. Choose a longer, unique password. | A source reported the password. |
| `BRD-60002` | This password could not be checked right now. Try again in a moment. | No source could answer, and one of them is set to refuse. |

Both are resolved through the bundled resource bundle, so they localise with everything else. Neither message
carries an occurrence count: a count invites treating a smaller number as safer, and offers the user nothing
actionable.

## The source model

The core knows nothing about any particular breach corpus. It discovers **sources** — OSGi services
implementing `BreachSource` — and orders them by the priority each one declares:

```
  candidate password
         │
         ▼
  ┌─────────────────┐  priority 100, offline
  │  localList      │  in-process, microseconds, no network
  └─────────────────┘
         │ not found
         ▼
  ┌─────────────────┐  priority 500, remote
  │  hibp           │  bounded by timeout, on a worker thread
  └─────────────────┘
         │ not found
         ▼
       accepted
```

Three consequences worth understanding:

- **A match short-circuits.** The passwords an operator most wants blocked never leave the deployment and never
  consume a third party's quota.
- **Ordering is data, not code.** An offline source declaring a low number runs before a network round trip
  without the engine knowing what either one is.
- **Offline sources are called inline.** A source that declares `isOffline()` answers in microseconds, so a
  thread hand-off would cost more than the lookup. `evaluation_timeout_ms` and `worker_threads` bound remote
  sources only.

Each source owns its own enablement and its own configuration surface. The core publishes no governance
connector and holds no per-organization policy, which is why a source's Console presence appears when its
bundle is installed and disappears when it is removed.

## When a source cannot answer

A source that cannot reach its corpus, times out, exhausts a quota, or fails to parse a response reports
**`UNAVAILABLE`** — never `NOT_FOUND`. That distinction is the whole design. Collapsing the two is what makes a
breach check silently stop enforcing while still presenting as switched on.

What happens to the password then is each source's own decision, per organization, because the right answer
differs by source:

| | |
|---|---|
| `ALLOW` | Let the password through and record the gap. The default. |
| `DENY` | Refuse it, with a message distinguishable from a breach (`BRD-60002`). |

A hosted corpus that cannot be reached is somebody else's outage, and refusing would let them stop every
password change in your deployment — so `ALLOW` is the defensible default there. See
[Known gaps](#known-gaps) for the local list's current behaviour, which differs from what you might expect.

## Configuration reference

### Deployment level

```toml
[event.default_listener.breach_detection]
enable = true          # the kill switch: off disables the capability for every tenant
priority = 420         # leave this alone unless you know why you are moving it

[breach_detection]
evaluation_timeout_ms = "1500"    # per remote source; offline sources are not bounded by it
worker_threads = "20"             # pool for remote source calls
exempt_bulk_operations = false    # skip evaluation during bulk import / migration
```

### The local blocklist

```toml
[breach_detection.sources.localList]
enable = true
path = "${carbon.home}/repository/resources/security/breached-passwords.txt"
format = "sha1"
max_heap_entries = 1000000
```

| Key | Required | Default | |
|---|---|---|---|
| `enable` | no | `true` | `false` parks a configured list without removing its settings, and releases the memory. |
| `path` | **yes** | — | Confined to `carbon.home` and the config directory. `${carbon.home}` expands. A path outside those is refused and logged. |
| `format` | **yes** | — | `sha1`, `sha256`, or `plaintext`. |
| `max_heap_entries` | no | `5000000` | Loading stops here and logs at ERROR. |

Connector settings live under their own namespace — `[breach_detection.sources.<id>]` — and the keys are
whatever the connector declares. The core resolves them and hands them over; a connector reads no file and
holds no vault handle of its own. A value written as `$secret{alias}` is resolved through the secure vault.

## The local blocklist

The one source that ships in the core. It crosses no boundary, so there is no third-party API to track, and it
is what makes the capability work at all in a network-isolated deployment.

### `format` is required, and never guessed

The file dictates the algorithm. A list of already-dumped hashes can only be compared on the algorithm it was
dumped with — you cannot re-hash a hash. And a wrong algorithm **does not fail**: it silently stops matching.
So there is no default and no auto-detection. An absent or unrecognised value leaves the source not configured
rather than picking one for you.

| `format` | The file holds | Compared with |
|---|---|---|
| `sha1` | 40-character hex digests | SHA-1 of the candidate |
| `sha256` | 64-character hex digests | SHA-256 of the candidate |
| `plaintext` | passwords, one per line | SHA-256, hashed at load |

### File rules

- Blank lines and lines starting `#` are ignored, and are **not** counted as malformed.
- A hashed entry may carry an occurrence count after a colon — `<digest>:<count>` — as the Have I Been Pwned
  download does. The count is ignored.
- Passwords are case- and whitespace-significant. Nothing is trimmed or folded; doing so would refuse
  credentials you never listed.
- Plaintext entries are hashed on the way in, so your file stays the only place those passwords exist in
  readable form and a heap dump never carries a list of them.
- A malformed line is skipped and counted; the count is logged so you can tell a file that loaded from one
  that mostly did not.

### Sizing

Held entirely in memory. `max_heap_entries` caps the entry **count**, not bytes:

| `format` | Per entry | 100k | 1M | 5M (default cap) |
|---|---|---|---|---|
| `sha1` | 122.5 bytes | 12 MB | 117 MB | 584 MB |
| `sha256` | 146.5 bytes | 14 MB | 140 MB | 699 MB |

**A long list is a signal to write a source, not to raise the limit.** This file is the right home for
passwords you specifically want blocked — a corporate policy list, credentials from a known incident, the
most-reused passwords. It is the wrong home for a full breach corpus: password reuse follows a power law, so a
list an order of magnitude shorter than the ceiling carries nearly all of the protective value, and the tail
costs heap the server needs for everything else. A corpus that wants more belongs behind a connector answering
from its own storage.

## Deployment suggestions

### Start with the local list alone

It needs no network, no third party, and no credentials. Put a few thousand entries in it — your corporate
denylist plus a public top-N list — and you have meaningful coverage with nothing to go wrong at runtime.

```toml
[breach_detection.sources.localList]
enable = true
path = "${carbon.home}/repository/resources/security/breached-passwords.txt"
format = "plaintext"
max_heap_entries = 1000000
```

### Lower `max_heap_entries` deliberately

The default of 5,000,000 permits 584–699 MB. On a 2–4 GB heap that is 15–30% of it, claimed by a setting nobody
looks at. Set it to what you actually intend — `1000000` (~117 MB) is a defensible ceiling.

### The file must exist on every node

The path is local. In a cluster, each node loads its own copy into its own heap, so the memory cost is
**per node**, not per deployment — 584 MB across four nodes is 2.3 GB of aggregate heap. Ship the file with
your node image or configuration management; there is no shared state and no replication.

### File changes take effect on restart

There is no watcher and no polling, which is the convention across Identity Server: file-backed configuration
is read at startup. Plan blocklist updates as a rolling restart.

Connectors are the exception — a bundle added to `dropins` binds without a restart, because that is an OSGi
service event rather than a file change.

### Adding a remote source

Add one when you want coverage the local list cannot carry. The reference connector checks Have I Been Pwned
without the password leaving the deployment: only a 20-bit prefix of the SHA-1 digest goes out, the service
returns every hash sharing that prefix (roughly two thousand), and the match is made in process — so it never
learns which password was checked.

Two settings deserve thought:

- **`refuseWhenUnreachable`** — leave it off unless you would rather block every password change in the
  deployment than accept one unverified password during someone else's outage. With the local list in place you
  still have a floor when the remote source is down.
- **An API key is optional and reduces privacy.** The range endpoint needs no authentication, so sending a key
  attaches a billing identity to otherwise anonymous lookups for no benefit.

### Exempt bulk operations

A migration importing a million users should not pay a network round trip per row, or burn a third party's
quota on data already in the store:

```toml
[breach_detection]
exempt_bulk_operations = true
```

This only exempts writes the platform attributes to a bulk flow. Ordinary password changes still evaluate.

### Order of precedence when you have both

Keep the offline source at a lower priority than any remote one — priority 100 and 500 respectively is what
ships. Then the passwords you care most about are caught locally, cost nothing, and never leave the box.

## What to monitor

One log line matters more than the rest:

```
ERROR ... Breached password detection is not enforcing for tenant '<x>':
          no enabled source could return a verdict.
```

That is the state where everything looks healthy from outside and nothing is being checked. Alert on it.

The lesser signal, at WARN, means some sources answered and some did not:

```
WARN  ... Breached password detection is degraded for tenant '<x>':
          1 of 2 sources could not answer.
```

At startup, confirm the entry count is what you expect. `entries=0` with a large `skipped` count means the
declared `format` does not match the file — see below.

## Troubleshooting

**A listed password is accepted.**

1. Check the startup log for `Loaded the breach blocklist: entries=N`. If `N` is 0, or `skipped` is large, the
   declared `format` does not match the file.
2. Check the composition rules did not refuse it first for an unrelated reason — those run at order 3.
3. For a hashed file, confirm the digest in the file matches what the server computes. Digests are compared
   case-insensitively but must be the right length and valid hex.
4. Confirm the source is enabled: `Breach source bound: id=localList` must appear, and `enable` must not be
   `false`.

**The bundles seem to be ignored.** The `dropins` filename must be
`<symbolic-name>_<version>.jar` — underscore, no `-SNAPSHOT`. Then clear
`repository/components/default/configuration/org.eclipse.osgi` and restart.

**Nothing in `deployment.toml` takes effect.** The `[breach_detection]` keys only reach the runtime through
`identity.xml.j2`. Confirm the rendered `repository/conf/identity/identity.xml` contains a `<BreachDetection>`
element. Never edit that file directly — it is regenerated on every start.

**A source is named in configuration but never consulted.** Look for
`Breach detection configuration names sources that are not installed: [...]` at startup. It usually means the
connector JAR is missing.

## Known gaps

Current as of this revision. Stated here rather than left to be discovered.

1. **A local list that fails to load resolves to allow, not refuse.** `isEnabled()` is
   `enabled && isConfigured()`, so a list that did not load makes the source report itself *not enabled*, the
   engine leaves it out of the plan, and nothing is asked. The source declares `FailureAction.DENY`, but that
   path is unreachable. If the local list is your only source, a broken file means no enforcement — and the
   capability reports itself as *off*, the same as if you had configured nothing.
2. **A declared `format` that does not match the file** rejects every line, loads successfully with nothing in
   it, and answers `NOT_FOUND` to everything. The entry and skipped counts in the log give it away; the
   reported state does not.
3. **`max_heap_entries` caps count, not bytes**, and nothing consults available heap. Exceeding it truncates
   and logs at ERROR, but a `format` change from `sha1` to `sha256` silently raises the memory cost by 20%.

## Writing a breach source

Implement `BreachSource` and register it from your bundle activator:

```java
bundleContext.registerService(BreachSource.class, new MyBreachSource(), null);
```

Only `getId()` and `evaluate(BreachContext)` are abstract. Everything else has a default, and the contract
gains default methods rather than abstract ones, so your connector keeps compiling across additive revisions.

Declare your settings through `getProperties()`; the core resolves them and hands them back via
`configure(SourceConfiguration)`. That is what keeps the `secret` flag on a property enforceable rather than
advisory — a secret is vault-resolved and never reachable as a plain value.

Three rules a source must honour:

1. **Return `UNAVAILABLE` — or throw `BreachSourceException` — for anything that is not a positive
   determination.** Never invent `NOT_FOUND` because a call failed. This is the one rule the whole design rests
   on.
2. **Never log, cache, or transmit the credential in a recoverable form**, and never retain it past the call.
   The candidate arrives as a `char[]` on a `Credential` that has no meaningful `toString`; use
   `digestHex(algorithm)` rather than reading the characters.
3. **Own your own enablement.** `isEnabled(tenantDomain)` defaults to `false`, so your source is consulted only
   when it says so — and whatever configuration surface an administrator needs to make that decision is yours
   to publish.

Declare `isOffline()` as `true` only if you answer without crossing the deployment boundary; the engine then
calls you on the calling thread, unbounded by the evaluation timeout.
