# identity-breached-credential-detection

Breached credential detection for WSO2 Identity Server, with a pluggable breach source SPI.

Refuses passwords that already circulate in credential breaches, on every path that sets a password.

## What is here

Two parts, and the split is the design:

| | |
|---|---|
| **`org.wso2.carbon.identity.breach.detection.api`** | The `BreachSource` SPI. Versioned on its own clock so a connector keeps compiling across additive revisions. |
| **`org.wso2.carbon.identity.breach.detection`** | The enforcement point, the evaluation engine, and the one source that ships in-tree — a blocklist file held in memory. |

Everything else is a **connector**: a bundle dropped into `dropins` that registers a `BreachSource` and is picked
up with no configuration edit. Remote sources are released on their own clock against the published contract.
[identity-password-validator-hibp](https://github.com/wso2-extensions/identity-password-validator-hibp) is the
reference implementation.

## Where enforcement happens

`BreachDetectionListener` sits on `AbstractUserStoreManager` at order **420**. Every path that sets a password
converges there — self-registration, administrative creation, recovery, invitation acceptance, the management
APIs, and any path added later, including one against a secondary user store.

Order 420 puts it **after** composition rules at 3, so a password failing length or character class never reaches
a breach source, and **before** the service extension at 10000, so in-product policy resolves first.

A refusal is a client error carrying its reason, never a server fault:

| Code | Meaning |
|---|---|
| `BRD-60001` | The password appears in a known breach. |
| `BRD-60002` | The password could not be checked, and the source that failed is set to refuse. |

## Configuration

```toml
# The deployment kill switch. Off disables the capability for every tenant
# without removing software, and leaves stored tenant policy untouched.
[event.default_listener.breach_detection]
enable = true
priority = 420

[breach_detection]
evaluation_timeout_ms = "1500"   # per remote source; offline sources are called inline
worker_threads = "20"
exempt_bulk_operations = false   # skip evaluation during bulk import / migration

[breach_detection.sources.localList]
enable = true
path = "${carbon.home}/repository/resources/security/breached-passwords.txt"
format = "sha1"
```

### The local blocklist

| Key | Required | Default | |
|---|---|---|---|
| `enable` | no | `true` | Set to `false` to park a configured list without removing its settings. |
| `path` | **yes** | — | Confined to `carbon.home` and the config directory. `${carbon.home}` expands. |
| `format` | **yes** | — | `sha1`, `sha256`, or `plaintext`. Must match how the file is written. |
| `max_heap_entries` | no | `5000000` | Loading stops here and reports truncation. |

`format` has no default and is never guessed. The file dictates the algorithm — a list of already-dumped hashes
can only be compared on the algorithm it was dumped with — and a wrong guess does not fail, it silently stops
matching. An absent or unrecognised value leaves the source **not configured** rather than picking one.

File contents are treated strictly as evaluation data. A line is a password or a digest, never a directive or a
path. Blank lines and lines beginning `#` are ignored and are not counted as malformed. An already-hashed entry
may carry an occurrence count after a colon (`<digest>:<count>`), as the Have I Been Pwned download does.
Plaintext entries are hashed on the way in, so the file stays the only place those passwords exist in readable
form.

### What each condition reports

| Condition | State | Consulted |
|---|---|---|
| `path` and `format` set, file loads | `READY` | yes |
| `enable = false` | `NOT_CONFIGURED` | no |
| `path` unset | `NOT_CONFIGURED` | no |
| `format` unset or unrecognised | `NOT_CONFIGURED` | no |
| file unreadable on reload | `READY` | yes — the previously loaded list stays in effect |
| over `max_heap_entries` | `READY`, truncated | yes — the remainder is not enforced |

A source that cannot answer reports **unavailable**, never *not found*. Collapsing those two is what makes a
breach check silently stop enforcing while still presenting as enabled.

## Sizing the local blocklist

The list is held entirely in memory, and `max_heap_entries` caps the entry **count**, not bytes. Measured cost:

| Format | Digest | Per entry | 1M entries | 5M entries |
|---|---|---|---|---|
| `sha1` | 40 hex chars | 122.5 bytes | 117 MB | 584 MB |
| `sha256` | 64 hex chars | 146.5 bytes | 140 MB | 699 MB |

**A long list is a signal to write a source, not to raise the limit.** This file is the right home for the
passwords an operator specifically wants blocked — a corporate policy list, credentials from a known incident,
the most-reused passwords. It is the wrong home for a full breach corpus: password reuse follows a power law, so
a list an order of magnitude shorter than the ceiling carries nearly all of the protective value, and the tail
costs heap the server needs for everything else.

A corpus that wants more than this belongs behind a `BreachSource` connector, which answers from its own storage
— a hosted service, a local database, a memory-mapped index it owns — instead of from the server's heap. That is
what the SPI is for, and it is why the local list stays deliberately small.

## Restarts

**A changed blocklist file takes effect on restart.** There is no watcher and no polling, which is the
convention across Identity Server: file-backed configuration is read at startup. Connectors registering or
unregistering are the exception — a bundle added to `dropins` binds without a restart, because that is an OSGi
service event rather than a file change.

## Writing a source

Implement `BreachSource` and register it from your bundle activator:

```java
bundleContext.registerService(BreachSource.class, new MyBreachSource(), null);
```

Only `getId()`, `getDescriptor()` and `evaluate(BreachContext)` are abstract; everything else has a default, so
an existing connector keeps compiling as the contract gains methods. Declare your settings through
`getProperties()` and the core resolves them and hands them back via `configure(SourceConfiguration)` — a
connector reads no file and holds no vault handle of its own, which is what makes the `secret` flag on a
property enforceable rather than advisory.

Three rules a source must honour:

1. Return `Outcome.UNAVAILABLE` — or throw `BreachSourceException` — for anything that is not a positive
   determination. Never invent `NOT_FOUND` because a call failed.
2. Never log, cache, or transmit the credential in a recoverable form, and never retain it past the call.
3. Own your own enablement. `isEnabled(tenantDomain)` defaults to `false`, so a source is consulted only when it
   says so — and whatever configuration surface it needs to let an administrator decide that is the source's to
   publish.

## Building

```bash
mvn clean install
```

Java 11 or later, Maven 3.6 or later.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
