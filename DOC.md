# Breached credential detection

Password composition rules — length, character classes, repeated characters — say nothing about whether a
password has already been published. A password can satisfy every rule in your policy and still appear in a
breach corpus millions of times, which is what makes credential stuffing effective.

Breached credential detection refuses those passwords at the point they are set, on every path that sets one.
It checks against pluggable **breach sources**: a blocklist file that ships with the feature, and any number of
connectors that answer from a hosted or local corpus.

This guide explains how you can enable breached credential detection, configure the sources it checks against,
and size it for your deployment.

For building and deploying the bundles, see [README.md](README.md).

## Prerequisites

- WSO2 Identity Server 7.3.0 or later.
- The `org.wso2.carbon.identity.breach.detection.api` and `org.wso2.carbon.identity.breach.detection` bundles
  deployed to `<IS_HOME>/repository/components/dropins`. See [README.md](README.md#deploy).

## How it works

Breached credential detection runs as a user operation event listener at **order 420**, where every path that
sets a password converges.

<table>
    <tr>
        <th>Path</th>
        <th>Listener hook</th>
    </tr>
    <tr>
        <td>Self-registration, administrative user creation, invitation acceptance</td>
        <td><code>doPreAddUser</code></td>
    </tr>
    <tr>
        <td>Self-service password change</td>
        <td><code>doPreUpdateCredential</code></td>
    </tr>
    <tr>
        <td>Administrative reset, password recovery</td>
        <td><code>doPreUpdateCredentialByAdmin</code></td>
    </tr>
</table>

Because the check is applied at the user store rather than at each portal, paths added later are covered
automatically, including paths against a secondary user store.

Order 420 places the check **after** password input validation at order 3, so a password that fails length or
character class requirements never reaches a breach source, and **before** the service extension at order
10000, so in-product policy resolves before any custom extension runs.

### What the user sees

A refusal is returned as a client error carrying its reason, so portals can render the cause.

<table>
    <tr>
        <th>Error code</th>
        <th>Message</th>
        <th>Cause</th>
    </tr>
    <tr>
        <td><code>BRD-60001</code></td>
        <td>This password has appeared in a known data breach. Choose a longer, unique password.</td>
        <td>A source reported the password as breached.</td>
    </tr>
    <tr>
        <td><code>BRD-60002</code></td>
        <td>This password could not be checked right now. Try again in a moment.</td>
        <td>No source could return a verdict, and a source is configured to refuse in that case.</td>
    </tr>
</table>

Messages resolve through the bundled resource bundle and localize with the rest of the product. Neither message
includes an occurrence count.

## Configure breached credential detection

Configuration is applied in `<IS_HOME>/repository/conf/deployment.toml`.

> [!NOTE]
> These keys reach the runtime through `identity.xml.j2`. Do not edit the generated
> `repository/conf/identity/identity.xml` directly — it is regenerated from the template on every server start.

1. Enable the listener.

    ```toml
    [event.default_listener.breach_detection]
    enable = true
    priority = 420
    ```

2. Provide a blocklist file. Blank lines and lines beginning with `#` are ignored.

    ```bash
    printf 'Qwerty@123\nPassword@1\nSummer2023!\n' \
      > <IS_HOME>/repository/resources/security/breached-passwords.txt
    ```

3. Configure the local blocklist source.

    ```toml
    [breach_detection.sources.localList]
    enable = true
    path = "${carbon.home}/repository/resources/security/breached-passwords.txt"
    format = "plaintext"
    max_heap_entries = 1000000
    ```

4. Restart the server.

5. Confirm the blocklist loaded. `repository/logs/wso2carbon.log` reports the entry count at startup.

    ```
    Loaded the breach blocklist: entries=3, skipped=0, format=plaintext.
    Breach source bound: id=localList, priority=100. Bound sources are now [localList@100].
    Breached password detection started. Deployment switch: on, listener order: 420, ...
    ```

To disable the feature for every organization without removing software, set `enable = false` under
`[event.default_listener.breach_detection]`. Stored source configuration is retained.

## Configuration options

### Deployment options

Configured under `[breach_detection]`.

<table>
    <tr>
        <th>Parameter</th>
        <th>Description</th>
    </tr>
    <tr>
        <td>evaluation_timeout_ms</td>
        <td>[Optional] The time a single remote source is given to answer, in milliseconds. Offline sources are
        called inline and are not bounded by this. <br> <b>Default:</b> <code>1500</code></td>
    </tr>
    <tr>
        <td>worker_threads</td>
        <td>[Optional] The size of the thread pool used for remote source calls. <br> <b>Default:</b>
        <code>20</code></td>
    </tr>
    <tr>
        <td>exempt_bulk_operations</td>
        <td>[Optional] Skips evaluation for writes the server attributes to a bulk flow, such as a user import
        or a migration. Ordinary password changes are still evaluated. <br> <b>Default:</b>
        <code>false</code></td>
    </tr>
</table>

### Local blocklist options

Configured under `[breach_detection.sources.localList]`.

<table>
    <tr>
        <th>Parameter</th>
        <th>Description</th>
    </tr>
    <tr>
        <td>enable</td>
        <td>[Optional] Set to <code>false</code> to stop consulting a configured blocklist without removing its
        settings. The list is released from memory. <br> <b>Default:</b> <code>true</code></td>
    </tr>
    <tr>
        <td>path</td>
        <td><b>Required.</b> Absolute path to the blocklist file. <code>${carbon.home}</code> expands. The path
        must resolve inside the deployment directory or the configuration directory; a path outside them is
        refused and logged.</td>
    </tr>
    <tr>
        <td>format</td>
        <td><b>Required.</b> How the file is written: <code>sha1</code>, <code>sha256</code>, or
        <code>plaintext</code>. There is no default and no auto-detection — see
        <a href="#blocklist-file-formats">Blocklist file formats</a>.</td>
    </tr>
    <tr>
        <td>max_heap_entries</td>
        <td>[Optional] The maximum number of entries loaded into memory. Loading stops at this count and the
        server logs an error. <br> <b>Default:</b> <code>5000000</code></td>
    </tr>
</table>

Connector-based sources are configured under their own namespace, `[breach_detection.sources.<id>]`, using the
parameters the connector declares. A value written as `$secret{alias}` is resolved through the secure vault.

## Breach sources

The feature does not know about any particular breach corpus. It discovers sources at runtime and consults
them in the order of the priority each one declares.

<table>
    <tr>
        <th>Source</th>
        <th>Priority</th>
        <th>Behavior</th>
    </tr>
    <tr>
        <td>Local blocklist</td>
        <td>100</td>
        <td>Offline. Answers from memory, in microseconds, without a network call.</td>
    </tr>
    <tr>
        <td>Connector, for example Have I Been Pwned</td>
        <td>500</td>
        <td>Remote. Bounded by <code>evaluation_timeout_ms</code> on a worker thread.</td>
    </tr>
</table>

A match ends the evaluation, so passwords caught by the local blocklist never reach a remote source or consume
a third party's quota.

### The local blocklist

The one source that ships with the feature. It crosses no boundary, so it works in a network-isolated
deployment.

#### Blocklist file formats

`format` is required and is never inferred. The file determines the algorithm — a list of already-hashed
entries can only be compared using the algorithm it was hashed with — and an incorrect algorithm does not
produce an error, it simply stops matching. If `format` is absent or unrecognized, the source reports itself as
not configured.

<table>
    <tr>
        <th>Value</th>
        <th>The file contains</th>
        <th>Candidate passwords are compared using</th>
    </tr>
    <tr>
        <td><code>sha1</code></td>
        <td>40-character hexadecimal digests</td>
        <td>SHA-1</td>
    </tr>
    <tr>
        <td><code>sha256</code></td>
        <td>64-character hexadecimal digests</td>
        <td>SHA-256</td>
    </tr>
    <tr>
        <td><code>plaintext</code></td>
        <td>Passwords, one per line</td>
        <td>SHA-256, applied to file entries when they are loaded</td>
    </tr>
</table>

#### Blocklist file rules

- Blank lines and lines beginning with `#` are ignored and are not counted as malformed entries.
- A hashed entry may include an occurrence count after a colon, as `<digest>:<count>`. The count is ignored.
  This is the format of the Have I Been Pwned offline download.
- Passwords are case- and whitespace-significant. Entries are not trimmed or case-folded.
- Plaintext entries are hashed when the file is loaded, so the file remains the only place those passwords
  exist in readable form.
- Malformed entries are skipped and counted, and the count is reported in the startup log.

### Connector-based sources

Deploy a connector bundle to `<IS_HOME>/repository/components/dropins` and restart. The connector registers
itself; no configuration change is needed for the feature to discover it, and removing the bundle removes the
source.

Each connector owns its own enablement and publishes its own configuration surface, which is why a connector
appears in the Console when its bundle is installed and disappears when it is removed.

[Have I Been Pwned](https://github.com/wso2-extensions/identity-password-validator-hibp) is the reference
connector. It checks the corpus without the password leaving the deployment: only a 20-bit prefix of the
password's SHA-1 digest is sent, the service returns every digest sharing that prefix, and the comparison is
performed in the server.

## When a source cannot answer

A source that cannot reach its corpus, times out, exhausts a quota, or cannot parse a response reports the
password as **unavailable**, never as *not found*. Treating the two as equivalent is what allows a breach check
to stop enforcing while still reporting itself as enabled.

Each source decides what happens to a password it could not check, per organization.

<table>
    <tr>
        <th>Failure action</th>
        <th>Result</th>
    </tr>
    <tr>
        <td>Allow</td>
        <td>The password is accepted and the gap is recorded in the logs. This is the default.</td>
    </tr>
    <tr>
        <td>Deny</td>
        <td>The password is refused with <code>BRD-60002</code>, which is distinguishable from a breach
        refusal.</td>
    </tr>
</table>

> [!NOTE]
> For a remote source, an outage belongs to the third party. Setting it to deny lets that outage stop every
> password change in your deployment. Keeping a local blocklist configured gives you enforcement that continues
> during such an outage. See [Limitations](#limitations) for the local blocklist's current behavior.

## Deployment recommendations

### Start with the local blocklist

The local blocklist requires no network access, no third-party account, and no credentials. A list of a few
thousand entries — a corporate denylist together with a public list of the most reused passwords — provides
meaningful coverage with no runtime dependency.

### Size the local blocklist deliberately

The blocklist is held entirely in memory, and `max_heap_entries` limits the entry count rather than the memory
used. Measured cost per entry:

<table>
    <tr>
        <th>format</th>
        <th>Per entry</th>
        <th>100,000 entries</th>
        <th>1,000,000 entries</th>
        <th>5,000,000 entries (default limit)</th>
    </tr>
    <tr>
        <td><code>sha1</code></td>
        <td>122.5 bytes</td>
        <td>12 MB</td>
        <td>117 MB</td>
        <td>584 MB</td>
    </tr>
    <tr>
        <td><code>sha256</code></td>
        <td>146.5 bytes</td>
        <td>14 MB</td>
        <td>140 MB</td>
        <td>699 MB</td>
    </tr>
</table>

The default limit permits 584–699 MB, which is a significant share of a typical heap. Set `max_heap_entries` to
a value you intend; `1000000` is a reasonable ceiling.

> [!TIP]
> A list that is long enough to approach the limit is a signal to use a connector rather than to raise the
> limit. Password reuse follows a power law, so a list an order of magnitude shorter than the limit carries
> nearly all of the protective value. A full breach corpus belongs behind a connector that answers from its own
> storage.

### Deploy the blocklist file to every node

The path is local to each node. In a clustered deployment, every node loads its own copy into its own heap, so
the memory cost applies per node rather than per deployment. Distribute the file with your node image or
configuration management; the feature performs no replication.

### Plan blocklist updates as a restart

A changed blocklist file takes effect when the server restarts. The feature does not watch or poll the file,
which is consistent with other file-backed configuration in the product. Plan updates as a rolling restart.

Connector bundles are the exception: adding one to `dropins` binds it without a restart, because that is a
service event rather than a file change.

### Exempt bulk operations during migration

A migration that imports a large number of users should not perform a check per row.

```toml
[breach_detection]
exempt_bulk_operations = true
```

### Configure a remote source's API key with care

Where a connector's API key is optional, review whether providing one is appropriate. For the Have I Been Pwned
range endpoint, no key is required, and supplying one associates your lookups with an identity without
improving the result.

## Monitor enforcement

Alert on the following error, which indicates that the feature is enabled but no source can return a verdict.
This is the state in which the deployment appears healthy and no password is being checked.

```
ERROR ... Breached password detection is not enforcing for tenant '<tenant>':
          no enabled source could return a verdict.
```

The corresponding warning indicates partial coverage — some sources answered and some did not.

```
WARN  ... Breached password detection is degraded for tenant '<tenant>':
          1 of 2 sources could not answer.
```

At startup, confirm that the reported entry count matches the file you supplied. An entry count of `0` together
with a large skipped count indicates that the configured `format` does not match the file.

## Troubleshooting

**A password that is present in the blocklist is accepted.**

1. Check the startup log for `Loaded the breach blocklist: entries=N`. If `N` is `0`, or the skipped count is
   large, the configured `format` does not match the file.
2. Confirm the password was not refused earlier by password input validation, which runs at order 3.
3. For a hashed file, confirm the digest is the correct length and valid hexadecimal. Digests are compared
   case-insensitively.
4. Confirm the source is enabled. `Breach source bound: id=localList` must appear in the startup log, and
   `enable` must not be set to `false`.

**The bundles appear to be ignored.**

Files in `dropins` must be named `<symbolic-name>_<version>.jar`, with an underscore before the version and no
`-SNAPSHOT` suffix. After correcting the name, delete
`repository/components/default/configuration/org.eclipse.osgi` and restart.

**Configuration in `deployment.toml` has no effect.**

Confirm that the generated `repository/conf/identity/identity.xml` contains a `<BreachDetection>` element. If it
does not, `identity.xml.j2` does not yet render these keys.

**A configured source is never consulted.**

Look for `Breach detection configuration names sources that are not installed` in the startup log. This
usually indicates that a connector bundle is missing.

## Limitations

<table>
    <tr>
        <th>Limitation</th>
        <th>Effect</th>
    </tr>
    <tr>
        <td>A local blocklist that fails to load is not consulted</td>
        <td>The source reports itself as not enabled and is excluded from evaluation, so the failure results in
        the password being <b>allowed</b> rather than refused, and the feature reports itself as off. If the
        local blocklist is your only source, a file that fails to load means no enforcement.</td>
    </tr>
    <tr>
        <td>A <code>format</code> that does not match the file is not detected</td>
        <td>Every entry is rejected, the file loads with no entries, and every password is reported as not
        found. The entry and skipped counts in the startup log identify this; the reported state does not.</td>
    </tr>
    <tr>
        <td><code>max_heap_entries</code> limits count, not memory</td>
        <td>Available heap is not consulted. Changing <code>format</code> from <code>sha1</code> to
        <code>sha256</code> increases the memory used by the same number of entries by approximately 20%.</td>
    </tr>
</table>

## Implement a breach source

Implement `BreachSource` and register it as an OSGi service from your bundle activator.

```java
bundleContext.registerService(BreachSource.class, new MyBreachSource(), null);
```

Every method on the interface is abstract. Enablement, failure behaviour and configuration must each be
stated by the source rather than inherited from a default.

<table>
    <tr>
        <th>Method</th>
        <th>Contract</th>
    </tr>
    <tr>
        <td><code>getId()</code></td>
        <td>A stable id, lowercase and without spaces. Deployment configuration is namespaced on it.</td>
    </tr>
    <tr>
        <td><code>getPropertyNames()</code></td>
        <td>The deployment setting names this source reads. A configured key that is not listed is reported as
        unrecognised at startup, so a typo does not silently leave the source on its defaults.</td>
    </tr>
    <tr>
        <td><code>getPriority()</code></td>
        <td>A cost hint. The server calls sources in ascending order and stops at the first
        <code>FOUND</code>.</td>
    </tr>
    <tr>
        <td><code>configure(SourceConfiguration)</code></td>
        <td>Receive the resolved deployment settings. Called when the source binds and again on
        reconfiguration.</td>
    </tr>
    <tr>
        <td><code>isEnabled(tenantDomain)</code></td>
        <td>Whether the organization wants this source consulted, and whether it is configured well enough to
        answer. A source that is not usable returns <code>false</code> here.</td>
    </tr>
    <tr>
        <td><code>refusesWhenUnavailable(tenantDomain)</code></td>
        <td>Whether a password this source could not check is refused or allowed.</td>
    </tr>
    <tr>
        <td><code>evaluate(credential, tenantDomain)</code></td>
        <td><code>FOUND</code>, <code>NOT_FOUND</code>, or <code>UNAVAILABLE</code>.</td>
    </tr>
</table>

### Reading configuration

Settings reach the source through `configure(SourceConfiguration)`. The source reads no configuration file
and resolves no secret alias itself. Each accessor takes the fallback the source wants, so a default is
written once, where it is used.

```java
this.baseUrl = configuration.getString("base_url").orElse(DEFAULT_BASE_URL);
this.readTimeoutMs = configuration.getInt("read_timeout_ms", 1500);
```

Any property value may be a secure vault reference, written either as `$secret{alias}` or as a
`secretAlias` attribute on the property element. The configuration layer resolves it before `configure` is
called, so the source always receives plain text.

`getPath(name)` resolves a filesystem path and confines it to the deployment and configuration directories. A
path outside them resolves to empty and is logged.

### Rules a source must observe

<table>
    <tr>
        <th>Rule</th>
        <th>Reason</th>
    </tr>
    <tr>
        <td>Return <code>UNAVAILABLE</code> for any result that is not a positive determination, and log why.
        Never return <code>NOT_FOUND</code> because a call failed.</td>
        <td>Reporting a failed check as a clean password is what allows enforcement to stop silently.</td>
    </tr>
    <tr>
        <td>Never log, cache, or transmit the credential, and do not retain it after the call returns. Use
        <code>digestHex(algorithm)</code> rather than reading the characters.</td>
        <td>The candidate is supplied as a <code>char[]</code> that the server clears after evaluation.</td>
    </tr>
    <tr>
        <td>Do not assume <code>evaluate</code> runs on the caller's thread, and do not block without a
        timeout of your own.</td>
        <td>Every source is called on a worker thread and bounded by <code>evaluation_timeout_ms</code>. A
        source that exceeds it is abandoned and treated as <code>UNAVAILABLE</code>.</td>
    </tr>
</table>
