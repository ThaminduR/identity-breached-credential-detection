# identity-breached-credential-detection

Breached credential detection for WSO2 Identity Server, with a pluggable breach source SPI.

Password composition rules — length, character classes, repeated characters — say nothing about whether a
password has already been published. A password can satisfy every rule in your policy and still appear in a
breach corpus millions of times, which is what makes credential stuffing effective.

Breached credential detection refuses those passwords at the point they are set, on every path that sets one.
It checks against pluggable **breach sources**: a blocklist file that ships with the feature, and any number of
connectors that answer from a hosted or local corpus.

## Requirements

| | |
|---|---|
| WSO2 Identity Server | 7.3.0 or later |
| JDK | 11 or later |
| Maven | 3.6 or later |

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

Neither message includes an occurrence count. See
[Error codes and localization](#error-codes-and-localization) for how far these codes travel today.

## Build

Optional — skip this if you already have the JARs.

```bash
mvn clean install
```

Produces one bundle:

```
components/org.wso2.carbon.identity.breach.detection/target/org.wso2.carbon.identity.breach.detection-<version>.jar
```

It contains the enforcement point, the engine, the local blocklist source, and the `BreachSource` contract
that connectors implement. Three packages are exported: `...breach.detection.spi` for the contract,
`...breach.detection.model` for the `Credential` and `Decision` types it uses, and
`...breach.detection.constants` for the error codes. Everything else is private to the bundle.

## Deploy

### 1. Copy the bundle

Carbon expects the filename `<symbolic-name>_<osgi-version>.jar`, with an underscore before the version and
no `-SNAPSHOT` suffix:

```bash
IS_HOME=/path/to/wso2is-7.3.0

cp components/org.wso2.carbon.identity.breach.detection/target/org.wso2.carbon.identity.breach.detection-1.0.0-SNAPSHOT.jar \
   "$IS_HOME/repository/components/dropins/org.wso2.carbon.identity.breach.detection_1.0.0.SNAPSHOT.jar"
```

Carbon skips a JAR it cannot parse a version out of, and it does so without logging anything. A wrong
filename is the most common reason the bundle appears to be ignored.

### 2. Supply a blocklist file

Any file of passwords or digests, one per line. Blank lines and lines starting `#` are ignored.

```bash
printf 'Qwerty@123\nPassword@1\nSummer2023!\n' \
  > "$IS_HOME/repository/resources/security/breached-passwords.txt"
```

See [The local blocklist](#the-local-blocklist) for the hashed formats and for how long the file should be.

### 3. Configure

Everything lives in one `[[event_listener]]` block in `repository/conf/deployment.toml`: the listener
declaration and the settings of every source.

```toml
# The whole capability is declared in one block. `enable = false` is the
# deployment kill switch: it disables the capability for every tenant without
# removing software.
[[event_listener]]
id = "breach_detection"
type = "org.wso2.carbon.user.core.listener.UserOperationEventListener"
name = "org.wso2.carbon.identity.breach.detection.listener.BreachDetectionListener"
order = 420
enable = true
properties."sources.localList.enable" = true
properties."sources.localList.path" = "${carbon.home}/repository/resources/security/breached-passwords.txt"
properties."sources.localList.format" = "plaintext"
```

No product file has to be modified. The stock `identity.xml.j2` already renders the properties of any
custom listener, so a pack needs nothing but this block. Never edit the generated
`repository/conf/identity/identity.xml` directly; it is regenerated from the template on every start.

> **Quote the keys.** A per-source key must be written as `properties."sources.<id>.<property>"`. Unquoted,
> as `properties.sources.localList.enable`, the config parser renders it as one property holding a map and
> the source never receives it. The server logs a warning naming the key it ignored.

### 4. Restart

```bash
rm -rf "$IS_HOME/repository/components/default/configuration/org.eclipse.osgi"   # force a bundle re-scan
sh "$IS_HOME/bin/wso2server.sh" restart
```

Clearing the OSGi cache matters when replacing a bundle you have deployed before — otherwise the old one is
resolved from the cache and nothing appears to change.

### 5. Confirm it loaded

`repository/logs/wso2carbon.log` should carry three lines:

```
Loaded the breach blocklist: entries=3, skipped=0, format=plaintext.
Breach source bound: id=localList, priority=100. Bound sources are now [localList@100].
Breached password detection started. Deployment switch: on, listener order: 420.
```

Then check it actually refuses:

```bash
curl -sk -u admin:admin -X POST https://localhost:9443/scim2/Users \
  -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"t1","password":"Qwerty@123"}'
```

Expect **HTTP 400**, with the refusal in `detail`:

> Error in adding the user: t\*. This password has appeared in a known data breach. Choose a longer, unique
> password.

The `BRD-60001` code itself does not reach the client on this path — SCIM reports `scimType: invalidValue`
and passes the message through. See [Error codes and localization](#error-codes-and-localization).

A unique password should return **HTTP 201**. If a listed password is accepted, work through
[Troubleshooting](#troubleshooting).

To disable the feature for every organization without removing software, set `enable = false` on the
`[[event_listener]]` block. Stored source configuration is retained. Removing the block entirely also
disables the feature, which is the state of a pack that was never configured.

## Configuration options

### Local blocklist options

Configured with keys named `properties."sources.localList.<property>"`.

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
        <td>[Optional] The maximum number of digests held in memory. Loading stops at this count and the
        server logs an error, so the remainder of the file is not enforced. <br> <b>Default:</b>
        <code>1000000</code></td>
    </tr>
</table>

Connector-based sources are configured under their own id, `properties."sources.<id>.<property>"`, using the
parameters the connector declares. A value written as `$secret{alias}` is resolved through the secure vault
before the source sees it.

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
        <td>Remote. The connector applies its own read and connect timeouts, retries and circuit
        breaker.</td>
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
- Passwords are case-significant. Entries are not trimmed or case-folded.
- The SCIM 2.0 APIs strip leading and trailing whitespace from a password before it reaches the check, so on
  those paths an entry cannot be distinguished from the same entry with surrounding whitespace. Internal
  whitespace is significant.
- Plaintext entries are hashed when the file is loaded, so the file remains the only place those passwords
  exist in readable form.
- Malformed entries are skipped and counted, and the count is reported in the startup log.

### Connector-based sources

Deploy a connector bundle to `<IS_HOME>/repository/components/dropins` and restart. The connector registers
itself; no configuration change is needed for the feature to discover it, and removing the bundle removes the
source.

Each connector owns its own enablement and publishes its own configuration surface, which is why a connector
appears in the Console when its bundle is installed and disappears when it is removed.

A connector compiles against this bundle and imports `org.wso2.carbon.identity.breach.detection.spi` and
`...breach.detection.model` at `[1.0.0, 2.0.0)`. Those packages carry the contract's own version, not the
repository's release number, so a release that does not change the contract does not invalidate a connector
built against it.

[Have I Been Pwned](https://github.com/wso2-extensions/identity-password-validator-hibp) is the reference
connector. It checks the corpus without the password leaving the deployment: only a 20-bit prefix of the
password's SHA-1 digest is sent, the service returns every digest sharing that prefix, and the comparison is
performed in the server.

To write your own, see [Implement a breach source](#implement-a-breach-source).

## When a source cannot answer

A source that cannot reach its corpus, times out, exhausts a quota, or cannot parse a response logs the
reason and applies the failure policy configured for it. It never reports the password as checked and clean
without a record, because that would let a breach check stop enforcing while still reporting itself as
enabled.

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
        <th>1,000,000 entries (default limit)</th>
        <th>5,000,000 entries</th>
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

The default limit permits 117–140 MB, against the 1 GB maximum heap the pack ships with. Raise it only
together with the heap: the limit caps the entry count, not the bytes, and nothing checks the memory actually
available.

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

### Bulk imports

A write the server marks as a bulk import is not evaluated. The passwords in an import are being migrated
rather than chosen, so the user cannot act on a refusal, and a large import would otherwise perform one check
per row. There is no setting for this.

> [!WARNING]
> This depends on the server setting the `BULK_RESOURCE_UPDATE` flow on the identity context. In 7.3.0 the
> SCIM 2.0 bulk endpoint does not set a flow, so an import through `/scim2/Bulk` **is** evaluated and a
> breached password in it is refused. Plan an import accordingly, or switch the feature off for the import
> window with `enable = false` on the `[[event_listener]]` block.

### Configure a remote source's API key with care

Where a connector's API key is optional, review whether providing one is appropriate. For the Have I Been Pwned
range endpoint, no key is required, and supplying one associates your lookups with an identity without
improving the result.

## Monitor enforcement

The startup log is what tells you the feature is enforcing. Confirm all three lines appear, and that the
reported entry count matches the file you supplied. An entry count of `0` together with a large skipped count
indicates that the configured `format` does not match the file.

```
Loaded the breach blocklist: entries=3, skipped=0, format=plaintext.
Breach source bound: id=localList, priority=100. Bound sources are now [localList@100].
Breached password detection started. Deployment switch: on, listener order: 420.
```

Alert on the following, each of which means a source stopped contributing while the feature still reports
itself as started.

<table>
    <tr>
        <th>Log line</th>
        <th>Meaning</th>
    </tr>
    <tr>
        <td><code>Breach source '&lt;id&gt;' failed while checking a password.</code></td>
        <td>The source threw. The password was treated as accepted and the remaining sources still ran.</td>
    </tr>
    <tr>
        <td><code>Breach source '&lt;id&gt;' failed to report whether it is enabled.</code></td>
        <td>The source was skipped entirely for that write.</td>
    </tr>
    <tr>
        <td><code>The breach blocklist at &lt;path&gt; exceeds the maximum of &lt;n&gt; entries</code></td>
        <td>The remainder of the file is not being enforced. Raise <code>max_heap_entries</code> together with
        the heap, or shorten the file.</td>
    </tr>
    <tr>
        <td><code>Breached password detection failed unexpectedly.</code></td>
        <td>The engine itself failed. The credential write was refused, so this surfaces to users as a failed
        password change.</td>
    </tr>
</table>

## Troubleshooting

**A password that is present in the blocklist is accepted.**

1. Check the startup log for `Loaded the breach blocklist: entries=N`. If `N` is `0`, or the skipped count is
   large, the configured `format` does not match the file.
2. Confirm the password was not refused earlier by password input validation, which runs at order 3.
3. For a hashed file, confirm the digest is the correct length and valid hexadecimal. Digests are compared
   case-insensitively.
4. Confirm the source is enabled. `Breach source bound: id=localList` must appear in the startup log, and
   `enable` must not be set to `false`.

**The bundle appears to be ignored.**

Files in `dropins` must be named `<symbolic-name>_<version>.jar`, with an underscore before the version and no
`-SNAPSHOT` suffix. After correcting the name, delete
`repository/components/default/configuration/org.eclipse.osgi` and restart.

**Configuration in `deployment.toml` has no effect.**

Look for `Ignoring the breach detection listener property` in the startup log. A per-source key written
unquoted is rendered as one property holding a map, and the source never receives it. Write it as
`properties."sources.<id>.<property>"`.

If no such warning appears, confirm that the generated `repository/conf/identity/identity.xml` contains an
`EventListener` element with `id="breach_detection"` carrying a `Property` child per setting.

**A configured source is never consulted.**

No `Breach source bound: id=<id>` line means the bundle providing that source is not installed or did not
resolve. For the local blocklist, check instead for `The local breach blocklist needs both a path and a
format` and `The breach blocklist file is not readable`, either of which leaves the source reporting itself
as not enabled.

## Error codes and localization

A refusal carries a code and an English message.

<table>
    <tr>
        <th>Code</th>
        <th>Meaning</th>
    </tr>
    <tr>
        <td><code>BRD-60001</code></td>
        <td>The password was found in a breach source.</td>
    </tr>
    <tr>
        <td><code>BRD-60002</code></td>
        <td>A source could not check the password and is configured to refuse.</td>
    </tr>
</table>

There is no server-side resource bundle. A backend listener runs on a thread that carries no user locale, so
a message resolved there would use the server's locale for every user. Localization belongs in the client,
which is how the shipped connectors are written.

> [!WARNING]
> The codes above do not currently reach a client. Each API reports a policy failure with its own generic
> code and passes the message through as the description, measured on 7.3.0:
>
> | Flow | Code returned |
> |---|---|
> | `POST /scim2/Users`, `PATCH /scim2/Users/{id}` | `invalidValue`, no code |
> | `POST /api/identity/user/v1.0/me` (self-registration) | `20035` Password Policy Violate |
> | `POST /api/identity/recovery/v0.9/set-password` | `20035` Password Policy Violate |
> | `POST /api/users/v1/me/change-password` | `PWD-10005` Password update failed |
>
> A breach refusal is therefore indistinguishable by code from a length or history failure, and a client
> that wants to localize has only the English text to match on.
>
> Fixing this means propagating the original error code from `UserStoreClientException` through
> `identity-recovery` and `scim2.common`. That benefits every password policy connector, not only this one,
> and is not a change this connector can make.

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

The contract is five methods. A source owns everything about how it reaches its data, including its
timeouts, its retries, and what happens to a password it could not check.

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
        <td><code>getPriority()</code></td>
        <td>The call order hint. The server calls sources in ascending order and stops at the first
        refusal.</td>
    </tr>
    <tr>
        <td><code>configure(SourceConfiguration)</code></td>
        <td>Receive the resolved deployment settings. Called when the source binds and again on
        reconfiguration.</td>
    </tr>
    <tr>
        <td><code>isEnabled(tenantDomain)</code></td>
        <td>Whether the organization wants this source consulted, and whether it is configured well enough to
        answer. A source that cannot answer returns <code>false</code>.</td>
    </tr>
    <tr>
        <td><code>check(credential, tenantDomain)</code></td>
        <td>Returns <code>REFUSE_BREACHED</code>, <code>REFUSE_UNVERIFIED</code>, or
        <code>ACCEPT</code>.</td>
    </tr>
</table>

### Deciding the result

`check` returns a `Decision`, which is the same type the server acts on. There is no separate step where the
server interprets a source's failure.

<table>
    <tr>
        <th>Situation</th>
        <th>Return</th>
    </tr>
    <tr>
        <td>The password is in this source's data</td>
        <td><code>REFUSE_BREACHED</code></td>
    </tr>
    <tr>
        <td>The password is not in this source's data</td>
        <td><code>ACCEPT</code></td>
    </tr>
    <tr>
        <td>The source could not reach its data, and the organization configured it to refuse</td>
        <td><code>REFUSE_UNVERIFIED</code></td>
    </tr>
    <tr>
        <td>The source could not reach its data, and the organization configured it to allow</td>
        <td><code>ACCEPT</code>, with the reason logged</td>
    </tr>
</table>

The server calls the first source, and returns as soon as one returns something other than `ACCEPT`. A source
that throws is logged and treated as `ACCEPT`, and the remaining sources still run.

### Reading configuration

Settings reach the source through `configure(SourceConfiguration)`. The source reads no configuration file
and resolves no secret alias. Each accessor takes the fallback value to use when the setting is absent.

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
        <td>Apply your own timeout to every outbound call.</td>
        <td>The server calls <code>check</code> on the thread performing the password write and does not
        bound it. A source that blocks indefinitely blocks the write.</td>
    </tr>
    <tr>
        <td>Never return <code>ACCEPT</code> to mean "I could not check" without logging the reason.</td>
        <td>An unlogged failure leaves no record that the password went unchecked.</td>
    </tr>
    <tr>
        <td>Never log, cache, or transmit the credential, and do not retain it after the call returns. Use
        <code>digestHex(algorithm)</code> rather than reading the characters.</td>
        <td>The candidate is supplied as a <code>char[]</code> that the server clears after the last source
        returns.</td>
    </tr>
</table>

## Uninstall

```bash
rm "$IS_HOME"/repository/components/dropins/org.wso2.carbon.identity.breach.detection*.jar
rm -rf "$IS_HOME/repository/components/default/configuration/org.eclipse.osgi"
```

Remove the `[[event_listener]]` block with `id = "breach_detection"` from `deployment.toml`, then restart.
To switch enforcement off without removing anything, set `enable = false` on that block.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
