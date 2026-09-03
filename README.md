# identity-breached-credential-detection

Breached credential detection for WSO2 Identity Server, with a pluggable breach source SPI.

Refuses passwords that already circulate in credential breaches, on every path that sets a password.

For what it does, how it behaves, and how to size it — see **[DOC.md](DOC.md)**. This file covers building and
deploying it.

## Requirements

| | |
|---|---|
| WSO2 Identity Server | 7.3.0 or later |
| JDK | 11 or later |
| Maven | 3.6 or later |

## Build

Optional — skip this if you already have the JARs.

```bash
mvn clean install
```

Produces two bundles under `components/*/target/`:

| Artifact | |
|---|---|
| `org.wso2.carbon.identity.breach.detection.api-<version>.jar` | The `BreachSource` SPI. Connectors compile against this. |
| `org.wso2.carbon.identity.breach.detection-<version>.jar` | The enforcement point, the engine, and the local blocklist source. |

Both are needed. The SPI bundle is separate so a connector can depend on it without dragging in the core.

## Deploy

### 1. Copy the bundles

Carbon expects `<symbolic-name>_<osgi-version>.jar` — an underscore before the version, and no `-SNAPSHOT`
suffix:

```bash
IS_HOME=/path/to/wso2is-7.3.0

cp components/org.wso2.carbon.identity.breach.detection.api/target/*-1.0.0-SNAPSHOT.jar \
   "$IS_HOME/repository/components/dropins/org.wso2.carbon.identity.breach.detection.api_1.0.0.SNAPSHOT.jar"

cp components/org.wso2.carbon.identity.breach.detection/target/org.wso2.carbon.identity.breach.detection-1.0.0-SNAPSHOT.jar \
   "$IS_HOME/repository/components/dropins/org.wso2.carbon.identity.breach.detection_1.0.0.SNAPSHOT.jar"
```

Getting the filename wrong is the single most common reason the bundles appear to be ignored — Carbon skips a
JAR it cannot parse a version out of, silently.

### 2. Supply a blocklist file

Any file of passwords or digests, one per line. Blank lines and lines starting `#` are ignored.

```bash
printf 'Qwerty@123\nPassword@1\nSummer2023!\n' \
  > "$IS_HOME/repository/resources/security/breached-passwords.txt"
```

See [DOC.md](DOC.md#the-local-blocklist) for the hashed formats and for how long the file should be.

### 3. Configure

Add to `repository/conf/deployment.toml`:

```toml
# The deployment kill switch. Off disables the capability for every tenant
# without removing software.
[event.default_listener.breach_detection]
enable = true
priority = 420

[breach_detection.sources.localList]
enable = true
path = "${carbon.home}/repository/resources/security/breached-passwords.txt"
format = "plaintext"
```

> **Prerequisite.** These keys only reach the runtime once `identity.xml.j2` renders them — the listener
> declaration and the `<BreachDetection>` element. That template change ships with the product; until it
> lands, add the equivalent block to `repository/resources/conf/templates/repository/conf/identity/identity.xml.j2`
> by hand. Never edit the generated `identity.xml` directly; it is regenerated from the template on every
> start.

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
Breached password detection started. Deployment switch: on, listener order: 420, ...
```

Then check it actually refuses:

```bash
curl -sk -u admin:admin -X POST https://localhost:9443/scim2/Users \
  -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"t1","password":"Qwerty@123"}'
```

Expect **HTTP 400** and `BRD-60001`:

> This password has appeared in a known data breach. Choose a longer, unique password.

A unique password should return **HTTP 201**. If a listed password is accepted, work through
[DOC.md → Troubleshooting](DOC.md#troubleshooting).

## Adding a breach source connector

Drop the connector's bundle into `dropins` and restart. It registers itself; the core needs no configuration
edit to discover it, and removing the JAR unbinds it and changes nothing else.

[identity-password-validator-hibp](https://github.com/wso2-extensions/identity-password-validator-hibp) is the
reference connector — Have I Been Pwned, checked without the password leaving the deployment.

To write your own, see [DOC.md → Implement a breach source](DOC.md#implement-a-breach-source).

## Uninstall

```bash
rm "$IS_HOME"/repository/components/dropins/org.wso2.carbon.identity.breach.detection*.jar
rm -rf "$IS_HOME/repository/components/default/configuration/org.eclipse.osgi"
```

Remove the `[breach_detection.*]` and `[event.default_listener.breach_detection]` blocks from
`deployment.toml`, then restart. To switch enforcement off without removing anything, set
`enable = false` under `[event.default_listener.breach_detection]`.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
