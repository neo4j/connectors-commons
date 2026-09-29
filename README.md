# Connectors Commons

This repository contains the source code for the connectors commons project, which provides a set of reusable modules to
be reused across different connectors.

## Modules

| Module                         | Baseline | Purpose                                                                                                  |
|--------------------------------|----------|----------------------------------------------------------------------------------------------------------|
| `commons-authn-spi`            | Java 8   | Driver-agnostic authentication token and token supplier interfaces.                                      |
| `commons-authn-provided`       | Java 8   | Token suppliers provided by Neo4j: `basic`, `bearer`, `kerberos`, `custom`, `none`.                      |
| `commons-authn-keycloak`       | Java 8   | Keycloak OIDC token supplier.                                                                            |
| `commons-driver-auth-spi`      | Java 17  | Looks up `org.neo4j.driver.AuthTokenManager` implementations by name, for the Neo4j Java Driver **6.x**. |
| `commons-driver-auth-provided` | Java 17  | Token managers provided by Neo4j: `basic`, `bearer`, `kerberos`, `custom`, `none`.                       |
| `commons-driver-auth-oidc`     | Java 17  | One `oidc` token manager for any OAuth 2.0 / OpenID Connect provider, driven by configuration.           |
| `commons-reauth-driver`        | Java 8   | Wrapper driver that rebuilds the `Driver` on token expiry, for the Neo4j Java Driver **4.4**.            |

The `commons-authn-*` modules are bound to no driver version. The two driver-bound modules target different driver
majors, which can never share a classpath. They use the same packages under the same coordinates. Driver 5.x is not
targeted explicitly, as main target connects don't have a version using 5.x . However, `commons-driver-auth-*` modules 
should be compatible with 5.x in theory. 

### Which driver-bound module to use

Use `commons-driver-auth-spi` on driver 6.x. It produces native `AuthTokenManager` instances, so the driver refreshes
expired tokens over Bolt 5.1 `LOGOFF`/`LOGON` without dropping connections:

```java
AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();
AuthTokenManager manager = registry.create("basic", AuthConfig.of(username, password, parameters));
Driver driver = GraphDatabase.driver(uri, manager);
```

Names are resolved in two tiers: native `AuthTokenManagerFactory` services first, then legacy
`AuthenticationTokenSupplierFactory` services, wrapped on the fly. Every existing supplier keeps working through that
bridge, so all of `basic`, `bearer`, `kerberos`, `custom`, `none` and the Keycloak supplier resolve without change.

Add `commons-driver-auth-provided` to get `basic`, `bearer`, `kerberos`, `custom` and `none` as native factories
instead. They produce the same tokens as their `commons-authn-provided` counterparts, but skip the bridge: each one is
a static token, so the driver only re-reads it after an `AuthenticationException`, and never treats a
`TokenExpiredException` as retryable. Being native, they win over the legacy suppliers of the same name whenever both
modules are on the classpath. Mandatory parameters are reported as an `IllegalArgumentException` naming the missing
key, at the point the manager is created.

Use `commons-reauth-driver` **only** on driver 4.4 with a Java 8 baseline. It exists because 4.4 cannot re-authenticate
an open connection, so the whole `Driver` has to be rebuilt when a token expires. Driver 6.x does this natively, which
makes the module redundant there. Reach for `commons-driver-auth-spi` instead.

## OIDC token manager

`commons-driver-auth-oidc` registers a single token manager under the name **`oidc`** that obtains
and refreshes bearer tokens from any OAuth 2.0 / OpenID Connect provider. See detailed documentation [here](driver-auth/oidc/README.md). 