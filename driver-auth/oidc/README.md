## OIDC token manager

`commons-driver-auth-oidc` registers a single token manager under the name **`oidc`** that obtains
and refreshes bearer tokens from any OAuth 2.0 / OpenID Connect provider. All required details are provided via settings.

```java
AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();
AuthTokenManager manager = registry.create("oidc", AuthConfig.of(null, null, Map.of(
        "issuer", "https://keycloak.example.com/realms/neo4j",
        "clientId", "neo4j-client",
        "clientSecret", secret,
        "scope", "openid")));
Driver driver = GraphDatabase.driver(uri, manager);
```

Refreshing is the driver's job. `AuthTokenManagers.bearerAsync` re-invokes the token source once the
token has expired and when the server answers with `TokenExpiredException` or
`AuthenticationException`, and de-duplicates concurrent refreshes, so this module runs no timer and
no background thread. A rejection is passed back to the token source as well, so a token that the
server refuses before its expiry, because it was revoked or because the clocks disagree, is dropped
rather than handed out again.

The OAuth 2.0 protocol itself - grants, client authentication, discovery, signed assertions and
RFC 6749 error bodies - is handled by [`com.nimbusds:oauth2-oidc-sdk`](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk).
Transport is not: requests are shipped with the JDK's asynchronous `HttpClient`, because the
driver's `bearerAsync` wants a `CompletionStage` and the SDK's own `send()` is blocking. What is
left to this module is the settings vocabulary, the caching and retry layers, and the driver
integration.

Creating the manager performs no I/O: discovery, the secret file and the key file are all resolved
on the first token fetch, and a misconfiguration is an `IllegalArgumentException` naming the
offending key at creation time.

### Settings

The credentials for the `password` grant come from `AuthConfig.username()` / `AuthConfig.password()`, not from the parameter map.

#### Where to get tokens 
One of the three is required.

| Setting | Meaning | Default |
|---------|---------|---------|
| `issuer` | Base URL. Discovery at `{issuer}/.well-known/openid-configuration`. | - |
| `discoveryUrl` | The discovery URL, given directly. The document is read as RFC 8414 metadata, so it must carry `issuer` and `token_endpoint`. | derived from `issuer` |
| `expectedIssuer` | The issuer the discovery document must advertise. Set it only when the provider is reached at one address and advertises another. | `issuer` |
| `tokenEndpoint` | The token URL, given directly. Skips discovery. | from discovery |

When `issuer` is configured, the discovery document must advertise that same issuer or it is
refused, as OpenID Connect Discovery requires: otherwise a substituted document could name any
`token_endpoint`, and this client would post its credentials to it. A provider behind a reverse
proxy, or a Keycloak whose frontend hostname differs from the address it is reached at,
legitimately advertises a different value; name that value in `expectedIssuer`. It is the value the
tokens carry in `iss`, so it should match `dbms.security.oidc.<name>.issuer`.

Redirects are never followed. A `307` or `308` from a token endpoint would replay the request body,
which carries the client secret, the end user's password or a signed assertion, to whatever host
`Location` names.

#### How to ask

| Setting | Meaning | Default |
|---------|---------|---------|
| `grantType` | `client_credentials`, `password`, `refresh_token`, `jwt_bearer`, `token_exchange` | `client_credentials` |
| `scope` | Space-separated scopes. | - |
| `audience` | `audience` form field. | - |
| `resource` | `resource` form field. | - |
| `extraParam.<name>` | Any additional form field, sent as-is. Applied last, so it overrides anything else. | - |
| `refreshToken` | The initial refresh token, for `grantType=refresh_token`. Rolled forward as the provider rotates it. | - |
| `subjectTokenFile` | File holding the subject token, for `token_exchange`. Re-read on every fetch. | - |
| `subjectTokenType` | The `subject_token_type` to declare. | `urn:ietf:params:oauth:token-type:jwt` |

#### How to prove who we are

| Setting | Meaning | Default |
|---------|---------|---------|
| `clientId` | Client identifier. Required unless `clientAuthMethod` is `none`. | - |
| `clientSecret` | Client secret. | - |
| `clientSecretFile` | File holding the secret, instead of `clientSecret`. Re-read on every fetch, so a rotated mount is picked up. | - |
| `clientAuthMethod` | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none`. Cannot be `none` when `grantType` is `client_credentials`, which is itself a client credential (RFC 6749 section 4.4.2). | `client_secret_basic` |
| `privateKeyFile` | PKCS#8 key, PEM or DER, for `private_key_jwt` and `jwt_bearer`. | - |
| `privateKeyId` | `kid` header of the signed JWT. | - |
| `privateKeyAlgorithm` | `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`. | `RS256` |
| `assertion.claim.<name>` | A claim in the signed JWT. `iss`, `sub`, `aud`, `iat`, `exp` and `jti` are filled in per RFC 7523 unless set here. Values that read as an integer or a boolean are emitted as such. | - |
| `assertionTtlSeconds` | How long a signed assertion is valid for. | `300` |

Only PKCS#8 keys are read. Convert a legacy `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` file
with `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem`; the error message says so too.

With `private_key_jwt` no separate `client_id` form field is sent: per RFC 7523 section 2.2 the
assertion's `iss` and `sub` already name the client, and both Okta and Entra ID accept that.

#### Reading the reply

| Setting | Meaning | Default |
|---------|---------|---------|
| `tokenField` | Which response field holds the token: `access_token` or `id_token`. | `access_token` |
| `refreshSkewSeconds` | Treat the token as expired this many seconds early. | `30` |
| `defaultTtlSeconds` | Lifetime to assume when the reply has no `expires_in` and the token is not a JWT. | `300` |

Expiry is taken from `expires_in`, then from the JWT `exp` claim, then from `defaultTtlSeconds`,
minus `refreshSkewSeconds`. The `exp` claim is a fallback rather than the primary source because it
cannot be read out of an opaque token. A token whose whole lifetime is shorter than the skew is
reported as valid for one more second rather than as already expired, so a short-lived token does
not turn into a refetch on every call.

#### Transport

| Setting | Meaning | Default |
|---------|---------|---------|
| `connectTimeoutMs` | Connect timeout. | `10000` |
| `requestTimeoutMs` | Per-request timeout. | `30000` |
| `maxRetries` | Retries on timeout, `408`, `429` and `5xx`. Never on `invalid_client` or `invalid_grant`. | `3` |
| `retryBackoffMs` | Initial backoff, doubled per attempt, capped at 30 seconds. `Retry-After` wins over it. | `500` |
| `trustStoreFile`, `trustStorePassword`, `trustStoreType` | Custom CA, for self-hosted providers. Otherwise `AuthContext.sslContext()` is used. | JDK default, `PKCS12` |
| `proxyHost`, `proxyPort` | HTTP proxy. Configure both or neither. | JDK default |

#### Bundle

| Setting | Meaning | Default |
|---------|---------|---------|
| `profile` | Name of a defaults bundle to load: `google`, `okta` or `entra`. | none |

A profile is a properties file at `profiles/<name>.properties` on the classpath whose values are
merged *underneath* yours. It carries no logic and builds no URLs, every value in it is overridable,
and omitting the setting changes nothing. Adding your own is a matter of dropping a file onto the
classpath.

The bundle is read with `AuthContext.classLoader()`, which `AuthTokenManagerRegistry.using(loader)`
sets for you, so a host that isolates plugins gets the bundle shipped with the plugin. Two bundles
of the same name on one classpath is an error naming both, rather than a silent pick: which copy a
class loader returns depends on search order and on whether delegation is parent first, and neither
is predictable in a connector runtime.

### Worked configurations

Each block lists the connector-side parameters and the matching `dbms.security.oidc.<name>.*`
server-side settings. Neo4j only accepts a JWT its own configuration trusts, so the issuer, the
audience and the username claim all have match server configuration.

#### Keycloak
The realm is part of the URL, not a separate setting, unlike `authn` implementation.

```
issuer       = https://keycloak.example.com/realms/neo4j
clientId     = neo4j-client
clientSecret = ...
scope        = openid
# or, for an end-user token, grantType = password with the connector's own username and password
```

```
dbms.security.oidc.keycloak.issuer           = https://keycloak.example.com/realms/neo4j
dbms.security.oidc.keycloak.audience         = account
dbms.security.oidc.keycloak.client_id        = neo4j-client
dbms.security.oidc.keycloak.claims.username  = preferred_username
dbms.security.oidc.keycloak.claims.groups    = groups
dbms.security.oidc.keycloak.well_known_discovery_uri = \
    https://keycloak.example.com/realms/neo4j/.well-known/openid-configuration
```

#### Okta 
Point `issuer` at a **custom** authorisation server. Without one Okta returns an opaque
token rather than a JWT, and Neo4j cannot verify it; the module logs a warning when that happens
rather than letting the server reject the token anonymously.

```
profile      = okta
issuer       = https://example.okta.com/oauth2/ausXXXXXXXX
clientId     = 0oaXXXXXXXX
clientSecret = ...
scope        = neo4j.read
# or clientAuthMethod = private_key_jwt with privateKeyFile and privateKeyId
```

```
dbms.security.oidc.okta.issuer          = https://example.okta.com/oauth2/ausXXXXXXXX
dbms.security.oidc.okta.audience        = api://neo4j
dbms.security.oidc.okta.claims.username = sub
dbms.security.oidc.okta.claims.groups   = groups
```

#### Microsoft Entra ID
The scope must be `{appIdUri}/.default`; the profile moves the secret into the form, which is what Entra expects.

```
profile      = entra
issuer       = https://login.microsoftonline.com/<tenant>/v2.0
clientId     = <application id>
clientSecret = ...
scope        = api://neo4j/.default
# or clientAuthMethod = private_key_jwt with the certificate's key in privateKeyFile
```

```
dbms.security.oidc.entra.issuer          = https://login.microsoftonline.com/<tenant>/v2.0
dbms.security.oidc.entra.audience        = <application id>
dbms.security.oidc.entra.claims.username = sub
dbms.security.oidc.entra.claims.groups   = roles
```

#### Google
The signed JWT *is* the credential, and the JWT Neo4j can verify is the `id_token`, not
the `access_token`. Extract `private_key` from the service-account JSON into a PKCS#8 PEM file
yourself - the module does not read that JSON.

```
profile                            = google
privateKeyFile                     = /etc/neo4j/service-account.pk8.pem
privateKeyId                       = <private_key_id from the service account JSON>
assertion.claim.iss                = svc@project.iam.gserviceaccount.com
assertion.claim.sub                = svc@project.iam.gserviceaccount.com
assertion.claim.target_audience    = neo4j
```

```
dbms.security.oidc.google.issuer          = https://accounts.google.com
dbms.security.oidc.google.audience        = neo4j
dbms.security.oidc.google.claims.username = email
```

#### Amazon Cognito
An ordinary OIDC provider; no profile and no special handling.

```
issuer       = https://cognito-idp.<region>.amazonaws.com/<user pool id>
clientId     = ...
clientSecret = ...
scope        = neo4j/read
```

```
dbms.security.oidc.cognito.issuer          = https://cognito-idp.<region>.amazonaws.com/<pool id>
dbms.security.oidc.cognito.audience        = <client id>
dbms.security.oidc.cognito.claims.username = username
```

#### Token exchange

The `token_exchange` grant implements RFC 8693: a token you already hold, read from a file, is
swapped for one the provider issues. The file is re-read on every fetch, so a token the platform
rotates is picked up.

```
issuer           = https://<provider>
grantType        = token_exchange
clientAuthMethod = none
subjectTokenFile = /var/run/secrets/tokens/token
audience         = <what the issued token should be addressed to>
```

Whether this yields something Neo4j accepts depends on what the provider returns. Neo4j can only
verify a JWT, so a provider whose exchange returns an opaque token is of no use here even when the
grant itself works.

**Cloud workload identity is not covered by this.** Google's STS is not an OIDC provider, exposes no
discovery document, and its exchange returns an opaque access token rather than a JWT; obtaining a
JWT additionally needs an ID-token issuance call that this module does not implement. On EKS the
projected file already holds a JWT signed by the cluster's OIDC provider, so if Neo4j trusts that
issuer the token needs no exchange at all, which is a case this module has no grant for either.
Neither path has been verified end to end, so neither is documented as supported.
