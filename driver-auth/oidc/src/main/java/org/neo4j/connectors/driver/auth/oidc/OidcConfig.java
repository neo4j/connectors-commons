/*
 * Copyright (c) "Neo4j"
 * Neo4j Sweden AB [https://neo4j.com]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.neo4j.connectors.driver.auth.oidc;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.oidc.clientauth.ClientAuthMethod;
import org.neo4j.connectors.driver.auth.oidc.grant.GrantType;
import org.neo4j.connectors.driver.auth.oidc.internal.AssertionFactory;

/**
 * The {@code oidc} scheme's settings, parsed and validated.
 *
 * <p>Everything a provider differs by is here as a value rather than in code: which URL, which
 * grant, how the client proves itself, which extra form fields, which assertion claims. That is what
 * lets Keycloak, Okta, Entra ID, Google and Cognito share one factory.
 *
 * <p>Parsing is total and eager, so a typo is an {@link IllegalArgumentException} naming the key at
 * the moment the connector starts. Nothing here touches the network or reads a credential file —
 * both are deferred to the first token fetch.
 */
public final class OidcConfig {
    static final String ISSUER = "issuer";
    static final String DISCOVERY_URL = "discoveryUrl";
    static final String TOKEN_ENDPOINT = "tokenEndpoint";
    static final String GRANT_TYPE = "grantType";
    static final String SCOPE = "scope";
    static final String AUDIENCE = "audience";
    static final String RESOURCE = "resource";
    static final String EXTRA_PARAM_PREFIX = "extraParam.";
    static final String SUBJECT_TOKEN_FILE = "subjectTokenFile";
    static final String SUBJECT_TOKEN_TYPE = "subjectTokenType";
    static final String REFRESH_TOKEN = "refreshToken";
    static final String CLIENT_ID = "clientId";
    static final String CLIENT_SECRET = "clientSecret";
    static final String CLIENT_SECRET_FILE = "clientSecretFile";
    static final String CLIENT_AUTH_METHOD = "clientAuthMethod";
    static final String PRIVATE_KEY_FILE = "privateKeyFile";
    static final String PRIVATE_KEY_ID = "privateKeyId";
    static final String PRIVATE_KEY_ALGORITHM = "privateKeyAlgorithm";
    static final String ASSERTION_CLAIM_PREFIX = "assertion.claim.";
    static final String ASSERTION_TTL_SECONDS = "assertionTtlSeconds";
    static final String TOKEN_FIELD = "tokenField";
    static final String REFRESH_SKEW_SECONDS = "refreshSkewSeconds";
    static final String DEFAULT_TTL_SECONDS = "defaultTtlSeconds";
    static final String CONNECT_TIMEOUT_MS = "connectTimeoutMs";
    static final String REQUEST_TIMEOUT_MS = "requestTimeoutMs";
    static final String MAX_RETRIES = "maxRetries";
    static final String RETRY_BACKOFF_MS = "retryBackoffMs";
    static final String TRUST_STORE_FILE = "trustStoreFile";
    static final String TRUST_STORE_PASSWORD = "trustStorePassword";
    static final String TRUST_STORE_TYPE = "trustStoreType";
    static final String PROXY_HOST = "proxyHost";
    static final String PROXY_PORT = "proxyPort";

    private static final String DISCOVERY_SUFFIX = "/.well-known/openid-configuration";
    private static final String DEFAULT_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    private final URI discoveryUrl;
    private final URI tokenEndpoint;
    private final GrantType grantType;
    private final String scope;
    private final String audience;
    private final String resource;
    private final Map<String, String> extraParams;
    private final Path subjectTokenFile;
    private final String subjectTokenType;
    private final String refreshToken;
    private final String username;
    private final String password;
    private final String clientId;
    private final String clientSecret;
    private final Path clientSecretFile;
    private final ClientAuthMethod clientAuthMethod;
    private final Path privateKeyFile;
    private final String privateKeyId;
    private final String privateKeyAlgorithm;
    private final Map<String, String> assertionClaims;
    private final Duration assertionTtl;
    private final String tokenField;
    private final Duration refreshSkew;
    private final Duration defaultTtl;
    private final Duration connectTimeout;
    private final Duration requestTimeout;
    private final int maxRetries;
    private final Duration retryBackoff;
    private final Path trustStoreFile;
    private final String trustStorePassword;
    private final String trustStoreType;
    private final String proxyHost;
    private final int proxyPort;

    private OidcConfig(AuthConfig config, Settings settings) {
        this.tokenEndpoint = settings.uri(TOKEN_ENDPOINT).orElse(null);
        this.discoveryUrl = settings.uri(DISCOVERY_URL)
                .or(() -> settings.uri(ISSUER).map(OidcConfig::discoveryUrlOf))
                .orElse(null);
        if (tokenEndpoint == null && discoveryUrl == null) {
            throw new IllegalArgumentException("One of the authentication parameters '" + ISSUER + "', '"
                    + DISCOVERY_URL + "' or '" + TOKEN_ENDPOINT + "' is required, but none was configured");
        }

        this.grantType = settings.get(GRANT_TYPE)
                .map(value -> GrantType.fromSetting(value)
                        .orElseThrow(() -> Settings.invalid(GRANT_TYPE, value, "one of " + GrantType.settingValues())))
                .orElse(GrantType.CLIENT_CREDENTIALS);
        this.clientAuthMethod = settings.get(CLIENT_AUTH_METHOD)
                .map(value -> ClientAuthMethod.fromSetting(value)
                        .orElseThrow(() -> Settings.invalid(
                                CLIENT_AUTH_METHOD, value, "one of " + ClientAuthMethod.settingValues())))
                .orElse(ClientAuthMethod.CLIENT_SECRET_BASIC);

        this.scope = settings.get(SCOPE).orElse(null);
        this.audience = settings.get(AUDIENCE).orElse(null);
        this.resource = settings.get(RESOURCE).orElse(null);
        this.extraParams = settings.withPrefix(EXTRA_PARAM_PREFIX);
        this.subjectTokenFile = settings.path(SUBJECT_TOKEN_FILE).orElse(null);
        this.subjectTokenType = settings.get(SUBJECT_TOKEN_TYPE, DEFAULT_SUBJECT_TOKEN_TYPE);
        this.refreshToken = settings.get(REFRESH_TOKEN).orElse(null);
        this.username = config.username().orElse(null);
        this.password = config.password().orElse(null);

        this.clientId = clientAuthMethod == ClientAuthMethod.NONE
                ? settings.get(CLIENT_ID).orElse(null)
                : settings.require(CLIENT_ID);
        this.clientSecret = settings.get(CLIENT_SECRET).orElse(null);
        this.clientSecretFile = settings.path(CLIENT_SECRET_FILE).orElse(null);
        if (clientSecret != null && clientSecretFile != null) {
            throw Settings.conflict(CLIENT_SECRET, CLIENT_SECRET_FILE);
        }

        this.privateKeyFile = settings.path(PRIVATE_KEY_FILE).orElse(null);
        this.privateKeyId = settings.get(PRIVATE_KEY_ID).orElse(null);
        this.privateKeyAlgorithm = settings.get(PRIVATE_KEY_ALGORITHM, "RS256");
        AssertionFactory.algorithmOf(privateKeyAlgorithm);
        this.assertionClaims = settings.withPrefix(ASSERTION_CLAIM_PREFIX);
        this.assertionTtl = settings.seconds(ASSERTION_TTL_SECONDS, 300);

        this.tokenField = settings.get(TOKEN_FIELD, "access_token");
        this.refreshSkew = settings.seconds(REFRESH_SKEW_SECONDS, 30);
        this.defaultTtl = settings.seconds(DEFAULT_TTL_SECONDS, 300);

        this.connectTimeout = settings.millis(CONNECT_TIMEOUT_MS, 10_000);
        this.requestTimeout = settings.millis(REQUEST_TIMEOUT_MS, 30_000);
        this.maxRetries = (int) settings.number(MAX_RETRIES, 3, 0);
        this.retryBackoff = settings.millis(RETRY_BACKOFF_MS, 500);

        this.trustStoreFile = settings.path(TRUST_STORE_FILE).orElse(null);
        this.trustStorePassword = settings.get(TRUST_STORE_PASSWORD).orElse(null);
        this.trustStoreType = settings.get(TRUST_STORE_TYPE, "PKCS12");
        this.proxyHost = settings.get(PROXY_HOST).orElse(null);
        this.proxyPort = (int) settings.number(PROXY_PORT, 0, 0);

        validateCombinations();
    }

    /**
     * Parses and validates the settings of one {@code oidc} configuration.
     *
     * @param config the user-supplied connector configuration
     * @return the parsed settings
     * @throws IllegalArgumentException naming the offending key, if anything is missing, malformed or
     *     contradictory
     */
    public static OidcConfig parse(AuthConfig config) {
        return new OidcConfig(config, new Settings(Profiles.merge(config.asMap())));
    }

    private void validateCombinations() {
        switch (clientAuthMethod) {
            case CLIENT_SECRET_BASIC, CLIENT_SECRET_POST -> {
                if (clientSecret == null && clientSecretFile == null) {
                    throw Settings.requiredBecause(
                            CLIENT_SECRET,
                            "when " + CLIENT_AUTH_METHOD + " is '" + clientAuthMethod.settingValue() + "' (or use '"
                                    + CLIENT_SECRET_FILE + "')");
                }
            }
            case PRIVATE_KEY_JWT -> requirePrivateKey("when " + CLIENT_AUTH_METHOD + " is 'private_key_jwt'");
            case NONE -> {}
        }

        switch (grantType) {
            case PASSWORD -> {
                if (username == null || password == null) {
                    throw new IllegalArgumentException("The 'password' grant needs a username and a password, which"
                            + " come from the connector's own credential settings rather than from the"
                            + " authentication parameters, but one of them was not configured");
                }
            }
            case REFRESH_TOKEN -> {
                if (refreshToken == null) {
                    throw Settings.requiredBecause(REFRESH_TOKEN, "when " + GRANT_TYPE + " is 'refresh_token'");
                }
            }
            case JWT_BEARER -> requirePrivateKey("when " + GRANT_TYPE + " is 'jwt_bearer'");
            case TOKEN_EXCHANGE -> {
                if (subjectTokenFile == null) {
                    throw Settings.requiredBecause(SUBJECT_TOKEN_FILE, "when " + GRANT_TYPE + " is 'token_exchange'");
                }
            }
            case CLIENT_CREDENTIALS -> {
                if (clientAuthMethod == ClientAuthMethod.NONE) {
                    // RFC 6749 section 4.4.2: the client's own credentials are the whole grant, so
                    // there is nothing left to authorise with once client authentication is off.
                    throw new IllegalArgumentException("Authentication parameter '" + CLIENT_AUTH_METHOD
                            + "' cannot be 'none' when '" + GRANT_TYPE
                            + "' is 'client_credentials': that grant is the client's credentials");
                }
            }
        }

        if ((proxyHost == null) != (proxyPort == 0)) {
            throw new IllegalArgumentException("Authentication parameters '" + PROXY_HOST + "' and '" + PROXY_PORT
                    + "' must be configured together");
        }
    }

    private void requirePrivateKey(String reason) {
        if (privateKeyFile == null) {
            throw Settings.requiredBecause(PRIVATE_KEY_FILE, reason);
        }
    }

    private static URI discoveryUrlOf(URI issuer) {
        String base = issuer.toString();
        return URI.create((base.endsWith("/") ? base.substring(0, base.length() - 1) : base) + DISCOVERY_SUFFIX);
    }

    /**
     * Returns the token endpoint, when one was configured directly.
     *
     * @return the token endpoint, or {@link Optional#empty()} if it must be discovered
     */
    public Optional<URI> tokenEndpoint() {
        return Optional.ofNullable(tokenEndpoint);
    }

    /**
     * Returns the discovery document URL, derived from {@code issuer} unless given directly.
     *
     * @return the discovery URL, or {@link Optional#empty()} if the token endpoint was given instead
     */
    public Optional<URI> discoveryUrl() {
        return Optional.ofNullable(discoveryUrl);
    }

    /** @return the grant to use */
    public GrantType grantType() {
        return grantType;
    }

    /** @return the {@code scope} form field, or {@link Optional#empty()} */
    public Optional<String> scope() {
        return Optional.ofNullable(scope);
    }

    /** @return the {@code audience} form field, or {@link Optional#empty()} */
    public Optional<String> audience() {
        return Optional.ofNullable(audience);
    }

    /** @return the {@code resource} form field, or {@link Optional#empty()} */
    public Optional<String> resource() {
        return Optional.ofNullable(resource);
    }

    /** @return the additional form fields, sent as-is */
    public Map<String, String> extraParams() {
        return extraParams;
    }

    /** @return the file holding the subject token for {@code token_exchange}, or {@link Optional#empty()} */
    public Optional<Path> subjectTokenFile() {
        return Optional.ofNullable(subjectTokenFile);
    }

    /** @return the declared {@code subject_token_type} */
    public String subjectTokenType() {
        return subjectTokenType;
    }

    /** @return the configured refresh token, or {@link Optional#empty()} */
    public Optional<String> refreshToken() {
        return Optional.ofNullable(refreshToken);
    }

    /** @return the end-user name for the {@code password} grant, or {@link Optional#empty()} */
    public Optional<String> username() {
        return Optional.ofNullable(username);
    }

    /** @return the end-user password for the {@code password} grant, or {@link Optional#empty()} */
    public Optional<String> password() {
        return Optional.ofNullable(password);
    }

    /** @return the client identifier, absent only when no client authentication is configured */
    public Optional<String> clientId() {
        return Optional.ofNullable(clientId);
    }

    /** @return the inline client secret, or {@link Optional#empty()} */
    public Optional<String> clientSecret() {
        return Optional.ofNullable(clientSecret);
    }

    /** @return the file holding the client secret, or {@link Optional#empty()} */
    public Optional<Path> clientSecretFile() {
        return Optional.ofNullable(clientSecretFile);
    }

    /** @return how the client proves its identity */
    public ClientAuthMethod clientAuthMethod() {
        return clientAuthMethod;
    }

    /** @return the signing key file, or {@link Optional#empty()} */
    public Optional<Path> privateKeyFile() {
        return Optional.ofNullable(privateKeyFile);
    }

    /** @return the {@code kid} header of signed assertions, or {@link Optional#empty()} */
    public Optional<String> privateKeyId() {
        return Optional.ofNullable(privateKeyId);
    }

    /** @return the JWS algorithm to sign assertions with */
    public String privateKeyAlgorithm() {
        return privateKeyAlgorithm;
    }

    /** @return the configured assertion claims, which win over the RFC 7523 defaults */
    public Map<String, String> assertionClaims() {
        return assertionClaims;
    }

    /** @return how long a signed assertion is valid for */
    public Duration assertionTtl() {
        return assertionTtl;
    }

    /** @return the response field holding the token */
    public String tokenField() {
        return tokenField;
    }

    /** @return how early a token is treated as expired */
    public Duration refreshSkew() {
        return refreshSkew;
    }

    /** @return the lifetime assumed when the response carries none and the token is opaque */
    public Duration defaultTtl() {
        return defaultTtl;
    }

    /** @return the connect timeout */
    public Duration connectTimeout() {
        return connectTimeout;
    }

    /** @return the per-request timeout */
    public Duration requestTimeout() {
        return requestTimeout;
    }

    /** @return how many times a transient failure is retried */
    public int maxRetries() {
        return maxRetries;
    }

    /** @return the initial retry backoff */
    public Duration retryBackoff() {
        return retryBackoff;
    }

    /** @return the trust store holding the provider's certificate authority, or {@link Optional#empty()} */
    public Optional<Path> trustStoreFile() {
        return Optional.ofNullable(trustStoreFile);
    }

    /** @return the trust store password, or {@link Optional#empty()} */
    public Optional<String> trustStorePassword() {
        return Optional.ofNullable(trustStorePassword);
    }

    /** @return the trust store type */
    public String trustStoreType() {
        return trustStoreType;
    }

    /** @return the HTTP proxy host, or {@link Optional#empty()} */
    public Optional<String> proxyHost() {
        return Optional.ofNullable(proxyHost);
    }

    /** @return the HTTP proxy port, or {@code 0} when no proxy is configured */
    public int proxyPort() {
        return proxyPort;
    }

    /**
     * Returns a description that holds no secret.
     *
     * <p>Connector configuration ends up in logs and in support bundles, so the secret, the password,
     * the refresh token and the trust store password are never part of it.
     *
     * @return a redacted description
     */
    @Override
    public String toString() {
        return "OidcConfig{tokenEndpoint=" + tokenEndpoint
                + ", discoveryUrl=" + discoveryUrl
                + ", grantType=" + grantType.settingValue()
                + ", clientAuthMethod=" + clientAuthMethod.settingValue()
                + ", clientId=" + clientId
                + ", clientSecret=" + redacted(clientSecret)
                + ", clientSecretFile=" + clientSecretFile
                + ", refreshToken=" + redacted(refreshToken)
                + ", username=" + username
                + ", password=" + redacted(password)
                + ", scope=" + scope
                + ", audience=" + audience
                + ", resource=" + resource
                + ", extraParams=" + extraParams.keySet()
                + ", privateKeyFile=" + privateKeyFile
                + ", privateKeyAlgorithm=" + privateKeyAlgorithm
                + ", assertionClaims=" + assertionClaims.keySet()
                + ", tokenField=" + tokenField
                + ", refreshSkew=" + refreshSkew
                + ", defaultTtl=" + defaultTtl
                + ", trustStoreFile=" + trustStoreFile
                + ", trustStorePassword=" + redacted(trustStorePassword)
                + ", proxyHost=" + proxyHost
                + ", proxyPort=" + proxyPort
                + "}";
    }

    private static String redacted(String value) {
        return value == null ? "<absent>" : "<redacted>";
    }
}
