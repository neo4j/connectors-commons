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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.oidc.clientauth.ClientAuthMethod;
import org.neo4j.connectors.driver.auth.oidc.grant.GrantType;

class OidcConfigTest {

    @Test
    void derivesTheDiscoveryUrlFromTheIssuer() {
        OidcConfig config = parse(Map.of("issuer", "https://host/realms/neo4j", "clientId", "c", "clientSecret", "s"));

        assertThat(config.discoveryUrl())
                .contains(URI.create("https://host/realms/neo4j/.well-known/openid-configuration"));
        assertThat(config.tokenEndpoint()).isEmpty();
    }

    @Test
    void doesNotDoubleTheSlashOnAnIssuerThatEndsWithOne() {
        OidcConfig config = parse(Map.of("issuer", "https://host/realms/neo4j/", "clientId", "c", "clientSecret", "s"));

        assertThat(config.discoveryUrl())
                .contains(URI.create("https://host/realms/neo4j/.well-known/openid-configuration"));
    }

    @Test
    void prefersAnExplicitDiscoveryUrlOverTheIssuer() {
        OidcConfig config = parse(Map.of(
                "issuer", "https://host/realms/neo4j",
                "discoveryUrl", "https://elsewhere/.well-known/openid-configuration",
                "clientId", "c",
                "clientSecret", "s"));

        assertThat(config.discoveryUrl()).contains(URI.create("https://elsewhere/.well-known/openid-configuration"));
    }

    @Test
    void rejectsAConfigurationWithNowhereToGetTokensFrom() {
        assertThatThrownBy(() -> parse(Map.of("clientId", "c", "clientSecret", "s")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer")
                .hasMessageContaining("discoveryUrl")
                .hasMessageContaining("tokenEndpoint");
    }

    @Test
    void rejectsAMalformedUrl() {
        assertThatThrownBy(() -> parse(Map.of("issuer", "not a url", "clientId", "c", "clientSecret", "s")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void rejectsARelativeUrl() {
        assertThatThrownBy(() -> parse(Map.of("tokenEndpoint", "/token", "clientId", "c", "clientSecret", "s")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tokenEndpoint")
                .hasMessageContaining("absolute");
    }

    @Test
    void appliesTheDocumentedDefaults() {
        OidcConfig config = parse(base());

        assertThat(config.grantType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
        assertThat(config.clientAuthMethod()).isEqualTo(ClientAuthMethod.CLIENT_SECRET_BASIC);
        assertThat(config.tokenField()).isEqualTo("access_token");
        assertThat(config.refreshSkew()).isEqualTo(Duration.ofSeconds(30));
        assertThat(config.defaultTtl()).isEqualTo(Duration.ofSeconds(300));
        assertThat(config.connectTimeout()).isEqualTo(Duration.ofMillis(10_000));
        assertThat(config.requestTimeout()).isEqualTo(Duration.ofMillis(30_000));
        assertThat(config.maxRetries()).isEqualTo(3);
        assertThat(config.retryBackoff()).isEqualTo(Duration.ofMillis(500));
        assertThat(config.privateKeyAlgorithm()).isEqualTo("RS256");
        assertThat(config.trustStoreType()).isEqualTo("PKCS12");
    }

    @Test
    void readsABlankValueAsUnset() {
        OidcConfig config = parse(with("scope", ""));

        assertThat(config.scope()).isEmpty();
    }

    @Test
    void rejectsAnUnknownGrant() {
        assertThatThrownBy(() -> parse(with("grantType", "device_code")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("grantType")
                .hasMessageContaining("device_code")
                .hasMessageContaining("client_credentials");
    }

    @Test
    void rejectsAnUnknownClientAuthenticationMethod() {
        assertThatThrownBy(() -> parse(with("clientAuthMethod", "mtls")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientAuthMethod")
                .hasMessageContaining("private_key_jwt");
    }

    @Test
    void rejectsAnUnsupportedSigningAlgorithm() {
        assertThatThrownBy(() -> parse(with("privateKeyAlgorithm", "HS256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("privateKeyAlgorithm")
                .hasMessageContaining("RS256");
    }

    @Test
    void requiresAClientIdUnlessTheClientDoesNotAuthenticate() {
        assertThatThrownBy(() -> parse(Map.of("tokenEndpoint", "https://host/token", "clientSecret", "s")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId");

        OidcConfig config = parse(Map.of(
                "tokenEndpoint", "https://host/token",
                "clientAuthMethod", "none",
                "grantType", "refresh_token",
                "refreshToken", "a-refresh-token"));
        assertThat(config.clientId()).isEmpty();
    }

    @Test
    void rejectsClientCredentialsWithoutClientAuthentication() {
        assertThatThrownBy(() -> parse(Map.of("tokenEndpoint", "https://host/token", "clientAuthMethod", "none")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientAuthMethod")
                .hasMessageContaining("client_credentials");
    }

    @Test
    void requiresASecretForTheSecretBasedMethods() {
        assertThatThrownBy(() -> parse(Map.of("tokenEndpoint", "https://host/token", "clientId", "c")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientSecret")
                .hasMessageContaining("clientSecretFile");
    }

    @Test
    void acceptsASecretFileInsteadOfASecret() {
        OidcConfig config = parse(Map.of(
                "tokenEndpoint", "https://host/token",
                "clientId", "c",
                "clientSecretFile", "/run/secrets/client"));

        assertThat(config.clientSecret()).isEmpty();
        assertThat(config.clientSecretFile()).map(Object::toString).contains("/run/secrets/client");
    }

    @Test
    void rejectsBothASecretAndASecretFile() {
        assertThatThrownBy(() -> parse(Map.of(
                        "tokenEndpoint", "https://host/token",
                        "clientId", "c",
                        "clientSecret", "s",
                        "clientSecretFile", "/run/secrets/client")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientSecret")
                .hasMessageContaining("clientSecretFile")
                .hasMessageContaining("mutually exclusive");
    }

    @Test
    void requiresAKeyForPrivateKeyJwt() {
        assertThatThrownBy(() -> parse(Map.of(
                        "tokenEndpoint", "https://host/token",
                        "clientId", "c",
                        "clientAuthMethod", "private_key_jwt")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("privateKeyFile")
                .hasMessageContaining("private_key_jwt");
    }

    @Test
    void requiresAKeyForTheJwtBearerGrant() {
        assertThatThrownBy(() -> parse(Map.of(
                        "tokenEndpoint", "https://host/token",
                        "clientAuthMethod", "none",
                        "grantType", "jwt_bearer")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("privateKeyFile")
                .hasMessageContaining("jwt_bearer");
    }

    @Test
    void requiresCredentialsForThePasswordGrant() {
        Map<String, String> settings = with("grantType", "password");

        assertThatThrownBy(() -> OidcConfig.parse(AuthConfig.of(null, null, settings)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username")
                .hasMessageContaining("password");
    }

    @Test
    void takesThePasswordGrantCredentialsFromTheConnectorAndNotFromTheParameters() {
        OidcConfig config = OidcConfig.parse(AuthConfig.of("john", "secret", with("grantType", "password")));

        assertThat(config.username()).contains("john");
        assertThat(config.password()).contains("secret");
    }

    @Test
    void requiresARefreshTokenForTheRefreshTokenGrant() {
        assertThatThrownBy(() -> parse(with("grantType", "refresh_token")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("refreshToken");
    }

    @Test
    void requiresASubjectTokenFileForTokenExchange() {
        assertThatThrownBy(() -> parse(with("grantType", "token_exchange")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("subjectTokenFile");
    }

    @Test
    void requiresTheProxyHostAndPortTogether() {
        assertThatThrownBy(() -> parse(with("proxyHost", "proxy.internal")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("proxyHost")
                .hasMessageContaining("proxyPort");
    }

    @Test
    void collectsExtraParametersAndAssertionClaims() {
        Map<String, String> settings = base();
        settings.put("extraParam.audience_hint", "neo4j");
        settings.put("extraParam.tenant", "acme");
        settings.put("assertion.claim.target_audience", "neo4j");
        settings.put("assertion.claim.scope", "https://www.googleapis.com/auth/cloud-platform");

        OidcConfig config = parse(settings);

        assertThat(config.extraParams()).containsOnly(entry("audience_hint", "neo4j"), entry("tenant", "acme"));
        assertThat(config.assertionClaims())
                .containsOnly(
                        entry("target_audience", "neo4j"),
                        entry("scope", "https://www.googleapis.com/auth/cloud-platform"));
    }

    @Test
    void rejectsANonNumericTimeout() {
        assertThatThrownBy(() -> parse(with("requestTimeoutMs", "soon")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestTimeoutMs")
                .hasMessageContaining("integer");
    }

    @Test
    void rejectsANegativeRetryCount() {
        assertThatThrownBy(() -> parse(with("maxRetries", "-1")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maxRetries");
    }

    @Test
    void neverPrintsASecret() {
        Map<String, String> settings = base();
        settings.put("trustStorePassword", "changeit");
        OidcConfig config = OidcConfig.parse(AuthConfig.of("john", "hunter2", settings));

        assertThat(config.toString())
                .doesNotContain("topsecret")
                .doesNotContain("hunter2")
                .doesNotContain("changeit")
                .contains("<redacted>")
                .contains("clientId=a-client");
    }

    private static Map<String, String> base() {
        Map<String, String> settings = new HashMap<>();
        settings.put("tokenEndpoint", "https://host/token");
        settings.put("clientId", "a-client");
        settings.put("clientSecret", "topsecret");
        return settings;
    }

    private static Map<String, String> with(String key, String value) {
        Map<String, String> settings = base();
        settings.put(key, value);
        return settings;
    }

    private static OidcConfig parse(Map<String, String> settings) {
        return OidcConfig.parse(AuthConfig.of(null, null, settings));
    }
}
