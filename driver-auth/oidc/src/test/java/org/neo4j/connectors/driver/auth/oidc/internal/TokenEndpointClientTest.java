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
package org.neo4j.connectors.driver.auth.oidc.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.oidc.AccessToken;
import org.neo4j.connectors.driver.auth.oidc.TokenEndpointStub;
import org.neo4j.connectors.driver.auth.oidc.TokenRequestException;

class TokenEndpointClientTest {
    private static final Instant NOW = Instant.parse("2026-09-21T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private TokenEndpointStub provider;
    private HttpClient http;

    @BeforeEach
    void startProvider() {
        provider = new TokenEndpointStub();
        http = HttpClient.newHttpClient();
    }

    @AfterEach
    void stopProvider() {
        provider.close();
    }

    @Test
    void postsTheFormAndReadsTheToken() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"a-token\",\"expires_in\":3600}"));

        TokenRequest request = new TokenRequest.Builder(
                        provider.uri("/token"),
                        new ClientSecretBasic(new ClientID("a-client"), new Secret("a-secret")),
                        new ClientCredentialsGrant())
                .scope(Scope.parse("a b"))
                .build();

        AccessToken token = client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300))
                .requestToken(request)
                .toCompletableFuture()
                .join();

        assertThat(token.value()).isEqualTo("a-token");
        assertThat(provider.lastRequest().method()).isEqualTo("POST");
        assertThat(provider.lastRequest().body()).isEqualTo("grant_type=client_credentials&scope=a+b");
        assertThat(provider.lastRequest().headers())
                .containsEntry("accept", "application/json")
                .containsEntry(
                        "authorization",
                        "Basic "
                                + java.util.Base64.getEncoder()
                                        .encodeToString("a-client:a-secret".getBytes(StandardCharsets.UTF_8)));
        assertThat(provider.lastRequest().headers().get("content-type"))
                .startsWith("application/x-www-form-urlencoded");
    }

    @Test
    void prefersExpiresInOverTheJwtExpiryClaim() {
        provider.on(
                "/token",
                TokenEndpointStub.Response.json(
                        "{\"access_token\":\"" + jwt(NOW.plusSeconds(9999)) + "\",\"expires_in\":600}"));

        AccessToken token = fetch(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300)));

        assertThat(token.expiresAt()).isEqualTo(NOW.plusSeconds(600 - 30));
    }

    @Test
    void fallsBackToTheJwtExpiryClaimWhenTheResponseCarriesNoLifetime() {
        provider.on(
                "/token", TokenEndpointStub.Response.json("{\"access_token\":\"" + jwt(NOW.plusSeconds(1200)) + "\"}"));

        AccessToken token = fetch(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300)));

        assertThat(token.expiresAt()).isEqualTo(NOW.plusSeconds(1200 - 30));
    }

    @Test
    void fallsBackToTheConfiguredDefaultForAnOpaqueTokenWithNoLifetime() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"an-opaque-token\"}"));

        AccessToken token = fetch(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300)));

        assertThat(token.expiresAt()).isEqualTo(NOW.plusSeconds(300 - 30));
    }

    @Test
    void readsALifetimeSentAsAString() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"t\",\"expires_in\":\"3599\"}"));

        AccessToken token = fetch(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300)));

        assertThat(token.expiresAt()).isEqualTo(NOW.plusSeconds(3599 - 30));
    }

    @Test
    void neverReportsATokenAsAlreadyExpiredHoweverLargeTheSkew() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"t\",\"expires_in\":5}"));

        AccessToken token = fetch(client("access_token", Duration.ofSeconds(60), Duration.ofSeconds(300)));

        assertThat(token.expiresAt()).isEqualTo(NOW.plusSeconds(1));
    }

    @Test
    void readsTheIdTokenWhenThatIsWhereTheJwtIs() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"opaque\",\"id_token\":\"a-jwt\"}"));

        AccessToken token = fetch(client("id_token", Duration.ofSeconds(30), Duration.ofSeconds(300)));

        assertThat(token.value()).isEqualTo("a-jwt");
    }

    @Test
    void carriesTheRefreshTokenThrough() {
        provider.on(
                "/token",
                TokenEndpointStub.Response.json("{\"access_token\":\"t\",\"refresh_token\":\"r\",\"expires_in\":60}"));

        assertThat(fetch(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300)))
                        .refreshToken())
                .isEqualTo("r");
    }

    @Test
    void namesTheTokenFieldSettingWhenTheResponseHasNoSuchField() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"t\"}"));

        assertThatThrownBy(() -> fetch(client("id_token", Duration.ofSeconds(30), Duration.ofSeconds(300))))
                .hasRootCauseInstanceOf(TokenRequestException.class)
                .hasMessageContaining("id_token")
                .hasMessageContaining("tokenField");
    }

    @Test
    void turnsARefusalIntoAClassifiedFailure() {
        provider.on("/token", TokenEndpointStub.Response.of(401, "{\"error\":\"invalid_client\"}"));

        assertThatThrownBy(() -> fetch(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300))))
                .hasRootCauseInstanceOf(TokenRequestException.class)
                .hasMessageContaining("invalid_client");
    }

    @Test
    void carriesRetryAfterOffTheResponse() {
        provider.on("/token", TokenEndpointStub.Response.of(429, "").withHeader("Retry-After", "7"));

        TokenRequestException failure =
                failureOf(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300)));

        assertThat(failure.isRetryable()).isTrue();
        assertThat(failure.retryAfter()).contains(Duration.ofSeconds(7));
    }

    @Test
    void reportsABodyThatIsNotJson() {
        provider.on("/token", TokenEndpointStub.Response.json("<html/>"));

        assertThatThrownBy(() -> fetch(client("access_token", Duration.ofSeconds(30), Duration.ofSeconds(300))))
                .hasCauseInstanceOf(TokenRequestException.class)
                .hasMessageContaining("not valid JSON");
    }

    private TokenEndpointClient client(String tokenField, Duration skew, Duration defaultTtl) {
        return new TokenEndpointClient(http, Duration.ofSeconds(5), tokenField, skew, defaultTtl, CLOCK);
    }

    private AccessToken fetch(TokenEndpointClient client) {
        AuthorizationGrant grant = new ClientCredentialsGrant();
        return client.requestToken(new TokenRequest.Builder(
                                provider.uri("/token"),
                                new ClientSecretBasic(new ClientID("a-client"), new Secret("a-secret")),
                                grant)
                        .build())
                .toCompletableFuture()
                .join();
    }

    private TokenRequestException failureOf(TokenEndpointClient client) {
        try {
            fetch(client);
            throw new AssertionError("expected the fetch to fail");
        } catch (RuntimeException e) {
            return (TokenRequestException) TokenErrors.unwrap(e);
        }
    }

    private static String jwt(Instant expiry) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8))
                + "."
                + encoder.encodeToString(("{\"exp\":" + expiry.getEpochSecond() + "}").getBytes(StandardCharsets.UTF_8))
                + ".sig";
    }
}
