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

import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.AuthTokenManagerFactory;
import org.neo4j.connectors.driver.auth.AuthTokenManagerRegistry;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.exceptions.AuthenticationException;
import org.neo4j.driver.exceptions.SecurityException;
import org.neo4j.driver.exceptions.TokenExpiredException;

class OidcAuthTokenManagerFactoryTest {
    private final OidcAuthTokenManagerFactory factory = new OidcAuthTokenManagerFactory();
    private TokenEndpointStub provider;

    @BeforeEach
    void startProvider() {
        provider = new TokenEndpointStub();
    }

    @AfterEach
    void stopProvider() {
        provider.close();
    }

    @Test
    void isNamedOidcAndNotAfterAnyProvider() {
        assertThat(factory.getName()).isEqualTo("oidc");
    }

    @Test
    void isRegisteredAsAService() {
        assertThat(ServiceLoader.load(AuthTokenManagerFactory.class).stream()
                        .map(provider -> provider.get().getName()))
                .contains("oidc");
    }

    @Test
    void resolvesThroughTheRegistry() {
        AuthTokenManager manager = AuthTokenManagerRegistry.usingDefaultClassLoader()
                .create("oidc", AuthConfig.of(null, null, settings()));

        assertThat(manager).isNotNull();
    }

    @Test
    void producesABearerTokenWithTheExpiryTheProviderAdvertised() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"a-token\",\"expires_in\":3600}"));

        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, settings()), context());

        assertThat(manager.getToken().toCompletableFuture().join()).isEqualTo(AuthTokens.bearer("a-token"));
    }

    @Test
    void servesTheHeldTokenRatherThanRefetchingIt() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"a-token\",\"expires_in\":3600}"));
        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, settings()), context());

        manager.getToken().toCompletableFuture().join();
        manager.getToken().toCompletableFuture().join();
        manager.getToken().toCompletableFuture().join();

        assertThat(provider.requests()).hasSize(1);
    }

    @Test
    void refetchesAfterTheServerRejectsATokenThatHasNotExpired() {
        AtomicInteger issued = new AtomicInteger();
        provider.on(
                "/token",
                request -> TokenEndpointStub.Response.json(
                        "{\"access_token\":\"token-" + issued.incrementAndGet() + "\",\"expires_in\":3600}"));
        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, settings()), context());
        AuthToken first = manager.getToken().toCompletableFuture().join();

        boolean retryable = manager.handleSecurityException(
                first, new TokenExpiredException("Neo.ClientError.Security.TokenExpired", "revoked"));

        assertThat(retryable).isTrue();
        assertThat(manager.getToken().toCompletableFuture().join()).isNotEqualTo(first);
        assertThat(provider.requests()).hasSize(2);
    }

    @Test
    void refetchesAfterAnAuthenticationFailureToo() {
        AtomicInteger issued = new AtomicInteger();
        provider.on(
                "/token",
                request -> TokenEndpointStub.Response.json(
                        "{\"access_token\":\"token-" + issued.incrementAndGet() + "\",\"expires_in\":3600}"));
        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, settings()), context());
        AuthToken first = manager.getToken().toCompletableFuture().join();

        manager.handleSecurityException(
                first, new AuthenticationException("Neo.ClientError.Security.Unauthorized", "no longer valid"));
        manager.getToken().toCompletableFuture().join();

        assertThat(provider.requests()).hasSize(2);
    }

    @Test
    void keepsTheTokenWhenTheFailureIsNotAboutAuthentication() {
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"a-token\",\"expires_in\":3600}"));
        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, settings()), context());
        AuthToken first = manager.getToken().toCompletableFuture().join();

        boolean retryable = manager.handleSecurityException(
                first, new SecurityException("Neo.ClientError.Security.Forbidden", "not allowed"));

        assertThat(retryable).isFalse();
        assertThat(manager.getToken().toCompletableFuture().join()).isEqualTo(first);
        assertThat(provider.requests()).hasSize(1);
    }

    @Test
    void performsNoIoWhileBeingCreated() {
        Map<String, String> settings = settings();
        settings.put("clientSecretFile", "/does/not/exist");
        settings.remove("clientSecret");

        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, settings), context());

        assertThat(manager).isNotNull();
        assertThat(provider.requests()).isEmpty();
    }

    @Test
    void reportsAMisconfigurationWhenTheManagerIsCreated() {
        AuthConfig config = AuthConfig.of(null, null, Map.of("issuer", "https://host"));

        assertThatThrownBy(() -> factory.create(config, AuthContext.defaults()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId");
    }

    private Map<String, String> settings() {
        Map<String, String> settings = new java.util.HashMap<>();
        settings.put("tokenEndpoint", provider.uri("/token").toString());
        settings.put("clientId", "a-client");
        settings.put("clientSecret", "a-secret");
        return settings;
    }

    /**
     * The clock stays the system one: the driver hardcodes {@code Clock.systemUTC()} in its own
     * expiration-based manager and would treat a token minted against a fixed clock as already
     * expired. Only our own expiry arithmetic is testable against an injected clock, which is what
     * {@code TokenEndpointClientTest} does.
     */
    private static AuthContext context() {
        return AuthContext.builder().executor(Runnable::run).build();
    }
}
