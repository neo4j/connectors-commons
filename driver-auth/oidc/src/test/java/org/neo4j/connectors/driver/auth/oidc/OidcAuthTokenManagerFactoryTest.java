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
import static org.assertj.core.api.Assertions.catchThrowable;

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthConfigException;
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
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("clientId"))
                .hasMessageContaining("clientId");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("configurations")
    void validateAgreesWithCreate(String description, AuthConfig config) {
        Throwable created = catchThrowable(() -> factory.create(config, AuthContext.defaults()));
        Throwable validated = catchThrowable(() -> factory.validate(config, AuthContext.defaults()));

        if (created == null) {
            assertThat(validated).isNull();
        } else {
            assertThat(validated)
                    .isExactlyInstanceOf(created.getClass())
                    .isInstanceOf(AuthConfigException.class)
                    .hasMessage(created.getMessage());
            assertThat(((AuthConfigException) validated).keys())
                    .isNotEmpty()
                    .isEqualTo(((AuthConfigException) created).keys());
        }
    }

    static Stream<Arguments> configurations() {
        return Stream.of(
                Arguments.of("a valid configuration", config(null, null)),
                Arguments.of(
                        "a valid profile",
                        AuthConfig.of(
                                null,
                                null,
                                Map.of("profile", "google", "clientId", "c", "privateKeyFile", "/does/not/exist"))),
                Arguments.of("nowhere to get tokens from", AuthConfig.of(null, null, Map.of("clientId", "c"))),
                Arguments.of("no clientId", AuthConfig.of(null, null, Map.of("issuer", "https://host"))),
                Arguments.of("an unknown grant", config("grantType", "device_code")),
                Arguments.of("a malformed URL", config("tokenEndpoint", "not a url")),
                Arguments.of("an unsupported algorithm", config("privateKeyAlgorithm", "HS256")),
                Arguments.of("a secret and a secret file", config("clientSecretFile", "/run/secrets/client")),
                Arguments.of("the password grant without credentials", config("grantType", "password")),
                Arguments.of("a proxy host without a port", config("proxyHost", "proxy.internal")),
                Arguments.of("a profile that does not exist", config("profile", "nonesuch")));
    }

    @Test
    void validatesWithoutTouchingTheFilesItNamesOrStartingAnHttpClient() {
        Map<String, String> settings = new HashMap<>();
        settings.put("tokenEndpoint", provider.uri("/token").toString());
        settings.put("clientId", "a-client");
        settings.put("clientAuthMethod", "private_key_jwt");
        settings.put("privateKeyFile", "/does/not/exist.pem");
        settings.put("trustStoreFile", "/does/not/exist.p12");
        Set<Thread> before = Thread.getAllStackTraces().keySet();

        factory.validate(AuthConfig.of(null, null, settings), AuthContext.defaults());

        Set<String> started = Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> !before.contains(thread))
                .map(Thread::getName)
                .collect(Collectors.toSet());
        assertThat(started).noneMatch(name -> name.contains("HttpClient"));
        assertThat(provider.requests()).isEmpty();
    }

    @Test
    void rejectsAMisconfigurationWhenValidating() {
        AuthConfig config = AuthConfig.of(null, null, Map.of("issuer", "https://host"));

        assertThatThrownBy(() -> factory.validate(config, AuthContext.defaults()))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("clientId"))
                .hasMessageContaining("clientId");
    }

    @Test
    void validatesThroughTheRegistry() {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        registry.validate("oidc", AuthConfig.of(null, null, settings()));
        assertThatThrownBy(() -> registry.validate("oidc", AuthConfig.of(null, null, Map.of("clientId", "c"))))
                .isInstanceOfSatisfying(AuthConfigException.class, e -> assertThat(e.keys())
                        .containsExactly("issuer", "discoveryUrl", "tokenEndpoint"));
    }

    /** A valid configuration that reaches no real endpoint, with one setting changed. */
    private static AuthConfig config(String key, String value) {
        Map<String, String> settings = new HashMap<>();
        settings.put("tokenEndpoint", "https://host/token");
        settings.put("clientId", "a-client");
        settings.put("clientSecret", "a-secret");
        if (key != null) {
            settings.put(key, value);
        }
        return AuthConfig.of(null, null, settings);
    }

    private Map<String, String> settings() {
        Map<String, String> settings = new HashMap<>();
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
