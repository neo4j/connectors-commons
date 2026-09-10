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
package org.neo4j.connectors.driver.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.AuthenticationTokenSupplierFactory;
import org.neo4j.driver.AuthTokenAndExpiration;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokens;

class LegacyAuthBridgeTest {
    private static final Executor SAME_THREAD = Runnable::run;
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-08T10:15:30Z"), ZoneOffset.UTC);

    @Test
    void derivesTheExpiryOfAnExpiringToken() {
        Instant expiresAt = CLOCK.instant().plus(Duration.ofMinutes(5));

        assertThat(LegacyAuthBridge.expiryOf(AuthenticationToken.bearer("a-token", expiresAt)))
                .isEqualTo(expiresAt.toEpochMilli());
    }

    @Test
    void treatsAnExpiringTokenWithoutAnExpiryAsNonExpiring() {
        // AuthenticationToken.bearer(String) yields an ExpiringAuthenticationToken whose
        // getExpiresAt() is null
        assertThat(LegacyAuthBridge.expiryOf(AuthenticationToken.bearer("a-token")))
                .isEqualTo(Long.MAX_VALUE);
    }

    @Test
    void treatsANonExpiringTokenAsNonExpiring() {
        assertThat(LegacyAuthBridge.expiryOf(AuthenticationToken.usernameAndPassword("neo4j", "secret")))
                .isEqualTo(Long.MAX_VALUE);
    }

    @Test
    void mapsTheTokenAndItsExpiryTogether() {
        Instant expiresAt = CLOCK.instant().plus(Duration.ofMinutes(5));
        AuthTokenAndExpiration tokenAndExpiration = LegacyAuthBridge.tokenStageSupplier(
                        () -> AuthenticationToken.bearer("a-token", expiresAt), SAME_THREAD)
                .get()
                .toCompletableFuture()
                .join();

        assertThat(tokenAndExpiration.authToken()).isEqualTo(AuthTokens.bearer("a-token"));
        assertThat(tokenAndExpiration.expirationTimestamp()).isEqualTo(expiresAt.toEpochMilli());
    }

    @Test
    void neverProbesTheSupplierEagerly() {
        AtomicInteger invocations = new AtomicInteger();
        Supplier<AuthenticationToken> supplier = () -> {
            invocations.incrementAndGet();
            return AuthenticationToken.usernameAndPassword("neo4j", "secret");
        };

        AuthTokenManager manager = LegacyAuthBridge.fromSupplier(supplier, SAME_THREAD);
        assertThat(invocations).hasValue(0);

        assertThat(manager.getToken().toCompletableFuture().join()).isEqualTo(AuthTokens.basic("neo4j", "secret"));
        assertThat(invocations).hasValue(1);
    }

    @Test
    void invokesTheSupplierOnTheGivenExecutor() {
        AtomicInteger invocations = new AtomicInteger();
        Executor executor = command -> {
            invocations.incrementAndGet();
            command.run();
        };

        LegacyAuthBridge.fromSupplier(AuthenticationToken::none, executor)
                .getToken()
                .toCompletableFuture()
                .join();

        assertThat(invocations).hasValue(1);
    }

    @Test
    void wrapsALegacyFactoryUnderItsOwnName() {
        AuthenticationTokenSupplierFactory legacyFactory = new AuthenticationTokenSupplierFactory() {
            @Override
            public String getName() {
                return "a-legacy-scheme";
            }

            @Override
            public Supplier<AuthenticationToken> create(
                    String username, String password, Map<String, String> parameters) {
                return () -> AuthenticationToken.usernameAndPassword(username, password, parameters.get("realm"));
            }
        };

        AuthTokenManagerFactory factory = LegacyAuthBridge.fromFactory(legacyFactory);
        assertThat(factory.getName()).isEqualTo("a-legacy-scheme");

        AuthTokenManager manager = factory.create(
                AuthConfig.of("neo4j", "secret", Map.of("realm", "a-realm")),
                AuthContext.builder().executor(SAME_THREAD).build());

        assertThat(manager.getToken().toCompletableFuture().join())
                .isEqualTo(AuthTokens.basic("neo4j", "secret", "a-realm"));
    }
}
