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

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.function.Supplier;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.AuthenticationTokenSupplierFactory;
import org.neo4j.connectors.authn.ExpiringAuthenticationToken;
import org.neo4j.driver.AuthTokenAndExpiration;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokenManagers;

/**
 * Bridges the legacy {@link AuthenticationTokenSupplierFactory} SPI onto driver-native
 * {@link AuthTokenManager} instances.
 *
 * <p>The bridge lazily goes through {@link AuthTokenManagers#bearerAsync}, deriving the expiry from
 * each token as it arrives.
 *
 * <p>The accepted trade-off is that {@code bearerAsync} also treats
 * {@link org.neo4j.driver.exceptions.TokenExpiredException} as retryable, not just
 * {@link org.neo4j.driver.exceptions.AuthenticationException}. For a static basic token that turns a
 * hard failure into a retry that then fails.
 */
public final class LegacyAuthBridge {

    private LegacyAuthBridge() {}

    /**
     * Wraps a legacy token supplier in a driver token manager.
     *
     * @param supplier the legacy supplier, invoked whenever a fresh token is needed
     * @param executor the executor the supplier is invoked on; legacy suppliers are free to block,
     *     which the driver's own manager contract forbids on the calling thread
     * @return a new token manager
     */
    public static AuthTokenManager fromSupplier(Supplier<AuthenticationToken> supplier, Executor executor) {
        return AuthTokenManagers.bearerAsync(tokenStageSupplier(supplier, executor));
    }

    /**
     * Wraps a legacy supplier factory as an {@link AuthTokenManagerFactory} under the same name.
     *
     * @param factory the legacy factory
     * @return a factory producing driver token managers
     */
    public static AuthTokenManagerFactory fromFactory(AuthenticationTokenSupplierFactory factory) {
        return new LegacyAuthTokenManagerFactory(factory);
    }

    static Supplier<CompletionStage<AuthTokenAndExpiration>> tokenStageSupplier(
            Supplier<AuthenticationToken> supplier, Executor executor) {
        Objects.requireNonNull(supplier, "supplier must not be null");
        Objects.requireNonNull(executor, "executor must not be null");
        return () -> CompletableFuture.supplyAsync(
                () -> {
                    AuthenticationToken token = supplier.get();
                    return AuthTokenMapper.toDriverToken(token).expiringAt(expiryOf(token));
                },
                executor);
    }

    static long expiryOf(AuthenticationToken token) {
        if (token instanceof ExpiringAuthenticationToken expiringToken) {
            Instant expiresAt = expiringToken.getExpiresAt();
            if (expiresAt != null) {
                return expiresAt.toEpochMilli();
            }
        }
        return Long.MAX_VALUE;
    }
}
