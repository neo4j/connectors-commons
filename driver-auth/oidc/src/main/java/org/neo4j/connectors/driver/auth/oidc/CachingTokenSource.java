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

import java.time.Clock;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;
import org.neo4j.connectors.driver.auth.oidc.internal.TokenErrors;

/**
 * Holds a token until its refresh window opens, and lets only one fetch run at a time.
 *
 * <p>The driver already avoids asking for a token it believes is still valid, but it is not the only
 * caller — a connector that builds several drivers, or that calls
 * {@link org.neo4j.driver.AuthTokenManager#getToken()} directly, is. Two properties matter here:
 *
 * <ul>
 *   <li>a valid token is returned without any I/O, rather than re-fetched on every call;
 *   <li>the slot is claimed by installing an <em>empty</em> future, and the fetch is only started by
 *       the caller whose future won. The function passed to {@code updateAndGet} may re-run under
 *       contention, so it does nothing but choose between two references.
 * </ul>
 *
 * <p>A failed fetch clears the slot so the next caller retries, rather than caching the failure.
 */
final class CachingTokenSource implements TokenSource {
    private final TokenSource delegate;
    private final Clock clock;
    private final AtomicReference<CompletableFuture<AccessToken>> cached = new AtomicReference<>();

    CachingTokenSource(TokenSource delegate, Clock clock) {
        this.delegate = delegate;
        this.clock = clock;
    }

    @Override
    public CompletionStage<AccessToken> fetch() {
        CompletableFuture<AccessToken> current = cached.get();
        if (isUsable(current)) {
            return current;
        }
        CompletableFuture<AccessToken> claim = new CompletableFuture<>();
        CompletableFuture<AccessToken> winner = cached.updateAndGet(existing -> isUsable(existing) ? existing : claim);
        if (winner == claim) {
            start(claim);
        }
        return winner;
    }

    private void start(CompletableFuture<AccessToken> claim) {
        delegate.fetch().whenComplete((token, error) -> {
            if (error != null) {
                cached.compareAndSet(claim, null);
                claim.completeExceptionally(TokenErrors.unwrap(error));
            } else {
                claim.complete(token);
            }
        });
    }

    private boolean isUsable(CompletableFuture<AccessToken> current) {
        if (current == null) {
            return false;
        }
        if (!current.isDone()) {
            // A fetch is already in flight: join it rather than starting a second one.
            return true;
        }
        AccessToken token = current.getNow(null);
        return token != null && clock.instant().isBefore(token.expiresAt());
    }
}
