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

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.function.LongFunction;
import org.neo4j.connectors.driver.auth.oidc.internal.TokenErrors;

/**
 * Retries a fetch that failed for a reason that might not recur.
 *
 * <p>Only timeouts, {@code 408}, {@code 429} and {@code 5xx} qualify. An {@code invalid_client} or
 * {@code invalid_grant} is a configuration mistake, and retrying it would turn one bad credential
 * into a burst against a provider that rate-limits its token endpoint.
 *
 * <p>A {@code Retry-After} header wins over the backoff schedule. On a {@code 429} that schedule is
 * exactly what the provider is asking the client to stop doing.
 *
 * <p>Waiting is done with a delayed executor rather than a sleep, so no thread is parked.
 */
final class RetryingTokenSource implements TokenSource {
    /** The backoff doubles per attempt but never grows past this, so a long outage still polls. */
    private static final Duration MAXIMUM_BACKOFF = Duration.ofSeconds(30);

    private final TokenSource delegate;
    private final int maxRetries;
    private final Duration initialBackoff;
    private final LongFunction<Executor> delays;

    RetryingTokenSource(TokenSource delegate, int maxRetries, Duration initialBackoff, Executor executor) {
        this(delegate, maxRetries, initialBackoff, delayedExecutors(executor));
    }

    private static LongFunction<Executor> delayedExecutors(Executor executor) {
        return millis -> CompletableFuture.delayedExecutor(millis, TimeUnit.MILLISECONDS, executor);
    }

    /**
     * The seam the tests use to assert the backoff schedule without waiting for it.
     */
    RetryingTokenSource(TokenSource delegate, int maxRetries, Duration initialBackoff, LongFunction<Executor> delays) {
        this.delegate = delegate;
        this.maxRetries = maxRetries;
        this.initialBackoff = initialBackoff;
        this.delays = delays;
    }

    @Override
    public CompletionStage<AccessToken> fetch() {
        return attempt(0);
    }

    private CompletionStage<AccessToken> attempt(int attempt) {
        return delegate.fetch()
                .handle((token, error) ->
                        error == null ? CompletableFuture.completedStage(token) : retryOrFail(attempt, error))
                .thenCompose(stage -> stage);
    }

    private CompletionStage<AccessToken> retryOrFail(int attempt, Throwable error) {
        Throwable cause = TokenErrors.unwrap(error);
        if (attempt >= maxRetries || !TokenErrors.isRetryable(cause)) {
            return CompletableFuture.failedStage(cause);
        }
        return CompletableFuture.supplyAsync(
                        () -> null, delays.apply(delayFor(attempt, cause).toMillis()))
                .thenCompose(ignored -> attempt(attempt + 1));
    }

    private Duration delayFor(int attempt, Throwable cause) {
        if (cause instanceof TokenRequestException tokenRequestException) {
            Duration requested = tokenRequestException.retryAfter().orElse(null);
            if (requested != null) {
                return requested;
            }
        }
        Duration backoff = initialBackoff.multipliedBy(1L << Math.min(attempt, 20));
        return backoff.compareTo(MAXIMUM_BACKOFF) > 0 ? MAXIMUM_BACKOFF : backoff;
    }
}
