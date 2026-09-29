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

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;
import java.util.function.LongFunction;
import org.junit.jupiter.api.Test;

class RetryingTokenSourceTest {
    private static final Instant EXPIRY = Instant.parse("2026-09-21T11:00:00Z");
    private static final AccessToken TOKEN = new AccessToken("a-token", EXPIRY, null);

    @Test
    void doesNotRetryWhatSucceeded() {
        AtomicInteger calls = new AtomicInteger();

        AccessToken token = source(attempt -> {
                    calls.incrementAndGet();
                    return CompletableFuture.completedStage(TOKEN);
                })
                .fetch()
                .toCompletableFuture()
                .join();

        assertThat(token).isEqualTo(TOKEN);
        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    void retriesATransientFailureUntilItSucceeds() {
        AtomicInteger calls = new AtomicInteger();

        AccessToken token = source(attempt -> calls.incrementAndGet() < 3
                        ? CompletableFuture.failedStage(new IOException("connection reset"))
                        : CompletableFuture.completedStage(TOKEN))
                .fetch()
                .toCompletableFuture()
                .join();

        assertThat(token).isEqualTo(TOKEN);
        assertThat(calls.get()).isEqualTo(3);
    }

    @Test
    void neverRetriesADeadCredential() {
        AtomicInteger calls = new AtomicInteger();

        assertThatThrownBy(() -> source(attempt -> {
                            calls.incrementAndGet();
                            return CompletableFuture.failedStage(
                                    new TokenRequestException("no", 401, "invalid_client", false, null, null));
                        })
                        .fetch()
                        .toCompletableFuture()
                        .join())
                .hasCauseInstanceOf(TokenRequestException.class);

        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    void givesUpAfterTheConfiguredNumberOfAttempts() {
        AtomicInteger calls = new AtomicInteger();

        assertThatThrownBy(() -> source(attempt -> {
                            calls.incrementAndGet();
                            return CompletableFuture.failedStage(new IOException("down"));
                        })
                        .fetch()
                        .toCompletableFuture()
                        .join())
                .hasCauseInstanceOf(IOException.class);

        assertThat(calls.get()).isEqualTo(4);
    }

    @Test
    void doublesTheBackoffPerAttempt() {
        RecordingDelays delays = new RecordingDelays();
        AtomicInteger calls = new AtomicInteger();

        assertThatThrownBy(() -> new RetryingTokenSource(
                                () -> {
                                    calls.incrementAndGet();
                                    return CompletableFuture.failedStage(new IOException("down"));
                                },
                                3,
                                Duration.ofMillis(10),
                                delays)
                        .fetch()
                        .toCompletableFuture()
                        .join())
                .hasCauseInstanceOf(IOException.class);

        assertThat(delays.observed()).containsExactly(10L, 20L, 40L);
    }

    @Test
    void honoursRetryAfterOverItsOwnSchedule() {
        RecordingDelays delays = new RecordingDelays();
        AtomicInteger calls = new AtomicInteger();

        new RetryingTokenSource(
                        () -> calls.incrementAndGet() == 1
                                ? CompletableFuture.failedStage(new TokenRequestException(
                                        "slow down", 429, null, true, Duration.ofMillis(75), null))
                                : CompletableFuture.completedStage(TOKEN),
                        3,
                        Duration.ofMillis(10),
                        delays)
                .fetch()
                .toCompletableFuture()
                .join();

        assertThat(delays.observed()).containsExactly(75L);
    }

    private static TokenSource source(IntFunction<CompletionStage<AccessToken>> attempts) {
        AtomicInteger attempt = new AtomicInteger();
        return new RetryingTokenSource(
                () -> attempts.apply(attempt.getAndIncrement()), 3, Duration.ofMillis(1), Runnable::run);
    }

    /**
     * Records how long each retry was asked to wait and then runs it immediately, so the schedule can
     * be asserted without the test actually sleeping.
     */
    private static final class RecordingDelays implements LongFunction<Executor> {
        private final List<Long> delays = new CopyOnWriteArrayList<>();

        @Override
        public Executor apply(long millis) {
            delays.add(millis);
            return Runnable::run;
        }

        List<Long> observed() {
            return List.copyOf(delays);
        }
    }
}
