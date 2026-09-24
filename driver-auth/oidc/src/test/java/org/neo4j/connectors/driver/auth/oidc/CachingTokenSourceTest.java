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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class CachingTokenSourceTest {
    private static final Instant START = Instant.parse("2026-09-21T10:00:00Z");

    @Test
    void returnsTheHeldTokenWithoutAskingAgain() {
        CountingSource delegate = new CountingSource(START.plusSeconds(60));
        TokenSource source = new CachingTokenSource(delegate, Clock.fixed(START, ZoneOffset.UTC));

        IntStream.range(0, 5)
                .forEach(attempt -> source.fetch().toCompletableFuture().join());

        assertThat(delegate.calls()).isEqualTo(1);
    }

    @Test
    void asksAgainOnceTheRefreshWindowOpens() {
        CountingSource delegate = new CountingSource(START.plusSeconds(60));
        MovableClock clock = new MovableClock(START);
        TokenSource source = new CachingTokenSource(delegate, clock);

        source.fetch().toCompletableFuture().join();
        clock.advance(Duration.ofSeconds(61));
        source.fetch().toCompletableFuture().join();

        assertThat(delegate.calls()).isEqualTo(2);
    }

    @Test
    void doesNotRefetchExactlyAtTheExpiryInstant() {
        CountingSource delegate = new CountingSource(START.plusSeconds(60));
        MovableClock clock = new MovableClock(START);
        TokenSource source = new CachingTokenSource(delegate, clock);

        source.fetch().toCompletableFuture().join();
        clock.advance(Duration.ofSeconds(60));
        source.fetch().toCompletableFuture().join();

        assertThat(delegate.calls()).isEqualTo(2);
    }

    @Test
    void letsConcurrentCallersShareOneInFlightFetch() {
        DeferredSource delegate = new DeferredSource();
        TokenSource source = new CachingTokenSource(delegate, Clock.fixed(START, ZoneOffset.UTC));
        CyclicBarrier startLine = new CyclicBarrier(8);

        List<CompletableFuture<AccessToken>> fetches = IntStream.range(0, 8)
                .mapToObj(attempt -> CompletableFuture.supplyAsync(() -> {
                            await(startLine);
                            return source.fetch();
                        })
                        .thenCompose(stage -> stage))
                .toList();
        delegate.release(new AccessToken("a-token", START.plusSeconds(60), null));
        CompletableFuture.allOf(fetches.toArray(CompletableFuture[]::new)).join();

        assertThat(delegate.calls()).isEqualTo(1);
        assertThat(fetches).allSatisfy(fetch -> assertThat(fetch.join().value()).isEqualTo("a-token"));
    }

    @Test
    void doesNotCacheAFailure() {
        AtomicInteger calls = new AtomicInteger();
        TokenSource delegate = () -> calls.incrementAndGet() == 1
                ? CompletableFuture.failedStage(new TokenRequestException("nope", 503, null, true, null, null))
                : CompletableFuture.completedStage(new AccessToken("a-token", START.plusSeconds(60), null));
        TokenSource source = new CachingTokenSource(delegate, Clock.fixed(START, ZoneOffset.UTC));

        assertThatThrownBy(() -> source.fetch().toCompletableFuture().join())
                .hasCauseInstanceOf(TokenRequestException.class);

        assertThat(source.fetch().toCompletableFuture().join().value()).isEqualTo("a-token");
        assertThat(calls.get()).isEqualTo(2);
    }

    @Test
    void unwrapsTheCompletionExceptionSoCallersSeeTheRealFailure() {
        TokenSource delegate = () -> CompletableFuture.failedStage(new java.util.concurrent.CompletionException(
                new TokenRequestException("nope", 401, "invalid_client", false, null, null)));
        TokenSource source = new CachingTokenSource(delegate, Clock.fixed(START, ZoneOffset.UTC));

        assertThatThrownBy(() -> source.fetch().toCompletableFuture().join())
                .hasCauseInstanceOf(TokenRequestException.class);
    }

    private static void await(CyclicBarrier barrier) {
        try {
            barrier.await();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class CountingSource implements TokenSource {
        private final Instant expiresAt;
        private final AtomicInteger calls = new AtomicInteger();

        CountingSource(Instant expiresAt) {
            this.expiresAt = expiresAt;
        }

        @Override
        public CompletionStage<AccessToken> fetch() {
            calls.incrementAndGet();
            return CompletableFuture.completedStage(new AccessToken("a-token", expiresAt, null));
        }

        int calls() {
            return calls.get();
        }
    }

    /** Hands out one future and completes it only when the test says so. */
    private static final class DeferredSource implements TokenSource {
        private final AtomicInteger calls = new AtomicInteger();
        private final AtomicReference<CompletableFuture<AccessToken>> pending =
                new AtomicReference<>(new CompletableFuture<>());

        @Override
        public CompletionStage<AccessToken> fetch() {
            calls.incrementAndGet();
            return pending.get();
        }

        void release(AccessToken token) {
            pending.get().complete(token);
        }

        int calls() {
            return calls.get();
        }
    }

    private static final class MovableClock extends Clock {
        private Instant now;

        MovableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
