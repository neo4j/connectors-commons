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
package org.neo4j.connectors.common.driver.reauth;

import static java.util.Collections.emptyMap;
import static org.neo4j.driver.internal.AbstractQueryRunner.parameters;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Supplier;
import org.neo4j.driver.Bookmark;
import org.neo4j.driver.Query;
import org.neo4j.driver.Record;
import org.neo4j.driver.TransactionConfig;
import org.neo4j.driver.Value;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.async.AsyncTransaction;
import org.neo4j.driver.async.AsyncTransactionWork;
import org.neo4j.driver.async.ResultCursor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReAuthAsyncSession implements AsyncSession {

    private static final Logger log = LoggerFactory.getLogger(ReAuthRxSession.class);

    private final ReAuthDriver driver;
    private final AtomicReference<AsyncSession> delegate = new AtomicReference<>();
    private final Supplier<AsyncSession> sessionSupplier;

    public ReAuthAsyncSession(ReAuthDriver driver, Supplier<AsyncSession> sessionSupplier) {
        this.driver = driver;
        this.sessionSupplier = sessionSupplier;
        this.delegate.set(sessionSupplier.get());
    }

    @Override
    public CompletionStage<AsyncTransaction> beginTransactionAsync() {
        return beginTransactionAsync(TransactionConfig.empty());
    }

    @Override
    public CompletionStage<AsyncTransaction> beginTransactionAsync(TransactionConfig config) {
        return withExpiringAsyncSession(() -> delegate.get().beginTransactionAsync(config));
    }

    @Override
    public <T> CompletionStage<T> readTransactionAsync(AsyncTransactionWork<CompletionStage<T>> work) {
        return readTransactionAsync(work, TransactionConfig.empty());
    }

    @Override
    public <T> CompletionStage<T> readTransactionAsync(
            AsyncTransactionWork<CompletionStage<T>> work, TransactionConfig config) {
        return withExpiringAsyncSession(() -> delegate.get().readTransactionAsync(work, config));
    }

    @Override
    public <T> CompletionStage<T> writeTransactionAsync(AsyncTransactionWork<CompletionStage<T>> work) {
        return writeTransactionAsync(work, TransactionConfig.empty());
    }

    @Override
    public <T> CompletionStage<T> writeTransactionAsync(
            AsyncTransactionWork<CompletionStage<T>> work, TransactionConfig config) {
        return withExpiringAsyncSession(() -> delegate.get().writeTransactionAsync(work, config));
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, TransactionConfig config) {
        return runAsync(new Query(query, emptyMap()), config);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(
            String query, Map<String, Object> parameters, TransactionConfig config) {
        return runAsync(new Query(query, parameters), config);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(Query query, TransactionConfig config) {
        return withExpiringAsyncSession(() -> delegate.get().runAsync(query, config));
    }

    @Override
    public Bookmark lastBookmark() {
        return delegate.get().lastBookmark();
    }

    @Override
    public CompletionStage<Void> closeAsync() {
        return delegate.get().closeAsync();
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, Value parameters) {
        return runAsync(new Query(query, parameters), TransactionConfig.empty());
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, Map<String, Object> parameters) {
        return runAsync(new Query(query, parameters), TransactionConfig.empty());
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, Record parameters) {
        return runAsync(new Query(query, parameters(parameters)), TransactionConfig.empty());
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query) {
        return runAsync(new Query(query, emptyMap()), TransactionConfig.empty());
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(Query query) {
        return runAsync(query, TransactionConfig.empty());
    }

    private <T> CompletionStage<T> withExpiringAsyncSession(Supplier<CompletionStage<T>> block) {
        return driver.withRefreshAsync(block, () -> {
            log.debug("Creating new session to replace expired one");
            var oldSession = delegate.getAndSet(sessionSupplier.get());
            return oldSession
                    .closeAsync()
                    .handle((v, e) -> {
                        if (e != null) {
                            log.debug("Failed to close async session", e);
                        }
                        return CompletableFuture.completedStage(v);
                    })
                    .thenCompose(Function.identity());
        });
    }
}
