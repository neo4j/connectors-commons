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
import static org.neo4j.driver.internal.AbstractQueryRunner.*;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.neo4j.driver.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ReAuthSession implements Session {

    private static final Logger log = LoggerFactory.getLogger(ReAuthSession.class);

    private final ReAuthDriver driver;
    private final AtomicReference<Session> delegate = new AtomicReference<>();
    private final Supplier<Session> sessionSupplier;

    ReAuthSession(ReAuthDriver driver, Supplier<Session> sessionSupplier) {
        this.driver = driver;
        this.sessionSupplier = sessionSupplier;
        this.delegate.set(sessionSupplier.get());
    }

    @Override
    public Transaction beginTransaction() {
        return beginTransaction(TransactionConfig.empty());
    }

    @Override
    public Transaction beginTransaction(TransactionConfig config) {
        return withExpiringSession(() -> delegate.get().beginTransaction(config));
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work) {
        return readTransaction(work, TransactionConfig.empty());
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work, TransactionConfig config) {
        return withExpiringSession(() -> this.delegate.get().readTransaction(work, config));
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work) {
        return writeTransaction(work, TransactionConfig.empty());
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work, TransactionConfig config) {
        return withExpiringSession(() -> this.delegate.get().writeTransaction(work, config));
    }

    @Override
    public Result run(String query, TransactionConfig config) {
        return run(new Query(query, emptyMap()), config);
    }

    @Override
    public Result run(String query, Map<String, Object> parameters, TransactionConfig config) {
        return run(new Query(query, parameters), config);
    }

    @Override
    public Result run(Query query, TransactionConfig config) {
        return withExpiringSession(() -> this.delegate.get().run(query, config));
    }

    @Override
    public Bookmark lastBookmark() {
        return delegate.get().lastBookmark();
    }

    @Deprecated
    @Override
    public void reset() {
        delegate.get().reset();
    }

    @Override
    public void close() {
        delegate.get().close();
    }

    @Override
    public Result run(String query, Value parameters) {
        return run(new Query(query, parameters), TransactionConfig.empty());
    }

    @Override
    public Result run(String query, Map<String, Object> parameters) {
        return run(new Query(query, parameters), TransactionConfig.empty());
    }

    @Override
    public Result run(String query, Record parameters) {
        return run(new Query(query, parameters(parameters)), TransactionConfig.empty());
    }

    @Override
    public Result run(String query) {
        return run(new Query(query, emptyMap()), TransactionConfig.empty());
    }

    @Override
    public Result run(Query query) {
        return run(query, TransactionConfig.empty());
    }

    @Override
    public boolean isOpen() {
        return delegate.get().isOpen();
    }

    private <T> T withExpiringSession(Supplier<T> block) {
        return driver.withRefresh(block, () -> {
            log.debug("Creating new session to replace expired one");
            Utils.closeQuietly(delegate.getAndSet(sessionSupplier.get()));
        });
    }
}
