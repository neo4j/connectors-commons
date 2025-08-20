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
package org.neo4j.connectors.common.driver.reauth.tracking;

import java.util.Map;
import java.util.Objects;
import org.neo4j.driver.*;

public class TrackedSession implements Session {

    private final TrackingDriver driver;
    private final Session delegate;

    public TrackedSession(TrackingDriver driver, Session delegate) {
        this.driver = Objects.requireNonNull(driver);
        this.delegate = Objects.requireNonNull(delegate);
    }

    @Override
    public Transaction beginTransaction() {
        return delegate.beginTransaction();
    }

    @Override
    public Transaction beginTransaction(TransactionConfig config) {
        return delegate.beginTransaction(config);
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work) {
        return delegate.readTransaction(work);
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work, TransactionConfig config) {
        return delegate.readTransaction(work, config);
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work) {
        return delegate.writeTransaction(work);
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work, TransactionConfig config) {
        return delegate.writeTransaction(work, config);
    }

    @Override
    public Result run(String query, TransactionConfig config) {
        return delegate.run(query, config);
    }

    @Override
    public Result run(String query, Map<String, Object> parameters, TransactionConfig config) {
        return delegate.run(query, parameters, config);
    }

    @Override
    public Result run(Query query, TransactionConfig config) {
        return delegate.run(query, config);
    }

    @Override
    public Bookmark lastBookmark() {
        return delegate.lastBookmark();
    }

    @Deprecated
    @Override
    public void reset() {
        delegate.reset();
    }

    @Override
    public void close() {
        delegate.close();
        driver.onSessionClosure();
    }

    @Override
    public Result run(String query, Value parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public Result run(String query, Map<String, Object> parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public Result run(String query, Record parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public Result run(String query) {
        return delegate.run(query);
    }

    @Override
    public Result run(Query query) {
        return delegate.run(query);
    }

    @Override
    public boolean isOpen() {
        return delegate.isOpen();
    }
}
