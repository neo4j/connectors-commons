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

import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Metrics;
import org.neo4j.driver.Session;
import org.neo4j.driver.SessionConfig;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.types.TypeSystem;

public class TrackingDriver implements Driver {

    private final Driver delegate;
    private final AtomicInteger sessionCount = new AtomicInteger(0);

    public TrackingDriver(Driver delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean isEncrypted() {
        return delegate.isEncrypted();
    }

    @Override
    public Session session() {
        return session(SessionConfig.defaultConfig());
    }

    @Override
    public Session session(SessionConfig sessionConfig) {
        var session = delegate.session(sessionConfig);
        sessionCount.incrementAndGet();
        return new TrackedSession(this, session);
    }

    @Override
    public RxSession rxSession() {
        return rxSession(SessionConfig.defaultConfig());
    }

    @Override
    public RxSession rxSession(SessionConfig sessionConfig) {
        var session = delegate.rxSession(sessionConfig);
        sessionCount.incrementAndGet();
        return new TrackedRxSession(this, session);
    }

    @Override
    public AsyncSession asyncSession() {
        return asyncSession(SessionConfig.defaultConfig());
    }

    @Override
    public AsyncSession asyncSession(SessionConfig sessionConfig) {
        var session = delegate.asyncSession(sessionConfig);
        sessionCount.incrementAndGet();
        return new TrackedAsyncSession(this, session);
    }

    @Override
    public void close() {
        delegate.close();
    }

    @Override
    public CompletionStage<Void> closeAsync() {
        return delegate.closeAsync();
    }

    @Override
    public Metrics metrics() {
        return delegate.metrics();
    }

    @Override
    public boolean isMetricsEnabled() {
        return delegate.isMetricsEnabled();
    }

    @Override
    public TypeSystem defaultTypeSystem() {
        return delegate.defaultTypeSystem();
    }

    @Override
    public void verifyConnectivity() {
        delegate.verifyConnectivity();
    }

    @Override
    public CompletionStage<Void> verifyConnectivityAsync() {
        return delegate.verifyConnectivityAsync();
    }

    @Override
    public boolean supportsMultiDb() {
        return delegate.supportsMultiDb();
    }

    @Override
    public CompletionStage<Boolean> supportsMultiDbAsync() {
        return delegate.supportsMultiDbAsync();
    }

    public void onSessionClosure() {
        sessionCount.decrementAndGet();
    }

    public int getOpenSessionCount() {
        return sessionCount.get();
    }
}
