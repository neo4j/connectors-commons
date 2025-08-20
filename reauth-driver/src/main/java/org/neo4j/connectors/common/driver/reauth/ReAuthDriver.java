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

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.neo4j.connectors.common.driver.reauth.tracking.TrackingDriver;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Metrics;
import org.neo4j.driver.Session;
import org.neo4j.driver.SessionConfig;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.exceptions.SecurityException;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.types.TypeSystem;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

public class ReAuthDriver implements Driver {

    private static final Logger log = LoggerFactory.getLogger(ReAuthDriver.class);

    private static final long DEFAULT_CLEANUP_INTERVAL_MILLIS = 5 * 60 * 1000L;

    private final Supplier<Driver> driverFactory;

    private final AtomicReference<TrackingDriver> currentDriver = new AtomicReference<>();
    private final ReentrantLock currentDriverLock = new ReentrantLock();

    final List<TrackingDriver> expiredDrivers = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService cleanupExecutor;

    ReAuthDriver(Driver currentDriver, Supplier<Driver> driverFactory) {
        this(currentDriver, driverFactory, DEFAULT_CLEANUP_INTERVAL_MILLIS);
    }

    ReAuthDriver(Supplier<Driver> driverFactory) {
        this(driverFactory.get(), driverFactory, DEFAULT_CLEANUP_INTERVAL_MILLIS);
    }

    ReAuthDriver(Supplier<Driver> driverFactory, long cleanupIntervalMillis) {
        this(driverFactory.get(), driverFactory, cleanupIntervalMillis);
    }

    ReAuthDriver(Driver currentDriver, Supplier<Driver> driverFactory, long cleanupIntervalMillis) {
        this.driverFactory = driverFactory;
        this.currentDriver.set(new TrackingDriver(currentDriver));

        cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
        cleanupExecutor.scheduleAtFixedRate(
                this::cleanUpExpiredDrivers, cleanupIntervalMillis, cleanupIntervalMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public boolean isEncrypted() {
        return currentDriver.get().isEncrypted();
    }

    @Override
    public Session session() {
        return session(SessionConfig.defaultConfig());
    }

    @Override
    public Session session(SessionConfig sessionConfig) {
        return checkExpiration(
                () -> new ReAuthSession(this, () -> this.currentDriver.get().session(sessionConfig)));
    }

    @Override
    public RxSession rxSession() {
        return rxSession(SessionConfig.defaultConfig());
    }

    @Override
    public RxSession rxSession(SessionConfig sessionConfig) {
        return checkExpiration(
                () -> new ReAuthRxSession(this, () -> this.currentDriver.get().rxSession(sessionConfig)));
    }

    @Override
    public AsyncSession asyncSession() {
        return asyncSession(SessionConfig.defaultConfig());
    }

    @Override
    public AsyncSession asyncSession(SessionConfig sessionConfig) {
        return checkExpiration(() ->
                new ReAuthAsyncSession(this, () -> this.currentDriver.get().asyncSession(sessionConfig)));
    }

    @Override
    public void close() {
        expiredDrivers.forEach(Utils::closeQuietly);
        currentDriver.get().close();
        cleanupExecutor.shutdownNow();
    }

    @Override
    public CompletionStage<Void> closeAsync() {
        var closeAsync = currentDriver.get().closeAsync();
        return expiredDrivers.stream()
                .map(Driver::closeAsync)
                .reduce(closeAsync, (acc, ca) -> acc.thenCombine(ca, (a, b) -> b));
    }

    @Override
    public Metrics metrics() {
        return currentDriver.get().metrics();
    }

    @Override
    public boolean isMetricsEnabled() {
        return currentDriver.get().isMetricsEnabled();
    }

    @Override
    public TypeSystem defaultTypeSystem() {
        return currentDriver.get().defaultTypeSystem();
    }

    @Override
    public void verifyConnectivity() {
        currentDriver.get().verifyConnectivity();
    }

    @Override
    public CompletionStage<Void> verifyConnectivityAsync() {
        return currentDriver.get().verifyConnectivityAsync();
    }

    @Override
    public boolean supportsMultiDb() {
        return currentDriver.get().supportsMultiDb();
    }

    @Override
    public CompletionStage<Boolean> supportsMultiDbAsync() {
        return currentDriver.get().supportsMultiDbAsync();
    }

    void cleanUpExpiredDrivers() {
        var driverWithNoConnections = expiredDrivers.stream()
                .filter(driver -> driver.getOpenSessionCount() == 0)
                .collect(Collectors.toList());
        driverWithNoConnections.forEach(Utils::closeQuietly);
        expiredDrivers.removeAll(driverWithNoConnections);
    }

    private <T> T checkExpiration(Supplier<T> block) {
        return withRefresh(block, () -> {});
    }

    void withLock(Runnable block) {
        currentDriverLock.lock();
        try {
            block.run();
        } finally {
            currentDriverLock.unlock();
        }
    }

    <T> T withRefresh(Supplier<T> block, Runnable refresh) {
        var driverHashCode = System.identityHashCode(currentDriver.get());
        try {
            return block.get();
        } catch (SecurityException e) {
            withLock(() -> {
                log.debug("Caught authentication exception. Try to refresh the driver and retry.");
                rotateCurrentDriver(driverHashCode);
                refresh.run();
            });
            return block.get();
        }
    }

    <T> Publisher<T> withRxRefresh(Supplier<Publisher<T>> block, Supplier<Publisher<Void>> refresh) {
        return Mono.defer(() -> {
            var driverHashCode = System.identityHashCode(currentDriver.get());
            return Mono.from(block.get())
                    .onErrorResume(SecurityException.class, e -> Mono.fromRunnable(() -> withLock(() -> {
                                log.debug("Caught authentication exception. Try to refresh the driver and retry.");
                                rotateCurrentDriver(driverHashCode);
                            }))
                            .then(Mono.defer(() -> Mono.from(refresh.get())))
                            .then(Mono.defer(() -> Mono.from(block.get()))));
        });
    }

    <T> CompletionStage<T> withRefreshAsync(
            Supplier<CompletionStage<T>> block, Supplier<CompletionStage<Void>> refresh) {
        var driverHashCode = System.identityHashCode(currentDriver.get());
        return block.get()
                .handle((value, e) -> {
                    if (e == null) {
                        return CompletableFuture.completedStage(value);
                    }
                    if (e instanceof SecurityException || e.getCause() instanceof SecurityException) {
                        return CompletableFuture.runAsync(() -> withLock(() -> {
                                    log.debug("Caught authentication exception. Try to refresh the driver and retry.");
                                    rotateCurrentDriver(driverHashCode);
                                }))
                                .thenCompose(vd -> refresh.get())
                                .thenCompose(vd -> block.get());
                    }
                    return CompletableFuture.<T>failedStage(e);
                })
                .thenCompose(Function.identity());
    }

    void rotateCurrentDriver(int hashCode) {
        // Verify hash code because the current driver may be updated by another thread
        if (System.identityHashCode(currentDriver.get()) == hashCode) {
            expiredDrivers.add(currentDriver.get());
            currentDriver.set(new TrackingDriver(driverFactory.get()));
        }
    }
}
