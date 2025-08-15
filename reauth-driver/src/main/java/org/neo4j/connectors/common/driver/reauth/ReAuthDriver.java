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
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Metrics;
import org.neo4j.driver.Session;
import org.neo4j.driver.SessionConfig;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.exceptions.AuthenticationException;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.types.TypeSystem;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

public class ReAuthDriver implements Driver {

    private static final Logger log = LoggerFactory.getLogger(ReAuthDriver.class);

    private static final long DEFAULT_CLEANUP_INTERVAL_MILLIS = 5 * 60 * 1000L;

    private final Supplier<ExpiringDriver> driverFactory;

    private ExpiringDriver currentDriver;
    private final ReentrantLock currentDriverLock = new ReentrantLock();

    final List<Driver> expiredDrivers = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService cleanupExecutor;

    ReAuthDriver(ExpiringDriver currentDriver, Supplier<ExpiringDriver> driverFactory) {
        this(currentDriver, driverFactory, DEFAULT_CLEANUP_INTERVAL_MILLIS);
    }

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory) {
        this(driverFactory.get(), driverFactory, DEFAULT_CLEANUP_INTERVAL_MILLIS);
    }

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory, long cleanupIntervalMillis) {
        this(driverFactory.get(), driverFactory, cleanupIntervalMillis);
    }

    ReAuthDriver(ExpiringDriver currentDriver, Supplier<ExpiringDriver> driverFactory, long cleanupIntervalMillis) {
        this.driverFactory = driverFactory;
        this.currentDriver = currentDriver;
        if (!currentDriver.getDriver().isMetricsEnabled()) {
            throw new IllegalArgumentException("Driver must be configured with metrics enabled");
        }

        cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
        cleanupExecutor.scheduleAtFixedRate(
                this::cleanUpPreviousDrivers, cleanupIntervalMillis, cleanupIntervalMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public boolean isEncrypted() {
        return currentDriver.getDriver().isEncrypted();
    }

    @Override
    public Session session() {
        return session(SessionConfig.defaultConfig());
    }

    @Override
    public Session session(SessionConfig sessionConfig) {
        return checkExpiration(() ->
                new ReAuthSession(this, () ->
                        this.currentDriver.getDriver().session(sessionConfig)));
    }

    @Override
    public RxSession rxSession() {
        return rxSession(SessionConfig.defaultConfig());
    }

    @Override
    public RxSession rxSession(SessionConfig sessionConfig) {
        return checkExpiration(() ->
                new ReAuthRxSession(this, () ->
                        this.currentDriver.getDriver().rxSession(sessionConfig)));
    }

    @Override
    public AsyncSession asyncSession() {
        return asyncSession(SessionConfig.defaultConfig());
    }

    @Override
    public AsyncSession asyncSession(SessionConfig sessionConfig) {
        return checkExpiration(() -> this.currentDriver.getDriver().asyncSession(sessionConfig));
    }

    @Override
    public void close() {
        expiredDrivers.forEach(Driver::close);
        currentDriver.getDriver().close();
        cleanupExecutor.shutdownNow();
    }

    @Override
    public CompletionStage<Void> closeAsync() {
        var closeAsync = currentDriver.getDriver().closeAsync();
        return expiredDrivers.stream()
                .map(Driver::closeAsync)
                .reduce(closeAsync, (acc, ca) -> acc.thenCombine(ca, (a, b) -> b));
    }

    @Override
    public Metrics metrics() {
        return currentDriver.getDriver().metrics();
    }

    @Override
    public boolean isMetricsEnabled() {
        return currentDriver.getDriver().isMetricsEnabled();
    }

    @Override
    public TypeSystem defaultTypeSystem() {
        return currentDriver.getDriver().defaultTypeSystem();
    }

    @Override
    public void verifyConnectivity() {
        currentDriver.getDriver().verifyConnectivity();
    }

    @Override
    public CompletionStage<Void> verifyConnectivityAsync() {
        return currentDriver.getDriver().verifyConnectivityAsync();
    }

    @Override
    public boolean supportsMultiDb() {
        return currentDriver.getDriver().supportsMultiDb();
    }

    @Override
    public CompletionStage<Boolean> supportsMultiDbAsync() {
        return currentDriver.getDriver().supportsMultiDbAsync();
    }

    private void cleanUpPreviousDrivers() {
        var driverWithNoConnections = expiredDrivers.stream()
                .filter(driver -> {
                    var connectionPoolMetrics = driver.metrics().connectionPoolMetrics();
                    return connectionPoolMetrics.stream().allMatch(m -> m.inUse() == 0);
                })
                .collect(Collectors.toList());
        driverWithNoConnections.forEach(Driver::close);
        expiredDrivers.removeAll(driverWithNoConnections);
    }

    private <T> T checkExpiration(Supplier<T> block) {
        var latestDriverHashCode = System.identityHashCode(currentDriver.getDriver());
        if (currentDriver.isExpired()) {
            withLock(() -> rotateCurrentDriver(latestDriverHashCode));
        }
        return block.get();
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
        var driverHashCode = System.identityHashCode(currentDriver.getDriver());
        try {
            return block.get();
        } catch (AuthenticationException e) {
            withLock(() -> {
                log.debug("Driver has expired, re-creating a new one");
                rotateCurrentDriver(driverHashCode);
                refresh.run();
            });
            return block.get();
        }
    }

    <T> Publisher<T> withRxRefresh(Supplier<Publisher<T>> block, Runnable refresh) {
        return Mono.defer(() -> {
            var driverHashCode = System.identityHashCode(currentDriver.getDriver());
            return Mono.from(block.get())
                    .onErrorResume(AuthenticationException.class, e ->
                        Mono.fromRunnable(() -> withLock(() -> {
                            log.debug("Driver has expired, re-creating a new one");
                            rotateCurrentDriver(driverHashCode);
                            refresh.run();
                        }))
                        .then(Mono.defer(() -> Mono.from(block.get())))
                    );
        });
    }

    void rotateCurrentDriver(int hashCode) {
        log.debug("Rotating driver");
        // Verify hash code because the current driver may be updated by another thread
        if (System.identityHashCode(currentDriver.getDriver()) == hashCode) {
            log.debug("Replacing current driver with new one");
            expiredDrivers.add(currentDriver.getDriver());
            currentDriver = driverFactory.get();
        }
    }
}
