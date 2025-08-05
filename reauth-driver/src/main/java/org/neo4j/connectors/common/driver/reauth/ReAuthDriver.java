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
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.neo4j.driver.*;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.exceptions.TokenExpiredException;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.types.TypeSystem;

public class ReAuthDriver implements Driver {

    private static final long DEFAULT_CLEANUP_INTERVAL_MILLIS = 5 * 60 * 1000L;

    private final Supplier<ExpiringDriver> driverFactory;

    private ExpiringDriver currentDriver;
    private final ReentrantReadWriteLock currentDriverLock = new ReentrantReadWriteLock();

    final List<Driver> expiredDrivers = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService cleanupExecutor;

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory) {
        this(driverFactory, DEFAULT_CLEANUP_INTERVAL_MILLIS);
    }

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory, long cleanupIntervalMillis) {
        this.driverFactory = driverFactory;
        currentDriver = driverFactory.get();
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
        return checkExpiration((Driver driver) -> driver.session(sessionConfig));
    }

    @Override
    public RxSession rxSession() {
        return rxSession(SessionConfig.defaultConfig());
    }

    @Override
    public RxSession rxSession(SessionConfig sessionConfig) {
        return checkExpiration((Driver driver) -> driver.rxSession(sessionConfig));
    }

    @Override
    public AsyncSession asyncSession() {
        return asyncSession(SessionConfig.defaultConfig());
    }

    @Override
    public AsyncSession asyncSession(SessionConfig sessionConfig) {
        return checkExpiration((Driver driver) -> driver.asyncSession(sessionConfig));
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

    private <T> T checkExpiration(Function<Driver, T> block) {
        currentDriverLock.readLock().lock();
        var latestDriverHashCode = currentDriver.getDriver().hashCode();
        if (currentDriver.isExpired()) {
            currentDriverLock.readLock().unlock();
            rotateCurrentDriver(latestDriverHashCode);
            currentDriverLock.readLock().lock();
        }
        currentDriverLock.readLock().unlock();
        try {
            return block.apply(currentDriver.getDriver());
        } catch (TokenExpiredException e) {
            rotateCurrentDriver(latestDriverHashCode);
            return block.apply(currentDriver.getDriver());
        }
    }

    private void rotateCurrentDriver(int hashCode) {
        currentDriverLock.writeLock().lock();
        try {
            // Verify hash code because current driver may be updated by another thread
            if (currentDriver.getDriver().hashCode() == hashCode) {
                expiredDrivers.add(currentDriver.getDriver());
                currentDriver = driverFactory.get();
            }
        } finally {
            currentDriverLock.writeLock().unlock();
        }
    }
}
