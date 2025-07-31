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

import static java.util.function.Function.identity;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.neo4j.driver.*;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.exceptions.TokenExpiredException;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.types.TypeSystem;

public class ReAuthDriver implements Driver {

    private final static long DEFAULT_CLEANUP_INTERVAL_MILLIS = 5 * 60 * 1000L;

    private final Supplier<ExpiringDriver> driverFactory;

    private ExpiringDriver latestDriver;
    private final ReentrantReadWriteLock latestDriverLock = new ReentrantReadWriteLock();

    private final List<Driver> previousDrivers = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService cleanupExecutor;

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory) {
        this(driverFactory, DEFAULT_CLEANUP_INTERVAL_MILLIS);
    }

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory, long cleanupIntervalMillis) {
        this.driverFactory = driverFactory;
        latestDriver = driverFactory.get();

        cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
        cleanupExecutor.scheduleAtFixedRate(
                this::cleanUpPreviousDrivers, cleanupIntervalMillis, cleanupIntervalMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public boolean isEncrypted() {
        return latestDriver.getDriver().isEncrypted();
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
        previousDrivers.forEach(Driver::close);
        latestDriver.getDriver().close();
        cleanupExecutor.shutdown();
    }

    @Override
    public CompletionStage<Void> closeAsync() {
        var closeAsync = latestDriver.getDriver().closeAsync();
        return previousDrivers.stream()
                .map(Driver::closeAsync)
                .reduce(closeAsync, (acc, ca) -> acc.thenCombine(ca, (a, b) -> b));
    }

    @Override
    public Metrics metrics() {
        return latestDriver.getDriver().metrics();
    }

    @Override
    public boolean isMetricsEnabled() {
        return latestDriver.getDriver().isMetricsEnabled();
    }

    @Override
    public TypeSystem defaultTypeSystem() {
        return latestDriver.getDriver().defaultTypeSystem();
    }

    @Override
    public void verifyConnectivity() {
        checkExpiration(Driver::verifyConnectivity);
    }

    @Override
    public CompletionStage<Void> verifyConnectivityAsync() {
        return checkExpirationAsync(Driver::verifyConnectivityAsync);
    }

    @Override
    public boolean supportsMultiDb() {
        return checkExpiration(Driver::supportsMultiDb);
    }

    @Override
    public CompletionStage<Boolean> supportsMultiDbAsync() {
        return checkExpirationAsync(Driver::supportsMultiDbAsync);
    }

    private void cleanUpPreviousDrivers() {
        var driverWithNoConnections = previousDrivers.stream()
                .filter(driver -> {
                    var connectionPoolMetrics = driver.metrics().connectionPoolMetrics();
                    return connectionPoolMetrics.stream().allMatch(m -> m.inUse() == 0);
                })
                .collect(Collectors.toList());
        previousDrivers.removeAll(driverWithNoConnections);
    }

    private <T> CompletionStage<T> checkExpirationAsync(Function<Driver, CompletionStage<T>> block) {
        return block.apply(latestDriver.getDriver())
                .handle((v, throwable) -> {
                    if (throwable != null) {
                        if (throwable instanceof TokenExpiredException) {
                            rotateLatestDriver(latestDriver.hashCode());
                            return block.apply(latestDriver.getDriver());
                        }
                        return CompletableFuture.<T>failedFuture(throwable);
                    }
                    return CompletableFuture.completedFuture(v);
                })
                .thenCompose(identity());
    }

    private void checkExpiration(Consumer<Driver> block) {
        checkExpiration((Driver driver) -> {
            block.accept(driver);
            return null;
        });
    }

    private <T> T checkExpiration(Function<Driver, T> block) {
        latestDriverLock.readLock().lock();
        var latestDriverHashCode = latestDriver.getDriver().hashCode();
        if (latestDriver.isExpired()) {
            rotateLatestDriver(latestDriverHashCode);
        }
        try {
            return block.apply(latestDriver.getDriver());
        } catch (TokenExpiredException e) {
            rotateLatestDriver(latestDriverHashCode);
            return block.apply(latestDriver.getDriver());
        } finally {
            latestDriverLock.readLock().unlock();
        }
    }

    private void rotateLatestDriver(int hashCode) {
        latestDriverLock.readLock().unlock();
        latestDriverLock.writeLock().lock();
        try {
            if (latestDriver.getDriver().hashCode() == hashCode) {
                previousDrivers.add(latestDriver.getDriver());
                latestDriver = driverFactory.get();
            }
            latestDriverLock.readLock().lock();
        } finally {
            latestDriverLock.writeLock().unlock();
        }
    }
}
