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

    private ExpiringDriver currentDriver;
    private final ReentrantReadWriteLock currentDriverMock = new ReentrantReadWriteLock();

    private final List<Driver> expiredDrivers = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService cleanupExecutor;

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory) {
        this(driverFactory, DEFAULT_CLEANUP_INTERVAL_MILLIS);
    }

    ReAuthDriver(Supplier<ExpiringDriver> driverFactory, long cleanupIntervalMillis) {
        this.driverFactory = driverFactory;
        currentDriver = driverFactory.get();

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
        cleanupExecutor.shutdown();
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
        var driverWithNoConnections = expiredDrivers.stream()
                .filter(driver -> {
                    var connectionPoolMetrics = driver.metrics().connectionPoolMetrics();
                    return connectionPoolMetrics.stream().allMatch(m -> m.inUse() == 0);
                })
                .collect(Collectors.toList());
        expiredDrivers.removeAll(driverWithNoConnections);
    }

    private <T> CompletionStage<T> checkExpirationAsync(Function<Driver, CompletionStage<T>> block) {
        return block.apply(currentDriver.getDriver())
                .handle((v, throwable) -> {
                    if (throwable != null) {
                        if (throwable instanceof TokenExpiredException) {
                            rotateCurrentDriver(currentDriver.hashCode());
                            return block.apply(currentDriver.getDriver());
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
        currentDriverMock.readLock().lock();
        var latestDriverHashCode = currentDriver.getDriver().hashCode();
        if (currentDriver.isExpired()) {
            rotateCurrentDriver(latestDriverHashCode);
        }
        try {
            return block.apply(currentDriver.getDriver());
        } catch (TokenExpiredException e) {
            rotateCurrentDriver(latestDriverHashCode);
            return block.apply(currentDriver.getDriver());
        } finally {
            currentDriverMock.readLock().unlock();
        }
    }

    private void rotateCurrentDriver(int hashCode) {
        currentDriverMock.readLock().unlock();
        currentDriverMock.writeLock().lock();
        try {
            if (currentDriver.getDriver().hashCode() == hashCode) {
                expiredDrivers.add(currentDriver.getDriver());
                currentDriver = driverFactory.get();
            }
            currentDriverMock.readLock().lock();
        } finally {
            currentDriverMock.writeLock().unlock();
        }
    }
}
