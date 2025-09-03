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

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.testcontainers.shaded.org.awaitility.Awaitility.await;
import static reactor.core.publisher.Flux.from;
import static reactor.core.publisher.Flux.usingWhen;
import static reactor.core.publisher.Mono.*;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.authorization.client.Configuration;
import org.neo4j.connectors.authn.BearerAuthenticationToken;
import org.neo4j.connectors.authn.keycloak.KeycloakOIDCAuthenticationSupplier;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Config;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Logging;
import org.neo4j.driver.Session;
import org.neo4j.driver.Transaction;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.async.ResultCursor;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.reactive.RxTransaction;
import org.testcontainers.containers.Neo4jContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import reactor.core.publisher.Mono;

@Testcontainers(disabledWithoutDocker = true)
public class ReAuthDriverIT {

    private static final ScheduledExecutorService SCHEDULER = Executors.newSingleThreadScheduledExecutor();

    private static final Duration SERVER_SIDE_TOKEN_LIFESPAN = Duration.ofSeconds(35);

    private static final Network NETWORK = Network.newNetwork();

    private static final KeycloakContainer KEYCLOAK = new KeycloakContainer("quay.io/keycloak/keycloak:26.2.5")
            .withNetwork(NETWORK)
            .withNetworkAliases("keycloak")
            .useTlsKeystore("/keycloak.jks", "testpwd")
            .withRealmImportFile("neo4j-sso-test-realm.json")
            .withEnv("KC_HOSTNAME", "https://keycloak:8443")
            .withEnv("KC_HOSTNAME_BACKCHANNEL_DYNAMIC", "true")
            .withLogConsumer(outputFrame -> System.out.print(outputFrame.getUtf8String()));

    @SuppressWarnings("resource")
    private static final Neo4jContainer<?> NEO4J = new Neo4jContainer<>(Optional.ofNullable(
                            System.getProperty("neo4j-connectors-commons.default-neo4j-image", "neo4j:5.26"))
                    .map(v -> !v.contains("-enterprise") ? v + "-enterprise" : v)
                    .orElseThrow(() -> new NoSuchElementException("No value present")))
            .waitingFor(Neo4jContainer.WAIT_FOR_BOLT)
            .withNetwork(NETWORK)
            .withEnv("NEO4J_ACCEPT_LICENSE_AGREEMENT", "yes")
            .withCopyFileToContainer(MountableFile.forClasspathResource("/keycloak.jks"), "/tmp/keycloak.jks")
            .withNeo4jConfig(
                    "server.jvm.additional",
                    "-Djavax.net.ssl.keyStore=/tmp/keycloak.jks -Djavax.net.ssl.keyStorePassword=testpwd -Djavax.net.ssl.trustStore=/tmp/keycloak.jks -Djavax.net.ssl.trustStorePassword=testpwd")
            .withNeo4jConfig("dbms.security.authentication_providers", "oidc-keycloak,native")
            .withNeo4jConfig("dbms.security.authorization_providers", "oidc-keycloak,native")
            .withNeo4jConfig("dbms.security.oidc.keycloak.display_name", "Keycloak")
            .withNeo4jConfig("dbms.security.oidc.keycloak.auth_flow", "pkce")
            .withNeo4jConfig(
                    "dbms.security.oidc.keycloak.well_known_discovery_uri",
                    "https://keycloak:8443/realms/neo4j-sso-test/.well-known/openid-configuration")
            .withNeo4jConfig(
                    "dbms.security.oidc.keycloak.params",
                    "client_id=neo4j-commons-client;response_type=code;scope=openid email roles")
            .withNeo4jConfig("dbms.security.oidc.keycloak.audience", "account")
            .withNeo4jConfig("dbms.security.oidc.keycloak.issuer", "https://keycloak:8443/realms/neo4j-sso-test")
            .withNeo4jConfig("dbms.security.oidc.keycloak.client_id", "neo4j-commons-client")
            .withNeo4jConfig("dbms.security.oidc.keycloak.claims.username", "preferred_username")
            .withNeo4jConfig("dbms.security.oidc.keycloak.claims.groups", "groups")
            .withNeo4jConfig("dbms.security.auth_cache_ttl", "1s")
            .withLogConsumer(outputFrame -> System.out.print(outputFrame.getUtf8String()));

    private static KeycloakOIDCAuthenticationSupplier authenticationSupplier;

    private static Configuration authzConfiguration;

    @BeforeAll
    static void startContainersAndMetrics() {
        KEYCLOAK.start();
        NEO4J.start();

        authzConfiguration = new Configuration(
                format("http://%s:%d", KEYCLOAK.getHost(), KEYCLOAK.getHttpPort()),
                "neo4j-sso-test",
                "neo4j-commons-client",
                mapOf("secret", "QNrSpbh0mxhnlYlI21UcBaz3Htb734vi"),
                HttpClients.createMinimal());
        authenticationSupplier = (KeycloakOIDCAuthenticationSupplier)
                KeycloakOIDCAuthenticationSupplier.of("john-tester", "testerpwd", authzConfiguration);
    }

    static Stream<Arguments> expiringMethods() {
        Stream.Builder<Arguments> builder = Stream.<Arguments>builder();

        Consumer<Driver> sessionFunc = (Driver driver) -> {
            try (Session session = driver.session()) {
                Map<String, Object> params = mapOf("id", UUID.randomUUID().toString());
                session.writeTransaction(tx ->
                        tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params).consume());
            }
        };
        builder.add(Arguments.argumentSet("session", sessionFunc));

        Consumer<Driver> rxSessionFunc = (Driver driver) -> {
            Map<String, Object> params = mapOf("id", UUID.randomUUID().toString());
            Mono.usingWhen(
                            just(driver.rxSession()),
                            rxSession -> Mono.fromDirect(rxSession.writeTransaction(
                                    tx -> tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                                            .consume())),
                            RxSession::close)
                    .block();
        };
        builder.add(Arguments.argumentSet("rxSession", rxSessionFunc));

        Consumer<Driver> sessionAsyncFunc = (Driver driver) -> {
            Map<String, Object> params = mapOf("id", UUID.randomUUID().toString());
            AsyncSession asyncSession = driver.asyncSession();
            asyncSession
                    .writeTransactionAsync(tx -> tx.runAsync("MERGE (t:Test {id: $id}) RETURN t.id", params))
                    .whenComplete((result, error) -> asyncSession.closeAsync())
                    .toCompletableFuture()
                    .join();
        };
        builder.add(Arguments.argumentSet("asyncSession", sessionAsyncFunc));

        return builder.build();
    }

    @ParameterizedTest
    @MethodSource("expiringMethods")
    void reAuthDriverReturnsSessionWithRefreshedToken(Consumer<Driver> func) {
        // given
        List<Driver> driversLog = new CopyOnWriteArrayList<Driver>();
        try (Driver driver = new ReAuthDriver(driverSupplier(driversLog))) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only one driver to be created before token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            // when
            func.accept(driver);

            // then
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(2);
        }
    }

    @ParameterizedTest
    @MethodSource("expiringMethods")
    void reAuthDriverRefreshesTokensWhenUsedConcurrently(Consumer<Driver> func)
            throws InterruptedException, ExecutionException {
        // given
        List<Driver> driversLog = new CopyOnWriteArrayList<Driver>();
        try (Driver driver = new ReAuthDriver(driverSupplier(driversLog))) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only one driver to be created before token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            // when
            ExecutorService executor = Executors.newFixedThreadPool(10);
            try {
                List<Callable<Void>> jobs = IntStream.range(0, 20)
                        .mapToObj(i -> (Callable<Void>) () -> {
                            func.accept(driver);
                            return null;
                        })
                        .collect(Collectors.toList());
                List<Future<Void>> futures = executor.invokeAll(jobs);
                for (Future<Void> future : futures) {
                    future.get();
                }
            } finally {
                executor.shutdownNow();
            }

            // then
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(2);
        }
    }

    @ParameterizedTest
    @MethodSource("expiringMethods")
    void reAuthDriverCleansUpExpiredDrivers(Consumer<Driver> func) {
        // given
        List<Driver> driversLog = new CopyOnWriteArrayList<Driver>();
        try (ReAuthDriver driver = new ReAuthDriver(driverSupplier(driversLog), 500)) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            // when
            func.accept(driver);

            // then
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(2);

            await().atMost(Duration.ofSeconds(1)).until(driver.expiredDrivers::isEmpty);
        }
    }

    @ParameterizedTest
    @MethodSource("expiringMethods")
    void reAuthDriverCleansUpExpiredDriversWhileBeingUsed(Consumer<Driver> func)
            throws InterruptedException, ExecutionException {
        // given
        List<Driver> driversLog = new CopyOnWriteArrayList<Driver>();
        try (ReAuthDriver driver = new ReAuthDriver(driverSupplier(driversLog), 500)) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            ExecutorService executor = Executors.newFixedThreadPool(10);

            List<Callable<Void>> jobs = IntStream.range(0, 20)
                    .mapToObj(i -> (Callable<Void>) () -> {
                        func.accept(driver);
                        return null;
                    })
                    .collect(Collectors.toList());
            IntStream.range(0, 20)
                    .forEach(i -> jobs.add(() -> {
                        driver.cleanUpExpiredDrivers();
                        return null;
                    }));

            // if we clean up expired drivers at a random moment in time, it doesn't lead to errors
            Collections.shuffle(jobs);

            // when
            try {
                List<Future<Void>> futures = executor.invokeAll(jobs);
                for (Future<Void> future : futures) {
                    future.get();
                }
            } finally {
                executor.shutdownNow();
            }

            // then
            assertThat(driver.expiredDrivers).isEmpty();
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(2);
        }
    }

    static Stream<Arguments> sessionObtainedByDriverIsKeptActiveAfterTokenExpires() {
        Stream.Builder<Arguments> builder = Stream.builder();
        Consumer<Session> write = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);
            String actualId = session.writeTransaction(tx -> tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                    .single()
                    .get(0)
                    .asString());
            assertThat(actualId).isEqualTo(expectedId);
        };
        builder.add(Arguments.argumentSet("write", write));

        Consumer<Session> read = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            long actual = session.readTransaction(
                    tx -> tx.run("RETURN 42").single().get(0).asLong());
            assertThat(actual).isEqualTo(42L);
        };
        builder.add(Arguments.argumentSet("read", read));

        Consumer<Session> run = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            long actual = session.run("RETURN 42").single().get(0).asLong();
            assertThat(actual).isEqualTo(42L);
        };
        builder.add(Arguments.argumentSet("run", run));

        Consumer<Session> transaction = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            Transaction tx = session.beginTransaction();
            String actual = tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                    .single()
                    .get(0)
                    .asString();
            assertThat(actual).isEqualTo(expectedId);
            tx.commit();
        };
        builder.add(Arguments.argumentSet("transaction", transaction));

        Consumer<Session> openTransaction = (Session session) -> {
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            Transaction tx = session.beginTransaction();

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            String actual = tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                    .single()
                    .get(0)
                    .asString();
            assertThat(actual).isEqualTo(expectedId);
            tx.commit();
        };
        builder.add(Arguments.argumentSet("openTransaction", openTransaction));

        return builder.build();
    }

    @ParameterizedTest
    @MethodSource
    void sessionObtainedByDriverIsKeptActiveAfterTokenExpires(Consumer<Session> methodTest) {
        List<Driver> driversLog = new CopyOnWriteArrayList<Driver>();
        try (Driver driver = new ReAuthDriver(driverSupplier(driversLog))) {
            try (Session session = driver.session()) {
                methodTest.accept(session);
            }
        }
    }

    static Stream<Arguments> rxSessionObtainedByDriverIsKeptActiveAfterTokenExpires() {
        Stream.Builder<Arguments> builder = Stream.builder();
        Consumer<RxSession> write = (RxSession session) -> {
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            String actualId = usingWhen(
                            just(session),
                            rxSession -> from(rxSession.writeTransaction(
                                    tx -> tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                                            .records())),
                            RxSession::close)
                    .blockFirst()
                    .get(0)
                    .asString();
            assertThat(actualId).isEqualTo(expectedId);
        };
        builder.add(Arguments.argumentSet("write", write));

        Consumer<RxSession> read = (RxSession session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            long actual = usingWhen(
                            just(session),
                            rxSession -> from(rxSession.readTransaction(
                                    tx -> tx.run("RETURN 42").records())),
                            RxSession::close)
                    .blockFirst()
                    .get(0)
                    .asLong();
            assertThat(actual).isEqualTo(42L);
        };
        builder.add(Arguments.argumentSet("read", read));

        Consumer<RxSession> run = (RxSession session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            long actual = usingWhen(
                            just(session),
                            rxSession -> from(rxSession.run("RETURN 42").records()),
                            RxSession::close)
                    .blockFirst()
                    .get(0)
                    .asLong();
            assertThat(actual).isEqualTo(42L);
        };
        builder.add(Arguments.argumentSet("run", run));

        Consumer<RxSession> transaction = (RxSession session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            String actual = usingWhen(
                            just(session),
                            rxSession -> from(rxSession.beginTransaction())
                                    .flatMap(tx -> usingWhen(
                                            just(tx),
                                            t -> from(t.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                                                    .records()),
                                            RxTransaction::commit)),
                            RxSession::close)
                    .blockFirst()
                    .get(0)
                    .asString();
            assertThat(actual).isEqualTo(expectedId);
        };
        builder.add(Arguments.argumentSet("transaction", transaction));

        Consumer<RxSession> openTransaction = (RxSession session) -> {
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            String actual = usingWhen(
                            just(session),
                            rxSession -> from(rxSession.beginTransaction())
                                    .flatMap(tx -> usingWhen(
                                            just(tx),
                                            t -> delay(SERVER_SIDE_TOKEN_LIFESPAN)
                                                    .thenMany(from(t.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                                                            .records())),
                                            RxTransaction::commit,
                                            (t, ex) -> t.rollback(),
                                            RxTransaction::close)),
                            RxSession::close)
                    .blockFirst()
                    .get(0)
                    .asString();
            assertThat(actual).isEqualTo(expectedId);
        };
        builder.add(Arguments.argumentSet("openTransaction", openTransaction));

        return builder.build();
    }

    @ParameterizedTest
    @MethodSource
    void rxSessionObtainedByDriverIsKeptActiveAfterTokenExpires(Consumer<RxSession> methodTest) {
        // given
        List<Driver> driversLog = new CopyOnWriteArrayList<Driver>();
        try (Driver driver = new ReAuthDriver(driverSupplier(driversLog))) {
            RxSession rxSession = driver.rxSession();

            // when and then
            methodTest.accept(rxSession);
        }
    }

    static Stream<Arguments> asyncSessionObtainedByDriverIsKeptActiveAfterTokenExpires() {
        Stream.Builder<Arguments> builder = Stream.<Arguments>builder();
        Consumer<AsyncSession> write = (AsyncSession session) -> {
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            try {
                String actualId = session.writeTransactionAsync(
                                tx -> tx.runAsync("MERGE (t:Test {id: $id}) RETURN t.id", params)
                                        .thenCompose(ResultCursor::singleAsync)
                                        .thenApply(r -> r.get(0).asString()))
                        .whenComplete((result, error) -> session.closeAsync())
                        .toCompletableFuture()
                        .get();
                assertThat(actualId).isEqualTo(expectedId);
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        };
        builder.add(Arguments.argumentSet("write", write));

        Consumer<AsyncSession> read = (AsyncSession session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            try {
                long actual = session.readTransactionAsync(tx -> tx.runAsync("RETURN 42")
                                .thenCompose(ResultCursor::singleAsync)
                                .thenApply(r -> r.get(0).asLong()))
                        .whenComplete((result, error) -> session.closeAsync())
                        .toCompletableFuture()
                        .get();
                assertThat(actual).isEqualTo(42L);
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        };
        builder.add(Arguments.argumentSet("read", read));

        Consumer<AsyncSession> run = (AsyncSession session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            try {
                long actual = session.runAsync("RETURN 42")
                        .thenCompose(ResultCursor::singleAsync)
                        .thenApply(r -> r.get(0).asLong())
                        .whenComplete((result, error) -> session.closeAsync())
                        .toCompletableFuture()
                        .get();
                assertThat(actual).isEqualTo(42L);
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        };
        builder.add(Arguments.argumentSet("run", run));

        Consumer<AsyncSession> transaction = (AsyncSession session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            try {
                String actualId = session.beginTransactionAsync()
                        .thenCompose(tx -> tx.runAsync("MERGE (t:Test {id: $id}) RETURN t.id", params)
                                .thenCompose(ResultCursor::singleAsync)
                                .whenComplete((result, error) -> {
                                    if (error != null) {
                                        tx.rollbackAsync();
                                    } else {
                                        tx.commitAsync();
                                    }
                                })
                                .thenApply(r -> r.get(0).asString()))
                        .whenComplete((result, error) -> session.closeAsync())
                        .toCompletableFuture()
                        .get();
                assertThat(actualId).isEqualTo(expectedId);
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        };
        builder.add(Arguments.argumentSet("transaction", transaction));

        Consumer<AsyncSession> openTransaction = (AsyncSession session) -> {
            String expectedId = UUID.randomUUID().toString();
            Map<String, Object> params = mapOf("id", expectedId);

            try {
                String actualId = session.beginTransactionAsync()
                        .thenCompose(tx -> delayAsync(SERVER_SIDE_TOKEN_LIFESPAN)
                                .thenCompose(v -> tx.runAsync("MERGE (t:Test {id: $id}) RETURN t.id", params)
                                        .thenCompose(ResultCursor::singleAsync)
                                        .whenComplete((result, error) -> {
                                            if (error != null) {
                                                tx.rollbackAsync();
                                            } else {
                                                tx.commitAsync();
                                            }
                                        })
                                        .thenApply(r -> r.get(0).asString())))
                        .whenComplete((result, error) -> session.closeAsync())
                        .toCompletableFuture()
                        .get();
                assertThat(actualId).isEqualTo(expectedId);
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException(e);
            }
        };
        builder.add(Arguments.argumentSet("openTransaction", openTransaction));

        return builder.build();
    }

    @ParameterizedTest
    @MethodSource
    void asyncSessionObtainedByDriverIsKeptActiveAfterTokenExpires(Consumer<AsyncSession> methodTest) {
        // given
        List<Driver> driversLog = new CopyOnWriteArrayList<Driver>();
        try (Driver driver = new ReAuthDriver(driverSupplier(driversLog))) {
            AsyncSession asyncSession = driver.asyncSession();

            // when and then
            methodTest.accept(asyncSession);
        }
    }

    private static Supplier<Driver> driverSupplier(List<Driver> driversLog) {
        return () -> {
            Config config = Config.builder()
                    .withMaxConnectionLifetime(2, TimeUnit.SECONDS)
                    .withLogging(Logging.slf4j())
                    .build();
            BearerAuthenticationToken token = (BearerAuthenticationToken) authenticationSupplier.get();
            Driver driver = GraphDatabase.driver(NEO4J.getBoltUrl(), AuthTokens.bearer(token.getToken()), config);
            driversLog.add(driver);
            return driver;
        };
    }

    static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    static CompletionStage<Void> delayAsync(Duration duration) {
        CompletableFuture<Void> cFuture = new CompletableFuture<>();
        ScheduledFuture<?> scheduled =
                SCHEDULER.schedule(() -> cFuture.complete(null), duration.toMillis(), TimeUnit.MILLISECONDS);

        cFuture.whenComplete((r, e) -> {
            if (cFuture.isCancelled()) {
                scheduled.cancel(false);
            }
        });
        return cFuture;
    }

    static <K, V> Map<K, V> mapOf(K key, V value) {
        Map<K, V> map = new HashMap<>(1);
        map.put(key, value);
        return map;
    }

    @AfterAll
    static void cleanUp() {
        NEO4J.stop();
        KEYCLOAK.stop();
        NETWORK.close();
        SCHEDULER.shutdownNow();
    }
}
