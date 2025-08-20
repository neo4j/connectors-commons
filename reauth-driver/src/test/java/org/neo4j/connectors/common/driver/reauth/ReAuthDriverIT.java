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
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.authorization.client.Configuration;
import org.neo4j.connectors.authn.BearerAuthenticationToken;
import org.neo4j.connectors.authn.keycloak.KeycloakOIDCAuthenticationSupplier;
import org.neo4j.driver.*;
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
    private static final Neo4jContainer<?> NEO4J = new Neo4jContainer<>(
                    Optional.ofNullable(System.getProperty("neo4j-connectors-commons.default-neo4j-image"))
                            .or(() -> Optional.of("neo4j:5.26"))
                            .map(v -> !v.contains("-enterprise") ? v + "-enterprise" : v)
                            .orElseThrow())
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
                Map.of("secret", "QNrSpbh0mxhnlYlI21UcBaz3Htb734vi"),
                HttpClients.createMinimal());
        authenticationSupplier = (KeycloakOIDCAuthenticationSupplier)
                KeycloakOIDCAuthenticationSupplier.of("john-tester", "testerpwd", authzConfiguration);
    }

    static Stream<Arguments> expiringMethods() {
        var builder = Stream.<Arguments>builder();

        Consumer<Driver> sessionFunc = (Driver driver) -> {
            try (var session = driver.session()) {
                var params = Map.<String, Object>of("id", UUID.randomUUID().toString());
                session.writeTransaction(tx ->
                        tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params).consume());
            }
        };
        builder.add(Arguments.argumentSet("session", sessionFunc));

        Consumer<Driver> rxSessionFunc = (Driver driver) -> {
            var params = Map.<String, Object>of("id", UUID.randomUUID().toString());
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
            var params = Map.<String, Object>of("id", UUID.randomUUID().toString());
            var asyncSession = driver.asyncSession();
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only one driver to be created before token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            // when
            var executor = Executors.newFixedThreadPool(10);
            try {
                List<Callable<Void>> jobs = IntStream.range(0, 20)
                        .mapToObj(i -> (Callable<Void>) () -> {
                            func.accept(driver);
                            return null;
                        })
                        .collect(Collectors.toList());
                var futures = executor.invokeAll(jobs);
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog), 500)) {
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
    void reAuthDriverCleansUpExpiredDriversWhileBeingUsed(Consumer<Driver> func) throws InterruptedException, ExecutionException {
        // given
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog), 500)) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);


            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            var executor = Executors.newFixedThreadPool(10);

            List<Callable<Void>> jobs = IntStream.range(0, 20)
                    .mapToObj(i -> (Callable<Void>) () -> {
                        func.accept(driver);
                        return null;
                    })
                    .collect(Collectors.toList());
            IntStream.range(0, 20).forEach(i -> jobs.add(() -> {
                driver.cleanUpExpiredDrivers();
                return null;
            }));

            // if we clean up expired drivers at a random moment in time, it doesn't lead to errors
            Collections.shuffle(jobs);

            // when
            try {
                var futures = executor.invokeAll(jobs);
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
        var builder = Stream.<Arguments>builder();
        Consumer<Session> write = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);
            var actualId = session.writeTransaction(tx -> tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                    .single()
                    .get(0)
                    .asString());
            assertThat(actualId).isEqualTo(expectedId);
        };
        builder.add(Arguments.argumentSet("write", write));

        Consumer<Session> read = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            var actual = session.readTransaction(
                    tx -> tx.run("RETURN 42").single().get(0).asLong());
            assertThat(actual).isEqualTo(42L);
        };
        builder.add(Arguments.argumentSet("read", read));

        Consumer<Session> run = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            var actual = session.run("RETURN 42").single().get(0).asLong();
            assertThat(actual).isEqualTo(42L);
        };
        builder.add(Arguments.argumentSet("run", run));

        Consumer<Session> transaction = (Session session) -> {
            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            var tx = session.beginTransaction();
            var actual = tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
                    .single()
                    .get(0)
                    .asString();
            assertThat(actual).isEqualTo(expectedId);
            tx.commit();
        };
        builder.add(Arguments.argumentSet("transaction", transaction));

        Consumer<Session> openTransaction = (Session session) -> {
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            var tx = session.beginTransaction();

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);

            var actual = tx.run("MERGE (t:Test {id: $id}) RETURN t.id", params)
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            try (var session = driver.session()) {
                methodTest.accept(session);
            }
        }
    }

    static Stream<Arguments> rxSessionObtainedByDriverIsKeptActiveAfterTokenExpires() {
        var builder = Stream.<Arguments>builder();
        Consumer<RxSession> write = (RxSession session) -> {
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            var actualId = usingWhen(
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
            var actual = usingWhen(
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
            var actual = usingWhen(
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
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            var actual = usingWhen(
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
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            var actual = usingWhen(
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            var rxSession = driver.rxSession();

            // when and then
            methodTest.accept(rxSession);
        }
    }

    static Stream<Arguments> asyncSessionObtainedByDriverIsKeptActiveAfterTokenExpires() {
        var builder = Stream.<Arguments>builder();
        Consumer<AsyncSession> write = (AsyncSession session) -> {
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            sleep(SERVER_SIDE_TOKEN_LIFESPAN);
            try {
                var actualId = session.writeTransactionAsync(
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
                var actual = session.readTransactionAsync(tx -> tx.runAsync("RETURN 42")
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
                var actual = session.runAsync("RETURN 42")
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
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            try {
                var actualId = session.beginTransactionAsync()
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
            var expectedId = UUID.randomUUID().toString();
            var params = Map.<String, Object>of("id", expectedId);

            try {
                var actualId = session.beginTransactionAsync()
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            var asyncSession = driver.asyncSession();

            // when and then
            methodTest.accept(asyncSession);
        }
    }

    private static Supplier<Driver> driverSupplier(List<Driver> driversLog) {
        return () -> {
            var config = Config.builder()
                    .withConnectionTimeout(2, TimeUnit.SECONDS)
                    .withMaxConnectionLifetime(2, TimeUnit.SECONDS)
                    .withConnectionLivenessCheckTimeout(2, TimeUnit.SECONDS)
                    .withDriverMetrics()
                    .withLogging(Logging.slf4j())
                    .build();
            var token = (BearerAuthenticationToken) authenticationSupplier.get();
            var driver = GraphDatabase.driver(NEO4J.getBoltUrl(), AuthTokens.bearer(token.getToken()), config);
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
        return CompletableFuture.runAsync(
                () -> {}, CompletableFuture.delayedExecutor(duration.toMillis(), TimeUnit.MILLISECONDS));
    }

    @AfterAll
    static void cleanUp() {
        NEO4J.stop();
        KEYCLOAK.stop();
        NETWORK.close();
    }
}
