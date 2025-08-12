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

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import org.neo4j.connectors.authn.keycloak.KeycloakOIDCAuthenticationSupplier;
import org.neo4j.driver.*;
import org.neo4j.driver.async.ResultCursor;
import org.neo4j.driver.reactive.RxSession;
import org.testcontainers.containers.Neo4jContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;

@Testcontainers(disabledWithoutDocker = true)
public class ReAuthDriverIT {

    private static final Duration TOKEN_LIFESPAN_GUARANTEED = Duration.ofSeconds(4);

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

    @BeforeAll
    static void startContainersAndMetrics() {
        KEYCLOAK.start();
        NEO4J.start();

        var authzConfiguration = new Configuration(
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
                var params = Map.<String, Object>of("ts", System.currentTimeMillis());
                session.writeTransaction(tx ->
                        tx.run("MERGE (t:Test {ts: $ts}) RETURN t.ts", params).consume());
            }
        };
        builder.add(Arguments.argumentSet("session", sessionFunc));

        Consumer<Driver> rxSessionFunc = (Driver driver) -> {
            var params = Map.<String, Object>of("ts", System.currentTimeMillis());
            Mono.usingWhen(
                            Mono.just(driver.rxSession()),
                            rxSession -> Mono.fromDirect(rxSession.writeTransaction(
                                    tx -> tx.run("MERGE (t:Test {ts: $ts}) RETURN t.ts", params)
                                            .consume())),
                            RxSession::close)
                    .block();
        };
        builder.add(Arguments.argumentSet("rxSession", rxSessionFunc));

        Consumer<Driver> sessionAsyncFunc = (Driver driver) -> {
            var params = Map.<String, Object>of("ts", System.currentTimeMillis());
            var asyncSession = driver.asyncSession();
            asyncSession
                    .writeTransactionAsync(tx -> tx.runAsync("MERGE (t:Test {ts: $ts}) RETURN t.ts", params))
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only one driver to be created before token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            await().atMost(TOKEN_LIFESPAN_GUARANTEED).until(authenticationSupplier::currentTokenIsExpired);

            func.accept(driver);
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
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only one driver to be created before token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            await().atMost(TOKEN_LIFESPAN_GUARANTEED).until(authenticationSupplier::currentTokenIsExpired);

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

            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(2);
        }
    }

    @Test
    void reAuthDriverCleansUpExpiredDrivers() {
        @SuppressWarnings("unchecked")
        var func =
                (Consumer<Driver>) expiringMethods().findFirst().orElseThrow().get()[0];
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog), 500)) {
            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(1);

            await().atMost(TOKEN_LIFESPAN_GUARANTEED).until(authenticationSupplier::currentTokenIsExpired);

            func.accept(driver);
            assertThat(driversLog)
                    .overridingErrorMessage(() -> format(
                            "expected only two drivers to be created after token expires, but was %d",
                            driversLog.size()))
                    .hasSize(2);

            await().atMost(Duration.ofSeconds(1)).until(driver.expiredDrivers::isEmpty);
        }
    }

    @Test
    void sessionObtainedByDriverIsKeptActiveAfterTokenExpires() {
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            try (var session = driver.session()) {
                var expectedTimestamp = System.currentTimeMillis();
                var params = Map.<String, Object>of("ts", expectedTimestamp);

                await().atMost(TOKEN_LIFESPAN_GUARANTEED).until(authenticationSupplier::currentTokenIsExpired);

                var actualTimestamp =
                        session.writeTransaction(tx -> tx.run("MERGE (t:Test {ts: $ts}) RETURN t.ts", params)
                                .single()
                                .get(0)
                                .asLong());
                assertThat(actualTimestamp).isEqualTo(expectedTimestamp);
            }
        }
    }

    @Test
    void rxSessionObtainedByDriverIsKeptActiveAfterTokenExpires() {
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            var expectedTimestamp = System.currentTimeMillis();
            var params = Map.<String, Object>of("ts", expectedTimestamp);

            var actual = Flux.usingWhen(
                            Mono.just(driver.rxSession())
                                    .zipWhen(s -> Mono.delay(TOKEN_LIFESPAN_GUARANTEED))
                                    .map(Tuple2::getT1),
                            rxSession -> Flux.from(rxSession.writeTransaction(
                                    tx -> tx.run("MERGE (t:Test {ts: $ts}) RETURN t.ts", params)
                                            .records())),
                            RxSession::close)
                    .blockFirst();
            assertThat(actual.get(0).asLong()).isEqualTo(expectedTimestamp);
        }
    }

    @Test
    void asyncSessionObtainedByDriverIsKeptActiveAfterTokenExpires() throws ExecutionException, InterruptedException {
        var driversLog = new CopyOnWriteArrayList<Driver>();
        try (var driver = new ReAuthDriver(driverSupplier(driversLog))) {
            var expectedTimestamp = System.currentTimeMillis();
            var params = Map.<String, Object>of("ts", expectedTimestamp);

            var asyncSession = driver.asyncSession();
            var actual = asyncSession
                    .writeTransactionAsync(tx -> {
                        await().atMost(TOKEN_LIFESPAN_GUARANTEED).until(authenticationSupplier::currentTokenIsExpired);
                        return tx.runAsync("MERGE (t:Test {ts: $ts}) RETURN t.ts", params)
                                .thenCompose(ResultCursor::singleAsync)
                                .thenApply(r -> r.get(0).asLong());
                    })
                    .whenComplete((result, error) -> asyncSession.closeAsync())
                    .toCompletableFuture()
                    .get();

            assertThat(actual).isEqualTo(expectedTimestamp);
        }
    }

    private static Supplier<ExpiringDriver> driverSupplier(List<Driver> driversLog) {
        return () -> {
            var token = authenticationSupplier.get();
            var driver = GraphDatabase.driver(
                    NEO4J.getBoltUrl(), AuthTokens.bearer(token.getToken()), ReAuthDriverFactory.defaultConfig());
            driversLog.add(driver);
            return new ExpiringDriver(driver, token.getExpiresAt());
        };
    }

    @AfterAll
    static void cleanUp() {
        NEO4J.stop();
        KEYCLOAK.stop();
        NETWORK.close();
    }
}
