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

import static org.assertj.core.api.Assertions.assertThat;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Supplier;
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
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.reactive.RxSession;
import org.testcontainers.containers.Neo4jContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.shaded.org.awaitility.Awaitility;
import org.testcontainers.utility.MountableFile;
import reactor.core.publisher.Mono;

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
            .withEnv("KC_HOSTNAME_BACKCHANNEL_DYNAMIC", "true");

    @SuppressWarnings("resource")
    private static final Neo4jContainer<?> NEO4J = new Neo4jContainer<>(
                    Optional.ofNullable(System.getProperty("neo4j-connectors-commons.default-neo4j-image"))
                            .or(() -> Optional.of("neo4j:5.26.8"))
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
            .withNeo4jConfig("dbms.security.auth_cache_ttl", "1s");

    private static KeycloakOIDCAuthenticationSupplier authenticationSupplier;

    @BeforeAll
    static void startContainersAndMetrics() {
        KEYCLOAK.start();
        NEO4J.start();

        var authzConfiguration = new Configuration(
                String.format("http://%s:%d", KEYCLOAK.getHost(), KEYCLOAK.getHttpPort()),
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
        var createdDrivers = new CopyOnWriteArrayList<Driver>();
        Supplier<ExpiringDriver> driverSupplier = () -> {
            var token = (BearerAuthenticationToken) authenticationSupplier.get();
            var driver = GraphDatabase.driver(NEO4J.getBoltUrl(), AuthTokens.bearer(token.getToken()));
            createdDrivers.add(driver);
            return new ExpiringDriver(driver, token.getExpiresAt());
        };

        try (var driver = new ReAuthDriver(driverSupplier)) {
            func.accept(driver);
            assertThat(createdDrivers).hasSize(1);

            Awaitility.await().atMost(TOKEN_LIFESPAN_GUARANTEED).until(authenticationSupplier::currentTokenIsExpired);

            func.accept(driver);
            assertThat(createdDrivers).hasSize(2);
        }
    }

    @AfterAll
    static void cleanUp() {
        NEO4J.stop();
        KEYCLOAK.stop();
        NETWORK.close();
    }
}
