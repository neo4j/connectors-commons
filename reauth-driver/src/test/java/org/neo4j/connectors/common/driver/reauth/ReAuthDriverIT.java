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

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.client.Configuration;
import org.neo4j.connectors.common.driver.reauth.tmp.KCAuthenticationSupplier;
import org.neo4j.connectors.common.driver.reauth.tmp.TokenAuthentication;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.GraphDatabase;
import org.testcontainers.containers.Neo4jContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

@Testcontainers(disabledWithoutDocker = true)
public class ReAuthDriverIT {

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
            .withNeo4jConfig("dbms.security.auth_cache_ttl", "5s")
            .withLogConsumer(outputFrame -> System.out.print(outputFrame.getUtf8String()));

    private static KCAuthenticationSupplier authenticationSupplier;

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
        authenticationSupplier =
                (KCAuthenticationSupplier) KCAuthenticationSupplier.of("john-tester", "testerpwd", authzConfiguration);
    }

    @Test
    void reAuthDriverReturnsSessionWithRefreshedToken() {
        Supplier<ExpiringDriver> driverSupplier = () -> {
            var token = (TokenAuthentication) authenticationSupplier.get();
            return new ExpiringDriver(GraphDatabase.driver(NEO4J.getBoltUrl(), AuthTokens.bearer(token.getValue())), token.expiresAt());
        };
        try (var driver = new ReAuthDriver(driverSupplier)) {
            driver.verifyConnectivity();
        }
    }

    @AfterAll
    static void cleanUp() {
        NEO4J.stop();
        KEYCLOAK.stop();
        NETWORK.close();
    }
}
