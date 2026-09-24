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
package org.neo4j.connectors.driver.auth.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.AuthTokenManagerRegistry;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Session;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.neo4j.Neo4jContainer;
import org.testcontainers.utility.MountableFile;

/**
 * The end of the chain: a real Keycloak issues a token that really expires, and a real Neo4j accepts
 * the replacement without the driver dropping its connections.
 *
 * <p>The realm gives {@code neo4j-commons-client} a three second access token lifespan, which is
 * what makes an expiry observable inside a test rather than in five minutes' time.
 */
@Testcontainers(disabledWithoutDocker = true)
public class KeycloakOidcIT {
    private static final String REALM = "neo4j-sso-test";
    private static final String CLIENT_ID = "neo4j-commons-client";
    private static final String CLIENT_SECRET = "QNrSpbh0mxhnlYlI21UcBaz3Htb734vi";
    private static final Duration SERVER_SIDE_TOKEN_LIFESPAN = Duration.ofSeconds(3);

    private static final Network NETWORK = Network.newNetwork();

    private static final KeycloakContainer KEYCLOAK = new KeycloakContainer("quay.io/keycloak/keycloak:26.2.5")
            .withNetwork(NETWORK)
            .withNetworkAliases("keycloak")
            .useTlsKeystore("/keycloak.jks", "testpwd")
            .withRealmImportFile("neo4j-sso-test-realm.json")
            .withEnv("KC_HOSTNAME", "https://keycloak:8443")
            .withEnv("KC_HOSTNAME_BACKCHANNEL_DYNAMIC", "true");

    private static final Neo4jContainer NEO4J = new Neo4jContainer(Optional.ofNullable(
                            System.getProperty("neo4j-connectors-commons.default-neo4j-image", "neo4j:5.26"))
                    .map(image -> image.contains("-enterprise") ? image : image + "-enterprise")
                    .orElseThrow(() -> new NoSuchElementException("No value present")))
            .waitingFor(Neo4jContainer.WAIT_FOR_BOLT)
            .withNetwork(NETWORK)
            .withEnv("NEO4J_ACCEPT_LICENSE_AGREEMENT", "yes")
            .withCopyFileToContainer(MountableFile.forClasspathResource("/keycloak.jks"), "/tmp/keycloak.jks")
            .withNeo4jConfig(
                    "server.jvm.additional",
                    "-Djavax.net.ssl.keyStore=/tmp/keycloak.jks -Djavax.net.ssl.keyStorePassword=testpwd"
                            + " -Djavax.net.ssl.trustStore=/tmp/keycloak.jks"
                            + " -Djavax.net.ssl.trustStorePassword=testpwd")
            .withNeo4jConfig("dbms.security.authentication_providers", "oidc-keycloak,native")
            .withNeo4jConfig("dbms.security.authorization_providers", "oidc-keycloak,native")
            .withNeo4jConfig("dbms.security.oidc.keycloak.display_name", "Keycloak")
            .withNeo4jConfig("dbms.security.oidc.keycloak.auth_flow", "pkce")
            .withNeo4jConfig(
                    "dbms.security.oidc.keycloak.well_known_discovery_uri",
                    "https://keycloak:8443/realms/" + REALM + "/.well-known/openid-configuration")
            .withNeo4jConfig(
                    "dbms.security.oidc.keycloak.params",
                    "client_id=" + CLIENT_ID + ";response_type=code;scope=openid email roles")
            .withNeo4jConfig("dbms.security.oidc.keycloak.audience", "account")
            .withNeo4jConfig("dbms.security.oidc.keycloak.issuer", "https://keycloak:8443/realms/" + REALM)
            .withNeo4jConfig("dbms.security.oidc.keycloak.client_id", CLIENT_ID)
            .withNeo4jConfig("dbms.security.oidc.keycloak.claims.username", "preferred_username")
            .withNeo4jConfig("dbms.security.oidc.keycloak.claims.groups", "groups")
            .withNeo4jConfig("dbms.security.auth_cache_ttl", "1s");

    @BeforeAll
    static void startContainers() {
        KEYCLOAK.start();
        NEO4J.start();
    }

    @AfterAll
    static void stopContainers() {
        NEO4J.stop();
        KEYCLOAK.stop();
        NETWORK.close();
    }

    @Test
    void keepsWorkingOnceTheTokenTheDriverHoldsHasExpired() throws Exception {
        AuthTokenManager manager = manager();
        List<String> written = new CopyOnWriteArrayList<>();

        try (Driver driver = GraphDatabase.driver(NEO4J.getBoltUrl(), manager)) {
            AuthToken first = manager.getToken().toCompletableFuture().join();
            written.add(write(driver));

            Thread.sleep(SERVER_SIDE_TOKEN_LIFESPAN.plusSeconds(2).toMillis());

            written.add(write(driver));
            AuthToken second = manager.getToken().toCompletableFuture().join();

            assertThat(second)
                    .as("the driver should have re-authenticated with a freshly minted token")
                    .isNotEqualTo(first);
        }

        assertThat(written).hasSize(2).doesNotHaveDuplicates();
    }

    @Test
    void resolvesTheTokenEndpointThroughDiscovery() {
        AuthTokenManager manager = AuthTokenManagerRegistry.usingDefaultClassLoader()
                .create("oidc", AuthConfig.of("john-tester", "testerpwd", settings()));

        assertThat(manager.getToken().toCompletableFuture().join()).isNotNull();
    }

    private static AuthTokenManager manager() {
        return new OidcAuthTokenManagerFactory()
                .create(AuthConfig.of("john-tester", "testerpwd", settings()), AuthContext.defaults());
    }

    private static Map<String, String> settings() {
        Map<String, String> settings = new HashMap<>();
        // Reached over plain HTTP on the mapped port: the container's certificate is issued for the
        // name 'keycloak', which only resolves inside the docker network. The token Keycloak mints
        // still carries the https://keycloak:8443 issuer the Neo4j container is configured to trust.
        settings.put("issuer", "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getHttpPort() + "/realms/" + REALM);
        settings.put("grantType", "password");
        settings.put("clientId", CLIENT_ID);
        settings.put("clientSecret", CLIENT_SECRET);
        settings.put("scope", "openid email roles");
        // The realm caps this client at three seconds, so the default thirty second skew would
        // report every token as already expired.
        settings.put("refreshSkewSeconds", "0");
        return settings;
    }

    private static String write(Driver driver) {
        String id = UUID.randomUUID().toString();
        try (Session session = driver.session()) {
            session.executeWrite(tx -> tx.run("MERGE (t:Test {id: $id}) RETURN t.id", Map.of("id", id))
                    .single()
                    .get(0)
                    .asString());
        }
        return id;
    }
}
