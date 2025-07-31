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
package org.neo4j.connectors.it.authn.sso;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.condition.DisabledInNativeImage;
import org.testcontainers.containers.Neo4jContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers(disabledWithoutDocker = true)
@DisabledInNativeImage
public class ReauthenticationIT {
    private static final Network NETWORK = Network.newNetwork();

    private static final KeycloakContainer KEYCLOAK = new KeycloakContainer("quay.io/keycloak/keycloak:26.3.2")
            .withNetwork(NETWORK)
            .useTlsKeystore("/keys.jks", "verysecret")
            .withRealmImportFile("neo4j-sso-test.jsom")
            .withNetworkAliases("keycloak")
            .withEnv("KC_HOSTNAME", "https://keycloak:8443")
            .withEnv("KC_HOSTNAME_BACKCHANNEL_DYNAMIC", "true");

    @SuppressWarnings("resource")
    private static final Neo4jContainer<?> NEO4J = new Neo4jContainer<>("neo4j:5.26.8-enterprise")
            .waitingFor(Neo4jContainer.WAIT_FOR_BOLT)
            .withNetwork(NETWORK)
            .withEnv("NEO4J_ACCEPT_LICENSE_AGREEMENT", "yes");

    /* a driver that uses authentication supplier needed to implement this test */
}
