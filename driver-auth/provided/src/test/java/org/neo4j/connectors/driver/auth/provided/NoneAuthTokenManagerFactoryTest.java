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
package org.neo4j.connectors.driver.auth.provided;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokens;

class NoneAuthTokenManagerFactoryTest {
    private final NoneAuthTokenManagerFactory factory = new NoneAuthTokenManagerFactory();

    @Test
    void isNamedNone() {
        assertThat(factory.getName()).isEqualTo("none");
    }

    @Test
    void createsAManagerRequiringNoConfiguration() {
        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, null), AuthContext.defaults());

        assertThat(manager.getToken().toCompletableFuture().join()).isEqualTo(AuthTokens.none());
    }

    @Test
    void ignoresAnyConfiguredCredentials() {
        AuthTokenManager manager =
                factory.create(AuthConfig.of("neo4j", "secret", Map.of("token", "a-token")), AuthContext.defaults());

        assertThat(manager.getToken().toCompletableFuture().join()).isEqualTo(AuthTokens.none());
    }
}
