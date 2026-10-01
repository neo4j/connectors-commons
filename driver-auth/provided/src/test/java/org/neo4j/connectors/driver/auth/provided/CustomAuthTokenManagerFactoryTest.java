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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthConfigException;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokens;

class CustomAuthTokenManagerFactoryTest {
    private final CustomAuthTokenManagerFactory factory = new CustomAuthTokenManagerFactory();

    @Test
    void isNamedCustom() {
        assertThat(factory.getName()).isEqualTo("custom");
    }

    @Test
    void createsAManagerForTheConfiguredParameters() {
        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, parameters()), AuthContext.defaults());

        assertThat(manager.getToken().toCompletableFuture().join())
                .isEqualTo(AuthTokens.custom("a-principal", "a-credential", "a-realm", "a-scheme"));
    }

    @Test
    void treatsTheRealmAsOptional() {
        Map<String, String> parameters = parameters();
        parameters.remove("realm");

        AuthTokenManager manager = factory.create(AuthConfig.of(null, null, parameters), AuthContext.defaults());

        assertThat(manager.getToken().toCompletableFuture().join())
                .isEqualTo(AuthTokens.custom("a-principal", "a-credential", null, "a-scheme"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"principal", "credentials", "scheme"})
    void rejectsAMissingMandatoryParameter(String missing) {
        Map<String, String> parameters = parameters();
        parameters.remove(missing);
        AuthConfig config = AuthConfig.of(null, null, parameters);

        assertThatThrownBy(() -> factory.create(config, AuthContext.defaults()))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly(missing))
                .hasMessageContaining(missing);
    }

    private static Map<String, String> parameters() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("principal", "a-principal");
        parameters.put("credentials", "a-credential");
        parameters.put("realm", "a-realm");
        parameters.put("scheme", "a-scheme");
        return parameters;
    }
}
