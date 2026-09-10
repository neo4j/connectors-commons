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
package org.neo4j.connectors.driver.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthConfigTest {

    @Test
    void exposesCredentials() {
        AuthConfig config = AuthConfig.of("neo4j", "secret", Map.of());

        assertThat(config.username()).contains("neo4j");
        assertThat(config.password()).contains("secret");
    }

    @Test
    void reportsAbsentCredentialsAsEmpty() {
        AuthConfig config = AuthConfig.of(null, null, Map.of());

        assertThat(config.username()).isEmpty();
        assertThat(config.password()).isEmpty();
    }

    @Test
    void readsParameters() {
        AuthConfig config = AuthConfig.of(null, null, Map.of("token", "a-token"));

        assertThat(config.get("token")).contains("a-token");
        assertThat(config.get("missing")).isEmpty();
        assertThat(config.require("token")).isEqualTo("a-token");
        assertThat(config.asMap()).containsExactly(Map.entry("token", "a-token"));
    }

    @Test
    void namesTheMissingKeyWhenRequiringIt() {
        AuthConfig config = AuthConfig.of(null, null, Map.of());

        assertThatThrownBy(() -> config.require("client-secret"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("client-secret");
    }

    @Test
    void readsNullParametersAsEmpty() {
        AuthConfig config = AuthConfig.of("neo4j", "secret", null);

        assertThat(config.asMap()).isEmpty();
        assertThat(config.get("token")).isEmpty();
    }

    @Test
    void copiesParametersAndExposesThemAsUnmodifiable() {
        Map<String, String> parameters = new HashMap<>(Map.of("token", "a-token"));
        AuthConfig config = AuthConfig.of(null, null, parameters);

        parameters.put("token", "another-token");

        assertThat(config.get("token")).contains("a-token");
        assertThatThrownBy(() -> config.asMap().put("token", "yet-another-token"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
