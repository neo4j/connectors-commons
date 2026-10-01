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

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuthConfigExceptionTest {

    @Test
    void isAnIllegalArgumentException() {
        assertThat(new AuthConfigException("a message", List.of("clientId")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("a message")
                .hasNoCause();
    }

    @Test
    void carriesItsKeysAndCause() {
        RuntimeException cause = new RuntimeException("underlying");

        AuthConfigException exception = new AuthConfigException("a message", List.of("proxyHost", "proxyPort"), cause);

        assertThat(exception.keys()).containsExactly("proxyHost", "proxyPort");
        assertThat(exception).hasCause(cause);
    }

    @Test
    void allowsNoKeyWhenNoSingleParameterIsAtFault() {
        assertThat(new AuthConfigException("a message", List.of()).keys()).isEmpty();
    }

    @Test
    void copiesItsKeysAndExposesThemAsUnmodifiable() {
        List<String> keys = new ArrayList<>(List.of("clientId"));
        AuthConfigException exception = new AuthConfigException("a message", keys);

        keys.add("clientSecret");

        assertThat(exception.keys()).containsExactly("clientId");
        assertThatThrownBy(() -> exception.keys().add("clientSecret"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsNullKeys() {
        assertThatThrownBy(() -> new AuthConfigException("a message", null)).isInstanceOf(NullPointerException.class);
    }
}
