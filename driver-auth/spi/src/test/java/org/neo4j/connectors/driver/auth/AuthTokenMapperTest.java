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

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.driver.AuthTokens;

class AuthTokenMapperTest {

    @Test
    void mapsUsernameAndPassword() {
        assertThat(AuthTokenMapper.toDriverToken(AuthenticationToken.usernameAndPassword("neo4j", "secret")))
                .isEqualTo(AuthTokens.basic("neo4j", "secret"));
    }

    @Test
    void mapsUsernameAndPasswordWithRealm() {
        assertThat(AuthTokenMapper.toDriverToken(AuthenticationToken.usernameAndPassword("neo4j", "secret", "a-realm")))
                .isEqualTo(AuthTokens.basic("neo4j", "secret", "a-realm"));
    }

    @Test
    void mapsBearer() {
        assertThat(AuthTokenMapper.toDriverToken(AuthenticationToken.bearer("a-token")))
                .isEqualTo(AuthTokens.bearer("a-token"));
    }

    @Test
    void mapsExpiringBearerToThePlainDriverToken() {
        AuthenticationToken token = AuthenticationToken.bearer("a-token", Instant.parse("2026-09-08T10:15:30Z"));

        assertThat(AuthTokenMapper.toDriverToken(token)).isEqualTo(AuthTokens.bearer("a-token"));
    }

    @Test
    void mapsKerberos() {
        assertThat(AuthTokenMapper.toDriverToken(AuthenticationToken.kerberos("a-ticket")))
                .isEqualTo(AuthTokens.kerberos("a-ticket"));
    }

    @Test
    void mapsNone() {
        assertThat(AuthTokenMapper.toDriverToken(AuthenticationToken.none())).isEqualTo(AuthTokens.none());
    }

    @Test
    void mapsCustom() {
        assertThat(AuthTokenMapper.toDriverToken(
                        AuthenticationToken.custom("a-principal", "a-credential", "a-realm", "a-scheme")))
                .isEqualTo(AuthTokens.custom("a-principal", "a-credential", "a-realm", "a-scheme"));
    }

    @Test
    void mapsCustomWithParameters() {
        Map<String, Object> parameters = Map.of("key", "value");

        assertThat(AuthTokenMapper.toDriverToken(
                        AuthenticationToken.custom("a-principal", "a-credential", "a-realm", "a-scheme", parameters)))
                .isEqualTo(AuthTokens.custom("a-principal", "a-credential", "a-realm", "a-scheme", parameters));
    }

    @Test
    void rejectsUnknownTokenTypes() {
        AuthenticationToken token = new AuthenticationToken() {};

        assertThatThrownBy(() -> AuthTokenMapper.toDriverToken(token))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("is not supported");
    }
}
