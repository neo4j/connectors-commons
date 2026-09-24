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
package org.neo4j.connectors.driver.auth.oidc.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class JwtsTest {
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    @Test
    void recognisesAJwt() {
        assertThat(Jwts.isJwt(jwt("{\"exp\":1780000000}"))).isTrue();
    }

    @Test
    void rejectsAnOpaqueToken() {
        assertThat(Jwts.isJwt("0AbcDefGhi_jKlMnOpQrStUvWxYz")).isFalse();
        assertThat(Jwts.isJwt("only.two")).isFalse();
        assertThat(Jwts.isJwt(null)).isFalse();
    }

    @Test
    void readsTheExpiryClaim() {
        assertThat(Jwts.expiry(jwt("{\"exp\":1780000000}"))).contains(Instant.ofEpochSecond(1780000000L));
    }

    @Test
    void returnsNothingForATokenWithoutAnExpiryClaim() {
        assertThat(Jwts.expiry(jwt("{\"sub\":\"john\"}"))).isEmpty();
    }

    @Test
    void returnsNothingRatherThanFailingOnAnUnparseablePayload() {
        assertThat(Jwts.expiry("aaa.not-base64-%%%.bbb")).isEmpty();
        assertThat(Jwts.expiry(jwt("not json"))).isEmpty();
        assertThat(Jwts.expiry("an-opaque-okta-token")).isEmpty();
    }

    private static String jwt(String payload) {
        return ENCODER.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8))
                + "."
                + ENCODER.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".signature";
    }
}
