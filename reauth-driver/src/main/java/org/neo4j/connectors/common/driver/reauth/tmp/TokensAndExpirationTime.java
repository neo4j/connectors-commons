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
package org.neo4j.connectors.common.driver.reauth.tmp;

import com.fasterxml.jackson.jr.ob.JSON;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import org.keycloak.representations.AccessTokenResponse;

class TokensAndExpirationTime {

    private final String accessToken;
    private final Instant expiresAt;
    private final String refreshToken;

    private static final Base64.Decoder DECODER = Base64.getDecoder();

    TokensAndExpirationTime(String accessToken, Instant expiresAt, String refreshToken) {
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
        this.refreshToken = refreshToken;
    }

    static TokensAndExpirationTime of(AccessTokenResponse accessTokenResponse) throws IOException {
        var chunks = accessTokenResponse.getToken().split("\\.");
        var payload = JSON.std.mapFrom(DECODER.decode(chunks[1]));
        var exp = Instant.ofEpochSecond(((Number) payload.get("exp")).longValue());
        return new TokensAndExpirationTime(accessTokenResponse.getToken(), exp, accessTokenResponse.getRefreshToken());
    }

    public String getAccessToken() {
        return accessToken;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    Authentication toAuthentication() {
        return Authentication.bearer(this.accessToken, this.expiresAt);
    }
}
