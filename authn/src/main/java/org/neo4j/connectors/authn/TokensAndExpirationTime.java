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
package org.neo4j.connectors.authn;

import com.fasterxml.jackson.jr.ob.JSON;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import org.keycloak.representations.AccessTokenResponse;
import org.neo4j.jdbc.authn.spi.Authentication;

/**
 * POJO for wrapping a token with expiration, with a static method to consume keycloak server responses.
 */
public class TokensAndExpirationTime {
    private final String accessToken;
    private final Instant expiresAt;
    private final String refreshToken;

    static final Base64.Decoder DECODER = Base64.getDecoder();

    public TokensAndExpirationTime(String accessToken, Instant expiresAt, String refreshToken) {
        this.accessToken = accessToken;
        this.expiresAt = expiresAt;
        this.refreshToken = refreshToken;
    }

    static TokensAndExpirationTime of(AccessTokenResponse accessTokenResponse) throws IOException {
        var token = accessTokenResponse.getToken();
        var refreshToken = accessTokenResponse.getRefreshToken();
        var chunks = token.split("\\.");

        var payload = JSON.std.mapFrom(DECODER.decode(chunks[1]));
        var epoch = ((Number) payload.get("exp")).longValue();
        var expiration = Instant.ofEpochSecond(epoch);

        return new TokensAndExpirationTime(token, expiration, refreshToken);
    }

    public Authentication toAuthentication() {
        return Authentication.bearer(this.accessToken, this.expiresAt);
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
}
