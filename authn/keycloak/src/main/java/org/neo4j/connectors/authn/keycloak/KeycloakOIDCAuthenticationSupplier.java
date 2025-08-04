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
package org.neo4j.connectors.authn.keycloak;

import com.fasterxml.jackson.jr.ob.JSON;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.representations.AccessTokenResponse;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.BearerAuthenticationToken;

/**
 * This supplier uses OAth2 resource owner flow via the Keycloak client.
 */
public class KeycloakOIDCAuthenticationSupplier implements Supplier<BearerAuthenticationToken> {
    private final String username;
    private final String password;
    private final Configuration config;
    private final AuthzClient client;
    private final Http http;
    private final String url;
    private final AtomicReference<BearerAuthenticationTokenAndTime> token = new AtomicReference<>();

    KeycloakOIDCAuthenticationSupplier(String username, String password, Configuration config) {
        this.username = username;
        this.password = password;
        this.config = config;
        this.client = AuthzClient.create(config);
        this.url = constructUrl(config);
        this.http = new Http(config, config.getClientCredentialsProvider());
    }

    public static Supplier<BearerAuthenticationToken> of(
            String username, String password, Configuration config) {
        return new KeycloakOIDCAuthenticationSupplier(username, password, config);
    }

    private String constructUrl(Configuration config) {
        return config.getAuthServerUrl() + "/realms/" + config.getRealm() + "/protocol/openid-connect/token";
    }

    /**
     * @return true if a token has been retrieved and it is expired
     */
    public boolean currentTokenIsExpired() {
        return token.get() == null || token.get().expireAt.isBefore(Instant.now());
    }

    @Override
    public BearerAuthenticationToken get() {
        BearerAuthenticationTokenAndTime freshToken = this.token.updateAndGet(this::get0);
        return freshToken.toAuthenticationToken();
    }

    private BearerAuthenticationTokenAndTime get0(BearerAuthenticationTokenAndTime previous) {
        if (previous == null) {
            return fetch();
        } else {
            return refresh(previous.refreshToken);
        }
    }

    private BearerAuthenticationTokenAndTime fetch() {
        try {
            AccessTokenResponse response = this.client.obtainAccessToken(this.username, this.password);
            return BearerAuthenticationTokenAndTime.of(response);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private BearerAuthenticationTokenAndTime refresh(String refreshToken) {
        try {
            AccessTokenResponse response = this.http
                    .<AccessTokenResponse>post(this.url)
                    .authentication()
                    .client()
                    .form()
                    .param("grant_type", "refresh_token")
                    .param("refresh_token", refreshToken)
                    .param("client_id", this.config.getResource())
                    .param("client_secret", (String)
                            this.config.getCredentials().get("secret"))
                    .response()
                    .json(AccessTokenResponse.class)
                    .execute();
            return BearerAuthenticationTokenAndTime.of(response);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Couples together a bearer token, with an expiration date, with a refresh token.
     * Internal helper class to help the supplier.
     */
    private static final class BearerAuthenticationTokenAndTime {
        static final Base64.Decoder DECODER = Base64.getDecoder();
        private final String token;
        private final Instant expireAt;
        private final String refreshToken;

        public BearerAuthenticationTokenAndTime(String token, Instant expireAt, String refreshToken) {
            this.token = token;
            this.expireAt = expireAt;
            this.refreshToken = refreshToken;
        }

        /**
         * Decodes an incoming AccessTokenResponse from the SSO server, then creates a new token based on it.
         */
        static BearerAuthenticationTokenAndTime of(AccessTokenResponse accessTokenResponse) throws IOException {
            String token = accessTokenResponse.getToken();
            String[] chunks = token.split("\\.");
            Map<String, Object> payload = JSON.std.mapFrom(DECODER.decode(chunks[1]));
            long epoch = ((Number) payload.get("exp")).longValue();
            Instant expireAt = Instant.ofEpochSecond(epoch);

            return new BearerAuthenticationTokenAndTime(token, expireAt, accessTokenResponse.getRefreshToken());
        }

        BearerAuthenticationToken toAuthenticationToken() {
            return AuthenticationToken.bearer(token, expireAt);
        }
    }
}
