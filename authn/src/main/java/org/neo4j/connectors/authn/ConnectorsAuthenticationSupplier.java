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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.representations.AccessTokenResponse;
import org.neo4j.jdbc.authn.spi.Authentication;

/**
 * This authentication supplier uses the OAuth2 resource owner flow via the Keycloak
 * client against a configured Keycloak server. It can either be used directly or via the
 * corresponding {@link org.neo4j.jdbc.authn.spi.AuthenticationSupplierFactory}.
 *
 * @author Michael J. Simons
 */
public final class ConnectorsAuthenticationSupplier implements Supplier<Authentication> {
    /**
     * Creates a new instance based on the given configuration object.
     * @param user the username of the user asking for an access token
     * @param password the password of the user asking for an access token
     * @param configuration the Keycloak config to use
     * @return a new instance
     */
    public static Supplier<Authentication> of(String user, String password, Configuration configuration) {
        return new ConnectorsAuthenticationSupplier(user, password, configuration);
    }
    private final String username;
    private final String password;
    private final Configuration cfg;
    private final AuthzClient authzClient;
    private final Http http;
    private final String url;
    private final AtomicReference<TokensAndExpirationTime> currentToken = new AtomicReference<>();

    ConnectorsAuthenticationSupplier(String user, String password, Configuration cfg) {
        this.username = user;
        this.password = password;
        this.cfg = cfg;
        this.authzClient = AuthzClient.create(cfg);
        this.url = cfg.getAuthServerUrl() + "/realms/" + cfg.getRealm() + "/protocol/openid-connect/token";
        this.http = new Http(cfg, cfg.getClientCredentialsProvider());
    }

    /**
     * {@return true if a token has been retrieved and it is still valid}
     */
    public boolean currentTokenIsExpired() {
        return Optional.ofNullable(this.currentToken.get())
                .filter(v -> Instant.now().isAfter(v.getExpiresAt()))
                .isPresent();
    }

    @Override
    public Authentication get() {
        return this.currentToken
                .updateAndGet(previous -> {
                    if (previous == null) {
                        return get0();
                    }
                    return refresh0(previous.getRefreshToken());
                })
                .toAuthentication();
    }

    TokensAndExpirationTime get0() {
        try {
            return TokensAndExpirationTime.of(this.authzClient.obtainAccessToken(this.username, this.password));
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    TokensAndExpirationTime refresh0(String refreshToken) {
        try {
            return TokensAndExpirationTime.of(this.http
                    .<AccessTokenResponse>post(this.url)
                    .authentication()
                    .client()
                    .form()
                    .param("grant_type", "refresh_token")
                    .param("refresh_token", refreshToken)
                    .param("client_id", this.cfg.getResource())
                    .param("client_secret", (String) this.cfg.getCredentials().get("secret"))
                    .response()
                    .json(AccessTokenResponse.class)
                    .execute());
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
