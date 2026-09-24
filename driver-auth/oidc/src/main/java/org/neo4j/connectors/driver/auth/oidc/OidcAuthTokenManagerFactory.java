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
package org.neo4j.connectors.driver.auth.oidc;

import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.AuthTokenManagerFactory;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokenManagers;
import org.neo4j.driver.AuthTokens;

/**
 * Creates a token manager for the {@code oidc} scheme: one factory for every OAuth 2.0 and OpenID
 * Connect provider, driven entirely by configuration.
 *
 * <p>OIDC providers differ in where the URL comes from,
 * which grant, how the client authenticates and which extra form fields are needed, and every one of
 * those is a setting here rather than a code path. There is deliberately no factory per provider,
 * and no provider name anywhere in this module.
 *
 * <p>Refreshing is the driver's job:
 * {@link AuthTokenManagers#bearerAsync(java.util.function.Supplier)} re-invokes the supplier when the
 * token has expired and when the server answers with
 * {@link org.neo4j.driver.exceptions.TokenExpiredException} or
 * {@link org.neo4j.driver.exceptions.AuthenticationException}, and de-duplicates concurrent
 * refreshes. This module therefore runs no timer and no background thread.
 *
 * <p>{@link #create(AuthConfig, AuthContext)} validates the settings and performs no I/O: the
 * discovery lookup, the secret file and the key file are all resolved on the first token fetch.
 *
 * <p>Note that this is not a way to authenticate with AWS IAM. Cognito is an ordinary OIDC provider
 * and works here; workload identity on EKS works through {@code token_exchange} and
 * {@code subjectTokenFile}; SigV4-signed requests are something Neo4j has no server-side scheme for,
 * so they are out of scope.
 */
public class OidcAuthTokenManagerFactory implements AuthTokenManagerFactory {
    @Override
    public String getName() {
        return "oidc";
    }

    @Override
    public AuthTokenManager create(AuthConfig config, AuthContext context) {
        OidcConfig parsed = OidcConfig.parse(config);
        TokenSource source = TokenSources.build(parsed, context);
        return AuthTokenManagers.bearerAsync(() -> source.fetch().thenApply(token -> AuthTokens.bearer(token.value())
                .expiringAt(token.expiresAt().toEpochMilli())));
    }
}
