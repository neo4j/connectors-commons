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

import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.AuthTokenManagerFactory;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokenManagers;
import org.neo4j.driver.AuthTokens;

/**
 * Creates a token manager for the {@code bearer} scheme, reading the mandatory {@code token}
 * parameter.
 *
 * <p>The token is static and carries no expiry, so the manager is built with
 * {@link AuthTokenManagers#basic(java.util.function.Supplier)} rather than
 * {@link AuthTokenManagers#bearer(java.util.function.Supplier)}. There is nothing to refresh, and
 * {@code bearer} would additionally treat
 * {@link org.neo4j.driver.exceptions.TokenExpiredException} as retryable, turning a hard failure
 * into a retry that then fails with the very same token.
 */
public class BearerAuthTokenManagerFactory implements AuthTokenManagerFactory {
    @Override
    public String getName() {
        return "bearer";
    }

    @Override
    public AuthTokenManager create(AuthConfig config, AuthContext context) {
        AuthToken token = AuthTokens.bearer(config.require("token"));
        return AuthTokenManagers.basic(() -> token);
    }
}
