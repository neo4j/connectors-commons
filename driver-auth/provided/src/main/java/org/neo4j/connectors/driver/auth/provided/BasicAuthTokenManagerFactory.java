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
 * Creates a token manager for the {@code basic} scheme, reading the configured username and
 * password.
 *
 * <p>Both are mandatory. The token is static, so the manager is built with
 * {@link AuthTokenManagers#basic(java.util.function.Supplier)}: the driver re-reads it only after an
 * {@link org.neo4j.driver.exceptions.AuthenticationException}, and gets the same token back.
 */
public class BasicAuthTokenManagerFactory implements AuthTokenManagerFactory {
    @Override
    public String getName() {
        return "basic";
    }

    @Override
    public AuthTokenManager create(AuthConfig config, AuthContext context) {
        String username = config.username()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Authentication scheme 'basic' requires a username but none was configured"));
        String password = config.password()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Authentication scheme 'basic' requires a password but none was configured"));

        AuthToken token = AuthTokens.basic(username, password);
        return AuthTokenManagers.basic(() -> token);
    }
}
