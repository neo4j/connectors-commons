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
 * Creates a token manager for the {@code custom} scheme, reading the {@code principal},
 * {@code credentials} and {@code scheme} parameters, plus an optional {@code realm}.
 *
 * <p>The three mandatory parameters are the ones {@link AuthTokens#custom} itself requires. The
 * token is static, so the manager is built with
 * {@link AuthTokenManagers#basic(java.util.function.Supplier)}.
 */
public class CustomAuthTokenManagerFactory implements AuthTokenManagerFactory {
    @Override
    public String getName() {
        return "custom";
    }

    @Override
    public AuthTokenManager create(AuthConfig config, AuthContext context) {
        AuthToken token = token(config);
        return AuthTokenManagers.basic(() -> token);
    }

    @Override
    public void validate(AuthConfig config, AuthContext context) {
        token(config);
    }

    private static AuthToken token(AuthConfig config) {
        return AuthTokens.custom(
                config.require("principal"),
                config.require("credentials"),
                config.get("realm").orElse(null),
                config.require("scheme"));
    }
}
