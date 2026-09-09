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

import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokenManagers;
import org.neo4j.driver.AuthTokens;

/**
 * A native factory claiming the same name as the legacy {@code basic} supplier factory. It is
 * deliberately <em>not</em> registered on the test classpath: {@link AuthTokenManagerRegistryTest}
 * registers it through a throwaway class loader so that the rest of the tests still see {@code basic}
 * resolve through the legacy bridge.
 */
public class OverridingBasicAuthTokenManagerFactory implements AuthTokenManagerFactory {

    @Override
    public String getName() {
        return "basic";
    }

    @Override
    public AuthTokenManager create(AuthConfig config, AuthContext context) {
        return AuthTokenManagers.basic(() -> AuthTokens.bearer("overridden"));
    }
}
