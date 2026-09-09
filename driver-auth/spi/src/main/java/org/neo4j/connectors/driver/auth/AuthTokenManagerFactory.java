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

/**
 * Creates a driver-native {@link AuthTokenManager} for a named authentication scheme.
 *
 * <p>Implementations are discovered by {@link AuthTokenManagerRegistry} through
 * {@link java.util.ServiceLoader}, so they must be registered in
 * {@code META-INF/services/org.neo4j.connectors.driver.auth.AuthTokenManagerFactory} and must have a
 * public no-argument constructor.
 */
public interface AuthTokenManagerFactory {
    /**
     * Returns the name this factory is selected by.
     *
     * @return the scheme name, never {@code null}
     */
    String getName();

    /**
     * Creates a token manager.
     *
     * @param config the user-supplied connector configuration
     * @param context the runtime collaborators provided by the host
     * @return a new token manager
     */
    AuthTokenManager create(AuthConfig config, AuthContext context);
}
