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

import java.util.*;

/**
 * User-supplied connector configuration for an {@link AuthTokenManagerFactory}.
 *
 * <p>An instance is constructible from configuration alone: it carries the credentials and the
 * scheme-specific parameters a connector was configured with, and nothing else. Runtime
 * collaborators live on {@link AuthContext} instead.
 *
 * <p>{@link #get(String)}, {@link #require(String)} and {@link #asMap()} all read from the
 * scheme-specific parameters; {@link #username()} and {@link #password()} are separate from them.
 */
public interface AuthConfig {
    /**
     * Creates a configuration from the credentials and parameters a connector was configured with.
     *
     * @param username the configured username, may be {@code null}
     * @param password the configured password, may be {@code null}
     * @param parameters the scheme-specific parameters, may be {@code null} which is read as empty
     * @return a new configuration holding a copy of {@code parameters}
     */
    static AuthConfig of(String username, String password, Map<String, String> parameters) {
        Map<String, String> copy = parameters == null
                ? Collections.emptyMap()
                : Map.copyOf(parameters);
        return new DefaultAuthConfig(username, password, copy);
    }

    /**
     * Returns the configured username.
     *
     * @return the username, or {@link Optional#empty()} if none was configured
     */
    Optional<String> username();

    /**
     * Returns the configured password.
     *
     * @return the password, or {@link Optional#empty()} if none was configured
     */
    Optional<String> password();

    /**
     * Returns the value of a scheme-specific parameter.
     *
     * @param key the parameter name
     * @return the value, or {@link Optional#empty()} if the parameter is absent
     */
    Optional<String> get(String key);

    /**
     * Returns the value of a mandatory scheme-specific parameter.
     *
     * @param key the parameter name
     * @return the value
     * @throws IllegalArgumentException if the parameter is absent, naming {@code key}
     */
    String require(String key);

    /**
     * Returns all scheme-specific parameters.
     *
     * @return an unmodifiable view of the parameters
     */
    Map<String, String> asMap();
}
