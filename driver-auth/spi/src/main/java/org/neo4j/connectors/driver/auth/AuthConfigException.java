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

import java.io.Serial;
import java.util.List;
import java.util.Objects;

/**
 * Signals that an {@link AuthConfig} is invalid, naming the parameters at fault.
 *
 * <p>{@link #keys()} lets a host point at the offending settings without parsing the message. Key
 * names are the ones {@link AuthConfig} uses: parameter names as they appear in
 * {@link AuthConfig#asMap()}, plus {@code username} and {@code password} for the credentials. They
 * carry no host prefix, so a host maps them onto its own setting names.
 *
 * <p>It extends {@link IllegalArgumentException}, so callers that catch that keep working.
 */
public class AuthConfigException extends IllegalArgumentException {
    @Serial
    private static final long serialVersionUID = 1L;

    private final List<String> keys;

    /**
     * Creates an exception.
     *
     * @param message the description, which must never contain a secret
     * @param keys the offending parameter names, empty when no single parameter is at fault
     */
    public AuthConfigException(String message, List<String> keys) {
        this(message, keys, null);
    }

    /**
     * Creates an exception.
     *
     * @param message the description, which must never contain a secret
     * @param keys the offending parameter names, empty when no single parameter is at fault
     * @param cause the underlying failure, may be {@code null}
     */
    public AuthConfigException(String message, List<String> keys, Throwable cause) {
        super(message, cause);
        this.keys = List.copyOf(Objects.requireNonNull(keys, "keys must not be null"));
    }

    /**
     * Returns the offending parameter names, as they appear in {@link AuthConfig} (no host prefix).
     *
     * @return an unmodifiable list, empty when no single parameter is at fault
     */
    public List<String> keys() {
        return keys;
    }
}
