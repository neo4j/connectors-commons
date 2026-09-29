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

import java.time.Instant;
import java.util.Objects;

/**
 * A token obtained from an OAuth 2.0 token endpoint, together with the moment it should stop being
 * used.
 *
 * <p>{@code expiresAt} already has the configured refresh skew subtracted, so it is the moment the
 * token must be replaced by, not the moment the provider will start rejecting it.
 *
 * @param value the token itself, never {@code null}
 * @param expiresAt when the token must be replaced, never {@code null}
 * @param refreshToken the refresh token the provider returned alongside it, may be {@code null}
 */
public record AccessToken(String value, Instant expiresAt, String refreshToken) {
    public AccessToken {
        Objects.requireNonNull(value, "value must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }

    /**
     * Returns a description that holds no secret.
     *
     * @return a redacted description
     */
    @Override
    public String toString() {
        return "AccessToken{value=<redacted>, expiresAt=" + expiresAt + ", refreshToken="
                + (refreshToken == null ? "<absent>" : "<redacted>") + "}";
    }
}
