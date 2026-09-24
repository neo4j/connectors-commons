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
package org.neo4j.connectors.driver.auth.oidc.internal;

import com.nimbusds.jwt.JWTParser;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

/**
 * Reading — never validating — a JWT we were handed.
 *
 * <p>Signature checking is the server's job: we mint tokens, Neo4j decides whether to trust them.
 * The only claim of interest here is {@code exp}, and only as a fallback for a response that omitted
 * {@code expires_in}.
 *
 * <p>Internal to this module; not API.
 */
public final class Jwts {
    private Jwts() {}

    /**
     * Returns whether a token parses as a JWT.
     *
     * <p>Used to tell a user that their provider handed back an opaque token, which Neo4j cannot
     * accept, rather than letting the server reject it without explanation.
     *
     * @param token the token, may be {@code null}
     * @return {@code true} if the token is a well-formed JWT
     */
    public static boolean isJwt(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        try {
            JWTParser.parse(token);
            return true;
        } catch (java.text.ParseException e) {
            return false;
        }
    }

    /**
     * Reads the {@code exp} claim of a JWT.
     *
     * @param token the token, may be {@code null} or opaque
     * @return the expiry, or {@link Optional#empty()} if the token is not a JWT or carries no
     *     {@code exp}
     */
    public static Optional<Instant> expiry(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            Date expiry = JWTParser.parse(token).getJWTClaimsSet().getExpirationTime();
            return Optional.ofNullable(expiry).map(Date::toInstant);
        } catch (Exception e) {
            // A token we cannot read is not a failure: expiry falls through to the configured default.
            return Optional.empty();
        }
    }
}
