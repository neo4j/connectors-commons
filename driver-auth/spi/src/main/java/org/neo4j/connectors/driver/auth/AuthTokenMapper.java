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

import static java.lang.String.format;

import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.BearerAuthenticationToken;
import org.neo4j.connectors.authn.CustomAuthenticationToken;
import org.neo4j.connectors.authn.DisabledAuthenticationToken;
import org.neo4j.connectors.authn.KerberosAuthenticationToken;
import org.neo4j.connectors.authn.UserNameAndPasswordAuthenticationToken;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokens;

/**
 * Maps a connector {@link AuthenticationToken} onto the driver's {@link AuthToken}.
 *
 * <p>{@link AuthToken} is a sealed interface, so every token has to be produced through
 * {@link AuthTokens}.
 */
public final class AuthTokenMapper {

    private AuthTokenMapper() {}

    /**
     * Maps a connector token onto its driver equivalent.
     *
     * @param token the connector token
     * @return the driver token
     * @throws IllegalArgumentException if the token is of an unsupported type
     */
    public static AuthToken toDriverToken(AuthenticationToken token) {
        if (token instanceof BearerAuthenticationToken bearerToken) {
            return AuthTokens.bearer(bearerToken.getToken());
        }
        if (token instanceof KerberosAuthenticationToken kerberosToken) {
            return AuthTokens.kerberos(kerberosToken.getToken());
        }
        if (token instanceof UserNameAndPasswordAuthenticationToken userNameAndPasswordToken) {
            return AuthTokens.basic(
                    userNameAndPasswordToken.getUsername(),
                    userNameAndPasswordToken.getPassword(),
                    userNameAndPasswordToken.getRealm());
        }
        if (token instanceof DisabledAuthenticationToken) {
            return AuthTokens.none();
        }
        if (token instanceof CustomAuthenticationToken customToken) {
            return AuthTokens.custom(
                    customToken.getPrincipal(),
                    customToken.getCredentials(),
                    customToken.getRealm(),
                    customToken.getScheme(),
                    customToken.getParameters());
        }
        throw new IllegalArgumentException(
                format("Authentication token of class %s is not supported", token.getClass()));
    }
}
