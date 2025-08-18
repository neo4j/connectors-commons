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
package org.neo4j.connectors.common.driver.reauth;

import static java.lang.String.format;

import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;
import org.neo4j.connectors.authn.*;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Value;
import org.neo4j.driver.internal.security.InternalAuthToken;

public class RefreshingInternalAuthToken extends InternalAuthToken {

    private final Supplier<AuthenticationToken> supplier;

    RefreshingInternalAuthToken(Supplier<AuthenticationToken> supplier) {
        super(Collections.emptyMap()); // we just use this class as an interface, ignoring parent class fields
        this.supplier = supplier;
    }

    private static AuthToken convertToAuthToken(AuthenticationToken token) throws IllegalArgumentException {
        if (token instanceof BearerAuthenticationToken) {
            var bearerToken = (BearerAuthenticationToken) token;
            return AuthTokens.bearer(bearerToken.getToken());
        }
        if (token instanceof KerberosAuthenticationToken) {
            var kerberosToken = (KerberosAuthenticationToken) token;
            return AuthTokens.kerberos(kerberosToken.getToken());
        }
        if (token instanceof UserNameAndPasswordAuthenticationToken) {
            var userNameAndPasswordToken = (UserNameAndPasswordAuthenticationToken) token;
            return AuthTokens.basic(
                    userNameAndPasswordToken.getUsername(),
                    userNameAndPasswordToken.getPassword(),
                    userNameAndPasswordToken.getRealm());
        }
        if (token instanceof DisabledAuthenticationToken) {
            return AuthTokens.none();
        }
        if (token instanceof CustomAuthenticationToken) {
            var customToken = (CustomAuthenticationToken) token;
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

    @Override
    public Map<String, Value> toMap() {
        return ((InternalAuthToken) convertToAuthToken(supplier.get())).toMap();
    }
}
