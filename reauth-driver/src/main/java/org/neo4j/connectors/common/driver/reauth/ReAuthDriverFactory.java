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

import java.net.URI;
import java.util.function.Supplier;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.BearerAuthenticationToken;
import org.neo4j.connectors.authn.CustomAuthenticationToken;
import org.neo4j.connectors.authn.DisabledAuthenticationToken;
import org.neo4j.connectors.authn.ExpiringAuthenticationToken;
import org.neo4j.connectors.authn.KerberosAuthenticationToken;
import org.neo4j.connectors.authn.UserNameAndPasswordAuthenticationToken;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Config;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;

public final class ReAuthDriverFactory {

    private ReAuthDriverFactory() {}

    public static Driver driver(String uri, Supplier<AuthenticationToken> authTokenSupplier) {
        return driver(URI.create(uri), authTokenSupplier, Config.defaultConfig());
    }

    public static Driver driver(URI uri, Supplier<AuthenticationToken> authTokenSupplier) {
        return driver(uri, authTokenSupplier, Config.defaultConfig());
    }

    public static Driver driver(String uri, Supplier<AuthenticationToken> authTokenSupplier, Config config) {
        return driver(URI.create(uri), authTokenSupplier, config);
    }

    public static Driver driver(URI uri, Supplier<AuthenticationToken> authTokenSupplier, Config config) {
        AuthenticationToken authenticationToken = authTokenSupplier.get();
        Driver originalDriver = GraphDatabase.driver(uri, convertToAuthToken(authenticationToken), config);

        if (!(authenticationToken instanceof ExpiringAuthenticationToken)) {
            return originalDriver;
        }

        Supplier<Driver> refresher = () -> {
            AuthenticationToken refreshedToken = authTokenSupplier.get();
            return GraphDatabase.driver(uri, convertToAuthToken(refreshedToken), config);
        };
        return new ReAuthDriver(originalDriver, refresher);
    }

    private static AuthToken convertToAuthToken(AuthenticationToken token) throws IllegalArgumentException {
        if (token instanceof BearerAuthenticationToken) {
            BearerAuthenticationToken bearerToken = (BearerAuthenticationToken) token;
            return AuthTokens.bearer(bearerToken.getToken());
        }
        if (token instanceof KerberosAuthenticationToken) {
            KerberosAuthenticationToken kerberosToken = (KerberosAuthenticationToken) token;
            return AuthTokens.kerberos(kerberosToken.getToken());
        }
        if (token instanceof UserNameAndPasswordAuthenticationToken) {
            UserNameAndPasswordAuthenticationToken userNameAndPasswordToken =
                    (UserNameAndPasswordAuthenticationToken) token;
            return AuthTokens.basic(
                    userNameAndPasswordToken.getUsername(),
                    userNameAndPasswordToken.getPassword(),
                    userNameAndPasswordToken.getRealm());
        }
        if (token instanceof DisabledAuthenticationToken) {
            return AuthTokens.none();
        }
        if (token instanceof CustomAuthenticationToken) {
            CustomAuthenticationToken customToken = (CustomAuthenticationToken) token;
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
