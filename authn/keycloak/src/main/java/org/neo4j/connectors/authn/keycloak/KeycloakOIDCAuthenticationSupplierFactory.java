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
package org.neo4j.connectors.authn.keycloak;

import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.authorization.client.Configuration;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.AuthenticationTokenSupplierFactory;

/**
 * Use this factory to spawn a keycloak oidc configured sso client.
 */
public class KeycloakOIDCAuthenticationSupplierFactory implements AuthenticationTokenSupplierFactory {

    @Override
    public String getName() {
        return "keycloak";
    }

    @Override
    public Supplier<AuthenticationToken> create(String username, String password, Map<String, String> parameters) {
        // make sure parameters are passed
        var url = Objects.requireNonNull(parameters.get("authServerUrl"));
        var realm = Objects.requireNonNull(parameters.get("realm"));
        var clientId = Objects.requireNonNull(parameters.get("clientId"));
        var clientSecret = Objects.requireNonNull(parameters.get("clientSecret"));

        return new KeycloakOIDCAuthenticationSupplier(
                username,
                password,
                new Configuration(url, realm, clientId, Map.of("secret", clientSecret), HttpClients.createMinimal()));
    }
}
