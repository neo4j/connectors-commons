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
package org.neo4j.connectors.authn.sso;

import java.util.function.Supplier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.Http;
import org.neo4j.connectors.authn.AuthenticationToken;

/**
 * This supplier uses OAth2 resource owner flow via the Keycloak client.
 */
public class ConnectorsAuthenticationSupplier implements Supplier<AuthenticationToken> {
    private final String username;
    private final String password;
    private final Configuration config;
    private final AuthzClient client;
    private final Http http;
    private final String url;

    ConnectorsAuthenticationSupplier(String username, String password, Configuration config) {
        this.username = username;
        this.password = password;
        this.config = config;
        this.client = AuthzClient.create(config);
        this.url = constructUrl(config);
        this.http = new Http(config, config.getClientCredentialsProvider());
    }

    private String constructUrl(Configuration c) {
        return c.getAuthServerUrl() + "/realms/" + c.getRealm() + "/protocol/openid-connect/token";
    }

    @Override
    public AuthenticationToken get() {
        return null;
    }
}
