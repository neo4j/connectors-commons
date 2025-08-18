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
package org.neo4j.connectors.authn;

import java.util.Map;

public class CustomAuthenticationToken implements AuthenticationToken {
    private final String principal;
    private final String credentials;
    private final String realm;
    private final String scheme;
    private final Map<String, Object> parameters;

    public CustomAuthenticationToken(
            String principal, String credentials, String realm, String scheme, Map<String, Object> parameters) {
        this.principal = principal;
        this.credentials = credentials;
        this.realm = realm;
        this.scheme = scheme;
        this.parameters = parameters;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getCredentials() {
        return credentials;
    }

    public String getRealm() {
        return realm;
    }

    public String getScheme() {
        return scheme;
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }
}
