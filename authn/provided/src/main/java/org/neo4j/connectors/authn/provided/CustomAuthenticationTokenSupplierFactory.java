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
package org.neo4j.connectors.authn.provided;

import java.util.Map;
import java.util.function.Supplier;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.AuthenticationTokenSupplierFactory;

public class CustomAuthenticationTokenSupplierFactory implements AuthenticationTokenSupplierFactory {
    @Override
    public String getName() {
        return "custom";
    }

    @Override
    public Supplier<AuthenticationToken> create(String username, String password, Map<String, String> parameters) {
        String principal = parameters.get("principal");
        String credentials = parameters.get("credentials");
        String realm = parameters.get("realm");
        String scheme = parameters.get("scheme");

        AuthenticationToken authenticationToken = AuthenticationToken.custom(principal, credentials, realm, scheme);
        return () -> authenticationToken;
    }
}
