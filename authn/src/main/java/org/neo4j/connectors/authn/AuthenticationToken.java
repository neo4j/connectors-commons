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

import java.time.Instant;

public interface AuthenticationToken {
    String getScheme();

    static AuthenticationToken bearer(String token) {
        return bearer(token, null);
    }

    static AuthenticationToken bearer(String token, Instant expiresAt) {
        return new BearerAuthenticationToken(token, expiresAt);
    }

    static AuthenticationToken kerberos(String token) {
        return new KerberosAuthenticationToken(token);
    }

    static AuthenticationToken none() {
        return DisabledAuthenticationToken.NONE;
    }

    static AuthenticationToken usernameAndPassword(String username, String password) {
        return usernameAndPassword(username, password, null);
    }

    static AuthenticationToken usernameAndPassword(String username, String password, String realm) {
        return new UserNameAndPasswordAuthenticationToken(username, password, realm);
    }
}
