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
package org.neo4j.connectors.driver.auth.oidc.clientauth;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The ways a client can prove its identity to a token endpoint.
 */
public enum ClientAuthMethod {
    /** RFC 6749 section 2.3.1: HTTP Basic, the OAuth 2.0 default. */
    CLIENT_SECRET_BASIC("client_secret_basic"),
    /** RFC 6749 section 2.3.1: the secret as a form field. */
    CLIENT_SECRET_POST("client_secret_post"),
    /** RFC 7523 section 2.2: a JWT signed with the client's private key. */
    PRIVATE_KEY_JWT("private_key_jwt"),
    /** No client authentication, for public clients and for grants where the assertion is the credential. */
    NONE("none");

    private final String settingValue;

    ClientAuthMethod(String settingValue) {
        this.settingValue = settingValue;
    }

    /**
     * Resolves the value of the {@code clientAuthMethod} setting.
     *
     * @param value the configured value, may be {@code null}
     * @return the method, or {@link Optional#empty()} if the value names none
     */
    public static Optional<ClientAuthMethod> fromSetting(String value) {
        return Arrays.stream(values())
                .filter(method -> method.settingValue.equalsIgnoreCase(value))
                .findFirst();
    }

    /**
     * Returns every accepted value of the {@code clientAuthMethod} setting, for error messages.
     *
     * @return the accepted values, comma separated
     */
    public static String settingValues() {
        return Arrays.stream(values()).map(ClientAuthMethod::settingValue).collect(Collectors.joining(", "));
    }

    /**
     * Returns the value a user writes into {@code clientAuthMethod}.
     *
     * @return the setting value
     */
    public String settingValue() {
        return settingValue;
    }
}
