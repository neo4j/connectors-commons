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
package org.neo4j.connectors.driver.auth.oidc.grant;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The OAuth 2.0 grants this module can drive.
 *
 * <p>Two names each: the short one a user writes into {@code grantType}, and the URN or keyword that
 * goes onto the wire as {@code grant_type}.
 */
public enum GrantType {
    /** RFC 6749 section 4.4. */
    CLIENT_CREDENTIALS("client_credentials", "client_credentials"),
    /** RFC 6749 section 4.3. */
    PASSWORD("password", "password"),
    /** RFC 6749 section 6. */
    REFRESH_TOKEN("refresh_token", "refresh_token"),
    /** RFC 7523 section 2.1. */
    JWT_BEARER("jwt_bearer", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
    /** RFC 8693. */
    TOKEN_EXCHANGE("token_exchange", "urn:ietf:params:oauth:grant-type:token-exchange");

    private final String settingValue;
    private final String wireValue;

    GrantType(String settingValue, String wireValue) {
        this.settingValue = settingValue;
        this.wireValue = wireValue;
    }

    /**
     * Resolves the value of the {@code grantType} setting.
     *
     * @param value the configured value, may be {@code null}
     * @return the grant, or {@link Optional#empty()} if the value names none
     */
    public static Optional<GrantType> fromSetting(String value) {
        return Arrays.stream(values())
                .filter(grant -> grant.settingValue.equalsIgnoreCase(value))
                .findFirst();
    }

    /**
     * Returns every accepted value of the {@code grantType} setting, for error messages.
     *
     * @return the accepted values, comma separated
     */
    public static String settingValues() {
        return Arrays.stream(values()).map(GrantType::settingValue).collect(Collectors.joining(", "));
    }

    /**
     * Returns the value a user writes into {@code grantType}.
     *
     * @return the setting value
     */
    public String settingValue() {
        return settingValue;
    }

    /**
     * Returns the value sent as the {@code grant_type} form field.
     *
     * @return the wire value
     */
    public String wireValue() {
        return wireValue;
    }
}
