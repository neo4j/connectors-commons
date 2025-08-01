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
package org.neo4j.connectors.common.driver.reauth.tmp;

import java.time.Instant;
import java.util.Map;

public class TokenAuthentication implements ExpiringAuthentication {

    private final String scheme;
    private final String value;
    private final Instant expiresAt;

    public TokenAuthentication(String scheme, String value, Instant expiresAt) {
        this.scheme = scheme;
        this.value = value;
        this.expiresAt = expiresAt;
    }

    public String getScheme() {
        return scheme;
    }

    public String getValue() {
        return value;
    }

    @Override
    public Instant expiresAt() {
        return expiresAt;
    }

    @Override
    public Map<String, Object> toMap() {
        return ExpiringAuthentication.super.toMap();
    }
}
