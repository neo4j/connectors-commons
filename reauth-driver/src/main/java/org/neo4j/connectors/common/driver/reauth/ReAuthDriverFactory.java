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

import java.net.URI;
import java.util.function.Supplier;
import org.neo4j.connectors.authn.BearerAuthenticationToken;
import org.neo4j.driver.*;

public final class ReAuthDriverFactory {

    private ReAuthDriverFactory() {}

    public static Driver driver(String uri, Supplier<BearerAuthenticationToken> authTokenSupplier) {
        return driver(URI.create(uri), authTokenSupplier, Config.defaultConfig());
    }

    public static Driver driver(URI uri, Supplier<BearerAuthenticationToken> authTokenSupplier) {
        return driver(uri, authTokenSupplier, Config.defaultConfig());
    }

    public static Driver driver(String uri, Supplier<BearerAuthenticationToken> authTokenSupplier, Config config) {
        return driver(URI.create(uri), authTokenSupplier, config);
    }

    public static Driver driver(URI uri, Supplier<BearerAuthenticationToken> authTokenSupplier, Config config) {
        return new ReAuthDriver(() -> {
            var authToken = authTokenSupplier.get();
            var driver = GraphDatabase.driver(uri, AuthTokens.bearer(authToken.getToken()), config);
            return new ExpiringDriver(driver, authToken.getExpiresAt());
        });
    }
}
