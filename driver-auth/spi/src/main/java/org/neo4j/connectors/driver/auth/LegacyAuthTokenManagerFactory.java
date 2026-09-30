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
package org.neo4j.connectors.driver.auth;

import java.util.function.Supplier;
import org.neo4j.connectors.authn.AuthenticationToken;
import org.neo4j.connectors.authn.AuthenticationTokenSupplierFactory;
import org.neo4j.driver.AuthTokenManager;

final class LegacyAuthTokenManagerFactory implements AuthTokenManagerFactory {
    private final AuthenticationTokenSupplierFactory delegate;

    LegacyAuthTokenManagerFactory(AuthenticationTokenSupplierFactory delegate) {
        this.delegate = delegate;
    }

    @Override
    public String getName() {
        return delegate.getName();
    }

    @Override
    public AuthTokenManager create(AuthConfig config, AuthContext context) {
        Supplier<AuthenticationToken> supplier = delegate.create(
                config.username().orElse(null), config.password().orElse(null), config.asMap());
        return LegacyAuthBridge.fromSupplier(supplier, context.executor());
    }

    /** Legacy factories only offer a create-style method, which is not safe to call just to validate. */
    @Override
    public void validate(AuthConfig config, AuthContext context) {}
}
