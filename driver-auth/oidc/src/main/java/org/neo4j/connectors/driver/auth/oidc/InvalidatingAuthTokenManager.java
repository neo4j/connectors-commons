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
package org.neo4j.connectors.driver.auth.oidc;

import java.util.concurrent.CompletionStage;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.exceptions.SecurityException;

/**
 * Passes the driver's rejection of a token on to the token source that cached it.
 *
 * <p>The driver drops its own copy when the server answers with {@code TokenExpired} or
 * {@code Authentication}, then asks for a token again. Without this the caching source would answer
 * that request with the very token the server just refused, and would keep doing so until the
 * token's expiry passed, which for a revoked hour-long token means an hour of failures.
 */
final class InvalidatingAuthTokenManager implements AuthTokenManager {
    private final AuthTokenManager delegate;
    private final TokenSource source;

    InvalidatingAuthTokenManager(AuthTokenManager delegate, TokenSource source) {
        this.delegate = delegate;
        this.source = source;
    }

    @Override
    public CompletionStage<AuthToken> getToken() {
        return delegate.getToken();
    }

    @Override
    public boolean handleSecurityException(AuthToken authToken, SecurityException exception) {
        boolean retryable = delegate.handleSecurityException(authToken, exception);
        if (retryable) {
            source.invalidate();
        }
        return retryable;
    }
}
