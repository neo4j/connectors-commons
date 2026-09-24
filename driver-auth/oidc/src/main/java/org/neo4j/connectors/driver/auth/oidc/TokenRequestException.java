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

import java.time.Duration;
import java.util.Optional;

/**
 * Signals that a token could not be obtained from the token endpoint.
 *
 * <p>{@link #isRetryable()} carries the classification the retry layer acts on. Per RFC 6749 a
 * {@code invalid_client} or {@code invalid_grant} response means the credential is wrong and will
 * stay wrong, so retrying it only hammers the provider; only timeouts, {@code 429} and {@code 5xx}
 * are worth another attempt.
 */
public class TokenRequestException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final String errorCode;
    private final boolean retryable;
    private final Duration retryAfter;

    /**
     * Creates an exception.
     *
     * @param message the description, which must never contain a token or a secret
     * @param statusCode the HTTP status code, or {@code 0} if no response was received
     * @param errorCode the RFC 6749 {@code error} value, may be {@code null}
     * @param retryable whether another attempt could succeed
     * @param retryAfter how long to wait before the next attempt, may be {@code null}
     * @param cause the underlying failure, may be {@code null}
     */
    public TokenRequestException(
            String message, int statusCode, String errorCode, boolean retryable, Duration retryAfter, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
        this.errorCode = errorCode;
        this.retryable = retryable;
        this.retryAfter = retryAfter;
    }

    /**
     * Returns the HTTP status code of the offending response.
     *
     * @return the status code, or {@code 0} if the request never got a response
     */
    public int statusCode() {
        return statusCode;
    }

    /**
     * Returns the RFC 6749 error code the provider reported.
     *
     * @return the error code, or {@link Optional#empty()} if the body carried none
     */
    public Optional<String> errorCode() {
        return Optional.ofNullable(errorCode);
    }

    /**
     * Returns whether another attempt could succeed.
     *
     * @return {@code true} for timeouts, {@code 429} and {@code 5xx}
     */
    public boolean isRetryable() {
        return retryable;
    }

    /**
     * Returns the delay the provider asked for.
     *
     * @return the {@code Retry-After} delay, or {@link Optional#empty()} if none was sent
     */
    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }
}
