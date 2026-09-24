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
package org.neo4j.connectors.driver.auth.oidc.internal;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import org.neo4j.connectors.driver.auth.oidc.TokenRequestException;

/**
 * Turns a refused token request into a {@link TokenRequestException} that says whether trying again
 * could help.
 *
 * <p>The RFC 6749 error body is read by the SDK's {@link TokenErrorResponse}; the classification is
 * ours, because it is a policy decision the specification does not make. It is deliberately narrow:
 * only a timeout, a {@code 408}, a {@code 429} and a {@code 5xx} are transient. An
 * {@code invalid_client} or {@code invalid_grant} means the credential is wrong and will stay wrong,
 * and reporting that as retryable would have the driver hammer the provider with a dead credential
 * until the rate limiter notices.
 *
 * <p>Internal to this module; not API.
 */
public final class TokenErrors {
    private TokenErrors() {}

    /**
     * Builds the exception for a non-2xx token endpoint response.
     *
     * @param endpoint the endpoint that was called
     * @param status the HTTP status code
     * @param body the response body, which is read for the RFC 6749 {@code error} fields
     * @param retryAfter the parsed {@code Retry-After}, may be {@code null}
     * @return the exception to fail the fetch with
     */
    public static TokenRequestException fromResponse(URI endpoint, int status, String body, Duration retryAfter) {
        ErrorObject error = parse(status, body);
        String code = error == null ? null : error.getCode();
        String description = error == null ? null : error.getDescription();

        StringBuilder message = new StringBuilder("The token endpoint ")
                .append(endpoint)
                .append(" refused the request with HTTP ")
                .append(status);
        if (code != null) {
            message.append(" (").append(code);
            if (description != null) {
                message.append(": ").append(description);
            }
            message.append(")");
        }
        boolean retryable = isRetryable(status);
        if (!retryable && code != null) {
            message.append(". This is a configuration problem, not a transient one, so it will not be retried");
        }
        return new TokenRequestException(message.toString(), status, code, retryable, retryAfter, null);
    }

    /**
     * Builds the exception for a discovery document that could not be fetched.
     *
     * @param discoveryUrl the URL that was called
     * @param status the HTTP status code
     * @param retryAfter the parsed {@code Retry-After}, may be {@code null}
     * @return the exception to fail the fetch with
     */
    public static TokenRequestException discoveryFailed(URI discoveryUrl, int status, Duration retryAfter) {
        return new TokenRequestException(
                "The discovery document at " + discoveryUrl + " could not be fetched: HTTP " + status,
                status,
                null,
                isRetryable(status),
                retryAfter,
                null);
    }

    /**
     * Returns whether a status code is worth another attempt.
     *
     * @param status the HTTP status code
     * @return {@code true} for {@code 408}, {@code 429} and {@code 5xx}
     */
    public static boolean isRetryable(int status) {
        return status == 408 || status == 429 || status >= 500;
    }

    /**
     * Returns whether a failure is worth another attempt.
     *
     * <p>Transport failures — a connection reset, a timeout — are; anything the provider decided is
     * classified by {@link TokenRequestException#isRetryable()}.
     *
     * @param error the failure, may be wrapped in a {@link CompletionException}
     * @return {@code true} if another attempt could succeed
     */
    public static boolean isRetryable(Throwable error) {
        Throwable cause = unwrap(error);
        if (cause instanceof TokenRequestException tokenRequestException) {
            return tokenRequestException.isRetryable();
        }
        return cause instanceof IOException || cause instanceof TimeoutException;
    }

    /**
     * Unwraps the {@link CompletionException} the {@code CompletableFuture} machinery adds.
     *
     * @param error the failure
     * @return the underlying failure
     */
    public static Throwable unwrap(Throwable error) {
        Throwable cause = error;
        while ((cause instanceof CompletionException || cause instanceof ExecutionException)
                && cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }

    /**
     * Reads a {@code Retry-After} header, in either of the two forms RFC 9110 allows.
     *
     * @param headers the response headers
     * @param clock the clock, for the HTTP-date form
     * @return the delay, or {@link Optional#empty()} if the header is absent or unreadable
     */
    public static Optional<Duration> retryAfter(HttpHeaders headers, Clock clock) {
        return headers.firstValue("retry-after").flatMap(value -> retryAfter(value, clock));
    }

    private static Optional<Duration> retryAfter(String value, Clock clock) {
        String trimmed = value.strip();
        try {
            return Optional.of(Duration.ofSeconds(Long.parseLong(trimmed)));
        } catch (NumberFormatException ignored) {
            // Not delay-seconds; fall through to the HTTP-date form.
        }
        try {
            Instant when = Instant.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(trimmed));
            Duration delay = Duration.between(clock.instant(), when);
            return Optional.of(delay.isNegative() ? Duration.ZERO : delay);
        } catch (RuntimeException ignored) {
            return Optional.empty();
        }
    }

    private static ErrorObject parse(int status, String body) {
        HTTPResponse response = new HTTPResponse(status);
        response.setEntityContentType(com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON);
        response.setBody(body == null ? "" : body);
        try {
            ErrorObject error = TokenErrorResponse.parse(response).getErrorObject();
            return error == null || error.getCode() == null ? null : error;
        } catch (ParseException e) {
            return null;
        }
    }
}
