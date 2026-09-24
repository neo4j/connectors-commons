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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.neo4j.connectors.driver.auth.oidc.TokenRequestException;

class TokenErrorsTest {
    private static final URI ENDPOINT = URI.create("https://host/token");

    @ParameterizedTest
    @ValueSource(strings = {"invalid_client", "invalid_grant", "unauthorized_client", "invalid_scope"})
    void doesNotRetryACredentialThatWillStayWrong(String error) {
        TokenRequestException exception =
                TokenErrors.fromResponse(ENDPOINT, 400, "{\"error\":\"" + error + "\"}", null);

        assertThat(exception.isRetryable()).isFalse();
        assertThat(exception.errorCode()).contains(error);
        assertThat(exception.statusCode()).isEqualTo(400);
        assertThat(exception).hasMessageContaining("will not be retried");
    }

    @ParameterizedTest
    @ValueSource(ints = {408, 429, 500, 502, 503})
    void retriesWhatMightNotRecur(int status) {
        assertThat(TokenErrors.fromResponse(ENDPOINT, status, "", null).isRetryable())
                .isTrue();
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 403, 404})
    void doesNotRetryWhatTheProviderDecided(int status) {
        assertThat(TokenErrors.fromResponse(ENDPOINT, status, "", null).isRetryable())
                .isFalse();
    }

    @Test
    void putsTheProvidersOwnDescriptionInTheMessage() {
        TokenRequestException exception = TokenErrors.fromResponse(
                ENDPOINT,
                401,
                "{\"error\":\"invalid_client\",\"error_description\":\"Client secret not provided\"}",
                null);

        assertThat(exception)
                .hasMessageContaining("https://host/token")
                .hasMessageContaining("HTTP 401")
                .hasMessageContaining("invalid_client")
                .hasMessageContaining("Client secret not provided");
    }

    @Test
    void copesWithABodyThatIsNotJson() {
        TokenRequestException exception = TokenErrors.fromResponse(ENDPOINT, 503, "<html>gateway</html>", null);

        assertThat(exception.errorCode()).isEmpty();
        assertThat(exception.isRetryable()).isTrue();
    }

    @Test
    void treatsTransportFailuresAsWorthAnotherAttempt() {
        assertThat(TokenErrors.isRetryable(new IOException("connection reset"))).isTrue();
        assertThat(TokenErrors.isRetryable(new HttpTimeoutException("timed out")))
                .isTrue();
        assertThat(TokenErrors.isRetryable(new CompletionException(new IOException("reset"))))
                .isTrue();
        assertThat(TokenErrors.isRetryable(new IllegalArgumentException("bad config")))
                .isFalse();
    }

    @Test
    void readsRetryAfterInSeconds() {
        assertThat(TokenErrors.retryAfter(headers("Retry-After", "12"), Clock.systemUTC()))
                .contains(Duration.ofSeconds(12));
    }

    @Test
    void readsRetryAfterAsAnHttpDate() {
        Clock clock = Clock.fixed(Instant.parse("2026-09-21T10:00:00Z"), ZoneOffset.UTC);

        assertThat(TokenErrors.retryAfter(headers("Retry-After", "Mon, 21 Sep 2026 10:00:30 GMT"), clock))
                .contains(Duration.ofSeconds(30));
    }

    @Test
    void clampsAnHttpDateInThePastToNoDelay() {
        Clock clock = Clock.fixed(Instant.parse("2026-09-21T10:00:00Z"), ZoneOffset.UTC);

        assertThat(TokenErrors.retryAfter(headers("Retry-After", "Mon, 21 Sep 2026 09:59:00 GMT"), clock))
                .contains(Duration.ZERO);
    }

    @Test
    void ignoresAnUnreadableRetryAfter() {
        assertThat(TokenErrors.retryAfter(headers("Retry-After", "soon"), Clock.systemUTC()))
                .isEmpty();
        assertThat(TokenErrors.retryAfter(headers("X-Other", "1"), Clock.systemUTC()))
                .isEmpty();
    }

    private static HttpHeaders headers(String name, String value) {
        return HttpHeaders.of(Map.of(name, List.of(value)), (a, b) -> true);
    }
}
