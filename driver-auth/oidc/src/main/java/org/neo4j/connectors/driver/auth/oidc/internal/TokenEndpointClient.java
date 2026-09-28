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

import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;
import org.neo4j.connectors.driver.auth.oidc.AccessToken;
import org.neo4j.connectors.driver.auth.oidc.TokenRequestException;

/**
 * Sends an SDK-built {@link TokenRequest} over the JDK's asynchronous client and reads the reply.
 *
 * <p>The SDK builds the request and classifies the error body; the transport stays
 * {@link HttpClient#sendAsync}, because the driver's {@code bearerAsync} already wants a
 * {@link CompletionStage} and the SDK's own {@code HTTPRequest.send()} is blocking. Bridging the two
 * costs a dozen lines and keeps every token fetch off whichever thread asked for it.
 *
 * <p>The success body is read here rather than by {@code TokenResponse.parse}, which insists on
 * {@code token_type}. Google's {@code jwt_bearer} flow does not return that field at all, because
 * its reply carries only {@code id_token}. Reading the configured {@code tokenField} out of the
 * JSON object keeps that provider working.
 *
 * <p>Internal to this module; not API.
 */
public final class TokenEndpointClient {
    private static final System.Logger LOG = System.getLogger(TokenEndpointClient.class.getName());

    /** Headers the JDK client reserves; the SDK never sets them, but a custom one might. */
    private static final Set<String> RESTRICTED = Set.of("connection", "content-length", "expect", "host", "upgrade");

    /**
     * The shortest lifetime this client reports. A provider whose tokens live for less than the
     * configured refresh skew would otherwise yield an already expired token, and the driver would
     * request a new one on every call.
     */
    private static final Duration MINIMUM_LIFETIME = Duration.ofSeconds(1);

    private final Supplier<HttpClient> http;
    private final Duration requestTimeout;
    private final String tokenField;
    private final Duration refreshSkew;
    private final Duration defaultTtl;
    private final Clock clock;

    /**
     * Creates the client.
     *
     * @param http supplies the client to send with, built on first use
     * @param requestTimeout the per-request timeout
     * @param tokenField the response field holding the token, {@code access_token} or {@code id_token}
     * @param refreshSkew how early to treat the token as expired
     * @param defaultTtl the lifetime to assume when nothing else says
     * @param clock the clock every expiry is computed against
     */
    public TokenEndpointClient(
            Supplier<HttpClient> http,
            Duration requestTimeout,
            String tokenField,
            Duration refreshSkew,
            Duration defaultTtl,
            Clock clock) {
        this.http = http;
        this.requestTimeout = requestTimeout;
        this.tokenField = tokenField;
        this.refreshSkew = refreshSkew;
        this.defaultTtl = defaultTtl;
        this.clock = clock;
    }

    /**
     * Sends a token request.
     *
     * @param request the request the SDK assembled
     * @return a stage completing with the token
     */
    public CompletionStage<AccessToken> requestToken(TokenRequest request) {
        try {
            HTTPRequest sdkRequest = request.toHTTPRequest();
            URI endpoint = sdkRequest.getURI();
            return http.get()
                    .sendAsync(toJdk(sdkRequest), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                    .thenApply(response -> toAccessToken(endpoint, response));
        } catch (RuntimeException e) {
            return CompletableFuture.failedStage(e);
        }
    }

    private HttpRequest toJdk(HTTPRequest sdkRequest) {
        String body = sdkRequest.getBody() == null ? "" : sdkRequest.getBody();
        HttpRequest.Builder builder = HttpRequest.newBuilder(sdkRequest.getURI())
                .timeout(requestTimeout)
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        sdkRequest.getHeaderMap().forEach((name, values) -> {
            if (!RESTRICTED.contains(name.toLowerCase(java.util.Locale.ROOT))) {
                values.forEach(value -> builder.header(name, value));
            }
        });
        return builder.build();
    }

    private AccessToken toAccessToken(URI endpoint, HttpResponse<String> response) {
        Duration retryAfter = TokenErrors.retryAfter(response.headers(), clock).orElse(null);
        if (response.statusCode() >= 300 & response.statusCode() < 400) {
            // Not followed: a 307 or 308 would replay this request, credentials and all, to
            // whatever host Location names.
            throw new TokenRequestException(
                    "The token endpoint " + endpoint + " answered with HTTP " + response.statusCode()
                            + ". Redirects from a token endpoint are not followed, because the request carries"
                            + " this client's credentials. Configure 'tokenEndpoint' with the final URL.",
                    response.statusCode(),
                    null,
                    false,
                    retryAfter,
                    null);
        }
        if (response.statusCode() >= 400 || response.statusCode() < 200) {
            throw TokenErrors.fromResponse(endpoint, response.statusCode(), response.body(), retryAfter);
        }

        Map<String, Object> body;
        try {
            body = JSONObjectUtils.parse(response.body());
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new TokenRequestException(
                    "The token endpoint " + endpoint + " returned a body that is not valid JSON",
                    response.statusCode(),
                    null,
                    false,
                    retryAfter,
                    e);
        }

        Object token = body.get(tokenField);
        if (token == null) {
            throw new TokenRequestException(
                    "The token endpoint " + endpoint + " returned no '" + tokenField
                            + "' field. Check the 'tokenField' parameter: Google's jwt_bearer flow returns the JWT as"
                            + " 'id_token', most other providers as 'access_token'.",
                    response.statusCode(),
                    null,
                    false,
                    retryAfter,
                    null);
        }
        String value = token.toString();
        warnIfOpaque(endpoint, value);

        Object refreshToken = body.get("refresh_token");
        return new AccessToken(
                value, expiryOf(value, body.get("expires_in")), refreshToken == null ? null : refreshToken.toString());
    }

    /**
     * Derives when the token must be replaced: {@code expires_in}, then the JWT {@code exp} claim,
     * then the configured default, each minus the refresh skew.
     *
     * <p>The {@code exp} claim is the fallback rather than the primary source because an opaque
     * token has no claims to read, and that is what Okta returns without a custom authorisation
     * server.
     */
    private Instant expiryOf(String token, Object expiresIn) {
        Instant now = clock.instant();
        Instant expiry = asSeconds(expiresIn)
                .map(now::plusSeconds)
                .or(() -> Jwts.expiry(token))
                .orElseGet(() -> now.plus(defaultTtl))
                .minus(refreshSkew);
        Instant earliest = now.plus(MINIMUM_LIFETIME);
        return expiry.isBefore(earliest) ? earliest : expiry;
    }

    private static Optional<Long> asSeconds(Object expiresIn) {
        if (expiresIn instanceof Number number) {
            return Optional.of(number.longValue());
        }
        if (expiresIn instanceof String text) {
            try {
                return Optional.of(Long.parseLong(text.strip()));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private void warnIfOpaque(URI endpoint, String token) {
        if (!Jwts.isJwt(token)) {
            LOG.log(
                    System.Logger.Level.WARNING,
                    () -> "The token endpoint " + endpoint + " returned an opaque '" + tokenField
                            + "', not a JWT. Neo4j only accepts a JWT, so authentication will fail at the server.");
        }
    }
}
