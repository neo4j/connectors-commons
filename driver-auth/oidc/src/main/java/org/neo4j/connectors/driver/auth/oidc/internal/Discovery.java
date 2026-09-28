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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Fetches {@code .well-known/openid-configuration} once, and remembers the answer.
 *
 * <p>Parsed as RFC 8414 authorization server metadata rather than as OpenID Connect provider
 * metadata. Only {@code token_endpoint} is needed here, and {@code OIDCProviderMetadata}
 * additionally requires {@code subject_types_supported} and other fields, rejecting documents this
 * module could otherwise use.
 *
 * <p>The fetch is deferred to the first token request so that creating a token manager performs no
 * I/O. Concurrent callers share one in-flight request: the function handed to
 * {@link java.util.concurrent.atomic.AtomicReference#updateAndGet} only chooses between two
 * references, and the HTTP call is started afterwards by whichever caller's future was installed.
 *
 * <p>A failed lookup clears the slot, so a provider that was briefly unreachable is asked again
 * rather than poisoning the token manager for the life of the process.
 *
 * <p>Internal to this module; not API.
 */
public final class Discovery {
    private final Supplier<HttpClient> http;
    private final URI discoveryUrl;
    private final String expectedIssuer;
    private final Duration requestTimeout;
    private final AtomicReference<CompletableFuture<AuthorizationServerMetadata>> metadata = new AtomicReference<>();

    /**
     * Creates the lookup.
     *
     * @param http supplies the client to fetch with, built on first use
     * @param discoveryUrl the discovery document URL
     * @param expectedIssuer the issuer the document must advertise, or {@code null} to accept any
     * @param requestTimeout the per-request timeout
     */
    public Discovery(Supplier<HttpClient> http, URI discoveryUrl, String expectedIssuer, Duration requestTimeout) {
        this.http = http;
        this.discoveryUrl = discoveryUrl;
        this.expectedIssuer = expectedIssuer;
        this.requestTimeout = requestTimeout;
    }

    /**
     * Returns the advertised token endpoint.
     *
     * @return a stage completing with the token endpoint
     */
    public CompletionStage<URI> tokenEndpoint() {
        return metadata().thenApply(document -> {
            URI tokenEndpoint = document.getTokenEndpointURI();
            if (tokenEndpoint == null) {
                throw new IllegalStateException("The discovery document at " + discoveryUrl
                        + " advertises no 'token_endpoint'. Set the 'tokenEndpoint' parameter to bypass discovery.");
            }
            return tokenEndpoint;
        });
    }

    /**
     * Returns the provider metadata, fetching it at most once.
     *
     * @return a stage completing with the metadata
     */
    CompletionStage<AuthorizationServerMetadata> metadata() {
        CompletableFuture<AuthorizationServerMetadata> current = metadata.get();
        if (current != null) {
            return current;
        }
        CompletableFuture<AuthorizationServerMetadata> promise = new CompletableFuture<>();
        CompletableFuture<AuthorizationServerMetadata> winner =
                metadata.updateAndGet(existing -> existing == null ? promise : existing);
        if (winner == promise) {
            start(promise);
        }
        return winner;
    }

    private void start(CompletableFuture<AuthorizationServerMetadata> promise) {
        fetch().whenComplete((fetched, error) -> {
            if (error != null) {
                metadata.compareAndSet(promise, null);
                promise.completeExceptionally(TokenErrors.unwrap(error));
            } else {
                promise.complete(fetched);
            }
        });
    }

    private CompletableFuture<AuthorizationServerMetadata> fetch() {
        HttpRequest request = HttpRequest.newBuilder(discoveryUrl)
                .timeout(requestTimeout)
                .header("Accept", "application/json")
                .GET()
                .build();
        return http.get()
                .sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(this::parse);
    }

    private AuthorizationServerMetadata parse(HttpResponse<String> response) {
        if (response.statusCode() >= 300 && response.statusCode() < 400) {
            throw new IllegalStateException("The discovery document at " + discoveryUrl + " answered with HTTP "
                    + response.statusCode() + ". Redirects are not followed, because the endpoints they lead to are"
                    + " later sent credentials. Configure 'discoveryUrl' or 'tokenEndpoint' with the final URL.");
        }
        if (response.statusCode() >= 400 || response.statusCode() < 200) {
            throw TokenErrors.discoveryFailed(
                    discoveryUrl,
                    response.statusCode(),
                    // Real elapsed time, not the host's clock: an HTTP-date says when the provider
                    // will be ready, so the wait is measured against the wall clock rather than
                    // against the clock used for token expiry.
                    TokenErrors.retryAfter(response.headers(), Clock.systemUTC())
                            .orElse(null));
        }
        AuthorizationServerMetadata metadata;
        try {
            metadata = AuthorizationServerMetadata.parse(response.body());
        } catch (ParseException e) {
            throw new IllegalStateException(
                    "The discovery document at " + discoveryUrl + " could not be read: " + e.getMessage(), e);
        }
        requireExpectedIssuer(metadata);
        return metadata;
    }

    /**
     * OpenID Connect Discovery section 4.3 and RFC 8414 section 3.3 both require the advertised
     * issuer to equal the one the discovery URL was built from, and the document to be discarded
     * otherwise. Without the check a substituted document could name any {@code token_endpoint}, and
     * this client's secret or signed assertion would be posted to it.
     */
    private void requireExpectedIssuer(AuthorizationServerMetadata metadata) {
        if (expectedIssuer == null) {
            return;
        }
        String advertised =
                metadata.getIssuer() == null ? null : metadata.getIssuer().getValue();
        if (!expectedIssuer.equals(withoutTrailingSlash(advertised))) {
            throw new IllegalStateException("The discovery document at " + discoveryUrl + " advertises issuer '"
                    + advertised + "', but '" + expectedIssuer + "' was configured. The document is not used,"
                    + " because its token endpoint would be sent this client's credentials. If the provider is"
                    + " reached at one address and advertises another, name the advertised one in"
                    + " 'expectedIssuer'.");
        }
    }

    private static String withoutTrailingSlash(String issuer) {
        if (issuer == null) {
            return null;
        }
        return issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
    }
}
