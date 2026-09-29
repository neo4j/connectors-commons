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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CyclicBarrier;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.oidc.TokenEndpointStub;
import org.neo4j.connectors.driver.auth.oidc.TokenRequestException;

class DiscoveryTest {
    private static final String WELL_KNOWN = "/.well-known/openid-configuration";
    private static final String DOCUMENT = "{\"issuer\":\"https://host\",\"token_endpoint\":\"https://host/token\"}";

    private TokenEndpointStub provider;
    private HttpClient http;

    @BeforeEach
    void startProvider() {
        provider = new TokenEndpointStub();
        http = HttpClient.newHttpClient();
    }

    @AfterEach
    void stopProvider() {
        provider.close();
    }

    @Test
    void readsTheTokenEndpointOutOfTheDocument() {
        provider.on(WELL_KNOWN, TokenEndpointStub.Response.json(DOCUMENT));

        Discovery discovery = discovery();

        assertThat(discovery.metadata().toCompletableFuture().join().getIssuer().getValue())
                .isEqualTo("https://host");
        assertThat(discovery.tokenEndpoint().toCompletableFuture().join()).isEqualTo(URI.create("https://host/token"));
    }

    @Test
    void fetchesTheDocumentOnceHoweverManyTokensAreAskedFor() {
        provider.on(WELL_KNOWN, TokenEndpointStub.Response.json(DOCUMENT));
        Discovery discovery = discovery();

        IntStream.range(0, 10)
                .mapToObj(attempt -> discovery.tokenEndpoint())
                .toList()
                .forEach(stage -> stage.toCompletableFuture().join());

        assertThat(provider.requests()).hasSize(1);
    }

    @Test
    void letsConcurrentCallersShareOneInFlightLookup() {
        provider.on(WELL_KNOWN, TokenEndpointStub.Response.json(DOCUMENT));
        Discovery discovery = discovery();
        CyclicBarrier startLine = new CyclicBarrier(8);

        List<CompletableFuture<URI>> lookups = IntStream.range(0, 8)
                .mapToObj(attempt -> CompletableFuture.supplyAsync(() -> {
                            await(startLine);
                            return discovery.tokenEndpoint();
                        })
                        .thenCompose(stage -> stage))
                .toList();
        CompletableFuture.allOf(lookups.toArray(CompletableFuture[]::new)).join();

        assertThat(provider.requests()).hasSize(1);
        assertThat(lookups).allSatisfy(lookup -> assertThat(lookup.join()).isEqualTo(URI.create("https://host/token")));
    }

    @Test
    void asksAgainAfterAFailedLookupRatherThanCachingTheFailure() {
        provider.onEach(WELL_KNOWN, TokenEndpointStub.Response.of(503, ""), TokenEndpointStub.Response.json(DOCUMENT));
        Discovery discovery = discovery();

        assertThatThrownBy(() -> discovery.tokenEndpoint().toCompletableFuture().join())
                .hasCauseInstanceOf(TokenRequestException.class);

        assertThat(discovery.tokenEndpoint().toCompletableFuture().join()).isEqualTo(URI.create("https://host/token"));
    }

    @Test
    void reportsADocumentThatAdvertisesNoTokenEndpoint() {
        provider.on(WELL_KNOWN, TokenEndpointStub.Response.json("{\"issuer\":\"https://host\"}"));

        assertThatThrownBy(
                        () -> discovery().tokenEndpoint().toCompletableFuture().join())
                .hasRootCauseInstanceOf(IllegalStateException.class)
                .hasMessageContaining("token_endpoint")
                .hasMessageContaining("tokenEndpoint");
    }

    @Test
    void reportsADocumentThatIsNotJson() {
        provider.on(WELL_KNOWN, TokenEndpointStub.Response.json("<html/>"));

        assertThatThrownBy(
                        () -> discovery().tokenEndpoint().toCompletableFuture().join())
                .hasCauseInstanceOf(IllegalStateException.class)
                .hasMessageContaining("could not be read");
    }

    @Test
    void reportsADocumentMissingTheMandatoryIssuer() {
        provider.on(WELL_KNOWN, TokenEndpointStub.Response.json("{\"token_endpoint\":\"https://host/token\"}"));

        assertThatThrownBy(
                        () -> discovery().tokenEndpoint().toCompletableFuture().join())
                .hasCauseInstanceOf(IllegalStateException.class)
                .hasMessageContaining("issuer");
    }

    @Test
    void acceptsADocumentThatAdvertisesTheConfiguredIssuer() {
        provider.on(WELL_KNOWN, TokenEndpointStub.Response.json(DOCUMENT));

        assertThat(discoveryExpecting("https://host")
                        .tokenEndpoint()
                        .toCompletableFuture()
                        .join())
                .isEqualTo(URI.create("https://host/token"));
    }

    @Test
    void ignoresATrailingSlashWhenComparingTheIssuer() {
        provider.on(
                WELL_KNOWN,
                TokenEndpointStub.Response.json(
                        "{\"issuer\":\"https://host/\",\"token_endpoint\":\"https://host/token\"}"));

        assertThat(discoveryExpecting("https://host")
                        .tokenEndpoint()
                        .toCompletableFuture()
                        .join())
                .isEqualTo(URI.create("https://host/token"));
    }

    @Test
    void refusesADocumentThatAdvertisesADifferentIssuer() {
        provider.on(
                WELL_KNOWN,
                TokenEndpointStub.Response.json(
                        "{\"issuer\":\"https://attacker\",\"token_endpoint\":\"https://attacker/token\"}"));

        assertThatThrownBy(() -> discoveryExpecting("https://host")
                        .tokenEndpoint()
                        .toCompletableFuture()
                        .join())
                .hasCauseInstanceOf(IllegalStateException.class)
                .hasMessageContaining("https://attacker")
                .hasMessageContaining("https://host");
    }

    @Test
    void refusesToFollowARedirectFromTheDiscoveryUrl() {
        provider.on(
                WELL_KNOWN,
                TokenEndpointStub.Response.of(302, "").withHeader("Location", "https://elsewhere/.well-known"));

        assertThatThrownBy(
                        () -> discovery().tokenEndpoint().toCompletableFuture().join())
                .hasCauseInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Redirects are not followed");
    }

    /** No expected issuer: the case where only {@code discoveryUrl} was configured. */
    private Discovery discovery() {
        return discoveryExpecting(null);
    }

    private Discovery discoveryExpecting(String expectedIssuer) {
        return new Discovery(() -> http, provider.uri(WELL_KNOWN), expectedIssuer, Duration.ofSeconds(5));
    }

    private static void await(CyclicBarrier barrier) {
        try {
            barrier.await();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
