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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;

class TokenSourcesTest {

    @TempDir
    Path directory;

    @Test
    void buildsWithoutStartingAnHttpClient() {
        long before = httpClientThreads();

        TokenSource source = TokenSources.build(config(base()), AuthContext.defaults());

        assertThat(source).isNotNull();
        assertThat(httpClientThreads())
                .as("building a token source must not start a selector thread; on Java 17 it could never be stopped")
                .isEqualTo(before);
    }

    @Test
    void buildsWithoutTouchingTheNetworkOrTheFilesystem() {
        Map<String, String> settings = base();
        settings.put("issuer", "https://provider.invalid");
        settings.put("clientSecretFile", "/does/not/exist");
        settings.put("trustStoreFile", "/does/not/exist/either.p12");
        settings.remove("clientSecret");
        settings.remove("tokenEndpoint");

        assertThat(TokenSources.build(config(settings), AuthContext.defaults())).isNotNull();
    }

    @Test
    void readsTheTrustStoreOnTheFirstFetchRatherThanWhenBuilt() {
        Map<String, String> settings = base();
        settings.put("trustStoreFile", directory.resolve("absent.p12").toString());
        settings.put("maxRetries", "0");
        TokenSource source = TokenSources.build(config(settings), AuthContext.defaults());

        assertThatCode(() -> TokenSources.build(config(settings), AuthContext.defaults()))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> source.fetch().toCompletableFuture().join())
                .hasCauseInstanceOf(UncheckedIOException.class)
                .hasMessageContaining("absent.p12");
    }

    @Test
    void reportsATrustStoreItCannotOpen() throws Exception {
        Path store = Files.writeString(directory.resolve("broken.p12"), "not a key store");
        Map<String, String> settings = base();
        settings.put("trustStoreFile", store.toString());
        settings.put("maxRetries", "0");
        TokenSource source = TokenSources.build(config(settings), AuthContext.defaults());

        assertThatThrownBy(() -> source.fetch().toCompletableFuture().join()).hasMessageContaining("broken.p12");
    }

    @Test
    void failsEveryFetchRatherThanHangingWhenTheClientCannotBeBuiltOnTheDiscoveryPath() throws Exception {
        Path store = directory.resolve("appears-later.p12");
        Map<String, String> settings = base();
        settings.remove("tokenEndpoint");
        settings.put("issuer", "https://127.0.0.1:1/realms/neo4j");
        settings.put("trustStoreFile", store.toString());
        settings.put("trustStorePassword", "testpwd");
        settings.put("maxRetries", "0");
        TokenSource source = TokenSources.build(config(settings), AuthContext.defaults());

        for (int attempt = 1; attempt <= 2; attempt++) {
            int number = attempt;
            assertThatThrownBy(() -> source.fetch()
                            .toCompletableFuture()
                            .orTimeout(1, TimeUnit.SECONDS)
                            .join())
                    .as("fetch %d must report the missing store, not park on a promise nobody completes", number)
                    .hasMessageContaining("appears-later.p12");
        }

        Files.copy(onClasspath("keycloak.jks"), store);

        assertThatThrownBy(() -> source.fetch()
                        .toCompletableFuture()
                        .orTimeout(5, TimeUnit.SECONDS)
                        .join())
                .as("neither cache holds a poisoned slot, so this fetch gets as far as the network")
                .hasRootCauseInstanceOf(IOException.class)
                .hasMessageNotContaining("appears-later.p12");
    }

    @Test
    void usesAConfiguredTrustStore() {
        Map<String, String> settings = base();
        settings.put("trustStoreFile", onClasspath("keycloak.jks").toString());
        settings.put("trustStorePassword", "testpwd");
        settings.put("trustStoreType", "PKCS12");
        settings.put("tokenEndpoint", "https://127.0.0.1:1/token");
        settings.put("maxRetries", "0");
        TokenSource source = TokenSources.build(config(settings), AuthContext.defaults());

        // The client is built, so the failure is the unreachable endpoint rather than the store.
        assertThatThrownBy(() -> source.fetch().toCompletableFuture().join())
                .hasRootCauseInstanceOf(IOException.class)
                .hasMessageNotContaining("trust store");
    }

    @Test
    void usesTheHostsSslContextWhenNoTrustStoreIsConfigured() throws Exception {
        SSLContext hostContext = SSLContext.getInstance("TLS");
        hostContext.init(null, null, null);
        AuthContext context = AuthContext.builder().sslContext(hostContext).build();

        assertThat(TokenSources.build(config(base()), context)).isNotNull();
    }

    @Test
    void acceptsAProxy() {
        Map<String, String> settings = base();
        settings.put("proxyHost", "proxy.internal");
        settings.put("proxyPort", "3128");

        assertThat(TokenSources.build(config(settings), AuthContext.defaults())).isNotNull();
    }

    private static long httpClientThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.getName().contains("HttpClient"))
                .count();
    }

    private static Map<String, String> base() {
        Map<String, String> settings = new HashMap<>();
        settings.put("tokenEndpoint", "https://provider.invalid/token");
        settings.put("clientId", "a-client");
        settings.put("clientSecret", "a-secret");
        return settings;
    }

    private static OidcConfig config(Map<String, String> settings) {
        return OidcConfig.parse(AuthConfig.of(null, null, settings));
    }

    private static Path onClasspath(String resource) {
        try {
            return Paths.get(TokenSourcesTest.class.getResource("/" + resource).toURI());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
