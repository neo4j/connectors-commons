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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;

class TokenSourcesTest {

    @TempDir
    Path directory;

    @Test
    void buildsWithoutTouchingTheNetworkOrTheFilesystem() {
        Map<String, String> settings = base();
        settings.put("issuer", "https://provider.invalid");
        settings.put("clientSecretFile", "/does/not/exist");
        settings.remove("clientSecret");

        assertThat(TokenSources.build(config(settings), AuthContext.defaults())).isNotNull();
    }

    @Test
    void buildsAnSslContextFromAConfiguredTrustStore() {
        Map<String, String> settings = base();
        settings.put("trustStoreFile", onClasspath("keycloak.jks").toString());
        settings.put("trustStorePassword", "testpwd");
        settings.put("trustStoreType", "PKCS12");

        assertThat(TokenSources.build(config(settings), AuthContext.defaults())).isNotNull();
    }

    @Test
    void reportsATrustStoreThatIsNotThere() {
        Map<String, String> settings = base();
        settings.put("trustStoreFile", directory.resolve("absent.p12").toString());

        assertThatThrownBy(() -> TokenSources.build(config(settings), AuthContext.defaults()))
                .isInstanceOf(UncheckedIOException.class)
                .hasMessageContaining("absent.p12");
    }

    @Test
    void reportsATrustStoreItCannotOpen() throws Exception {
        Path store = Files.writeString(directory.resolve("broken.p12"), "not a key store");
        Map<String, String> settings = base();
        settings.put("trustStoreFile", store.toString());

        assertThatThrownBy(() -> TokenSources.build(config(settings), AuthContext.defaults()))
                .isInstanceOfAny(UncheckedIOException.class, IllegalArgumentException.class)
                .hasMessageContaining("broken.p12");
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
