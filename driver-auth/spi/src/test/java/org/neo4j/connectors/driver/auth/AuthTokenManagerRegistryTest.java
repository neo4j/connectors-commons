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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.neo4j.driver.AuthTokenManager;
import org.neo4j.driver.AuthTokens;

class AuthTokenManagerRegistryTest {
    private static final Executor SAME_THREAD = Runnable::run;

    @Test
    void discoversNativeAndLegacyFactories() {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        assertThat(registry.names())
                .containsExactly("basic", "bearer", "custom", "kerberos", "none", TestAuthTokenManagerFactory.NAME);
    }

    @Test
    void resolvesANativeFactory() {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        assertThat(registry.find(TestAuthTokenManagerFactory.NAME))
                .containsInstanceOf(TestAuthTokenManagerFactory.class);
    }

    @Test
    void createsAManagerFromANativeFactory() {
        AuthTokenManager manager = AuthTokenManagerRegistry.usingDefaultClassLoader()
                .create(TestAuthTokenManagerFactory.NAME, AuthConfig.of(null, null, Map.of("token", "a-token")));

        assertThat(manager.getToken().toCompletableFuture().join()).isEqualTo(AuthTokens.bearer("a-token"));
    }

    @Test
    void handsTheContextToTheFactory() {
        AtomicInteger invocations = new AtomicInteger();
        Executor executor = command -> {
            invocations.incrementAndGet();
            command.run();
        };

        AuthTokenManagerRegistry.usingDefaultClassLoader()
                .withContext(AuthContext.builder().executor(executor).build())
                .create(TestAuthTokenManagerFactory.NAME, AuthConfig.of(null, null, Map.of("token", "a-token")))
                .getToken()
                .toCompletableFuture()
                .join();

        assertThat(invocations).hasValue(1);
    }

    @Test
    void leavesTheOriginalRegistryUnchangedWhenRebinding() {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        AuthTokenManagerRegistry rebound =
                registry.withContext(AuthContext.builder().executor(SAME_THREAD).build());

        assertThat(rebound).isNotSameAs(registry);
        assertThat(rebound.names()).isEqualTo(registry.names());
    }

    @Test
    void namesTheKnownFactoriesWhenAskedForAnUnknownOne() {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        assertThat(registry.find("no-such-scheme")).isEmpty();
        assertThatThrownBy(() -> registry.create("no-such-scheme", AuthConfig.of(null, null, Map.of())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no-such-scheme")
                .hasMessageContaining("basic")
                .hasMessageContaining(TestAuthTokenManagerFactory.NAME);
    }

    @Test
    void exposesNamesAsUnmodifiable() {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        assertThatThrownBy(() -> registry.names().add("a-scheme")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void prefersANativeFactoryOverALegacyOneOfTheSameName(@TempDir Path serviceDirectory) throws IOException {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.using(
                classLoaderRegistering(serviceDirectory, OverridingBasicAuthTokenManagerFactory.class));

        assertThat(registry.find("basic")).containsInstanceOf(OverridingBasicAuthTokenManagerFactory.class);
        assertThat(registry.find("bearer")).containsInstanceOf(LegacyAuthTokenManagerFactory.class);
    }

    @ParameterizedTest
    @CsvSource({"basic", "bearer", "custom", "kerberos", "none"})
    void resolvesEveryProvidedFactoryThroughTheLegacyBridge(String name) {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader()
                .withContext(AuthContext.builder().executor(SAME_THREAD).build());

        assertThat(registry.find(name)).containsInstanceOf(LegacyAuthTokenManagerFactory.class);
        assertThat(registry.create(name, providedConfig())
                        .getToken()
                        .toCompletableFuture()
                        .join())
                .isNotNull();
    }

    @Test
    void bridgesTheProvidedBasicFactory() {
        AuthTokenManager manager = AuthTokenManagerRegistry.usingDefaultClassLoader()
                .withContext(AuthContext.builder().executor(SAME_THREAD).build())
                .create("basic", providedConfig());

        assertThat(manager.getToken().toCompletableFuture().join()).isEqualTo(AuthTokens.basic("neo4j", "secret"));
    }

    /**
     * Registers {@code factory} as a service through a throwaway class loader, so that it is only
     * visible to the registry under test. The class itself is loaded by the parent, so it keeps its
     * usual identity.
     */
    private static ClassLoader classLoaderRegistering(Path directory, Class<? extends AuthTokenManagerFactory> factory)
            throws IOException {
        Path services = Files.createDirectories(directory.resolve("META-INF").resolve("services"));
        Files.writeString(services.resolve(AuthTokenManagerFactory.class.getName()), factory.getName());
        return new URLClassLoader(
                new URL[] {directory.toUri().toURL()}, AuthTokenManagerRegistryTest.class.getClassLoader());
    }

    /**
     * Parameters covering every {@code commons-authn-provided} factory at once; each reads only the
     * keys it knows about.
     */
    private static AuthConfig providedConfig() {
        return AuthConfig.of(
                "neo4j",
                "secret",
                Map.of(
                        "token", "a-token",
                        "ticket", "a-ticket",
                        "principal", "a-principal",
                        "credentials", "a-credential",
                        "realm", "a-realm",
                        "scheme", "a-scheme"));
    }
}
