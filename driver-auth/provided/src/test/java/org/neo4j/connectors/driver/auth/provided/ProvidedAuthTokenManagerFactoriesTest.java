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
package org.neo4j.connectors.driver.auth.provided;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthConfigException;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.AuthTokenManagerFactory;
import org.neo4j.connectors.driver.auth.AuthTokenManagerRegistry;

/**
 * The registry-level view of this module. {@code commons-authn-provided} is on the test classpath,
 * so every name here is also claimed by a legacy supplier factory. These tests pin down that the
 * native factory is the one that wins.
 */
class ProvidedAuthTokenManagerFactoriesTest {

    @Test
    void areAllDiscoverableByName() {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        assertThat(registry.names()).containsExactly("basic", "bearer", "custom", "kerberos", "none");
    }

    @ParameterizedTest
    @CsvSource({
        "basic, org.neo4j.connectors.driver.auth.provided.BasicAuthTokenManagerFactory",
        "bearer, org.neo4j.connectors.driver.auth.provided.BearerAuthTokenManagerFactory",
        "custom, org.neo4j.connectors.driver.auth.provided.CustomAuthTokenManagerFactory",
        "kerberos, org.neo4j.connectors.driver.auth.provided.KerberosAuthTokenManagerFactory",
        "none, org.neo4j.connectors.driver.auth.provided.NoneAuthTokenManagerFactory"
    })
    void takePrecedenceOverTheLegacySupplierOfTheSameName(String name, Class<?> expected) {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        assertThat(registry.find(name)).containsInstanceOf(expected);
    }

    @ParameterizedTest
    @CsvSource({"basic", "bearer", "custom", "kerberos", "none"})
    void allCreateAManagerThatYieldsAToken(String name) {
        AuthTokenManagerRegistry registry = AuthTokenManagerRegistry.usingDefaultClassLoader();

        assertThat(registry.create(name, fullyPopulatedConfig())
                        .getToken()
                        .toCompletableFuture()
                        .join())
                .isNotNull();
    }

    @ParameterizedTest(name = "{0} with {1}")
    @MethodSource("factoriesAndConfigs")
    void validateAgreesWithCreate(String name, String description, AuthConfig config) {
        AuthTokenManagerFactory factory =
                AuthTokenManagerRegistry.usingDefaultClassLoader().find(name).orElseThrow();

        Throwable created = catchThrowable(() -> factory.create(config, AuthContext.defaults()));
        Throwable validated = catchThrowable(() -> factory.validate(config, AuthContext.defaults()));

        if (created == null) {
            assertThat(validated).isNull();
        } else {
            assertThat(validated)
                    .isExactlyInstanceOf(created.getClass())
                    .isInstanceOf(AuthConfigException.class)
                    .hasMessage(created.getMessage());
            assertThat(((AuthConfigException) validated).keys())
                    .isNotEmpty()
                    .isEqualTo(((AuthConfigException) created).keys());
        }
    }

    static Stream<Arguments> factoriesAndConfigs() {
        Map<String, AuthConfig> configs = Map.of(
                "nothing", AuthConfig.of(null, null, null),
                "everything", fullyPopulatedConfig(),
                "no password", AuthConfig.of("neo4j", null, Map.of()),
                "no username", AuthConfig.of(null, "secret", Map.of()),
                "a token", AuthConfig.of(null, null, Map.of("token", "a-token")),
                "a ticket", AuthConfig.of(null, null, Map.of("ticket", "a-ticket")),
                "no principal", AuthConfig.of(null, null, Map.of("credentials", "a-credential", "scheme", "a-scheme")),
                "no credentials", AuthConfig.of(null, null, Map.of("principal", "a-principal", "scheme", "a-scheme")),
                "no scheme",
                        AuthConfig.of(null, null, Map.of("principal", "a-principal", "credentials", "a-credential")));
        return List.of("basic", "bearer", "custom", "kerberos", "none").stream()
                .flatMap(name -> configs.entrySet().stream()
                        .map(config -> Arguments.of(name, config.getKey(), config.getValue())));
    }

    /**
     * Parameters covering every factory in this module at once; each reads only the keys it knows
     * about.
     */
    private static AuthConfig fullyPopulatedConfig() {
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
