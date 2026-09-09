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

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthTokenManagerRegistry;

/**
 * The registry-level view of this module. {@code commons-authn-provided} is on the test classpath,
 * so every name here is also claimed by a legacy supplier factory — these tests pin down that the
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
