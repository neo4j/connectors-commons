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
import static org.assertj.core.api.Assertions.entry;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.oidc.clientauth.ClientAuthMethod;
import org.neo4j.connectors.driver.auth.oidc.grant.GrantType;

class ProfilesTest {
    private static final ClassLoader LOADER = ProfilesTest.class.getClassLoader();

    @Test
    void changesNothingWhenNoProfileIsNamed() {
        Map<String, String> settings = Map.of("clientId", "c");

        assertThat(Profiles.merge(settings, LOADER)).isSameAs(settings);
    }

    @Test
    void mergesTheBundleUnderneathTheUsersSettings() {
        Map<String, String> merged = Profiles.merge(Map.of("profile", "google", "tokenField", "access_token"), LOADER);

        assertThat(merged)
                .contains(entry("grantType", "jwt_bearer"), entry("clientAuthMethod", "none"))
                .contains(entry("tokenField", "access_token"));
    }

    @Test
    void googlesBundleIsUsableWithoutAnythingElseBeingImplied() {
        OidcConfig config = OidcConfig.parse(
                AuthConfig.of(null, null, Map.of("profile", "google", "privateKeyFile", "/keys/service-account.pk8")));

        assertThat(config.grantType()).isEqualTo(GrantType.JWT_BEARER);
        assertThat(config.clientAuthMethod()).isEqualTo(ClientAuthMethod.NONE);
        assertThat(config.tokenField()).isEqualTo("id_token");
        assertThat(config.tokenEndpoint()).map(Object::toString).contains("https://oauth2.googleapis.com/token");
    }

    @Test
    void entrasBundleOnlyMovesTheSecretIntoTheForm() {
        OidcConfig config = OidcConfig.parse(AuthConfig.of(
                null,
                null,
                Map.of(
                        "profile", "entra",
                        "issuer", "https://login.microsoftonline.com/tenant/v2.0",
                        "clientId", "c",
                        "clientSecret", "s")));

        assertThat(config.clientAuthMethod()).isEqualTo(ClientAuthMethod.CLIENT_SECRET_POST);
        assertThat(config.grantType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
    }

    @Test
    void readsTheBundleWithTheClassLoaderTheHostChose() {
        ClassLoader loader =
                loaderServing("profiles/in-house.properties", "grantType=client_credentials\nscope=neo4j.read\n");

        Map<String, String> merged = Profiles.merge(Map.of("profile", "in-house"), loader);

        assertThat(merged).contains(entry("grantType", "client_credentials"), entry("scope", "neo4j.read"));
    }

    @Test
    void takesTheClassLoaderFromTheContext() {
        ClassLoader loader = loaderServing("profiles/in-house.properties", "scope=neo4j.read\n");
        AuthContext context = AuthContext.builder().classLoader(loader).build();
        Map<String, String> settings = Map.of(
                "profile", "in-house", "tokenEndpoint", "https://host/token", "clientId", "c", "clientSecret", "s");

        OidcConfig config = OidcConfig.parse(AuthConfig.of(null, null, settings), context);

        assertThat(config.scope()).contains("neo4j.read");
    }

    @Test
    void doesNotSeeABundleTheHostsClassLoaderCannotReach() {
        ClassLoader empty = new ClassLoader(null) {};

        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "google"), empty))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("profiles/google.properties");
    }

    @Test
    void reportsAProfileThatIsNotOnTheClasspath() {
        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "nonesuch"), LOADER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("profile")
                .hasMessageContaining("profiles/nonesuch.properties");
    }

    @Test
    void refusesToTraverseOutOfTheProfileDirectory() {
        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "../../etc/passwd"), LOADER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("profile");
    }

    /** A loader that serves one resource and delegates nothing, standing in for a plugin loader. */
    private static ClassLoader loaderServing(String resource, String contents) {
        return new ClassLoader(null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                return resource.equals(name)
                        ? new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8))
                        : null;
            }
        };
    }
}
