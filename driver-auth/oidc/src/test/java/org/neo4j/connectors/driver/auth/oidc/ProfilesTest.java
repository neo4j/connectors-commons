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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthConfigException;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.oidc.clientauth.ClientAuthMethod;
import org.neo4j.connectors.driver.auth.oidc.grant.GrantType;

class ProfilesTest {
    private static final ClassLoader LOADER = ProfilesTest.class.getClassLoader();

    @TempDir
    Path directory;

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
        ClassLoader loader = loaderOver(bundle("only", "in-house", "grantType=client_credentials", "scope=neo4j.read"));

        Map<String, String> merged = Profiles.merge(Map.of("profile", "in-house"), loader);

        assertThat(merged).contains(entry("grantType", "client_credentials"), entry("scope", "neo4j.read"));
    }

    @Test
    void takesTheClassLoaderFromTheContext() {
        ClassLoader loader = loaderOver(bundle("ctx", "in-house", "scope=neo4j.read"));
        AuthContext context = AuthContext.builder().classLoader(loader).build();
        Map<String, String> settings = Map.of(
                "profile", "in-house",
                "tokenEndpoint", "https://host/token",
                "clientId", "c",
                "clientSecret", "s");

        OidcConfig config = OidcConfig.parse(AuthConfig.of(null, null, settings), context);

        assertThat(config.scope()).contains("neo4j.read");
    }

    @Test
    void refusesToGuessBetweenTwoBundlesOfTheSameName() {
        ClassLoader loader = loaderOver(
                bundle("first", "in-house", "tokenEndpoint=https://first/token"),
                bundle("second", "in-house", "tokenEndpoint=https://second/token"));

        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "in-house"), loader))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("profile"))
                .hasMessageContaining("profile")
                .hasMessageContaining("2 bundles")
                .hasMessageContaining("profiles/in-house.properties")
                .hasMessageContaining("rename all but one");
    }

    @Test
    void refusesToLetABundleShadowABuiltInName() {
        // The module's own bundle is on the parent loader, a second copy on the child. Parent first
        // delegation would silently pick the module's and ignore the user's.
        ClassLoader loader =
                new URLClassLoader(urlsOf(bundle("mine", "google", "tokenEndpoint=https://mirror/token")), LOADER);

        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "google"), loader))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("profile"))
                .hasMessageContaining("2 bundles")
                .hasMessageContaining("profiles/google.properties");
    }

    @Test
    void readsTheSameJarListedTwiceAsOneBundle() {
        Path root = bundle("once", "in-house", "scope=neo4j.read");
        ClassLoader loader = loaderOver(root, root);

        assertThat(Profiles.merge(Map.of("profile", "in-house"), loader)).contains(entry("scope", "neo4j.read"));
    }

    @Test
    void doesNotSeeABundleTheHostsClassLoaderCannotReach() {
        ClassLoader empty = new URLClassLoader(new URL[0], null);

        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "google"), empty))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("profile"))
                .hasMessageContaining("profiles/google.properties");
    }

    @Test
    void reportsAProfileThatIsNotOnTheClasspath() {
        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "nonesuch"), LOADER))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("profile"))
                .hasMessageContaining("profile")
                .hasMessageContaining("profiles/nonesuch.properties");
    }

    @Test
    void refusesToTraverseOutOfTheProfileDirectory() {
        assertThatThrownBy(() -> Profiles.merge(Map.of("profile", "../../etc/passwd"), LOADER))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("profile"))
                .hasMessageContaining("profile");
    }

    /** Writes {@code <dir>/profiles/<name>.properties} and returns the directory, ready for a classpath. */
    private Path bundle(String dir, String name, String... lines) {
        try {
            Path profiles = Files.createDirectories(directory.resolve(dir).resolve("profiles"));
            Files.writeString(profiles.resolve(name + ".properties"), String.join("\n", lines) + "\n");
            return directory.resolve(dir);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A loader over the given directories only, standing in for an isolated plugin loader. */
    private static ClassLoader loaderOver(Path... roots) {
        return new URLClassLoader(urlsOf(roots), null);
    }

    private static URL[] urlsOf(Path... roots) {
        URL[] urls = new URL[roots.length];
        for (int index = 0; index < roots.length; index++) {
            try {
                urls[index] = roots[index].toUri().toURL();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return urls;
    }
}
