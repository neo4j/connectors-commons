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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.neo4j.connectors.driver.auth.oidc.Keys;

class PrivateKeysTest {

    @TempDir
    Path directory;

    @Test
    void loadsAPkcs8PemRsaKey() {
        KeyPair keyPair = Keys.rsa();
        Path file = Keys.writePkcs8Pem(directory.resolve("key.pem"), keyPair);

        assertThat(PrivateKeys.load(file, "RS256")).isEqualTo(keyPair.getPrivate());
    }

    @Test
    void loadsAPkcs8PemEcKey() {
        KeyPair keyPair = Keys.ec("secp256r1");
        Path file = Keys.writePkcs8Pem(directory.resolve("key.pem"), keyPair);

        assertThat(PrivateKeys.load(file, "ES256")).isEqualTo(keyPair.getPrivate());
    }

    @Test
    void loadsARawDerKey() throws Exception {
        KeyPair keyPair = Keys.rsa();
        Path file =
                Files.write(directory.resolve("key.der"), keyPair.getPrivate().getEncoded());

        assertThat(PrivateKeys.load(file, "RS256")).isEqualTo(keyPair.getPrivate());
    }

    @Test
    void loadsTheKeyOnceAndOnFirstUseOnly() {
        KeyPair keyPair = Keys.rsa();
        Path file = directory.resolve("late.pem");

        var lazy = PrivateKeys.lazy(file, "RS256");
        Keys.writePkcs8Pem(file, keyPair);

        assertThat(lazy.get()).isEqualTo(keyPair.getPrivate());
        assertThat(lazy.get()).isSameAs(lazy.get());
    }

    @Test
    void tellsTheUserHowToConvertALegacyPkcs1Key() throws Exception {
        Path file = Files.writeString(
                directory.resolve("key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n");

        assertThatThrownBy(() -> PrivateKeys.load(file, "RS256"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PKCS#1")
                .hasMessageContaining("openssl pkcs8 -topk8");
    }

    @Test
    void tellsTheUserHowToDecryptAnEncryptedKey() throws Exception {
        Path file = Files.writeString(
                directory.resolve("key.pem"),
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE\n-----END ENCRYPTED PRIVATE KEY-----\n");

        assertThatThrownBy(() -> PrivateKeys.load(file, "RS256"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("encrypted");
    }

    @Test
    void reportsAKeyThatDoesNotMatchTheConfiguredAlgorithm() {
        Path file = Keys.writePkcs8Pem(directory.resolve("key.pem"), Keys.rsa());

        assertThatThrownBy(() -> PrivateKeys.load(file, "ES256"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("privateKeyAlgorithm")
                .hasMessageContaining("ES256");
    }
}
