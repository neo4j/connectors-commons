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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Loading PKCS#8 private keys.
 *
 * <p>PKCS#8 only, in PEM or raw DER form. The older PKCS#1 ({@code BEGIN RSA PRIVATE KEY}) and SEC 1
 * ({@code BEGIN EC PRIVATE KEY}) containers are diagnosed rather than parsed: converting them is one
 * {@code openssl} command, and the alternative is pulling in BouncyCastle, which nimbus-jose-jwt
 * only needs for exactly this.
 *
 * <p>Internal to this module; not API.
 */
public final class PrivateKeys {
    private static final String PKCS8_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_END = "-----END PRIVATE KEY-----";

    private PrivateKeys() {}

    /**
     * Returns a supplier that loads the key on first use and then holds it.
     *
     * <p>Lazy because {@code create()} performs no I/O; memoised because signing keys, unlike
     * secrets, are not rotated under a running process.
     *
     * @param file the key file
     * @param algorithm the JWS algorithm the key will be used with, e.g. {@code RS256}
     * @return a memoising supplier
     */
    public static Supplier<PrivateKey> lazy(Path file, String algorithm) {
        AtomicReference<PrivateKey> loaded = new AtomicReference<>();
        return () -> {
            PrivateKey key = loaded.get();
            if (key == null) {
                key = load(file, algorithm);
                loaded.compareAndSet(null, key);
            }
            return key;
        };
    }

    /**
     * Loads a key.
     *
     * @param file the key file
     * @param algorithm the JWS algorithm the key will be used with, e.g. {@code RS256}
     * @return the key
     * @throws IllegalArgumentException if the file holds no usable PKCS#8 key
     */
    public static PrivateKey load(Path file, String algorithm) {
        byte[] contents;
        try {
            contents = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the private key from " + file, e);
        }
        byte[] der = isPem(contents) ? decodePem(new String(contents, StandardCharsets.UTF_8), file) : contents;
        String keyAlgorithm = keyAlgorithmOf(algorithm);
        try {
            return KeyFactory.getInstance(keyAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "The private key in " + file + " could not be read as a PKCS#8 " + keyAlgorithm
                            + " key, which is what privateKeyAlgorithm '" + algorithm + "' implies",
                    e);
        }
    }

    /**
     * Returns the key algorithm a JWS algorithm implies, for {@link KeyFactory}.
     *
     * @param algorithm the JWS algorithm
     * @return {@code RSA} or {@code EC}
     * @throws IllegalArgumentException if the algorithm is not supported
     */
    public static String keyAlgorithmOf(String algorithm) {
        if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
            return "RSA";
        }
        if (algorithm.startsWith("ES")) {
            return "EC";
        }
        throw new IllegalArgumentException("Unsupported signing algorithm " + algorithm);
    }

    private static boolean isPem(byte[] contents) {
        return contents.length > 0 && contents[0] == '-';
    }

    private static byte[] decodePem(String pem, Path file) {
        int begin = pem.indexOf(PKCS8_BEGIN);
        if (begin < 0) {
            throw new IllegalArgumentException(unsupportedContainer(pem, file));
        }
        int end = pem.indexOf(PKCS8_END, begin);
        if (end < 0) {
            throw new IllegalArgumentException("The PEM block in " + file + " is missing its '" + PKCS8_END + "' line");
        }
        String body = pem.substring(begin + PKCS8_BEGIN.length(), end).replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The PEM block in " + file + " is not valid base64", e);
        }
    }

    private static String unsupportedContainer(String pem, Path file) {
        if (pem.contains("BEGIN RSA PRIVATE KEY") || pem.contains("BEGIN EC PRIVATE KEY")) {
            return "The private key in " + file + " is in the legacy PKCS#1 or SEC 1 format, which is not supported. "
                    + "Convert it with: openssl pkcs8 -topk8 -nocrypt -in " + file.getFileName() + " -out key.pk8.pem";
        }
        if (pem.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
            return "The private key in " + file + " is encrypted, which is not supported. "
                    + "Decrypt it with: openssl pkcs8 -in " + file.getFileName() + " -out key.pk8.pem";
        }
        return "No '" + PKCS8_BEGIN + "' block was found in " + file;
    }
}
