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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;

/**
 * Where a client secret comes from.
 *
 * <p>A file-backed secret is re-read on every fetch rather than cached, because the usual reason to
 * put a secret in a file is that something else rotates it, such as a Kubernetes secret mount.
 * Reading it lazily also keeps {@code create()} free of I/O.
 *
 * <p>Internal to this module; not API.
 */
public final class SecretSource {
    private SecretSource() {}

    /**
     * Returns a source for a secret given inline.
     *
     * @param secret the secret
     * @return a supplier returning it
     */
    public static Supplier<String> of(String secret) {
        return () -> secret;
    }

    /**
     * Returns a source that re-reads a file on every call.
     *
     * @param file the file holding the secret
     * @return a supplier reading it
     */
    public static Supplier<String> fromFile(Path file) {
        return () -> {
            try {
                return Files.readString(file).strip();
            } catch (IOException e) {
                throw new UncheckedIOException("Could not read the client secret from " + file, e);
            }
        };
    }
}
