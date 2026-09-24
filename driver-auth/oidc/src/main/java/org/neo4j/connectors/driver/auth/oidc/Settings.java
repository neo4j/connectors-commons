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

import static java.lang.String.format;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Typed reads over the raw settings map, each failure naming the key that caused it.
 *
 * <p>A blank value is read as absent: connector configuration frameworks routinely materialise every
 * declared key, so {@code scope=} has to mean "not set" rather than "set to the empty string".
 */
final class Settings {
    private final Map<String, String> values;

    Settings(Map<String, String> values) {
        this.values = values;
    }

    Map<String, String> asMap() {
        return values;
    }

    Optional<String> get(String key) {
        String value = values.get(key);
        return value == null || value.isBlank() ? Optional.empty() : Optional.of(value.strip());
    }

    String get(String key, String defaultValue) {
        return get(key).orElse(defaultValue);
    }

    String require(String key) {
        return get(key).orElseThrow(() -> required(key));
    }

    Optional<URI> uri(String key) {
        return get(key).map(value -> {
            try {
                URI uri = new URI(value);
                if (!uri.isAbsolute()) {
                    throw invalid(key, value, "an absolute URL");
                }
                return uri;
            } catch (URISyntaxException e) {
                throw invalid(key, value, "a valid URL");
            }
        });
    }

    Optional<Path> path(String key) {
        return get(key).map(value -> {
            try {
                return Path.of(value);
            } catch (InvalidPathException e) {
                throw invalid(key, value, "a valid file path");
            }
        });
    }

    long number(String key, long defaultValue, long minimum) {
        return get(key).map(value -> {
                    long parsed;
                    try {
                        parsed = Long.parseLong(value);
                    } catch (NumberFormatException e) {
                        throw invalid(key, value, "an integer");
                    }
                    if (parsed < minimum) {
                        throw invalid(key, value, "an integer of at least " + minimum);
                    }
                    return parsed;
                })
                .orElse(defaultValue);
    }

    Duration millis(String key, long defaultValue) {
        return Duration.ofMillis(number(key, defaultValue, 1));
    }

    Duration seconds(String key, long defaultValue) {
        return Duration.ofSeconds(number(key, defaultValue, 0));
    }

    /**
     * Collects every {@code <prefix><name>} setting into a map keyed by {@code name}.
     *
     * <p>Sorted, so that a signed assertion and a form body are byte-for-byte reproducible for a
     * given configuration, which is what makes the contract tests assertable.
     */
    Map<String, String> withPrefix(String prefix) {
        Map<String, String> collected = new TreeMap<>();
        values.forEach((key, value) -> {
            if (key.startsWith(prefix) && key.length() > prefix.length()) {
                collected.put(key.substring(prefix.length()), value);
            }
        });
        return new LinkedHashMap<>(collected);
    }

    static IllegalArgumentException required(String key) {
        return new IllegalArgumentException(
                format("Authentication parameter '%s' is required but was not configured", key));
    }

    static IllegalArgumentException requiredBecause(String key, String reason) {
        return new IllegalArgumentException(
                format("Authentication parameter '%s' is required %s but was not configured", key, reason));
    }

    static IllegalArgumentException invalid(String key, String value, String expected) {
        return new IllegalArgumentException(
                format("Authentication parameter '%s' has invalid value '%s'; expected %s", key, value, expected));
    }

    static IllegalArgumentException conflict(String first, String second) {
        return new IllegalArgumentException(format(
                "Authentication parameters '%s' and '%s' are mutually exclusive but both were configured",
                first, second));
    }
}
