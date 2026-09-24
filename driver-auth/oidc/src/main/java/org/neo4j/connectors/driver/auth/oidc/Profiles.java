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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * Loads a bundle of default settings from the classpath and puts it <em>underneath</em> the user's.
 *
 * <p>A profile is defaults and nothing else: no logic, no branching, no URL built from a shorthand.
 * Every value it carries is overridable, and omitting the {@code profile} setting changes nothing.
 * Their value is fewer surprises for the user, not less code here — the engine has no idea which
 * provider it is talking to.
 *
 * <p>Bundles live at {@code profiles/<name>.properties} on the classpath, so adding one is a matter
 * of dropping a file onto it.
 */
final class Profiles {
    private static final Pattern VALID_NAME = Pattern.compile("[A-Za-z0-9._-]+");
    private static final String PROFILE = "profile";

    private Profiles() {}

    /**
     * Returns the settings with the named bundle merged underneath them.
     *
     * @param settings the user's settings
     * @return the merged settings, or {@code settings} itself when no profile is named
     * @throws IllegalArgumentException if the named bundle is not on the classpath
     */
    static Map<String, String> merge(Map<String, String> settings) {
        String name = settings.get(PROFILE);
        if (name == null || name.isBlank()) {
            return settings;
        }
        Map<String, String> merged = new LinkedHashMap<>(load(name.strip()));
        merged.putAll(settings);
        return merged;
    }

    private static Map<String, String> load(String name) {
        if (!VALID_NAME.matcher(name).matches()) {
            throw Settings.invalid(PROFILE, name, "a name made of letters, digits, '.', '_' and '-'");
        }
        String resource = "profiles/" + name + ".properties";
        Properties properties = new Properties();
        try (InputStream stream = open(resource)) {
            if (stream == null) {
                throw new IllegalArgumentException("Authentication parameter '" + PROFILE + "' names '" + name
                        + "', but no '" + resource + "' was found on the classpath");
            }
            properties.load(stream);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the profile bundle '" + resource + "'", e);
        }
        Map<String, String> defaults = new LinkedHashMap<>();
        properties.forEach((key, value) -> defaults.put(key.toString(), value.toString()));
        return defaults;
    }

    private static InputStream open(String resource) {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        if (contextClassLoader != null) {
            InputStream stream = contextClassLoader.getResourceAsStream(resource);
            if (stream != null) {
                return stream;
            }
        }
        return Profiles.class.getClassLoader().getResourceAsStream(resource);
    }
}
