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
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Loads a bundle of default settings from the classpath and puts it <em>underneath</em> the user's.
 *
 * <p>A profile carries default values and nothing else: no logic, no branching, no URL built from a
 * shorthand. Every value it carries is overridable, and omitting the {@code profile} setting
 * changes nothing. A profile saves the user from having to know a provider's conventions; it does
 * not save this module any code, which has no idea which provider it is talking to.
 *
 * <p>Bundles live at {@code profiles/<name>.properties} and are read with the class loader on the
 * {@link org.neo4j.connectors.driver.auth.AuthContext}, so a host can ship its own alongside the
 * plugin.
 */
final class Profiles {
    private static final Pattern VALID_NAME = Pattern.compile("[A-Za-z0-9._-]+");
    private static final String PROFILE = "profile";

    private Profiles() {}

    /**
     * Returns the settings with the named bundle merged underneath them.
     *
     * @param settings the user's settings
     * @param loader the class loader to read the bundle with
     * @return the merged settings, or {@code settings} itself when no profile is named
     * @throws IllegalArgumentException if the named bundle is not on the classpath
     */
    static Map<String, String> merge(Map<String, String> settings, ClassLoader loader) {
        String name = settings.get(PROFILE);
        if (name == null || name.isBlank()) {
            return settings;
        }
        Map<String, String> merged = new LinkedHashMap<>(load(name.strip(), loader));
        merged.putAll(settings);
        return merged;
    }

    /** Distinct by URL, so the same jar listed twice on the classpath is not read as a clash. */
    private static List<URL> locate(String resource, ClassLoader loader) {
        try {
            Set<String> seen = new LinkedHashSet<>();
            List<URL> found = new ArrayList<>();
            for (URL url : Collections.list(loader.getResources(resource))) {
                if (seen.add(url.toString())) {
                    found.add(url);
                }
            }
            return found;
        } catch (IOException e) {
            throw new UncheckedIOException("Could not scan the classpath for '" + resource + "'", e);
        }
    }

    private static Map<String, String> load(String name, ClassLoader loader) {
        if (!VALID_NAME.matcher(name).matches()) {
            throw Settings.invalid(PROFILE, name, "a name made of letters, digits, '.', '_' and '-'");
        }
        String resource = "profiles/" + name + ".properties";
        List<URL> found = locate(resource, loader);
        if (found.isEmpty()) {
            throw new IllegalArgumentException("Authentication parameter '" + PROFILE + "' names '" + name
                    + "', but no '" + resource + "' was found on the classpath");
        }
        if (found.size() > 1) {
            // Which copy a class loader hands back depends on search order and on whether delegation
            // is parent first, neither of which the user controls in a connector runtime. Sourcing
            // tokens from whichever endpoint happened to win is worse than refusing to start.
            throw new IllegalArgumentException("Authentication parameter '" + PROFILE + "' names '" + name
                    + "', but the classpath holds " + found.size() + " bundles called '" + resource + "': " + found
                    + ". Only one of them would be used, and which one is not predictable, so rename all but one.");
        }
        Properties properties = new Properties();
        try (InputStream stream = found.get(0).openStream()) {
            properties.load(stream);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the profile bundle '" + resource + "'", e);
        }
        Map<String, String> defaults = new LinkedHashMap<>();
        properties.forEach((key, value) -> defaults.put(key.toString(), value.toString()));
        return defaults;
    }
}
