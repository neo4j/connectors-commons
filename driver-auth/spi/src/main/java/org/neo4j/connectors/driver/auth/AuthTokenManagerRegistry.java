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
package org.neo4j.connectors.driver.auth;

import static java.lang.String.format;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeMap;
import org.neo4j.connectors.authn.AuthenticationTokenSupplierFactory;
import org.neo4j.driver.AuthTokenManager;

/**
 * Looks up {@link AuthTokenManagerFactory} implementations by name and creates
 * {@link AuthTokenManager} instances from them.
 *
 * <p>Discovery is two-tier: native {@link AuthTokenManagerFactory} services are found first, then
 * legacy {@link AuthenticationTokenSupplierFactory} services are wrapped through
 * {@link LegacyAuthBridge}. A native factory therefore takes precedence over a legacy one of the same
 * name. Within a single tier the first service {@link ServiceLoader} yields for a name wins.
 *
 * <p>Services are discovered and instantiated once, when the registry is created.
 */
public final class AuthTokenManagerRegistry {
    private final Map<String, AuthTokenManagerFactory> factories;
    private final AuthContext context;

    private AuthTokenManagerRegistry(Map<String, AuthTokenManagerFactory> factories, AuthContext context) {
        this.factories = factories;
        this.context = context;
    }

    /**
     * Creates a registry from the services visible to the thread context class loader.
     *
     * @return a new registry using {@link AuthContext#defaults()}
     */
    public static AuthTokenManagerRegistry usingDefaultClassLoader() {
        return new AuthTokenManagerRegistry(
                discover(
                        ServiceLoader.load(AuthTokenManagerFactory.class),
                        ServiceLoader.load(AuthenticationTokenSupplierFactory.class)),
                AuthContext.defaults());
    }

    /**
     * Creates a registry from the services visible to the given class loader.
     *
     * <p>The same loader is put on the {@link AuthContext}, so a factory reads its own classpath
     * resources with the loader the host chose rather than with the calling thread's.
     *
     * @param loader the class loader to discover services with
     * @return a new registry
     */
    public static AuthTokenManagerRegistry using(ClassLoader loader) {
        Objects.requireNonNull(loader, "loader must not be null");
        return new AuthTokenManagerRegistry(
                discover(
                        ServiceLoader.load(AuthTokenManagerFactory.class, loader),
                        ServiceLoader.load(AuthenticationTokenSupplierFactory.class, loader)),
                AuthContext.builder().classLoader(loader).build());
    }

    /**
     * Returns a registry over the same factories, handing them the given context.
     *
     * @param context the runtime collaborators to pass to every factory
     * @return a new registry; this one is left unchanged
     */
    public AuthTokenManagerRegistry withContext(AuthContext context) {
        Objects.requireNonNull(context, "context must not be null");
        return new AuthTokenManagerRegistry(factories, context);
    }

    /**
     * Returns the names of every discovered factory, in alphabetical order.
     *
     * @return an unmodifiable set of names
     */
    public Set<String> names() {
        return Collections.unmodifiableSet(factories.keySet());
    }

    /**
     * Finds the factory registered under a name.
     *
     * @param name the scheme name
     * @return the factory, or {@link Optional#empty()} if no factory is registered under that name
     */
    public Optional<AuthTokenManagerFactory> find(String name) {
        return Optional.ofNullable(factories.get(name));
    }

    /**
     * Creates a token manager from the factory registered under a name.
     *
     * @param name the scheme name
     * @param config the user-supplied connector configuration
     * @return a new token manager
     * @throws IllegalArgumentException if no factory is registered under that name, listing the names
     *     that are
     * @throws AuthConfigException if the configuration is invalid
     */
    public AuthTokenManager create(String name, AuthConfig config) {
        return require(name).create(config, context);
    }

    /**
     * Checks a configuration against the factory registered under a name, without creating a token
     * manager.
     *
     * <p>A factory that does not override {@link AuthTokenManagerFactory#validate} accepts anything.
     *
     * @param name the scheme name
     * @param config the user-supplied connector configuration
     * @throws IllegalArgumentException if no factory is registered under that name, listing the names
     *     that are
     * @throws AuthConfigException if the configuration is invalid
     */
    public void validate(String name, AuthConfig config) {
        require(name).validate(config, context);
    }

    private AuthTokenManagerFactory require(String name) {
        return find(name)
                .orElseThrow(() -> new IllegalArgumentException(format(
                        "No authentication token manager is registered under the name '%s', available names are %s",
                        name, names())));
    }

    /**
     * {@link ServiceLoader#stream()} is of no use here: the name is an instance method, so every
     * service has to be instantiated before it can be filtered. Their constructors are no-argument
     * and trivial.
     */
    private static Map<String, AuthTokenManagerFactory> discover(
            Iterable<AuthTokenManagerFactory> nativeFactories,
            Iterable<AuthenticationTokenSupplierFactory> legacyFactories) {
        Map<String, AuthTokenManagerFactory> factories = new TreeMap<>();
        for (AuthTokenManagerFactory factory : nativeFactories) {
            factories.putIfAbsent(factory.getName(), factory);
        }
        for (AuthenticationTokenSupplierFactory factory : legacyFactories) {
            factories.putIfAbsent(factory.getName(), LegacyAuthBridge.fromFactory(factory));
        }
        return factories;
    }
}
