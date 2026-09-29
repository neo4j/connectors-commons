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

import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import javax.net.ssl.SSLContext;

/**
 * Runtime collaborators injected by the host into an {@link AuthTokenManagerFactory}.
 *
 * <p>Every default matches the behaviour the driver or the JDK would exhibit on its own, so
 * implementors never have to null-check or fall back.
 */
public interface AuthContext {
    /**
     * Returns a context in which every collaborator is the default.
     *
     * @return a new context
     */
    static AuthContext defaults() {
        return builder().build();
    }

    /**
     * Returns a builder for a context that overrides some of the defaults.
     *
     * @return a new builder
     */
    static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the executor on which token retrieval should run.
     *
     * <p>Defaults to {@link ForkJoinPool#commonPool()}, which is where the driver's own
     * {@code AuthTokenManagers} run their suppliers. Hosts that make blocking calls to an identity
     * provider should override it.
     *
     * @return the executor, never {@code null}
     */
    default Executor executor() {
        return ForkJoinPool.commonPool();
    }

    /**
     * Returns the clock to read the current time from.
     *
     * <p>Defaults to {@link Clock#systemUTC()}, matching the clock the driver hardcodes in its own
     * expiration-based manager. Note that the driver offers no seam to inject a clock, so overriding
     * this only affects a factory's own expiry calculations, not the driver's.
     *
     * @return the clock, never {@code null}
     */
    default Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Returns the SSL context to use for outbound calls to an identity provider.
     *
     * <p>Defaults to {@link SSLContext#getDefault()}, so a factory that makes no HTTPS call of its
     * own can ignore it. Hosts that talk to a self-hosted provider behind a private certificate
     * authority should override it. This context has nothing to do with the driver's own Bolt
     * encryption, which is configured on the driver instead.
     *
     * @return the SSL context, never {@code null}
     * @throws IllegalStateException if the platform has no default SSL context
     */
    default SSLContext sslContext() {
        try {
            return SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The default SSL context is unavailable", e);
        }
    }

    /**
     * Returns the class loader to read classpath resources with.
     *
     * <p>Defaults to the thread context class loader, matching how
     * {@link AuthTokenManagerRegistry#usingDefaultClassLoader()} discovers services. Hosts that
     * isolate plugins in their own class loader should override it, so that a factory finds the
     * resources shipped alongside the plugin rather than whatever the calling thread happens to see.
     *
     * @return the class loader, never {@code null}
     */
    default ClassLoader classLoader() {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        return contextClassLoader != null ? contextClassLoader : AuthContext.class.getClassLoader();
    }

    /**
     * Builds an {@link AuthContext}, starting from the defaults.
     */
    final class Builder {
        private Executor executor = ForkJoinPool.commonPool();
        private Clock clock = Clock.systemUTC();
        private SSLContext sslContext;
        private ClassLoader classLoader;

        private Builder() {}

        /**
         * Sets the executor on which token retrieval should run.
         *
         * @param executor the executor, must not be {@code null}
         * @return this builder
         */
        public Builder executor(Executor executor) {
            this.executor = Objects.requireNonNull(executor, "executor must not be null");
            return this;
        }

        /**
         * Sets the clock to read the current time from.
         *
         * @param clock the clock, must not be {@code null}
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock must not be null");
            return this;
        }

        /**
         * Sets the SSL context to use for outbound calls to an identity provider.
         *
         * @param sslContext the SSL context, must not be {@code null}
         * @return this builder
         */
        public Builder sslContext(SSLContext sslContext) {
            this.sslContext = Objects.requireNonNull(sslContext, "sslContext must not be null");
            return this;
        }

        /**
         * Sets the class loader to read classpath resources with.
         *
         * @param classLoader the class loader, must not be {@code null}
         * @return this builder
         */
        public Builder classLoader(ClassLoader classLoader) {
            this.classLoader = Objects.requireNonNull(classLoader, "classLoader must not be null");
            return this;
        }

        /**
         * Builds the context.
         *
         * @return a new context
         */
        public AuthContext build() {
            return new DefaultAuthContext(executor, clock, sslContext, classLoader);
        }
    }
}
