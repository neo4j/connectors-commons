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

import java.time.Clock;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;

/**
 * A {@code null} {@code sslContext} means "not overridden": the interface default is resolved on
 * every read, which keeps {@link javax.net.ssl.SSLContext#getDefault()} out of the builder, where it
 * would run even for the hosts that never make an HTTPS call.
 */
record DefaultAuthContext(Executor executor, Clock clock, SSLContext sslContext) implements AuthContext {
    @Override
    public SSLContext sslContext() {
        return sslContext == null ? AuthContext.super.sslContext() : sslContext;
    }
}
