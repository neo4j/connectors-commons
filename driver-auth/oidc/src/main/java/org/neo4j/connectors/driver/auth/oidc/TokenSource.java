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

import java.util.concurrent.CompletionStage;

/**
 * Something that can produce an {@link AccessToken}, asynchronously and repeatedly.
 *
 * <p>Deliberately free of driver types: the engine underneath knows about OAuth 2.0 and nothing
 * about Neo4j. {@link org.neo4j.connectors.driver.auth.oidc.OidcAuthTokenManagerFactory} is the only
 * place the two meet.
 *
 * <p>Implementations must not block. The returned stage must complete exceptionally with a
 * {@link TokenRequestException} when the token endpoint refuses, so that callers can tell a dead
 * credential from a blip.
 */
@FunctionalInterface
public interface TokenSource {
    /**
     * Obtains a token, which may be a cached one.
     *
     * @return a stage completing with the token
     */
    CompletionStage<AccessToken> fetch();
}
