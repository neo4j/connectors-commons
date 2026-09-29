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

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import java.net.URI;

/**
 * Produces the SDK grant for one token request.
 *
 * <p>Per request rather than per configuration, because a grant that reads a rotating file or signs
 * a short-lived assertion is only correct if it is rebuilt each time. The SDK's grant objects are
 * immutable, so rebuilding is the only option anyway.
 *
 * <p>Implementations may block, and are always invoked on the host's executor.
 */
@FunctionalInterface
interface GrantFactory {
    /**
     * Builds the grant for a request about to be sent.
     *
     * @param tokenEndpoint the endpoint being called, the default {@code aud} of a signed assertion
     * @return the grant
     */
    AuthorizationGrant create(URI tokenEndpoint);

    /**
     * Notifies the factory of a token the provider just issued.
     *
     * <p>Only the {@code refresh_token} grant cares: it rolls forward onto the refresh token that
     * came back, which is what keeps a provider with rotating refresh tokens working.
     *
     * @param token the token that was just issued
     */
    default void onToken(AccessToken token) {}
}
