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

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.function.Function;
import java.util.function.Supplier;
import org.neo4j.connectors.driver.auth.oidc.internal.TokenEndpointClient;

/**
 * The engine: resolve the token URL, assemble the request, send it, read the reply.
 *
 * <p>Assembling is the SDK's job — which grant, which client authentication, how they serialise. The
 * only thing this class adds is the settings-driven shaping the SDK has no opinion about:
 * {@code scope}, {@code audience}, {@code resource} and the {@code extraParam.*} escape hatch, with
 * the escape hatch applied last so it can override any of them.
 *
 * <p>Assembly can block: it may read a rotating token file, a secret file, or sign an assertion.
 * That work is therefore dispatched to the host's executor rather than left on whichever thread
 * completed the discovery lookup.
 */
final class OAuth2TokenSource implements TokenSource {
    private final Supplier<CompletionStage<URI>> tokenEndpoint;
    private final TokenEndpointClient client;
    private final GrantFactory grants;
    private final Function<URI, ClientAuthentication> clientAuthentication;
    private final OidcConfig config;
    private final Executor executor;

    OAuth2TokenSource(
            Supplier<CompletionStage<URI>> tokenEndpoint,
            TokenEndpointClient client,
            GrantFactory grants,
            Function<URI, ClientAuthentication> clientAuthentication,
            OidcConfig config,
            Executor executor) {
        this.tokenEndpoint = tokenEndpoint;
        this.client = client;
        this.grants = grants;
        this.clientAuthentication = clientAuthentication;
        this.config = config;
        this.executor = executor;
    }

    @Override
    public CompletionStage<AccessToken> fetch() {
        return tokenEndpoint
                .get()
                .thenCompose(endpoint -> CompletableFuture.supplyAsync(() -> request(endpoint), executor)
                        .thenCompose(client::requestToken))
                .thenApply(token -> {
                    grants.onToken(token);
                    return token;
                });
    }

    private TokenRequest request(URI endpoint) {
        ClientAuthentication authentication = clientAuthentication.apply(endpoint);
        TokenRequest.Builder builder = builderFor(endpoint, authentication);

        // Resolved before handing anything to the SDK so that extraParam.* keeps overriding the
        // settings it collides with, rather than being appended alongside them.
        Map<String, String> shaping = new LinkedHashMap<>();
        config.scope().ifPresent(scope -> shaping.put("scope", scope));
        config.audience().ifPresent(audience -> shaping.put("audience", audience));
        config.resource().ifPresent(resource -> shaping.put("resource", resource));
        shaping.putAll(config.extraParams());

        String scope = shaping.remove("scope");
        if (scope != null) {
            builder.scope(Scope.parse(scope));
        }
        shaping.forEach(builder::customParameter);
        return builder.build();
    }

    private TokenRequest.Builder builderFor(URI endpoint, ClientAuthentication authentication) {
        if (authentication != null) {
            return new TokenRequest.Builder(endpoint, authentication, grants.create(endpoint));
        }
        // A public client is identified even though it is not authenticated; Google's jwt_bearer
        // flow configures no identifier at all, and then nothing is sent.
        return config.clientId()
                .map(clientId -> new TokenRequest.Builder(endpoint, new ClientID(clientId), grants.create(endpoint)))
                .orElseGet(() -> new TokenRequest.Builder(endpoint, grants.create(endpoint)));
    }
}
