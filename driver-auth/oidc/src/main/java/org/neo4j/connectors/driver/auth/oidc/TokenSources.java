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

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.JWTBearerGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessToken;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.connectors.driver.auth.oidc.internal.AssertionFactory;
import org.neo4j.connectors.driver.auth.oidc.internal.Discovery;
import org.neo4j.connectors.driver.auth.oidc.internal.LazyHttpClient;
import org.neo4j.connectors.driver.auth.oidc.internal.PrivateKeys;
import org.neo4j.connectors.driver.auth.oidc.internal.SecretSource;
import org.neo4j.connectors.driver.auth.oidc.internal.TokenEndpointClient;

/**
 * Assembles a token source out of a parsed configuration.
 *
 * <p>Maps this module's settings vocabulary onto the SDK's grant and client-authentication types.
 * That mapping is the whole of the provider matrix: nothing below this class knows which provider it
 * is talking to.
 *
 * <p>The chain is caching over retrying over the engine, so that a cache hit costs nothing and a
 * retry does not defeat the cache.
 *
 * <p>Nothing here performs I/O. Discovery, secret files and key files are all resolved on the first
 * fetch, so a provider that happens to be down when the connector starts does not stop it starting.
 */
public final class TokenSources {
    private TokenSources() {}

    /**
     * Builds the token source for one configuration.
     *
     * <p>Each call creates its own {@link HttpClient}, because the timeouts, the proxy and the trust
     * material are all configuration. The client's selector thread is a daemon, so it does not keep a
     * connector's JVM alive; {@link org.neo4j.driver.AuthTokenManager} has no {@code close()}, so
     * there is nowhere to shut it down explicitly. A connector that opens several drivers against the
     * same provider should therefore build one token manager and share it, rather than one per
     * driver.
     *
     * @param config the parsed settings
     * @param context the runtime collaborators provided by the host
     * @return a token source
     */
    public static TokenSource build(OidcConfig config, AuthContext context) {
        Supplier<HttpClient> http = new LazyHttpClient(() -> httpClient(config, context));
        Function<URI, SignedJWT> assertions = assertions(config, context);

        TokenSource source = new OAuth2TokenSource(
                tokenEndpoint(config, http),
                new TokenEndpointClient(
                        http,
                        config.requestTimeout(),
                        config.tokenField(),
                        config.refreshSkew(),
                        config.defaultTtl(),
                        context.clock()),
                grants(config, assertions),
                clientAuthentication(config, assertions),
                config,
                context.executor());
        source = new RetryingTokenSource(source, config.maxRetries(), config.retryBackoff(), context.executor());
        return new CachingTokenSource(source, context.clock());
    }

    private static Supplier<CompletionStage<URI>> tokenEndpoint(OidcConfig config, Supplier<HttpClient> http) {
        if (config.tokenEndpoint().isPresent()) {
            CompletionStage<URI> configured =
                    CompletableFuture.completedStage(config.tokenEndpoint().orElseThrow());
            return () -> configured;
        }
        Discovery discovery = new Discovery(
                http,
                config.discoveryUrl().orElseThrow(),
                config.expectedIssuer().orElse(null),
                config.requestTimeout());
        return discovery::tokenEndpoint;
    }

    private static GrantFactory grants(OidcConfig config, Function<URI, SignedJWT> assertions) {
        return switch (config.grantType()) {
            case CLIENT_CREDENTIALS -> endpoint -> new ClientCredentialsGrant();
            case PASSWORD ->
                endpoint -> new ResourceOwnerPasswordCredentialsGrant(
                        config.username().orElseThrow(),
                        new Secret(config.password().orElseThrow()));
            case REFRESH_TOKEN -> new RollingRefreshToken(config.refreshToken().orElseThrow());
            case JWT_BEARER -> endpoint -> new JWTBearerGrant(assertions.apply(endpoint));
            case TOKEN_EXCHANGE ->
                endpoint -> new TokenExchangeGrant(
                        new TypelessToken(read(config.subjectTokenFile().orElseThrow())),
                        subjectTokenType(config.subjectTokenType()));
        };
    }

    private static TokenTypeURI subjectTokenType(String configured) {
        try {
            return TokenTypeURI.parse(configured);
        } catch (ParseException e) {
            throw Settings.invalid(OidcConfig.SUBJECT_TOKEN_TYPE, configured, "a token type URI");
        }
    }

    /**
     * Re-read on every fetch rather than cached: on EKS and GKE the platform periodically rewrites
     * the projected token, so a value read once at startup stops working within the hour.
     */
    private static String read(Path subjectTokenFile) {
        try {
            return Files.readString(subjectTokenFile).strip();
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the subject token from " + subjectTokenFile, e);
        }
    }

    private static Function<URI, ClientAuthentication> clientAuthentication(
            OidcConfig config, Function<URI, SignedJWT> assertions) {
        return switch (config.clientAuthMethod()) {
            case CLIENT_SECRET_BASIC ->
                endpoint -> new ClientSecretBasic(
                        clientId(config), new Secret(clientSecret(config).get()));
            case CLIENT_SECRET_POST ->
                endpoint -> new ClientSecretPost(
                        clientId(config), new Secret(clientSecret(config).get()));
            case PRIVATE_KEY_JWT -> endpoint -> new PrivateKeyJWT(assertions.apply(endpoint));
            case NONE -> endpoint -> null;
        };
    }

    private static ClientID clientId(OidcConfig config) {
        return new ClientID(config.clientId().orElseThrow());
    }

    private static Supplier<String> clientSecret(OidcConfig config) {
        return config.clientSecret()
                .map(SecretSource::of)
                .orElseGet(() -> SecretSource.fromFile(config.clientSecretFile().orElseThrow()));
    }

    /**
     * Returns the assertion factory, or {@code null} when no signing key is configured. That covers
     * every configuration that neither signs its client authentication nor uses the
     * {@code jwt_bearer} grant.
     */
    private static Function<URI, SignedJWT> assertions(OidcConfig config, AuthContext context) {
        if (config.privateKeyFile().isEmpty()) {
            return null;
        }
        Supplier<PrivateKey> key =
                PrivateKeys.lazy(config.privateKeyFile().orElseThrow(), config.privateKeyAlgorithm());
        AssertionFactory factory = new AssertionFactory(
                key,
                config.privateKeyAlgorithm(),
                config.privateKeyId().orElse(null),
                config.assertionClaims(),
                config.clientId().orElse(null),
                config.assertionTtl(),
                context.clock());
        return factory::create;
    }

    private static HttpClient httpClient(OidcConfig config, AuthContext context) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(config.connectTimeout())
                .executor(context.executor())
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(sslContext(config, context));
        config.proxyHost()
                .ifPresent(host -> builder.proxy(ProxySelector.of(new InetSocketAddress(host, config.proxyPort()))));
        return builder.build();
    }

    private static SSLContext sslContext(OidcConfig config, AuthContext context) {
        Path trustStore = config.trustStoreFile().orElse(null);
        if (trustStore == null) {
            return context.sslContext();
        }
        char[] password = config.trustStorePassword().map(String::toCharArray).orElse(null);
        try (InputStream stream = Files.newInputStream(trustStore)) {
            KeyStore keyStore = KeyStore.getInstance(config.trustStoreType());
            keyStore.load(stream, password);
            TrustManagerFactory trustManagers =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(keyStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers.getTrustManagers(), null);
            return sslContext;
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read the trust store " + trustStore, e);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(
                    "Could not build an SSL context from the trust store " + trustStore + " of type "
                            + config.trustStoreType(),
                    e);
        }
    }

    /**
     * The {@code refresh_token} grant, seeded from configuration and then rolled forward.
     *
     * <p>Providers that rotate refresh tokens invalidate the previous one on use, so holding on to
     * the configured value would work exactly once.
     */
    private static final class RollingRefreshToken implements GrantFactory {
        private final AtomicReference<String> refreshToken;

        RollingRefreshToken(String refreshToken) {
            this.refreshToken = new AtomicReference<>(refreshToken);
        }

        @Override
        public AuthorizationGrant create(URI tokenEndpoint) {
            return new RefreshTokenGrant(new RefreshToken(refreshToken.get()));
        }

        @Override
        public void onToken(AccessToken token) {
            if (token.refreshToken() != null) {
                refreshToken.set(token.refreshToken());
            }
        }
    }
}
