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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.neo4j.connectors.driver.auth.AuthConfig;
import org.neo4j.connectors.driver.auth.AuthContext;
import org.neo4j.driver.AuthTokenManager;

/**
 * The provider matrix, asserted rather than documented: one test per provider pinning the exact form
 * body and headers its configuration puts on the wire.
 *
 * <p>The module has no provider-specific code, so this is the only place that records what a
 * working Keycloak, Okta, Entra ID, Cognito or Google configuration looks like, and the only thing
 * that notices if a change alters what goes on the wire.
 */
class ProviderContractTest {

    @TempDir
    Path directory;

    private TokenEndpointStub provider;

    @BeforeEach
    void startProvider() {
        provider = new TokenEndpointStub();
        provider.on(
                "/.well-known/openid-configuration",
                request -> TokenEndpointStub.Response.json("{\"issuer\":\"" + provider.uri("")
                        + "\",\"token_endpoint\":\"" + provider.uri("/token") + "\"}"));
        provider.on("/token", TokenEndpointStub.Response.json("{\"access_token\":\"a.b.c\",\"expires_in\":3600}"));
    }

    @AfterEach
    void stopProvider() {
        provider.close();
    }

    @Test
    void keycloakSendsClientCredentialsWithTheSecretInTheAuthorizationHeader() {
        Map<String, String> settings = new HashMap<>();
        settings.put("issuer", provider.uri("").toString());
        settings.put("clientId", "neo4j-client");
        settings.put("clientSecret", "s3cr3t");
        settings.put("scope", "openid");

        fetch(settings);

        assertThat(provider.requests()).hasSize(2);
        assertThat(provider.requests().get(0).path()).isEqualTo("/.well-known/openid-configuration");
        TokenEndpointStub.Recorded token = provider.lastRequest();
        assertThat(token.body()).isEqualTo("grant_type=client_credentials&scope=openid");
        assertThat(token.headers()).containsEntry("authorization", "Basic " + basic("neo4j-client", "s3cr3t"));
        assertThat(token.headers().get("content-type")).startsWith("application/x-www-form-urlencoded");
        assertThat(token.form()).doesNotContainKeys("client_id", "client_secret");
    }

    @Test
    void keycloakSendsThePasswordGrantWithTheConnectorsOwnCredentials() {
        Map<String, String> settings = new HashMap<>();
        settings.put("issuer", provider.uri("").toString());
        settings.put("grantType", "password");
        settings.put("clientId", "neo4j-client");
        settings.put("clientSecret", "s3cr3t");
        settings.put("scope", "openid");

        fetch(AuthConfig.of("john-tester", "testerpwd", settings));

        assertThat(provider.lastRequest().body())
                .isEqualTo("grant_type=password&username=john-tester&password=testerpwd&scope=openid");
    }

    @Test
    void oktaSendsClientCredentialsAgainstACustomAuthorisationServer() {
        Map<String, String> settings = new HashMap<>();
        settings.put("profile", "okta");
        settings.put("issuer", provider.uri("").toString());
        settings.put("clientId", "0oa1abcd");
        settings.put("clientSecret", "okta-secret");
        settings.put("scope", "neo4j.read");

        fetch(settings);

        TokenEndpointStub.Recorded token = provider.lastRequest();
        assertThat(token.body()).isEqualTo("grant_type=client_credentials&scope=neo4j.read");
        assertThat(token.headers()).containsEntry("authorization", "Basic " + basic("0oa1abcd", "okta-secret"));
    }

    @Test
    void entraSendsTheSecretInTheFormWithTheDefaultScope() {
        Map<String, String> settings = new HashMap<>();
        settings.put("profile", "entra");
        settings.put("issuer", provider.uri("").toString());
        settings.put("clientId", "11111111-2222-3333-4444-555555555555");
        settings.put("clientSecret", "entra-secret");
        settings.put("scope", "api://neo4j/.default");

        fetch(settings);

        TokenEndpointStub.Recorded token = provider.lastRequest();
        assertThat(token.headers()).doesNotContainKey("authorization");
        assertThat(token.form())
                .containsOnly(
                        entry("grant_type", "client_credentials"),
                        entry("scope", "api://neo4j/.default"),
                        entry("client_id", "11111111-2222-3333-4444-555555555555"),
                        entry("client_secret", "entra-secret"));
    }

    @Test
    void cognitoSendsPlainClientCredentials() {
        Map<String, String> settings = new HashMap<>();
        settings.put("issuer", provider.uri("").toString());
        settings.put("clientId", "cognito-client");
        settings.put("clientSecret", "cognito-secret");
        settings.put("scope", "neo4j/read");

        fetch(settings);

        assertThat(provider.lastRequest().body()).isEqualTo("grant_type=client_credentials&scope=neo4j%2Fread");
    }

    @Test
    void googleSendsASignedAssertionAndNothingElse() throws Exception {
        Path key = Keys.writePkcs8Pem(directory.resolve("service-account.pk8"), Keys.rsa());
        Map<String, String> settings = new HashMap<>();
        settings.put("profile", "google");
        settings.put("tokenEndpoint", provider.uri("/token").toString());
        settings.put("privateKeyFile", key.toString());
        settings.put("privateKeyId", "abc123");
        settings.put("assertion.claim.iss", "svc@project.iam.gserviceaccount.com");
        settings.put("assertion.claim.sub", "svc@project.iam.gserviceaccount.com");
        settings.put("assertion.claim.target_audience", "neo4j");
        provider.on("/token", TokenEndpointStub.Response.json("{\"id_token\":\"a.b.c\",\"expires_in\":3600}"));

        fetch(settings);

        TokenEndpointStub.Recorded token = provider.lastRequest();
        assertThat(token.formFieldNames()).containsExactly("grant_type", "assertion");
        assertThat(token.form()).containsEntry("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
        assertThat(token.headers()).doesNotContainKey("authorization");

        String assertion = token.form().get("assertion");
        assertThat(header(assertion).getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(header(assertion).getKeyID()).isEqualTo("abc123");
        assertThat(claims(assertion).getIssuer()).isEqualTo("svc@project.iam.gserviceaccount.com");
        assertThat(claims(assertion).getSubject()).isEqualTo("svc@project.iam.gserviceaccount.com");
        assertThat(claims(assertion).getClaim("target_audience")).isEqualTo("neo4j");
        assertThat(claims(assertion).getAudience())
                .containsExactly(provider.uri("/token").toString());
    }

    @Test
    void oktaAndEntraCanAuthenticateWithAKeyInsteadOfASecret() throws Exception {
        Path key = Keys.writePkcs8Pem(directory.resolve("client.pk8"), Keys.ec("secp256r1"));
        Map<String, String> settings = new HashMap<>();
        settings.put("tokenEndpoint", provider.uri("/token").toString());
        settings.put("clientId", "0oa1abcd");
        settings.put("clientAuthMethod", "private_key_jwt");
        settings.put("privateKeyFile", key.toString());
        settings.put("privateKeyAlgorithm", "ES256");
        settings.put("scope", "neo4j.read");

        fetch(settings);

        TokenEndpointStub.Recorded token = provider.lastRequest();
        assertThat(token.formFieldNames())
                .containsExactlyInAnyOrder("grant_type", "scope", "client_assertion_type", "client_assertion");
        assertThat(token.form())
                .containsEntry("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        // RFC 7523 section 2.2 makes client_id redundant once the assertion names the client in
        // iss and sub, and the SDK leaves it out.
        assertThat(claims(token.form().get("client_assertion")).getIssuer()).isEqualTo("0oa1abcd");
        assertThat(claims(token.form().get("client_assertion")).getSubject()).isEqualTo("0oa1abcd");
        assertThat(claims(token.form().get("client_assertion")).getAudience())
                .containsExactly(provider.uri("/token").toString());
    }

    @Test
    void tokenExchangeSendsTheSubjectTokenReadFromTheFile() throws Exception {
        Path subjectToken = java.nio.file.Files.writeString(directory.resolve("token"), "projected-token\n");
        Map<String, String> settings = new HashMap<>();
        settings.put("tokenEndpoint", provider.uri("/token").toString());
        settings.put("grantType", "token_exchange");
        settings.put("clientAuthMethod", "none");
        settings.put("clientId", "workload");
        settings.put("subjectTokenFile", subjectToken.toString());
        settings.put(
                "audience", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v");

        fetch(settings);

        assertThat(provider.lastRequest().form())
                .containsOnly(
                        entry("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                        entry("subject_token", "projected-token"),
                        entry("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
                        entry(
                                "audience",
                                "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v"),
                        entry("client_id", "workload"));
    }

    @Test
    void anExtraParameterOverridesWhateverTheModuleDecided() {
        Map<String, String> settings = new HashMap<>();
        settings.put("tokenEndpoint", provider.uri("/token").toString());
        settings.put("clientId", "a-client");
        settings.put("clientSecret", "a-secret");
        settings.put("scope", "openid");
        settings.put("extraParam.scope", "openid profile");
        settings.put("extraParam.acr_values", "urn:mace:incommon:iap:silver");

        fetch(settings);

        assertThat(provider.lastRequest().form())
                .containsEntry("scope", "openid profile")
                .containsEntry("acr_values", "urn:mace:incommon:iap:silver");
    }

    private void fetch(Map<String, String> settings) {
        fetch(AuthConfig.of(null, null, settings));
    }

    private void fetch(AuthConfig config) {
        AuthTokenManager manager = new OidcAuthTokenManagerFactory()
                .create(config, AuthContext.builder().executor(Runnable::run).build());
        manager.getToken().toCompletableFuture().join();
    }

    private static String basic(String clientId, String clientSecret) {
        return Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    private static JWTClaimsSet claims(String jwt) throws Exception {
        return SignedJWT.parse(jwt).getJWTClaimsSet();
    }

    private static com.nimbusds.jose.JWSHeader header(String jwt) throws Exception {
        return SignedJWT.parse(jwt).getHeader();
    }
}
