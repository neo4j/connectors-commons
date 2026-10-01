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
package org.neo4j.connectors.driver.auth.oidc.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jwt.JWTClaimsSet;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.neo4j.connectors.driver.auth.AuthConfigException;
import org.neo4j.connectors.driver.auth.oidc.Keys;

class AssertionFactoryTest {
    private static final Instant NOW = Instant.parse("2026-09-21T10:00:00Z");
    private static final URI ENDPOINT = URI.create("https://host/oauth2/v1/token");

    @Test
    void fillsInTheRfc7523DefaultsForPrivateKeyJwt() throws Exception {
        JWTClaimsSet claims = claimsOf(factory(Map.of(), "a-client"));

        assertThat(claims.getIssuer()).isEqualTo("a-client");
        assertThat(claims.getSubject()).isEqualTo("a-client");
        assertThat(claims.getAudience()).containsExactly("https://host/oauth2/v1/token");
        assertThat(claims.getIssueTime()).isEqualTo(Date.from(NOW));
        assertThat(claims.getExpirationTime()).isEqualTo(Date.from(NOW.plusSeconds(300)));
        assertThat(claims.getJWTID()).isNotBlank();
    }

    @Test
    void mintsAFreshJtiEveryTime() throws Exception {
        AssertionFactory factory = factory(Map.of(), "a-client");

        assertThat(claimsOf(factory).getJWTID()).isNotEqualTo(claimsOf(factory).getJWTID());
    }

    @Test
    void letsAConfiguredClaimWinOverADefault() throws Exception {
        JWTClaimsSet claims =
                claimsOf(factory(Map.of("aud", "https://accounts.google.com/o/oauth2/token"), "a-client"));

        assertThat(claims.getClaim("aud")).isEqualTo("https://accounts.google.com/o/oauth2/token");
    }

    @Test
    void carriesGooglesClaimsWithoutAnyCodeKnowingAboutGoogle() throws Exception {
        JWTClaimsSet claims = claimsOf(factory(
                Map.of(
                        "iss", "svc@project.iam.gserviceaccount.com",
                        "sub", "svc@project.iam.gserviceaccount.com",
                        "target_audience", "neo4j"),
                null));

        assertThat(claims.getIssuer()).isEqualTo("svc@project.iam.gserviceaccount.com");
        assertThat(claims.getSubject()).isEqualTo("svc@project.iam.gserviceaccount.com");
        assertThat(claims.getClaim("target_audience")).isEqualTo("neo4j");
    }

    @Test
    void emitsNumbersAndBooleansAsSuchRatherThanAsStrings() throws Exception {
        JWTClaimsSet claims =
                claimsOf(factory(Map.of("custom_ttl", "1780000000", "email_verified", "true", "tenant", "42x"), "c"));

        assertThat(claims.getClaim("custom_ttl")).isEqualTo(1780000000L);
        assertThat(claims.getClaim("email_verified")).isEqualTo(Boolean.TRUE);
        assertThat(claims.getClaim("tenant")).isEqualTo("42x");
    }

    @Test
    void omitsIssuerAndSubjectWhenThereIsNoClientIdToDefaultThemTo() throws Exception {
        JWTClaimsSet claims = claimsOf(factory(Map.of(), null));

        assertThat(claims.getIssuer()).isNull();
        assertThat(claims.getSubject()).isNull();
    }

    @Test
    void signsSoThatTheMatchingPublicKeyVerifies() throws Exception {
        var keyPair = Keys.rsa();
        AssertionFactory factory = new AssertionFactory(
                keyPair::getPrivate,
                "RS256",
                "key-1",
                Map.of(),
                "a-client",
                Duration.ofSeconds(300),
                Clock.fixed(NOW, ZoneOffset.UTC));

        var jwt = factory.create(ENDPOINT);

        assertThat(jwt.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(
                        (java.security.interfaces.RSAPublicKey) keyPair.getPublic())))
                .isTrue();
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("key-1");
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    }

    @Test
    void signsWithEllipticCurveKeysToo() throws Exception {
        var keyPair = Keys.ec("secp256r1");
        AssertionFactory factory = new AssertionFactory(
                keyPair::getPrivate,
                "ES256",
                null,
                Map.of(),
                "a-client",
                Duration.ofSeconds(300),
                Clock.fixed(NOW, ZoneOffset.UTC));

        var jwt = factory.create(ENDPOINT);

        assertThat(jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(
                        (java.security.interfaces.ECPublicKey) keyPair.getPublic())))
                .isTrue();
    }

    @Test
    void rejectsAnAlgorithmItCannotSignWith() {
        assertThatThrownBy(() -> AssertionFactory.algorithmOf("HS256"))
                .isInstanceOfSatisfying(
                        AuthConfigException.class, e -> assertThat(e.keys()).containsExactly("privateKeyAlgorithm"))
                .hasMessageContaining("privateKeyAlgorithm")
                .hasMessageContaining("HS256")
                .hasMessageContaining("RS256");
    }

    private static AssertionFactory factory(Map<String, String> configuredClaims, String defaultIssuer) {
        var keyPair = Keys.rsa();
        return new AssertionFactory(
                keyPair::getPrivate,
                "RS256",
                "key-1",
                configuredClaims,
                defaultIssuer,
                Duration.ofSeconds(300),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static JWTClaimsSet claimsOf(AssertionFactory factory) throws Exception {
        return factory.create(ENDPOINT).getJWTClaimsSet();
    }
}
