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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Assembles the claims of a signed assertion and signs it with nimbus-jose-jwt.
 *
 * <p>Signing is the library's job — in particular the ECDSA transcoding RFC 7518 requires, which is
 * the easiest thing in this module to get subtly wrong. The <em>claims</em> stay ours, because that
 * is what makes one factory serve every provider: the RFC 7523 defaults ({@code iss}, {@code sub},
 * {@code aud}, {@code exp}, {@code iat}, {@code jti}) are what Okta and Entra want for
 * {@code private_key_jwt}, and anything a provider wants differently — Google's {@code scope} or
 * {@code target_audience} — is an {@code assertion.claim.<name>} setting rather than a code path.
 *
 * <p>Internal to this module; not API.
 */
public final class AssertionFactory {
    private static final Set<String> SUPPORTED =
            Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512");

    private final Supplier<PrivateKey> key;
    private final JWSAlgorithm algorithm;
    private final String keyId;
    private final Map<String, String> configuredClaims;
    private final String defaultIssuer;
    private final Duration ttl;
    private final Clock clock;

    /**
     * Creates the factory.
     *
     * @param key supplies the signing key
     * @param algorithm the JWS algorithm
     * @param keyId the {@code kid} header, may be {@code null}
     * @param configuredClaims the {@code assertion.claim.*} settings, which win over every default
     * @param defaultIssuer the value of {@code iss} and {@code sub} unless configured, usually the
     *     client identifier
     * @param ttl how long the assertion is valid for
     * @param clock the clock to stamp {@code iat} and {@code exp} from
     */
    public AssertionFactory(
            Supplier<PrivateKey> key,
            String algorithm,
            String keyId,
            Map<String, String> configuredClaims,
            String defaultIssuer,
            Duration ttl,
            Clock clock) {
        this.key = key;
        this.algorithm = algorithmOf(algorithm);
        this.keyId = keyId;
        this.configuredClaims = Map.copyOf(configuredClaims);
        this.defaultIssuer = defaultIssuer;
        this.ttl = ttl;
        this.clock = clock;
    }

    /**
     * Validates that an algorithm is one this module can sign with.
     *
     * @param algorithm the configured value of {@code privateKeyAlgorithm}
     * @return the parsed algorithm
     * @throws IllegalArgumentException naming the setting, if it is not supported
     */
    public static JWSAlgorithm algorithmOf(String algorithm) {
        if (!SUPPORTED.contains(algorithm)) {
            throw new IllegalArgumentException("Authentication parameter 'privateKeyAlgorithm' has invalid value '"
                    + algorithm + "'; expected one of " + supportedAlgorithms());
        }
        return JWSAlgorithm.parse(algorithm);
    }

    /**
     * Returns every supported JWS algorithm, for error messages.
     *
     * @return the algorithms, comma separated
     */
    public static String supportedAlgorithms() {
        return SUPPORTED.stream().sorted().reduce((a, b) -> a + ", " + b).orElseThrow();
    }

    /**
     * Mints an assertion for a given audience.
     *
     * @param audience the token endpoint, the default {@code aud}
     * @return the signed assertion
     */
    public SignedJWT create(URI audience) {
        Instant now = clock.instant();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
        if (defaultIssuer != null) {
            claims.issuer(defaultIssuer);
            claims.subject(defaultIssuer);
        }
        claims.audience(List.of(audience.toString()));
        claims.issueTime(Date.from(now));
        claims.expirationTime(Date.from(now.plus(ttl)));
        claims.jwtID(UUID.randomUUID().toString());
        configuredClaims.forEach((name, value) -> claims.claim(name, coerce(value)));

        SignedJWT jwt =
                new SignedJWT(new JWSHeader.Builder(algorithm).keyID(keyId).build(), claims.build());
        try {
            jwt.sign(signer());
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not sign the JWT assertion with algorithm " + algorithm, e);
        }
        return jwt;
    }

    private JWSSigner signer() throws JOSEException {
        PrivateKey privateKey = key.get();
        if (privateKey instanceof ECPrivateKey ecPrivateKey) {
            return new ECDSASigner(ecPrivateKey);
        }
        return new RSASSASigner(privateKey);
    }

    /**
     * Turns a configured claim value into the JSON type a provider expects.
     *
     * <p>Configuration is all strings, but {@code exp} must be a number and some providers check the
     * type. Anything that reads as an integer or a boolean is emitted as one; everything else stays a
     * string.
     */
    private static Object coerce(String value) {
        if ("true".equals(value) || "false".equals(value)) {
            return Boolean.valueOf(value);
        }
        try {
            return Long.valueOf(value);
        } catch (NumberFormatException e) {
            return value;
        }
    }
}
