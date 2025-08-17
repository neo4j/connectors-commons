package org.neo4j.connectors.common.driver.reauth;

import org.neo4j.connectors.authn.*;
import org.neo4j.driver.AuthToken;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Value;
import org.neo4j.driver.internal.security.InternalAuthToken;

import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

import static java.lang.String.format;

public class RefreshingInternalAuthToken extends InternalAuthToken {

    private final Supplier<AuthenticationToken> supplier;

    RefreshingInternalAuthToken(Supplier<AuthenticationToken> supplier) {
        super(Collections.emptyMap());
        this.supplier = supplier;
    }

    private static AuthToken convertToAuthToken(AuthenticationToken token) throws IllegalArgumentException {
        if (token instanceof BearerAuthenticationToken) {
            var bearerToken = (BearerAuthenticationToken) token;
            return AuthTokens.bearer(bearerToken.getToken());
        }
        if (token instanceof KerberosAuthenticationToken) {
            var kerberosToken = (KerberosAuthenticationToken) token;
            return AuthTokens.kerberos(kerberosToken.getToken());
        }
        if (token instanceof UserNameAndPasswordAuthenticationToken) {
            var userNameAndPasswordToken = (UserNameAndPasswordAuthenticationToken) token;
            return AuthTokens.basic(userNameAndPasswordToken.getUsername(), userNameAndPasswordToken.getPassword());
        }
        if (token instanceof DisabledAuthenticationToken) {
            return AuthTokens.none();
        }
        if (token instanceof CustomAuthenticationToken) {
            var customToken = (CustomAuthenticationToken) token;
            return AuthTokens.custom(
                    customToken.getPrincipal(),
                    customToken.getCredentials(),
                    customToken.getRealm(),
                    customToken.getScheme(),
                    customToken.getParameters());
        }
        throw new IllegalArgumentException(
                format("Authentication token of class %s is not supported", token.getClass()));
    }

    public Map<String, Value> toMap() {
        return ((InternalAuthToken) convertToAuthToken(supplier.get())).toMap();
    }

}
