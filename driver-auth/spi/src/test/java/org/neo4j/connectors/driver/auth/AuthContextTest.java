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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

class AuthContextTest {

    @Test
    void defaultsMatchTheDriversOwnBehaviour() {
        AuthContext context = AuthContext.defaults();

        assertThat(context.executor()).isSameAs(ForkJoinPool.commonPool());
        assertThat(context.clock()).isEqualTo(Clock.systemUTC());
        assertThat(context.sslContext()).isSameAs(defaultSslContext());
    }

    @Test
    void overridesOnlyWhatIsSet() {
        Executor executor = Runnable::run;
        AuthContext context = AuthContext.builder().executor(executor).build();

        assertThat(context.executor()).isSameAs(executor);
        assertThat(context.clock()).isEqualTo(Clock.systemUTC());
        assertThat(context.sslContext()).isSameAs(defaultSslContext());
    }

    @Test
    void carriesAnOverriddenSslContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);

        assertThat(AuthContext.builder().sslContext(sslContext).build().sslContext())
                .isSameAs(sslContext);
    }

    @Test
    void carriesAnOverriddenClock() {
        Clock clock = Clock.fixed(Instant.parse("2026-09-08T10:15:30Z"), ZoneOffset.UTC);

        assertThat(AuthContext.builder().clock(clock).build().clock()).isSameAs(clock);
    }

    @Test
    void rejectsNullCollaborators() {
        assertThatThrownBy(() -> AuthContext.builder().executor(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> AuthContext.builder().clock(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> AuthContext.builder().sslContext(null)).isInstanceOf(NullPointerException.class);
    }

    private static SSLContext defaultSslContext() {
        try {
            return SSLContext.getDefault();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
