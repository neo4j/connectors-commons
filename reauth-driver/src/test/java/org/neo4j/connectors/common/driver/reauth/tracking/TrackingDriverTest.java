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
package org.neo4j.connectors.common.driver.reauth.tracking;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static reactor.core.publisher.Mono.from;
import static reactor.core.publisher.Mono.just;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.SessionConfig;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.reactive.RxSession;

@ExtendWith(MockitoExtension.class)
public class TrackingDriverTest {

    @Mock
    Driver driver;

    @Test
    void trackingDriverTracksSession() {
        // given
        TrackingDriver trackingDriver = new TrackingDriver(driver);
        Session session1 = mock(Session.class);
        Session session2 = mock(Session.class);
        given(driver.session(any(SessionConfig.class))).willReturn(session1, session2);

        doNothing().when(session1).close();
        doNothing().when(session2).close();

        // when and then
        Session trackedSession1 = trackingDriver.session();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(1);

        Session trackedSession2 = trackingDriver.session(SessionConfig.defaultConfig());
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(2);

        trackedSession1.close();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(1);

        trackedSession2.close();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(0);
    }

    @Test
    void trackingDriverTracksRxSession() {
        // given
        TrackingDriver trackingDriver = new TrackingDriver(driver);
        RxSession session1 = mock(RxSession.class);
        RxSession session2 = mock(RxSession.class);
        given(driver.rxSession(any(SessionConfig.class))).willReturn(session1, session2);

        given(session1.close()).willReturn(just(""));
        given(session2.close()).willReturn(just(""));

        // when and then
        RxSession trackedSession1 = trackingDriver.rxSession();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(1);

        RxSession trackedSession2 = trackingDriver.rxSession(SessionConfig.defaultConfig());
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(2);

        from(trackedSession1.close()).block();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(1);

        from(trackedSession2.close()).block();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(0);
    }

    @Test
    void trackingDriverTracksAsyncSession() throws ExecutionException, InterruptedException {
        // given
        TrackingDriver trackingDriver = new TrackingDriver(driver);
        AsyncSession session1 = mock(AsyncSession.class);
        AsyncSession session2 = mock(AsyncSession.class);
        given(driver.asyncSession(any(SessionConfig.class))).willReturn(session1, session2);

        given(session1.closeAsync()).willReturn(CompletableFuture.completedFuture(null));
        given(session2.closeAsync()).willReturn(CompletableFuture.completedFuture(null));

        // when and then
        AsyncSession trackedSession1 = trackingDriver.asyncSession();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(1);

        AsyncSession trackedSession2 = trackingDriver.asyncSession(SessionConfig.defaultConfig());
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(2);

        trackedSession1.closeAsync().toCompletableFuture().get();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(1);

        trackedSession2.closeAsync().toCompletableFuture().get();
        assertThat(trackingDriver.getOpenSessionCount()).isEqualTo(0);
    }
}
