package org.neo4j.connectors.common.driver.reauth;

import org.neo4j.driver.*;
import org.neo4j.driver.reactive.RxResult;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.reactive.RxTransaction;
import org.neo4j.driver.reactive.RxTransactionWork;
import org.neo4j.driver.summary.ResultSummary;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static java.util.Collections.emptyMap;
import static org.neo4j.driver.internal.AbstractQueryRunner.parameters;

public class ReAuthRxSession implements RxSession {

    private static final Logger log = LoggerFactory.getLogger(ReAuthRxSession.class);

    private final ReAuthDriver driver;
    private final AtomicReference<RxSession> delegate = new AtomicReference<>();
    private final Supplier<RxSession> sessionSupplier;

    public ReAuthRxSession(ReAuthDriver driver, Supplier<RxSession> sessionSupplier) {
        this.driver = driver;
        this.sessionSupplier = sessionSupplier;
        this.delegate.set(sessionSupplier.get());
    }

    @Override
    public Publisher<RxTransaction> beginTransaction() {
        return beginTransaction(TransactionConfig.empty());
    }

    @Override
    public Publisher<RxTransaction> beginTransaction(TransactionConfig config) {
        return withExpiringRxSession(() -> delegate.get().beginTransaction(config));
    }

    @Override
    public <T> Publisher<T> readTransaction(RxTransactionWork<? extends Publisher<T>> work) {
        return readTransaction(work, TransactionConfig.empty());
    }

    @Override
    public <T> Publisher<T> readTransaction(RxTransactionWork<? extends Publisher<T>> work, TransactionConfig config) {
        return withExpiringRxSession(() -> delegate.get().readTransaction(work, config));
    }

    @Override
    public <T> Publisher<T> writeTransaction(RxTransactionWork<? extends Publisher<T>> work) {
        return writeTransaction(work, TransactionConfig.empty());
    }

    @Override
    public <T> Publisher<T> writeTransaction(RxTransactionWork<? extends Publisher<T>> work, TransactionConfig config) {
        return withExpiringRxSession(() -> delegate.get().writeTransaction(work, config));
    }

    @Override
    public RxResult run(String query, TransactionConfig config) {
        return run(new Query(query, emptyMap()), config);
    }

    @Override
    public RxResult run(String query, Map<String, Object> parameters, TransactionConfig config) {
        return run(new Query(query, parameters), config);
    }

    @Override
    public RxResult run(Query query, TransactionConfig config) {
        return new ReAuthRxResult(() -> delegate.get().run(query, config));
    }

    @Override
    public Bookmark lastBookmark() {
        return delegate.get().lastBookmark(); // todo
    }

    @Override
    public <T> Publisher<T> close() {
        return delegate.get().close();
    }

    @Override
    public RxResult run(String query, Value parameters) {
        return run(new Query(query, parameters), TransactionConfig.empty());
    }

    @Override
    public RxResult run(String query, Map<String, Object> parameters) {
        return run(new Query(query, parameters), TransactionConfig.empty());
    }

    @Override
    public RxResult run(String query, Record parameters) {
        return run(new Query(query, parameters(parameters)), TransactionConfig.empty());
    }

    @Override
    public RxResult run(String query) {
        return run(new Query(query, emptyMap()), TransactionConfig.empty());
    }

    @Override
    public RxResult run(Query query) {
        return run(query, TransactionConfig.empty());
    }

    <T> Publisher<T> withExpiringRxSession(Supplier<Publisher<T>> block) {
        return withExpiringRxSession(block, () -> {});
    }

    <T> Publisher<T> withExpiringRxSession(Supplier<Publisher<T>> block, Runnable additionalRefresh) {
        return driver.withRxRefresh(block, () -> {
            log.info("Re-creating session");
            var oldSession = delegate.getAndSet(sessionSupplier.get());
            Mono.from(oldSession.close()).block(); // todo close quietly ?
            additionalRefresh.run();
        });
    }

    private class ReAuthRxResult implements RxResult {

        private final AtomicReference<RxResult> delegate = new AtomicReference<>();
        private final Supplier<RxResult> resultSupplier;

        private ReAuthRxResult(Supplier<RxResult> resultSupplier) {
            this.resultSupplier = resultSupplier;
            this.delegate.set(resultSupplier.get());
        }

        @Override
        public Publisher<List<String>> keys() {
            return withExpiringRxResult(() -> delegate.get().keys());
        }

        @Override
        public Publisher<Record> records() {
            return withExpiringRxResult(() -> delegate.get().records());
        }

        @Override
        public Publisher<ResultSummary> consume() {
            return withExpiringRxResult(() -> delegate.get().consume());
        }

        private <T> Publisher<T> withExpiringRxResult(Supplier<Publisher<T>> block) {
            return withExpiringRxSession(block, () -> delegate.set(resultSupplier.get()));
        };
    }
}
