package org.neo4j.connectors.common.driver.reauth.tracking;

import org.neo4j.driver.*;
import org.neo4j.driver.reactive.RxResult;
import org.neo4j.driver.reactive.RxSession;
import org.neo4j.driver.reactive.RxTransaction;
import org.neo4j.driver.reactive.RxTransactionWork;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.function.Function;

public class TrackedRxSession implements RxSession {

    private final TrackingDriver driver;
    private final RxSession delegate;

    public TrackedRxSession(TrackingDriver driver, RxSession delegate) {
        this.driver = driver;
        this.delegate = delegate;
    }

    @Override
    public Publisher<RxTransaction> beginTransaction() {
        return delegate.beginTransaction();
    }

    @Override
    public Publisher<RxTransaction> beginTransaction(TransactionConfig config) {
        return delegate.beginTransaction(config);
    }

    @Override
    public <T> Publisher<T> readTransaction(RxTransactionWork<? extends Publisher<T>> work) {
        return delegate.readTransaction(work);
    }

    @Override
    public <T> Publisher<T> readTransaction(RxTransactionWork<? extends Publisher<T>> work, TransactionConfig config) {
        return delegate.readTransaction(work, config);
    }

    @Override
    public <T> Publisher<T> writeTransaction(RxTransactionWork<? extends Publisher<T>> work) {
        return delegate.writeTransaction(work);
    }

    @Override
    public <T> Publisher<T> writeTransaction(RxTransactionWork<? extends Publisher<T>> work, TransactionConfig config) {
        return delegate.writeTransaction(work, config);
    }

    @Override
    public RxResult run(String query, TransactionConfig config) {
        return delegate.run(query, config);
    }

    @Override
    public RxResult run(String query, Map<String, Object> parameters, TransactionConfig config) {
        return delegate.run(query, parameters, config);
    }

    @Override
    public RxResult run(Query query, TransactionConfig config) {
        return delegate.run(query, config);
    }

    @Override
    public Bookmark lastBookmark() {
        return delegate.lastBookmark();
    }

    @Override
    public <T> Publisher<T> close() {
        return Mono.from(delegate.close())
                .then(Mono.fromRunnable(driver::onSessionClosure));
    }

    @Override
    public RxResult run(String query, Value parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public RxResult run(String query, Map<String, Object> parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public RxResult run(String query, Record parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public RxResult run(String query) {
        return delegate.run(query);
    }

    @Override
    public RxResult run(Query query) {
        return delegate.run(query);
    }
}
