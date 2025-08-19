package org.neo4j.connectors.common.driver.reauth.tracking;

import org.neo4j.driver.*;

import java.util.Map;
import java.util.Objects;

import static reactor.core.publisher.Flux.switchOnNext;

public class TrackedSession implements Session {

    private final TrackingDriver driver;
    private final Session delegate;

    public TrackedSession(TrackingDriver driver, Session delegate) {
        this.driver = Objects.requireNonNull(driver);
        this.delegate = Objects.requireNonNull(delegate);
    }

    @Override
    public Transaction beginTransaction() {
        return delegate.beginTransaction();
    }

    @Override
    public Transaction beginTransaction(TransactionConfig config) {
        return delegate.beginTransaction(config);
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work) {
        return delegate.readTransaction(work);
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work, TransactionConfig config) {
        return delegate.readTransaction(work, config);
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work) {
        return delegate.writeTransaction(work);
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work, TransactionConfig config) {
        return delegate.writeTransaction(work, config);
    }

    @Override
    public Result run(String query, TransactionConfig config) {
        return delegate.run(query, config);
    }

    @Override
    public Result run(String query, Map<String, Object> parameters, TransactionConfig config) {
        return delegate.run(query, parameters, config);
    }

    @Override
    public Result run(Query query, TransactionConfig config) {
        return delegate.run(query, config);
    }

    @Override
    public Bookmark lastBookmark() {
        return delegate.lastBookmark();
    }

    @Deprecated
    @Override
    public void reset() {
        delegate.reset();
    }

    @Override
    public void close() {
        delegate.close();
        driver.onSessionClosure();
    }

    @Override
    public Result run(String query, Value parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public Result run(String query, Map<String, Object> parameters) {
        return delegate.run(query, parameters);
    }

    @Override
    public Result run(String query, Record parameters) {
        return delegate.run(query, parameters);

    }

    @Override
    public Result run(String query) {
        return delegate.run(query);
    }

    @Override
    public Result run(Query query) {
        return delegate.run(query);
    }

    @Override
    public boolean isOpen() {
        return delegate.isOpen();
    }

}
