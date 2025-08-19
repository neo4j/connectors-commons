package org.neo4j.connectors.common.driver.reauth.tracking;

import org.neo4j.driver.*;
import org.neo4j.driver.async.AsyncSession;
import org.neo4j.driver.async.AsyncTransaction;
import org.neo4j.driver.async.AsyncTransactionWork;
import org.neo4j.driver.async.ResultCursor;

import java.util.Map;
import java.util.concurrent.CompletionStage;

public class TrackedAsyncSession implements AsyncSession {

    private final TrackingDriver driver;
    private final AsyncSession delegate;

    public TrackedAsyncSession(TrackingDriver driver, AsyncSession delegate) {
        this.driver = driver;
        this.delegate = delegate;
    }

    @Override
    public CompletionStage<AsyncTransaction> beginTransactionAsync() {
        return delegate.beginTransactionAsync();
    }

    @Override
    public CompletionStage<AsyncTransaction> beginTransactionAsync(TransactionConfig config) {
        return delegate.beginTransactionAsync(config);
    }

    @Override
    public <T> CompletionStage<T> readTransactionAsync(AsyncTransactionWork<CompletionStage<T>> work) {
        return delegate.readTransactionAsync(work);
    }

    @Override
    public <T> CompletionStage<T> readTransactionAsync(AsyncTransactionWork<CompletionStage<T>> work, TransactionConfig config) {
        return delegate.readTransactionAsync(work, config);
    }

    @Override
    public <T> CompletionStage<T> writeTransactionAsync(AsyncTransactionWork<CompletionStage<T>> work) {
        return delegate.writeTransactionAsync(work);
    }

    @Override
    public <T> CompletionStage<T> writeTransactionAsync(AsyncTransactionWork<CompletionStage<T>> work, TransactionConfig config) {
        return delegate.writeTransactionAsync(work, config);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, TransactionConfig config) {
        return delegate.runAsync(query, config);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, Map<String, Object> parameters, TransactionConfig config) {
        return delegate.runAsync(query, parameters, config);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(Query query, TransactionConfig config) {
        return delegate.runAsync(query, config);
    }

    @Override
    public Bookmark lastBookmark() {
        return delegate.lastBookmark();
    }

    @Override
    public CompletionStage<Void> closeAsync() {
        return delegate.closeAsync()
                .thenRun(driver::onSessionClosure);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, Value parameters) {
        return delegate.runAsync(query, parameters);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, Map<String, Object> parameters) {
        return delegate.runAsync(query, parameters);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query, Record parameters) {
        return delegate.runAsync(query, parameters);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(String query) {
        return delegate.runAsync(query);
    }

    @Override
    public CompletionStage<ResultCursor> runAsync(Query query) {
        return delegate.runAsync(query);
    }
}
