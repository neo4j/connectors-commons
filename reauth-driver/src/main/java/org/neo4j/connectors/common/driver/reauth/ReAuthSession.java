package org.neo4j.connectors.common.driver.reauth;

import org.neo4j.driver.*;
import org.neo4j.driver.exceptions.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.util.Collections.emptyMap;

class ReAuthSession implements Session {

    private final static Logger log = LoggerFactory.getLogger(ReAuthSession.class);

    private ReAuthDriver driver;
    private Session delegate;
    private Supplier<Session> sessionSupplier;

    ReAuthSession(ReAuthDriver driver, Supplier<Session> sessionSupplier) {
        this.driver = driver;
        this.delegate = sessionSupplier.get();
        this.sessionSupplier = sessionSupplier;
    }

    @Override
    public Transaction beginTransaction() {
        return beginTransaction(TransactionConfig.empty());
    }

    @Override
    public Transaction beginTransaction(TransactionConfig config) {
        return null; // todo
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work) {
        return readTransaction(work, TransactionConfig.empty());
    }

    @Override
    public <T> T readTransaction(TransactionWork<T> work, TransactionConfig config) {
        return null; // todo
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work) {
        return writeTransaction(work, TransactionConfig.empty());
    }

    @Override
    public <T> T writeTransaction(TransactionWork<T> work, TransactionConfig config) {
        return withExpiringSession(() -> this.delegate.writeTransaction(work, config) );
    }

    private <T> T withExpiringSession(Supplier<T> block) {
        return driver.withRefresh(block, () -> {
           log.info("Re-creating session");
           delegate = sessionSupplier.get();
        });
    }

    @Override
    public Result run(String query, TransactionConfig config) {
        return run(new Query(query, emptyMap()), TransactionConfig.empty());
    }

    @Override
    public Result run(String query, Map<String, Object> parameters, TransactionConfig config) {
        return run(new Query(query, parameters), config);
    }

    @Override
    public Result run(Query query, TransactionConfig config) {
        return null;
    }

    @Override
    public Bookmark lastBookmark() {
        return null;
    }

    @Deprecated
    @Override
    public void reset() {
        delegate.reset();
    }

    @Override
    public void close() {
        delegate.close();
    }

    @Override
    public Result run(String query, Value parameters) {
        return null;
    }

    @Override
    public Result run(String query, Map<String, Object> parameters) {
        return null;
    }

    @Override
    public Result run(String query, Record parameters) {
        return null;
    }

    @Override
    public Result run(String query) {
        return null;
    }

    @Override
    public Result run(Query query) {
        return null;
    }

    @Override
    public boolean isOpen() {
        return delegate.isOpen();
    }
}
