package org.neo4j.connectors.common.driver.reauth;

import org.slf4j.Logger;

import static org.slf4j.LoggerFactory.*;

public final class Utils {

    private Utils() {}

    private final static Logger log = getLogger(Utils.class);

    public static void closeQuietly(AutoCloseable closeable) {
        try {
            closeable.close();
        } catch (Exception e) {
            log.debug("Failed to close resource", e);
        }
    }

}
