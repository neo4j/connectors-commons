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
package org.neo4j.connectors.driver.auth.oidc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * A real HTTP server standing in for a token endpoint, so that the tests exercise the actual
 * {@link java.net.http.HttpClient} path: form encoding, headers, status handling and JSON parsing.
 *
 * <p>Records every request, which is what lets the contract tests assert the exact bytes each
 * provider's configuration puts on the wire.
 */
public final class TokenEndpointStub implements AutoCloseable {
    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final List<Recorded> requests = new CopyOnWriteArrayList<>();
    private final Set<String> registered = ConcurrentHashMap.newKeySet();

    public TokenEndpointStub() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.setExecutor(executor);
        server.start();
    }

    public URI uri(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
    }

    /** Always answers with the same response. */
    public void on(String path, Response response) {
        on(path, request -> response);
    }

    /** Answers with the next response in turn, repeating the last one once they run out. */
    public void onEach(String path, Response... responses) {
        AtomicInteger index = new AtomicInteger();
        on(path, request -> responses[Math.min(index.getAndIncrement(), responses.length - 1)]);
    }

    public void on(String path, Function<Recorded, Response> handler) {
        if (!registered.add(path)) {
            server.removeContext(path);
        }
        server.createContext(path, exchange -> {
            Recorded recorded = record(exchange);
            requests.add(recorded);
            Response response = handler.apply(recorded);
            byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
            response.headers()
                    .forEach((name, value) -> exchange.getResponseHeaders().add(name, value));
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(response.status(), body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
    }

    public List<Recorded> requests() {
        return List.copyOf(requests);
    }

    public Recorded lastRequest() {
        return requests.get(requests.size() - 1);
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private static Recorded record(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> headers = new LinkedHashMap<>();
        exchange.getRequestHeaders()
                .forEach((name, values) -> headers.put(name.toLowerCase(java.util.Locale.ROOT), values.get(0)));
        return new Recorded(
                exchange.getRequestMethod(), exchange.getRequestURI().getPath(), headers, body, parseForm(body));
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> form = new LinkedHashMap<>();
        if (body.isEmpty()) {
            return form;
        }
        for (String pair : body.split("&")) {
            int separator = pair.indexOf('=');
            String name = separator < 0 ? pair : pair.substring(0, separator);
            String value = separator < 0 ? "" : pair.substring(separator + 1);
            form.put(URLDecoder.decode(name, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return form;
    }

    public record Recorded(
            String method, String path, Map<String, String> headers, String body, Map<String, String> form) {
        public List<String> formFieldNames() {
            return new ArrayList<>(form.keySet());
        }
    }

    public record Response(int status, String body, Map<String, String> headers) {
        public static Response of(int status, String body) {
            return new Response(status, body, Map.of());
        }

        public static Response json(String body) {
            return of(200, body);
        }

        public Response withHeader(String name, String value) {
            Map<String, String> merged = new LinkedHashMap<>(headers);
            merged.put(name, value);
            return new Response(status, body, merged);
        }
    }
}
