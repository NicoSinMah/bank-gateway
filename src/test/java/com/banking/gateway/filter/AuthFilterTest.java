package com.banking.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class AuthFilterTest {

    @Test
    void publicAuthPathBypassesValidation() {
        AuthFilter filter = new AuthFilter(WebClient.builder(), "http://auth-service");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/auth/login").build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, calledChain(chainCalled)))
                .verifyComplete();

        assertThat(chainCalled).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void missingBearerTokenReturnsUnauthorized() {
        AuthFilter filter = new AuthFilter(WebClient.builder(), "http://auth-service");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts").build());
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        StepVerifier.create(filter.filter(exchange, calledChain(chainCalled)))
                .verifyComplete();

        assertThat(chainCalled).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validTokenAddsUserHeaderAndContinues() {
        AtomicReference<String> forwardedUserId = new AtomicReference<>();
        AuthFilter filter = new AuthFilter(WebClient.builder().exchangeFunction(request ->
                Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header(HttpHeaders.CONTENT_TYPE, "application/json")
                        .body("{\"valid\":true,\"userId\":\"user-123\"}")
                        .build())), "http://auth-service");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                        .build());
        GatewayFilterChain chain = chainedExchange -> {
            forwardedUserId.set(chainedExchange.getRequest().getHeaders().getFirst("X-User-Id"));
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        assertThat(forwardedUserId).hasValue("user-123");
    }

    @Test
    void invalidTokenReturnsUnauthorized() {
        AuthFilter filter = new AuthFilter(WebClient.builder().exchangeFunction(request ->
                Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header(HttpHeaders.CONTENT_TYPE, "application/json")
                        .body("{\"valid\":false,\"userId\":null}")
                        .build())), "http://auth-service");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                        .build());

        StepVerifier.create(filter.filter(exchange, calledChain(new AtomicBoolean(false))))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void authServiceFailureReturnsServiceUnavailable() {
        AuthFilter filter = new AuthFilter(WebClient.builder().exchangeFunction(request ->
                Mono.error(new IllegalStateException("auth down"))), "http://auth-service");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/accounts")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer token")
                        .build());

        StepVerifier.create(filter.filter(exchange, calledChain(new AtomicBoolean(false))))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    private GatewayFilterChain calledChain(AtomicBoolean called) {
        return exchange -> {
            called.set(true);
            return Mono.empty();
        };
    }
}
