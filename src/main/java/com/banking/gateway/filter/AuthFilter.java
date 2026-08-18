package com.banking.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthFilter implements GlobalFilter, Ordered {

    private final WebClient webClient;
    private static final String[] PUBLIC_PATHS = {
        "/api/v1/auth/register", "/api/v1/auth/login"
    };

    public AuthFilter(WebClient.Builder builder,
                       @org.springframework.beans.factory.annotation.Value("${auth.service.url}") String authServiceUrl) {
        this.webClient = builder.baseUrl(authServiceUrl).build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        for (String publicPath : PUBLIC_PATHS) {
            if (path.equals(publicPath)) {
                return chain.filter(exchange);
            }
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return webClient.get()
                .uri("/api/v1/auth/validate")
                .header("Authorization", authHeader)
                .retrieve()
                .bodyToMono(ValidateResponse.class)
                .flatMap(res -> {
                    if (!res.valid()) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    ServerWebExchange mutated = exchange.mutate()
                        .request(r -> r.header("X-User-Id", res.userId()))
                        .build();
                    return chain.filter(mutated);
                })
                .onErrorResume(e -> {
                    exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                    return exchange.getResponse().setComplete();
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }

    record ValidateResponse(boolean valid, String userId) {}
}
