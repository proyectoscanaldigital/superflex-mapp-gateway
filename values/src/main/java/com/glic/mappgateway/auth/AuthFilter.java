package com.glic.mappgateway.auth;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

public class AuthFilter implements WebFilter {

   public static final String AUTH_APP = "Auth-App";

   public static final String ACCESS_DENIED = "Acceso Denegado";

   @Value("${spring.application.jwtSecret}")
   private String jwtSecret;

   @Value("${spring.application.tokens}")
   private List<String> tokens;

   @Override
   public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
      try {
         if (excludedPath(exchange.getRequest().getPath().toString())) {
            return chain.filter(exchange);
         }
         if (validateAuthHeader(exchange.getRequest())) {
            return chain.filter(exchange);
         }
         return this.onError(exchange, ACCESS_DENIED, HttpStatus.UNAUTHORIZED);
      } catch (Exception e) {
         return this.onError(exchange, ACCESS_DENIED, HttpStatus.UNAUTHORIZED);
      }
   }

   private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
      ServerHttpResponse response = exchange.getResponse();
      response.setStatusCode(httpStatus);
      return response.setComplete();
   }

   public boolean validateAuthHeader(ServerHttpRequest request) {
      AtomicBoolean exist = new AtomicBoolean(false);
      if (request.getHeaders().containsKey(AUTH_APP)) {
         String jwtAuth = request.getHeaders().getFirst(AUTH_APP);
         if (tokens.contains(jwtAuth)) {
            exist.set(true);
         }
      }
      return exist.get();
   }

   public boolean excludedPath(String path) {
      return path.contains("/actuator");
   }

}
