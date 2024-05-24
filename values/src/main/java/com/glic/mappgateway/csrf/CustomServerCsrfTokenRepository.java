package com.glic.mappgateway.csrf;

import static java.util.Optional.ofNullable;

import java.util.Optional;
import java.util.UUID;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class CustomServerCsrfTokenRepository implements ServerCsrfTokenRepository {

   private final static String COOKIE_NAME = "XSRF-TOKEN";

   @Override
   public Mono<CsrfToken> generateToken(ServerWebExchange exchange) {
      return Mono.fromCallable(this::createCsrfToken);
   }

   @Override
   public Mono<Void> saveToken(ServerWebExchange exchange, CsrfToken token) {
      return Mono.fromRunnable(() -> {
         Optional<String> tokenValue = ofNullable(token).map(CsrfToken::getToken);
         ResponseCookie cookie = ResponseCookie
               .from(COOKIE_NAME, tokenValue.orElse(""))
               .domain("")
               .httpOnly(false)
               .maxAge(tokenValue.map(val -> -1).orElse(0))
               .path(getRequestContext(exchange.getRequest()))
               .secure(ofNullable(exchange.getRequest().getSslInfo()).isPresent())
               .build();

         exchange.getResponse().addCookie(cookie);
      });
   }

   @Override
   public Mono<CsrfToken> loadToken(ServerWebExchange exchange) {
      return Mono.fromCallable(() -> {
         HttpCookie csrfCookie = exchange.getRequest().getCookies().getFirst(COOKIE_NAME);
         if ((csrfCookie == null) || !StringUtils.hasText(csrfCookie.getValue())) {
            return null;
         }
         return createCsrfToken(csrfCookie.getValue());
      });
   }

   private CsrfToken createCsrfToken() {
      return createCsrfToken(createNewToken());
   }

   private CsrfToken createCsrfToken(String tokenValue) {
      return new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", tokenValue);
   }

   private String createNewToken() {
      return UUID.randomUUID().toString();
   }

   private String getRequestContext(ServerHttpRequest request) {
      String contextPath = request.getPath().contextPath().value();
      return StringUtils.hasLength(contextPath) ? contextPath : "/";
   }
}
