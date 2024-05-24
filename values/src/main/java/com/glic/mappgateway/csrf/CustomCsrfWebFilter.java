package com.glic.mappgateway.csrf;

import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.FORBIDDEN;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.csrf.CsrfException;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

public class CustomCsrfWebFilter implements WebFilter {

   public static final String API_CALL = "API-CALL";

   private final ServerWebExchangeMatcher requireCsrfProtectionMatcher = new AndServerWebExchangeMatcher(new HttpMethodCsrfProtectionMatcher(),
         new NegatedServerWebExchangeMatcher(ServerWebExchangeMatchers.pathMatchers(POST, "/mt-api/ms-app-user/users_app_auth/login")));

   @Autowired
   private CustomServerCsrfTokenRepository csrfTokenRepository;

   private final ServerAccessDeniedHandler accessDeniedHandler = new HttpStatusServerAccessDeniedHandler(FORBIDDEN);

   @Override
   public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

      if (exchange.getRequest().getHeaders().containsKey(API_CALL)) {
         return continueFilterChain(exchange, chain);
      } else {
         return this.requireCsrfProtectionMatcher
               .matches(exchange)
               .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
               .filter(matchResult -> !exchange.getAttributes().containsKey(CsrfToken.class.getName()))
               .flatMap(m -> validateToken(exchange))
               .flatMap(m -> continueFilterChain(exchange, chain))
               .switchIfEmpty(continueFilterChainEmpty(exchange, chain).then(Mono.empty()))
               .onErrorResume(CsrfException.class, e -> this.accessDeniedHandler.handle(exchange, e));
      }

   }

   private Mono<Void> validateToken(ServerWebExchange exchange) {
      return this.csrfTokenRepository
            .loadToken(exchange)
            .switchIfEmpty(Mono.defer(() -> Mono.error(new CsrfException("CSRF Token has been associated to this client"))))
            .filterWhen(expected -> containsValidCsrfToken(exchange, expected))
            .switchIfEmpty(Mono.defer(() -> Mono.error(new CsrfException("Invalid CSRF Token"))))
            .then();
   }

   private Mono<Boolean> containsValidCsrfToken(ServerWebExchange exchange, CsrfToken expected) {
      return exchange
            .getFormData()
            .flatMap(data -> Mono.justOrEmpty(data.getFirst(expected.getParameterName())))
            .switchIfEmpty(Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(expected.getHeaderName())))
            .map(actual -> actual.equals(expected.getToken()));
   }

   private Mono<Void> continueFilterChain(ServerWebExchange exchange, WebFilterChain chain) {
      return Mono.defer(() -> {
         Mono<CsrfToken> csrfToken = csrfToken(exchange);
         exchange.getAttributes().put(CsrfToken.class.getName(), csrfToken);
         return chain.filter(exchange);
      });
   }

   private Mono<Void> continueFilterChainEmpty(ServerWebExchange exchange, WebFilterChain chain) {
      return Mono.defer(() -> {
         Mono<CsrfToken> csrfToken = generateToken(exchange);
         exchange.getAttributes().put(CsrfToken.class.getName(), csrfToken);
         return chain.filter(exchange);
      });
   }

   private Mono<CsrfToken> csrfToken(ServerWebExchange exchange) {
      return this.csrfTokenRepository.loadToken(exchange).switchIfEmpty(generateToken(exchange));
   }

   private Mono<CsrfToken> generateToken(ServerWebExchange exchange) {
      return this.csrfTokenRepository.generateToken(exchange).delayUntil(token -> this.csrfTokenRepository.saveToken(exchange, token));
   }

}
