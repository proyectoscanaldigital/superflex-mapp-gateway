package com.glic.mappgateway.csrf;

import static java.util.Arrays.asList;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.HEAD;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.http.HttpMethod.TRACE;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

public class HttpMethodCsrfProtectionMatcher implements ServerWebExchangeMatcher {

   // Metodos HTTP que no requieren validacion CSRF
   private static final Set<HttpMethod> ALLOWED_METHODS = new HashSet<>(asList(GET, HEAD, TRACE, OPTIONS));


   /*
    * @method matches
    * @description Valida si cumple con los criterios de proteccion CSRF
    */
   @Override
   public Mono<MatchResult> matches(ServerWebExchange exchange) {
      return Mono
            .just(exchange.getRequest())
            .map(HttpRequest::getMethod)
            .filter(ALLOWED_METHODS::contains)
            .flatMap(m -> MatchResult.notMatch())
            .switchIfEmpty(MatchResult.match());
   }
}
