package com.glic.mappgateway.csrf;

import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.FORBIDDEN;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
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

   /*
    * @method requireCsrfProtectionMatcher
    * @description Definimos si se puede excluir la proteccion CSRF de una ruta especifica
    */
   private final ServerWebExchangeMatcher requireCsrfProtectionMatcher = new AndServerWebExchangeMatcher(
            new HttpMethodCsrfProtectionMatcher(),
            new NegatedServerWebExchangeMatcher(
                  ServerWebExchangeMatchers.pathMatchers(
                          POST,
                          "/mt-api/ms-app-user/users_app_auth/login"
                  )
            )
   );

   @Autowired
   private CustomServerCsrfTokenRepository csrfTokenRepository;

   /*
    * @method accessDeniedHandler
    * @description Maneja los errores de acceso
    */
   private final ServerAccessDeniedHandler accessDeniedHandler = new HttpStatusServerAccessDeniedHandler(FORBIDDEN);

   @Override
   public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
      // Si la peticion cuenta con "API-CALL" header, continua sin validar CSRF
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

   /*
    * @method validateToken
    * @description Valida el token CSRF
    */
   private Mono<Void> validateToken(ServerWebExchange exchange) {
      return this.csrfTokenRepository
            .loadToken(exchange)
            .switchIfEmpty(Mono.defer(() -> Mono.error(new CsrfException("CSRF Token has been associated to this client"))))
            .filterWhen(expected -> containsValidCsrfToken(exchange, expected))
            .switchIfEmpty(Mono.defer(() -> Mono.error(new CsrfException("Invalid CSRF Token"))))
            .then();
   }

   /*
    * @method containsValidCsrfToken
    * @description Compara token CSRF de request con el esperado
    */
   private Mono<Boolean> containsValidCsrfToken(ServerWebExchange exchange, CsrfToken expected) {
      return exchange
            .getFormData()
            .flatMap(data -> Mono.justOrEmpty(data.getFirst(expected.getParameterName())))
            .switchIfEmpty(Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(expected.getHeaderName())))
            .map(actual -> actual.equals(expected.getToken()));
   }

   /*
    * @method continueFilterChain
    * @description Agrega el token a los atributos del request y lo envia para continuar la cadena de filtrado
    */
   private Mono<Void> continueFilterChain(ServerWebExchange exchange, WebFilterChain chain) {
      return Mono.defer(() -> {
         Mono<CsrfToken> csrfToken = csrfToken(exchange);
         exchange.getAttributes().put(CsrfToken.class.getName(), csrfToken);
         return chain.filter(exchange);
      });
   }

   /*
    * @method continueFilterChainEmpty
    * @description Envia para continuar la cadena de filtrado sin Token CSRF existente
    */
   private Mono<Void> continueFilterChainEmpty(ServerWebExchange exchange, WebFilterChain chain) {
      return Mono.defer(() -> {
         Mono<CsrfToken> csrfToken = generateToken(exchange);
         exchange.getAttributes().put(CsrfToken.class.getName(), csrfToken);
         return chain.filter(exchange);
      });
   }

   /*
    * @method csrfToken
    * @description carga Token CSRF desde repositorio o crea uno nuevo si no lo encuentra
    */
   private Mono<CsrfToken> csrfToken(ServerWebExchange exchange) {
      return this.csrfTokenRepository.loadToken(exchange).switchIfEmpty(generateToken(exchange));
   }

   /*
    * @method generateToken
    * @description crea Token CSRF nuevo y lo guarda en repositorio
    */
   private Mono<CsrfToken> generateToken(ServerWebExchange exchange) {
      return this.csrfTokenRepository.generateToken(exchange).delayUntil(token -> this.csrfTokenRepository.saveToken(exchange, token));
   }

}
