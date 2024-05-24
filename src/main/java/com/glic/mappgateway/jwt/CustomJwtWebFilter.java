package com.glic.mappgateway.jwt;

import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;

import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

public class CustomJwtWebFilter implements WebFilter {

   public static final String AUTHORITIES = "AUTHORITIES";

   public static final String JWT_COOKIE_NAME = "JWT";

   public static final String COOKIE = "cookie";

   private static final String PREFIX_BEARER = "Bearer ";

   @Value("${spring.application.jwtSecret}")
   private String jwtSecret;

   @Override
   public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
      try {
         // Validamos si la ruta debe excluirse de validacion token JWT
         if (excludedPath(exchange.getRequest().getPath().toString())) {
            return chain.filter(exchange);
         }
         // Validamos el token JWT
         if (validateJWTToken(exchange.getRequest())) {
            return chain.filter(exchange);
         }
         return this.onError(exchange, "Access denied", HttpStatus.UNAUTHORIZED);
      } catch (Exception e) {
         return this.onError(exchange, "Access denied", HttpStatus.UNAUTHORIZED);
      }
   }

   /*
    * @method onError
    * @description Maneja los errores de validacion
    */
   private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
      ServerHttpResponse response = exchange.getResponse();
      response.setStatusCode(httpStatus);
      return response.setComplete();
   }

   /*
    * @method validateJWTToken
    * @description Validamos token desde request o cookies
    */
   public boolean validateJWTToken(ServerHttpRequest request) {
      AtomicBoolean exist = new AtomicBoolean(false);

      // Valida si el request contiene Authorization Header y el token JWT
      if (request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
         String jwtAuth = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
         if (StringUtils.hasText(jwtAuth) && jwtAuth.startsWith(PREFIX_BEARER)) {
            String jwtToken = jwtAuth.substring(7);
            if (((List) validateToken(jwtToken).get(AUTHORITIES)).size() > 0) {
               exist.set(true);
            }
         }
      }

      // Valida si el request contiene Cookie y el token JWT
      if (request.getHeaders().containsKey(COOKIE)) {
         MultiValueMap<String, HttpCookie> cookieMultiValueMap = request.getCookies();
         cookieMultiValueMap.get(JWT_COOKIE_NAME).forEach(httpCookie -> {
            if (JWT_COOKIE_NAME.equals(httpCookie.getName())) {
               if (((List) validateToken(httpCookie.getValue()).get(AUTHORITIES)).size() > 0) {
                  exist.set(true);
               }
            }
         });
      }
      return exist.get();
   }

   /*
    * @method validateToken
    * @description Valida el token JWT y extrae los claims (reclamaciones) del token.
    */
   public Claims validateToken(String jwtToken) {
      return Jwts
            .parserBuilder()
            .setSigningKey(new SecretKeySpec(Base64.getDecoder().decode(jwtSecret.getBytes()), HS256.getJcaName()))
            .build()
            .parseClaimsJws(jwtToken)
            .getBody();
   }

   /*
    * @method excludedPath
    * @description Verifica si la ruta de la solicitud debe ser excluida de la validación del JWT. Contiene una lista de rutas que no requieren validación
    */
   public boolean excludedPath(String path) {
      return path.contains("/users_app_auth/login") || path.contains("/users_app_auth/validate_phone") || path.contains(
            "/users_app_auth/validate_mobile") || path.contains("/users_app_auth/send_new_pin") || path.contains("/users_app_auth/validate_sms_pin")
            || path.contains("/users_app_auth/validate_email") || path.contains("/users_app_auth/validate_email_pin") || path.contains(
            "/users_app_auth/forgot_password") || path.contains("/users_app_auth/fgval_email_pin") || path.contains("/users_app_auth/users_app_auth")
            || path.contains("/users_app/new_password") || path.contains("/actuator") || path.contains("/enum") || path.contains("users_app/create")
            || path.contains("/auth_rsa/login") || path.contains("/auth_rsa/initauth") || path.contains("/app_user_services/terms_conditions")
            || path.contains("/hierarchy/point_sales/digital_point_sale_by_municipality") || path.contains("/app_user_services/data_policy")
            || path.contains("/client/document_type/app_documents") || path.contains("/app_user_services/latest") || path.contains(
            "/users_app/document") || path.contains("/api/chance/parametros-bnet") || path.contains("/api/chance/validar-chance-bnet");
   }

}
