package com.glic.mappgateway;

import java.util.Collections;

import static org.springframework.security.config.web.server.SecurityWebFiltersOrder.LAST;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;

import com.glic.mappgateway.auth.AuthFilter;
import com.glic.mappgateway.csrf.CustomCsrfWebFilter;
import com.glic.mappgateway.jwt.CustomJwtWebFilter;

import reactor.core.publisher.Mono;

@SpringBootApplication
@EnableDiscoveryClient
@EnableWebFluxSecurity
public class SuperflexMappGatewayApplication {

   public static void main(String[] args) {
      SpringApplication.run(SuperflexMappGatewayApplication.class, args);
   }

   /*
    * @method corsConfigurationSource
    * @description Configura seguridad pero principalmente gestiona headers, metodos y origenes, tambien registra la
    * configuracion para las rutas y nos permite gestionar el contenido del header
    */
   protected CorsConfigurationSource corsConfigurationSource() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration().applyPermitDefaultValues();
      config.addAllowedHeader("*");
      config.addAllowedMethod("*");
      config.setAllowedOriginPatterns(Collections.singletonList("*"));
      config.setAllowCredentials(true);
      config.addExposedHeader("Authorization");
      source.registerCorsConfiguration("/**", config);
      return source;
   }

   /*
    * @method securityWebFilterChain
    * @description Configuracion de seguridad
    */
   @Bean
   public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
      return http
            .requestCache()
              // Deshabilita el Cache Request
              .requestCache(NoOpServerRequestCache.getInstance())
              .and()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
              // Deshabilita login por default y autenticacion basica
              .formLogin().disable()
              .httpBasic().disable()
            // Habilita CORS con configuracion personalizada
            .cors().configurationSource(corsConfigurationSource())
              .and()
            // Deshabilita CSRF y logout
            .logout().disable()
            .csrf().disable()
             // Agrega filtros de autenticacion, jwt y csrf al final de la cadena de filtrado
            .addFilterAt(customAuthWebFilter(), LAST)
            .addFilterAt(customJwtWebFilter(), LAST)
            .addFilterAt(customCsrfWebFilter(), LAST)
            // Permite las transacciones sin autenticacion
            .authorizeExchange()
            .anyExchange()
              .permitAll()
               .and()
            .build();
   }

   // Bean del filtro CSRF
   @Bean
   public WebFilter customCsrfWebFilter() {
      return new CustomCsrfWebFilter();
   }

   // Bean del filtro JWT
   @Bean
   public WebFilter customJwtWebFilter() {
      return new CustomJwtWebFilter();
   }

   // Bean del filtro de autenticacion
   @Bean
   public WebFilter customAuthWebFilter() {
      return new AuthFilter();
   }

   // Bean para agregar token CSRF a los atributos de intercambio
   @Bean
   public WebFilter addCsrfToken() {
      return (serverWebExchange, webFilterChain) -> {
         // Genera token CSRF a partir de la transaccion
         Mono<CsrfToken> attribute = serverWebExchange.getAttribute(CsrfToken.class.getName());
         if (attribute != null) {
            // Si se cuenta con el Token CSRF continua con la cadena
            return attribute.doOnSuccess(CsrfToken::getToken).then(webFilterChain.filter(serverWebExchange));
         }
         return Mono.empty();
      };
   }

}
