package com.glic.mappgateway;

import java.util.Collections;

import static org.springframework.security.config.web.server.SecurityWebFiltersOrder.LAST;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
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

   @Bean
   public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
      return http
            .requestCache()
            .requestCache(NoOpServerRequestCache.getInstance())
            .and()
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .formLogin()
            .disable()
            .httpBasic()
            .disable()
            .cors()
            .configurationSource(corsConfigurationSource())
            .and()
            .logout()
            .disable()
            .csrf()
            .disable()
            .addFilterAt(customAuthWebFilter(), LAST)
            .addFilterAt(customJwtWebFilter(), LAST)
            .addFilterAt(customCsrfWebFilter(), LAST)
            .authorizeExchange()
            .anyExchange()
            .permitAll()
            .and()
            .build();
   }

   @Bean
   public WebFilter customCsrfWebFilter() {
      return new CustomCsrfWebFilter();
   }

   @Bean
   public WebFilter customJwtWebFilter() {
      return new CustomJwtWebFilter();
   }

   @Bean
   public WebFilter customAuthWebFilter() {
      return new AuthFilter();
   }

   @Bean
   public WebFilter addCsrfToken() {
      return (serverWebExchange, webFilterChain) -> {
         Mono<CsrfToken> attribute = serverWebExchange.getAttribute(CsrfToken.class.getName());
         if (attribute != null) {
            return attribute.doOnSuccess(CsrfToken::getToken).then(webFilterChain.filter(serverWebExchange));
         }
         return Mono.empty();
      };
   }

}
