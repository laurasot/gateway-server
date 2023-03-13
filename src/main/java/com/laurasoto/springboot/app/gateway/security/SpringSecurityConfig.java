package com.laurasoto.springboot.app.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
public class SpringSecurityConfig {
    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http){
        return http.authorizeExchange()
                .pathMatchers("/api/security/oauth/**").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/productos/listar", "/api/items/listar", "/api/usuarios/usuarios", "/api/items/listar/{id}/cantidad/{cantidad}", "/api/productos/listar/{id}").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/usuarios/usuarios/{id}").hasAnyRole("ADMIN", "USER")
                .pathMatchers("/api/productos/**", "/api/usuarios/usuarios/**", "/api/items/**").hasRole("ADMIN")
                .anyExchange().authenticated()
                .and().csrf().disable()
                .build();
    }
}
