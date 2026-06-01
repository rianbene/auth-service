package com.ucsal.auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Desabilita CSRF pois APIs REST com JWT não sofrem desse ataque
            .csrf(csrf -> csrf.disable())            
            // Define que a API é Stateless (não guarda sessão em memória)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Configura as regras de rota
            .authorizeHttpRequests(authorize -> authorize
                // libera os endpoints de entrada
                .requestMatchers("/auth/login", "/auth/register").permitAll()
                // qualquer outra requisição neste microsserviço precisa de autenticação
                .anyRequest().authenticated()
            )
            // Informa ao Spring qual Provedor de Autenticação usar (definido em ApplicationConfig)
            .authenticationProvider(authenticationProvider);
        return http.build(); 
    }
}
