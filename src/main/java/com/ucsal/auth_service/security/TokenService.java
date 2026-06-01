package com.ucsal.auth_service.security;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.ucsal.auth_service.model.Usuario;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(Usuario usuario){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withIssuer("autenticador-clinica-ucsal")
                    .withSubject(usuario.getLogin()) // o assunto do token é o login do usuario
                    .withClaim("id", usuario.getId())  // adiciona o id de usuario como claim
                    .withClaim("role", usuario.getRole().name()) // adiciona a role do usuario como claim
                    .withExpiresAt(genExpirationDate())
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            throw new RuntimeException("Erro ao gerar token JWT", e);   
        }
    }

    private Instant genExpirationDate() {
        // Gera o tempo de expiração de 2h após gerar o token JWT
        // considerando o fuso horário do Brasil (-03:00)
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
