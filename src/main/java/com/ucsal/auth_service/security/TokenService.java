package com.ucsal.auth_service.security;

import org.springframework.beans.factory.annotation.Value;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.ucsal.auth_service.model.Usuario;

public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(Usuario usuario){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withIssuer("autenticador-clinica-ucsal")
                    .withSubject(usuario.getLogin()) // o assunto do token é o login do usuario
                    .withClaim("id", usuario.getId()) 
                    .withClaim("role", usuario.getRole().name()) // adiciona a role do usuario como claim
                    .sign(algorithm);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar token JWT", e);   
        }
    }
}
