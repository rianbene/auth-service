package com.ucsal.auth_service.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ucsal.auth_service.controller.dto.AuthResponseDTO;
import com.ucsal.auth_service.controller.dto.LoginRequestDTO;
import com.ucsal.auth_service.controller.dto.RegisterRequestDTO;
import com.ucsal.auth_service.model.Usuario;
import com.ucsal.auth_service.repository.UsuarioRepository;
import com.ucsal.auth_service.security.TokenService;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UsuarioRepository repository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@RequestBody LoginRequestDTO data) {
        //cria uma variavel temporaria apenas com login e senha digitados
        var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.senha());
        //o spring security vai no banco, encontra o usuario e compara a senha com o BCrypt
        var auth = this.authenticationManager.authenticate(usernamePassword);
        //se encontrar o par login e senha, geramos o token JWT
        var token = tokenService.generateToken((Usuario) auth.getPrincipal());
        return ResponseEntity.ok(new AuthResponseDTO(token));
    }
    
    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody RegisterRequestDTO data) {
        // se ja tiver esse login, impede o registro
        if (this.repository.findByLogin(data.login()).isPresent()){
            return ResponseEntity.badRequest().build();
        }
        String encryptedPassword = passwordEncoder.encode(data.senha());
        Usuario newUser = new Usuario(null, data.login(), encryptedPassword, data.role());
        this.repository.save(newUser);
        return ResponseEntity.ok().build();
    }
    
}
