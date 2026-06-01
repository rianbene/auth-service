package com.ucsal.auth_service.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.ucsal.auth_service.model.Usuario;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    // metodo para buscar o usuario no banco pelo login
    Optional<Usuario> findByLogin(String login);
}
