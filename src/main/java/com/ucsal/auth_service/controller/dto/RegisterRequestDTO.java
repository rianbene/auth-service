package com.ucsal.auth_service.controller.dto;

import com.ucsal.auth_service.model.Role;

public record RegisterRequestDTO(String login, String senha, Role role) {

}
