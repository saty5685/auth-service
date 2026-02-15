package com.deezyWallet.auth_service.dto;

import java.util.Set;

import com.deezyWallet.auth_service.entities.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UserRegistrationRequestDTO(
@NotBlank
String username,
@NotBlank
String password,
@Email
@NotBlank
String email,
Set<Role> roles
) {
}
