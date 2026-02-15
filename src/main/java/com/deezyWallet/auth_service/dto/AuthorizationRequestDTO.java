package com.deezyWallet.auth_service.dto;


import jakarta.validation.constraints.NotBlank;

public record AuthorizationRequestDTO(
		@NotBlank
		String username,
		@NotBlank
		String password
) {
}
