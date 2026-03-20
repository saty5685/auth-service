package com.deezyWallet.auth_service.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login request — email + password only.
 *
 * WHY not validate password format here?
 *   On login we just need to check the hash — we don't care if the
 *   submitted password matches our current format rules. Users who
 *   registered before we tightened the regex should still be able to log in.
 *   Validation here is presence-only (not blank).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

	@NotBlank(message = "Email is required")
	@Email(message = "Invalid email format")
	private String email;

	@NotBlank(message = "Password is required")
	private String password;
}

