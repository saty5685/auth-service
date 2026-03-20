package com.deezyWallet.auth_service.user.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Confirms MFA setup by verifying the first TOTP code from the authenticator app.
 * Until this confirmation, mfaEnabled remains false on the User entity.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaConfirmRequest {

	@NotBlank
	@Pattern(regexp = "^\\d{6}$", message = "TOTP code must be exactly 6 digits")
	private String totpCode;
}
