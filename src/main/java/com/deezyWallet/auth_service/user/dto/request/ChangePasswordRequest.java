package com.deezyWallet.auth_service.user.dto.request;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordRequest {

	@NotBlank(message = "Current password is required")
	private String currentPassword;

	@NotBlank(message = "New password is required")
	@Pattern(
			regexp = UserConstants.PASSWORD_PATTERN,
			message = "New password must meet complexity requirements"
	)
	private String newPassword;
}
