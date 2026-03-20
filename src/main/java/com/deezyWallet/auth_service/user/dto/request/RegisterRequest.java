package com.deezyWallet.auth_service.user.dto.request;

import com.deezyWallet.auth_service.user.constants.UserConstants;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Registration request DTO.
 *
 * WHY validate phone with a pattern?
 *   E.164 format (+91XXXXXXXXXX) is the international standard.
 *   We enforce it at the API boundary so all downstream code can
 *   assume a normalized, dialable phone number.
 *   Pattern: + followed by 1-3 digit country code followed by 7-12 digits.
 *
 * WHY a password pattern instead of just @Size?
 *   Length alone doesn't guarantee complexity. Pattern enforces:
 *   - At least one uppercase letter
 *   - At least one lowercase letter
 *   - At least one digit
 *   - At least one special character
 *   This aligns with NIST SP 800-63B password strength recommendations.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

	@NotBlank(message = "Email is required")
	@Email(message = "Invalid email format")
	@Size(max = 100, message = "Email must not exceed 100 characters")
	private String email;

	@NotBlank(message = "Phone number is required")
	@Pattern(
			regexp = "^\\+[1-9]\\d{7,14}$",
			message = "Phone number must be in E.164 format (e.g. +919876543210)"
	)
	private String phoneNumber;

	@NotBlank(message = "Password is required")
	@Pattern(
			regexp = UserConstants.PASSWORD_PATTERN,
			message = "Password must be 8-128 characters and contain at least one uppercase, lowercase, digit, and special character (@$!%*?&)"
	)
	private String password;

	@NotBlank(message = "First name is required")
	@Size(min = 1, max = 60, message = "First name must be between 1 and 60 characters")
	private String firstName;

	@NotBlank(message = "Last name is required")
	@Size(min = 1, max = 60, message = "Last name must be between 1 and 60 characters")
	private String lastName;
}

