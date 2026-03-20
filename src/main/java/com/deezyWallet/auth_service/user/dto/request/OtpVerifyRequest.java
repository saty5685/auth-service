package com.deezyWallet.auth_service.user.dto.request;

import com.deezyWallet.auth_service.user.enums.OtpPurpose;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * OTP verification request.
 *
 * Used for both REGISTRATION OTP and MFA OTP flows.
 * The purpose discriminator tells the service which Redis namespace to check.
 *
 * WHY include userId vs phone?
 *   userId allows us to look up the stored phone number from DB without
 *   the client having to re-send it. Reduces surface area for phone spoofing.
 *   The userId was returned in the register/login response when OTP was initiated.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpVerifyRequest {

	@NotBlank(message = "User ID is required")
	private String userId;

	@NotNull(message = "OTP purpose is required")
	private OtpPurpose purpose;

	@NotBlank(message = "OTP code is required")
	@Pattern(regexp = "^\\d{6}$", message = "OTP must be exactly 6 digits")
	private String otpCode;
}
