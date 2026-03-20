package com.deezyWallet.auth_service.user.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Profile update request — only fields the user is allowed to change.
 *
 * WHY not include email or phone?
 *   Email and phone changes are sensitive operations — they affect login,
 *   OTP delivery, and fraud detection. They go through a separate verified
 *   flow (re-authentication + OTP) not included here.
 *   UpdateProfileRequest is for low-risk changes like name.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileRequest {

	@NotBlank(message = "First name is required")
	@Size(min = 1, max = 60)
	private String firstName;

	@NotBlank(message = "Last name is required")
	@Size(min = 1, max = 60)
	private String lastName;
}
