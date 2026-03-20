package com.deezyWallet.auth_service.user.dto.response;

import java.time.LocalDateTime;

import com.deezyWallet.auth_service.user.enums.KycStatus;
import com.deezyWallet.auth_service.user.enums.UserStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Public-facing user profile — fields safe to return to the client.
 *
 * WHY no passwordHash, mfaSecret, failedLoginAttempts, lockedUntil?
 *   These are internal security fields. They must NEVER appear in any
 *   API response. The mapper explicitly picks safe fields only.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse {

	private String      userId;
	private String      email;
	private String      phoneNumber;
	private String      firstName;
	private String      lastName;
	private UserStatus  status;
	private KycStatus   kycStatus;
	private boolean     mfaEnabled;
	private LocalDateTime createdAt;
	private LocalDateTime lastLoginAt;
}
