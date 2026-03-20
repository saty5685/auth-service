package com.deezyWallet.auth_service.user.mapper;

import org.springframework.stereotype.Component;

import com.deezyWallet.auth_service.user.dto.response.UserProfileResponse;
import com.deezyWallet.auth_service.user.dto.response.UserStatusResponse;
import com.deezyWallet.auth_service.user.entity.User;

/**
 * Hand-written mapper — no MapStruct.
 *
 * WHY hand-written?
 *   UserProfileResponse deliberately omits security-sensitive fields
 *   (passwordHash, mfaSecret, lockedUntil, failedLoginAttempts).
 *   MapStruct would map all matching fields by default — an incorrect
 *   config annotation could accidentally expose these fields.
 *   A hand-written mapper makes the safe-field selection explicit and
 *   visible in code review.
 *
 * All methods are stateless and static-eligible, but @Component allows
 * injection for testing and future extension.
 */
@Component
public class UserMapper {

	/**
	 * Maps User entity to the profile response safe for client consumption.
	 * EXPLICITLY omits: passwordHash, mfaSecret, failedLoginAttempts, lockedUntil.
	 */
	public UserProfileResponse toProfileResponse(User user) {
		if (user == null) return null;
		return UserProfileResponse.builder()
				.userId(user.getId())
				.email(user.getEmail())
				.phoneNumber(user.getPhoneNumber())
				.firstName(user.getFirstName())
				.lastName(user.getLastName())
				.status(user.getStatus())
				.kycStatus(user.getKycStatus())
				.mfaEnabled(user.isMfaEnabled())
				.createdAt(user.getCreatedAt())
				.lastLoginAt(user.getLastLoginAt())
				.build();
	}

	/**
	 * Maps User to minimal status response for internal service calls.
	 * Contains only what other services need — no personal data.
	 */
	public UserStatusResponse toStatusResponse(User user) {
		if (user == null) return null;
		return UserStatusResponse.builder()
				.userId(user.getId())
				.status(user.getStatus())
				.kycStatus(user.getKycStatus())
				.canTransact(user.getStatus().canTransact())
				.loginLocked(user.isLoginLocked())
				.build();
	}
}

