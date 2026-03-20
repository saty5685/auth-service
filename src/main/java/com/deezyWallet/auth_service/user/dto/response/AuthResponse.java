package com.deezyWallet.auth_service.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Authentication response — covers all states of the login/register flow.
 *
 * The `status` field discriminates the response type so clients know
 * what action to take next:
 *
 *   SUCCESS          — both tokens present; user is fully authenticated
 *   PENDING_OTP      — registration complete, waiting for phone OTP
 *   MFA_REQUIRED     — password verified, waiting for TOTP code
 *
 * WHY embed UserProfileResponse in the auth response?
 *   Reduces client round-trips — after a successful login, the client
 *   already has the user profile without needing a second GET /me call.
 *
 * WHY no constructor overloads for each state?
 *   Static factory methods clearly communicate intent:
 *     AuthResponse.success(...)      vs new AuthResponse(SUCCESS, ...)
 *     AuthResponse.pendingOtp(...)   vs new AuthResponse(PENDING_OTP, ...)
 *   Easier to read in AuthService.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

	public enum Status { SUCCESS, PENDING_OTP, MFA_REQUIRED }

	private Status status;

	/** Present only when status = SUCCESS */
	private String accessToken;

	/** Present only when status = SUCCESS */
	private String refreshToken;

	/** Present only when status = SUCCESS */
	private UserProfileResponse profile;

	/** Present when status = PENDING_OTP or MFA_REQUIRED — needed to submit OTP/TOTP */
	private String userId;

	// ── Static factories ──────────────────────────────────────────────────────

	public static AuthResponse success(String accessToken, String refreshToken,
			UserProfileResponse profile) {
		return AuthResponse.builder()
				.status(Status.SUCCESS)
				.accessToken(accessToken)
				.refreshToken(refreshToken)
				.profile(profile)
				.build();
	}

	public static AuthResponse pendingOtp(String userId) {
		return AuthResponse.builder()
				.status(Status.PENDING_OTP)
				.userId(userId)
				.build();
	}

	public static AuthResponse mfaRequired(String userId) {
		return AuthResponse.builder()
				.status(Status.MFA_REQUIRED)
				.userId(userId)
				.build();
	}
}
