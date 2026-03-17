package com.deezyWallet.auth_service.user.enums;

/**
 * The business purpose of a one-time password.
 *
 * Included in the Redis key to namespace OTPs by purpose:
 *   otp:{purpose}:{phoneNumber}
 *
 * WHY namespace by purpose?
 *   Without namespacing, a REGISTRATION OTP could be used as an MFA OTP.
 *   A user who has received a registration OTP and hasn't verified yet could
 *   have their MFA bypass attempted with that same code.
 *   Separate keys = separate TTLs = separate consume-once semantics per purpose.
 *
 * TTLs by purpose:
 *   REGISTRATION    — 10 minutes (new users are motivated, longer = risk)
 *   MFA             — 3 minutes  (shorter window, higher security)
 *   PASSWORD_RESET  — 10 minutes
 *   PHONE_CHANGE    — 5 minutes
 */
public enum OtpPurpose {
	REGISTRATION(600),   // 10 min in seconds
	MFA(180),            // 3 min
	PASSWORD_RESET(600), // 10 min
	PHONE_CHANGE(300);   // 5 min

	private final int ttlSeconds;

	OtpPurpose(int ttlSeconds) {
		this.ttlSeconds = ttlSeconds;
	}

	public int getTtlSeconds() {
		return ttlSeconds;
	}
}
