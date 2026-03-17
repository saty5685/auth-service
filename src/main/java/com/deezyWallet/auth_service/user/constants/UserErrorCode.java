package com.deezyWallet.auth_service.user.constants;

/**
 * Stable string error codes for all User Service exceptions.
 *
 * Returned in ErrorResponse.errorCode so API consumers can programmatically
 * distinguish error types without parsing human-readable messages.
 *
 * WHY string constants instead of an enum?
 *   Same reason as Wallet Service — string constants can be used in
 *   @interface values (e.g. custom annotations), switch statements without
 *   fully-qualified names, and serialized directly without .name() call.
 *   Also avoids the JVM overhead of Enum.values() in hot paths.
 *
 * Stability contract: once a code is deployed, it MUST NOT be renamed.
 *   Consumers may depend on these strings. Treat them as public API.
 *   Deprecate old codes with @Deprecated, never delete or rename.
 */
public final class UserErrorCode {

	private UserErrorCode() {}

	// ── Registration ──────────────────────────────────────────────────────────
	public static final String EMAIL_ALREADY_EXISTS     = "EMAIL_ALREADY_EXISTS";
	public static final String PHONE_ALREADY_EXISTS     = "PHONE_ALREADY_EXISTS";

	// ── Authentication ────────────────────────────────────────────────────────
	/**
	 * Generic auth failure — intentionally vague.
	 * Used for both wrong email AND wrong password to prevent user enumeration.
	 * Never expose which of the two failed.
	 */
	public static final String AUTH_FAILED              = "AUTH_FAILED";
	public static final String ACCOUNT_LOCKED           = "ACCOUNT_LOCKED";
	public static final String ACCOUNT_SUSPENDED        = "ACCOUNT_SUSPENDED";
	public static final String ACCOUNT_PENDING          = "ACCOUNT_PENDING";
	public static final String ACCOUNT_CLOSED           = "ACCOUNT_CLOSED";

	// ── OTP ───────────────────────────────────────────────────────────────────
	public static final String OTP_INVALID              = "OTP_INVALID";
	public static final String OTP_EXPIRED              = "OTP_EXPIRED";
	public static final String OTP_MAX_ATTEMPTS         = "OTP_MAX_ATTEMPTS_EXCEEDED";

	// ── Token ─────────────────────────────────────────────────────────────────
	public static final String TOKEN_EXPIRED            = "TOKEN_EXPIRED";
	public static final String TOKEN_INVALID            = "TOKEN_INVALID";
	public static final String TOKEN_REVOKED            = "TOKEN_REVOKED";
	public static final String MFA_REQUIRED             = "MFA_REQUIRED";

	// ── User operations ───────────────────────────────────────────────────────
	public static final String USER_NOT_FOUND           = "USER_NOT_FOUND";
	public static final String INVALID_CURRENT_PASSWORD = "INVALID_CURRENT_PASSWORD";
	public static final String MFA_ALREADY_ENABLED      = "MFA_ALREADY_ENABLED";
	public static final String MFA_NOT_ENABLED          = "MFA_NOT_ENABLED";
	public static final String MFA_TOTP_INVALID         = "MFA_TOTP_INVALID";

	// ── Generic ───────────────────────────────────────────────────────────────
	public static final String VALIDATION_FAILED        = "VALIDATION_FAILED";
	public static final String INTERNAL_ERROR           = "INTERNAL_ERROR";
	public static final String ACCESS_DENIED            = "ACCESS_DENIED";
}
