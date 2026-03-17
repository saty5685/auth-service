package com.deezyWallet.auth_service.user.enums;

/**
 * Audit-log action types — stored as VARCHAR in user_audit_log.
 *
 * Every entry in user_audit_log has one of these actions.
 * The table is append-only (compliance requirement).
 *
 * WHY an enum instead of free-text strings?
 *   Type safety: mistyped action strings silently skip audit entries.
 *   Queryability: WHERE action = 'LOGIN_SUCCESS' works reliably.
 *   Extensibility: adding a new action is a compile-time change, not a
 *   documentation update that might be missed.
 *
 * Stored as EnumType.STRING so the DB column is human-readable.
 */
public enum AuditAction {
	// Auth events
	REGISTER,
	OTP_VERIFIED,
	LOGIN_SUCCESS,
	LOGIN_FAILED,
	LOGOUT,
	TOKEN_REFRESHED,

	// Account lockout
	ACCOUNT_LOCKED,
	ACCOUNT_UNLOCKED,

	// Profile
	PASSWORD_CHANGED,
	PROFILE_UPDATED,
	PHONE_CHANGED,

	// MFA
	MFA_ENABLED,
	MFA_DISABLED,
	MFA_VERIFIED,

	// Admin actions
	ACCOUNT_SUSPENDED,
	ACCOUNT_REINSTATED,
	ACCOUNT_CLOSED,

	// KYC
	KYC_STATUS_UPDATED
}
