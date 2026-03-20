package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when an operation is blocked by the account's current status.
 *
 * Examples:
 *   - Login attempted on PENDING account (OTP not verified)
 *   - Login attempted on SUSPENDED account
 *   - Profile update attempted on SUSPENDED account
 *
 * HTTP status varies by context:
 *   SUSPENDED → 403 Forbidden (authenticated but blocked by policy)
 *   PENDING   → 403 Forbidden (not yet eligible)
 *   CLOSED    → 403 Forbidden (terminal state)
 */
public class AccountStatusException extends UserBaseException {
	public AccountStatusException(String errorCode, String message) {
		super(errorCode, message, HttpStatus.FORBIDDEN);
	}
}
