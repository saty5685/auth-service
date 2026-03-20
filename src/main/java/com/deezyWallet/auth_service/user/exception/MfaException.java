package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown for MFA-related errors: invalid TOTP, MFA already enabled, etc.
 *
 * Maps to HTTP 400 Bad Request for invalid TOTP codes.
 * Maps to HTTP 409 Conflict for already-enabled / not-enabled state errors.
 *
 * WHY a single exception class for both?
 *   The errorCode field distinguishes them programmatically.
 *   Using two classes (MfaConflictException + MfaInvalidException) would
 *   require two handlers and adds class proliferation for minor distinctions.
 */
public class MfaException extends UserBaseException {
	public MfaException(String errorCode, String message) {
		super(errorCode, message, HttpStatus.BAD_REQUEST);
	}
}
