package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

import com.deezyWallet.auth_service.user.constants.UserErrorCode;

/**
 * Thrown for internal lookups by ID that find no user.
 *
 * Maps to HTTP 404 Not Found.
 *
 * USAGE GUIDELINE:
 *   Use only for internal/admin endpoints where the caller already knows
 *   the userId (e.g. admin looking up a user by ID, internal service call).
 *   NEVER throw this from a login path — use AuthException instead
 *   to prevent user enumeration via error code differences.
 */
public class UserNotFoundException extends UserBaseException {
	public UserNotFoundException(String message) {
		super(UserErrorCode.USER_NOT_FOUND, message, HttpStatus.NOT_FOUND);
	}
}
