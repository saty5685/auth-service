package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

/**
 * Authentication failure — wrong credentials, expired token, invalid OTP flow.
 *
 * ALWAYS maps to HTTP 401 Unauthorized.
 * ALWAYS returns a vague message externally — never reveals which
 * field was wrong (email vs password).
 */
public class AuthException extends UserBaseException {
	public AuthException(String errorCode, String message) {
		super(errorCode, message, HttpStatus.UNAUTHORIZED);
	}
}
