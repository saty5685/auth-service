package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown for refresh token issues: invalid, expired, or revoked.
 *
 * Maps to HTTP 401 Unauthorized — the token does not grant access.
 * Client must re-authenticate (full login).
 */
public class TokenException extends UserBaseException {
	public TokenException(String errorCode, String message) {
		super(errorCode, message, HttpStatus.UNAUTHORIZED);
	}
}
