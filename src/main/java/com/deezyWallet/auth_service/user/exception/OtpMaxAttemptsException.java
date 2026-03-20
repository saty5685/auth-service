package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

import com.deezyWallet.auth_service.user.constants.UserErrorCode;

/**
 * Thrown when the OTP attempt limit is exceeded.
 *
 * Maps to HTTP 429 Too Many Requests — rate limit exceeded.
 * The OTP has been invalidated; a new one must be requested.
 */
public class OtpMaxAttemptsException extends UserBaseException {
	public OtpMaxAttemptsException(String message) {
		super(UserErrorCode.OTP_MAX_ATTEMPTS, message, HttpStatus.TOO_MANY_REQUESTS);
	}
}
