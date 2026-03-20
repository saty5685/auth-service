package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when an OTP submission is incorrect or the OTP has expired.
 *
 * Maps to HTTP 400 Bad Request — the submitted value is invalid.
 * (Not 401 — the user is not trying to authenticate, they're verifying a code.)
 */
public class InvalidOtpException extends UserBaseException {
	public InvalidOtpException(String errorCode, String message) {
		super(errorCode, message, HttpStatus.BAD_REQUEST);
	}
}
