package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

/**
 * Thrown when registration is attempted with an already-registered email or phone.
 *
 * Maps to HTTP 409 Conflict — the resource (user) already exists.
 *
 * WHY expose this as a distinct error (vs generic AUTH_FAILED)?
 *   Registration duplicate is not a security-sensitive path — the user
 *   is not authenticated yet and is providing new credentials.
 *   Telling a registering user "that email is taken" is useful UX.
 *   Contrast with login failures, where we never confirm email existence.
 */
public class UserAlreadyExistsException extends UserBaseException {
	public UserAlreadyExistsException(String errorCode, String message) {
		super(errorCode, message, HttpStatus.CONFLICT);
	}
}
