package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;

/**
 * Abstract base for all User Service domain exceptions.
 *
 * Carries:
 *   errorCode  → stable string from UserErrorCode (machine-readable)
 *   httpStatus → the HTTP status this exception maps to
 *   message    → human-readable detail (never exposes internal state)
 *
 * GlobalExceptionHandler catches UserBaseException and uses these fields
 * to build a consistent ErrorResponse without a handler per subclass.
 */
@Getter
public abstract class UserBaseException extends RuntimeException {

	private final String     errorCode;
	private final HttpStatus httpStatus;

	protected UserBaseException(String errorCode, String message, HttpStatus httpStatus) {
		super(message);
		this.errorCode  = errorCode;
		this.httpStatus = httpStatus;
	}
}
