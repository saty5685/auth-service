package com.deezyWallet.auth_service.user.exception;

import org.springframework.http.HttpStatus;

import com.deezyWallet.auth_service.user.constants.UserErrorCode;

/**
 * Thrown when a login attempt is made on a temporarily locked account.
 *
 * Maps to HTTP 423 Locked (RFC 4918) — semantically correct.
 * 423 is rarely used but is the most precise status for "locked resource".
 * Most clients treat any 4xx as an error — the specific code is for
 * programmatic consumers who may want to show "try again in X minutes".
 */
public class AccountLockedException extends UserBaseException {
	public AccountLockedException(String message) {
		super(UserErrorCode.ACCOUNT_LOCKED, message, HttpStatus.LOCKED);
	}
}
