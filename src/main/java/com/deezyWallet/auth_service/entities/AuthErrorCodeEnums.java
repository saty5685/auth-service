package com.deezyWallet.auth_service.entities;

import java.util.HashSet;
import java.util.Set;

public enum AuthErrorCodeEnums {
	USER_NOT_FOUND("AUTH_404", "User Not found."),
	INVALID_CREDENTIALS("AUTH_401", "Invalid Credentials."),
	TOKEN_EXPIRED("AUTH_403", "Token Expired."),
	ACCOUNT_LOCKED("AUTH_423", "Account Locked");

	private final String errorCode;
	private String errorDescription;

	public String getErrorDescription() {
		return errorDescription;
	}

	public String getErrorCode() {
		return errorCode;
	}

	AuthErrorCodeEnums(String errorCode, String errorDescription) {
		this.errorCode = errorCode;
		this.errorDescription = errorDescription;
	}

	// Code to ensure error code is unique
	public static void validateErrorCodes() {
		Set<String> usedCodes = new HashSet<String>();
		for (AuthErrorCodeEnums ece : AuthErrorCodeEnums.values()) {
			if (!usedCodes.add(ece.errorCode)) {
				throw new IllegalArgumentException(ece.errorCode + " is already used!");
			}
		}
		usedCodes.clear();
	}
}
