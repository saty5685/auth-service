package com.deezyWallet.auth_service.entities;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.deezyWallet.auth_service.dto.FieldErrorDetail;

public enum AuthErrorCodeEnums {
	USER_NOT_FOUND("AUTH_404", "User Not found."),
	INVALID_CREDENTIALS("AUTH_401", "Invalid Credentials."),
	TOKEN_EXPIRED("AUTH_403", "Token Expired."),
	ACCOUNT_LOCKED("AUTH_423", "Account Locked"),
	BAD_REQUEST("AUTH_400", "Bad Request");

	private final String errorCode;
	private String errorDescription;
	private List<FieldErrorDetail> errors;

	public String getErrorDescription() {
		return errorDescription;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public List<FieldErrorDetail> getErrors(){
		return errors;
	}

	AuthErrorCodeEnums(String errorCode, String errorDescription) {
		this.errorCode = errorCode;
		this.errorDescription = errorDescription;
	}

	AuthErrorCodeEnums(String errorCode, String errorDescription, List<FieldErrorDetail> errors) {
		this.errorCode = errorCode;
		this.errorDescription = errorDescription;
		this.errors=errors;
	}

	// Code to ensure error errorCode is unique
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
