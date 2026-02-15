package com.deezyWallet.auth_service.exceptions;

import com.deezyWallet.auth_service.entities.AuthErrorCodeEnums;

public class AuthServiceException extends RuntimeException{
	private final AuthErrorCodeEnums authErrorCodeEnum;

	public AuthServiceException(AuthErrorCodeEnums authErrorCodeEnum) {
		super(authErrorCodeEnum.getErrorDescription());
		this.authErrorCodeEnum = authErrorCodeEnum;
	}

	public AuthServiceException(String message, AuthErrorCodeEnums authErrorCodeEnum, Throwable cause) {
		super(message, cause);
		this.authErrorCodeEnum = authErrorCodeEnum;
	}

	public AuthErrorCodeEnums getError() {
		return authErrorCodeEnum;
	}
}
