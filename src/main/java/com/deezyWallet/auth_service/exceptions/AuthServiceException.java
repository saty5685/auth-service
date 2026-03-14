package com.deezyWallet.auth_service.exceptions;

import java.util.List;

import com.deezyWallet.auth_service.dto.FieldErrorDetail;
import com.deezyWallet.auth_service.entities.AuthErrorCodeEnums;

public class AuthServiceException extends RuntimeException{
	private final AuthErrorCodeEnums authErrorCodeEnum;
	private final List<FieldErrorDetail> errors;

	public AuthServiceException(AuthErrorCodeEnums authErrorCodeEnum) {
		super(authErrorCodeEnum.getErrorDescription());
		this.authErrorCodeEnum = authErrorCodeEnum;
		this.errors=null;
	}

	public AuthServiceException(String message, AuthErrorCodeEnums authErrorCodeEnum, Throwable cause) {
		super(message, cause);
		this.authErrorCodeEnum = authErrorCodeEnum;
		this.errors=null;
	}

	public AuthServiceException(AuthErrorCodeEnums authErrorCodeEnum,
			List<FieldErrorDetail> errors) {

		super(authErrorCodeEnum.getErrorDescription());
		this.authErrorCodeEnum = authErrorCodeEnum;
		this.errors = errors;
	}

	public AuthErrorCodeEnums getError() {
		return authErrorCodeEnum;
	}

	public List<FieldErrorDetail> getFieldErrors() {
		return errors;
	}
}
