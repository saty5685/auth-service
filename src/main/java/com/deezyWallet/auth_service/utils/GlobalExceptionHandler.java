package com.deezyWallet.auth_service.utils;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.deezyWallet.auth_service.dto.ErrorDetail;
import com.deezyWallet.auth_service.exceptions.AuthServiceException;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(AuthServiceException.class)
	public ResponseEntity<ErrorDetail> handleAuthServiceException(AuthServiceException ex) {
		ErrorDetail err=new ErrorDetail(ex.getError().getErrorCode(), ex.getError().getErrorDescription());
		HttpStatus status = switch (ex.getError()) {
			case USER_NOT_FOUND -> HttpStatus.NOT_FOUND;
			case INVALID_CREDENTIALS -> HttpStatus.UNAUTHORIZED;
			case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
			default -> HttpStatus.BAD_REQUEST;
		};
		return new ResponseEntity<>(err, status);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
		Map<String, String> errors = new HashMap<>();

		ex.getBindingResult().getFieldErrors().forEach(error ->
				errors.put(error.getField(), error.getDefaultMessage())
		);

		return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
	}
}
