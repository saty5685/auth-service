package com.deezyWallet.auth_service.utils;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.deezyWallet.auth_service.dto.ErrorDetail;
import com.deezyWallet.auth_service.exceptions.AuthServiceException;

@RestControllerAdvice
public class GlobalExceptionHandler {
	Logger logger= LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(AuthServiceException.class)
	public ResponseEntity<ErrorDetail> handleAuthServiceException(AuthServiceException ex) {
		ErrorDetail err=new ErrorDetail(ex.getError().getErrorCode(), ex.getError().getErrorDescription());
		if(ex.getFieldErrors()!=null && !ex.getFieldErrors().isEmpty()){
			err.setErrors(ex.getFieldErrors());
		}
		HttpStatus status = switch (ex.getError()) {
			case USER_NOT_FOUND -> HttpStatus.NOT_FOUND;
			case INVALID_CREDENTIALS -> HttpStatus.UNAUTHORIZED;
			case ACCOUNT_LOCKED -> HttpStatus.LOCKED;
			case BAD_REQUEST -> HttpStatus.BAD_REQUEST;
			default -> HttpStatus.BAD_REQUEST;
		};
		return new ResponseEntity<>(err, status);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
		Map<String, String> errors = new HashMap<>();
		logger.info(ex.getMessage(), ex);
		ex.getBindingResult().getFieldErrors().forEach(error ->
				errors.put(error.getField(), error.getDefaultMessage())
		);

		return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(RuntimeException.class)
	public ResponseEntity<ErrorDetail> handleGeneralExceptions(RuntimeException ex) {
		ErrorDetail err=new ErrorDetail("500", ex.getMessage());
		logger.info(ex.getMessage(), ex);
		return new ResponseEntity<>(err, HttpStatus.INTERNAL_SERVER_ERROR);
	}
}
