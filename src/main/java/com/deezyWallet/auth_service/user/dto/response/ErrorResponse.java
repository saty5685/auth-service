package com.deezyWallet.auth_service.user.dto.response;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Uniform error response — every non-2xx response from this service.
 *
 * fieldErrors is only present for validation failures (400).
 * @JsonInclude(NON_NULL) ensures it's omitted from other error types.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

	private String            errorCode;
	private String            message;
	private LocalDateTime     timestamp;
	private List<FieldError>  fieldErrors;  // Only on 400 validation failures

	@Data
	@AllArgsConstructor
	public static class FieldError {
		private String field;
		private String message;
	}

	public static ErrorResponse of(String errorCode, String message) {
		return ErrorResponse.builder()
				.errorCode(errorCode)
				.message(message)
				.timestamp(LocalDateTime.now())
				.build();
	}

	public static ErrorResponse ofValidation(String errorCode, List<FieldError> fieldErrors) {
		return ErrorResponse.builder()
				.errorCode(errorCode)
				.message("Validation failed")
				.timestamp(LocalDateTime.now())
				.fieldErrors(fieldErrors)
				.build();
	}
}